"""Artefact uploads (logo, HTML, screenshot, certificate) used as investigation inputs and pivots."""

from __future__ import annotations

import io
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from PIL import Image, UnidentifiedImageError

from app.analysis.brand import assess_brand
from app.analysis.content import classify_content
from app.api.deps import client_ip, db_dep, require, runner_dep
from app.collectors.tls import parse_certificate
from app.collectors.web import decode_body
from app.core.config import get_settings
from app.core.security import Permission
from app.db.mongo import Collections, get_fs
from app.fingerprints.images import hash_similarity, image_fingerprints
from app.fingerprints.similarity import simhash_similarity
from app.fingerprints.website import extract_website_fingerprints
from app.models.common import AssetType
from app.models.investigation import InvestigationOptions
from app.models.user import CurrentUser
from app.pipeline.runner import PipelineRunner
from app.repositories.artifacts import ArtifactRepository
from app.repositories.assets import AssetRepository
from app.services.audit import audit

router = APIRouter(prefix="/upload", tags=["Uploads"])
SCAN_LIMIT = 5000
MATCH_LIMIT = 100
IMAGE_TYPES = {"PNG", "JPEG", "GIF", "WEBP", "BMP", "ICO", "TIFF"}


async def _read(upload: UploadFile) -> bytes:
    limit = get_settings().max_upload_bytes
    content = await upload.read(limit + 1)
    if not content:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty upload")
    if len(content) > limit:
        raise HTTPException(413, f"Upload exceeds {limit // (1024 * 1024)} MB")
    return content


def _image_format(content: bytes) -> str:
    try:
        with Image.open(io.BytesIO(content)) as img:
            img.verify()
            fmt = img.format or ""
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError) as exc:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "File is not a supported image") from exc
    if fmt not in IMAGE_TYPES:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, f"Unsupported image format {fmt}")
    return fmt


def _match(doc: dict[str, Any], similarity: float, via: str) -> dict[str, Any]:
    return {
        "id": doc["_id"],
        "type": doc["type"],
        "value": doc["value"],
        "status": doc.get("status"),
        "confidence": doc.get("confidence"),
        "similarity": round(similarity, 3),
        "via": via,
    }


async def _image_matches(db, phash: str, threshold: float) -> list[dict[str, Any]]:
    cursor = (
        db[Collections.ASSETS]
        .find(
            {
                "$or": [
                    {"fingerprints.logo_phash": {"$exists": True}},
                    {"fingerprints.logo_phashes.0": {"$exists": True}},
                    {"fingerprints.favicon_phash": {"$ne": None}},
                    {"fingerprints.screenshot_phash": {"$ne": None}},
                ]
            },
            {
                "type": 1,
                "value": 1,
                "status": 1,
                "confidence": 1,
                "fingerprints.logo_phash": 1,
                "fingerprints.logo_phashes": 1,
                "fingerprints.favicon_phash": 1,
                "fingerprints.screenshot_phash": 1,
                "attributes.reference": 1,
            },
        )
        .limit(SCAN_LIMIT)
    )
    matches: list[dict[str, Any]] = []
    async for doc in cursor:
        fp = doc.get("fingerprints") or {}
        candidates = (
            [("logo", fp.get("logo_phash"))]
            + [("logo", h) for h in fp.get("logo_phashes") or []]
            + [("favicon", fp.get("favicon_phash")), ("screenshot", fp.get("screenshot_phash"))]
        )
        best = max(((hash_similarity(phash, h), via) for via, h in candidates if h), default=(0.0, ""))
        if best[0] >= threshold:
            matches.append(_match(doc, best[0], best[1]))
    return sorted(matches, key=lambda m: m["similarity"], reverse=True)[:MATCH_LIMIT]


@router.post("/logo", summary="Upload a brand logo: register as brand reference and find visually similar assets")
async def upload_logo(
    request: Request,
    file: UploadFile = File(..., description="PNG/JPEG/GIF/WEBP/ICO logo"),
    brand: str | None = Form(None, max_length=128),
    reference: bool = Form(True, description="Use as brand reference for impersonation scoring"),
    threshold: float = Form(0.85, ge=0.5, le=1.0),
    user: CurrentUser = Depends(require(Permission.UPLOAD)),
    db=Depends(db_dep),
) -> dict[str, Any]:
    content = await _read(file)
    fmt = _image_format(content)
    fp = image_fingerprints(content)
    art = await ArtifactRepository(db, get_fs()).store_file(
        "upload_logo",
        content,
        filename=file.filename or "logo",
        content_type=f"image/{fmt.lower()}",
        metadata={"brand": brand, "uploaded_by": user.username},
    )
    asset = await AssetRepository(db).upsert(
        AssetType.LOGO,
        fp["sha256"],
        source="upload",
        attributes={
            "reference": bool(reference and brand),
            "brand": brand,
            "brand_lc": brand.strip().lower() if brand else None,
            "file_id": art["file_id"],
            "filename": file.filename,
            "phash": fp.get("phash"),
            "ahash": fp.get("ahash"),
            "dhash": fp.get("dhash"),
            "uploaded_by": user.username,
        },
        fingerprints={"logo_phash": fp.get("phash"), "logo_ahash": fp.get("ahash"), "logo_dhash": fp.get("dhash")},
    )
    matches = [m for m in await _image_matches(db, fp["phash"], threshold) if m["id"] != asset["_id"]]
    await audit(
        "upload.logo",
        username=user.username,
        role=user.role,
        resource_type="asset",
        resource_id=asset["_id"],
        ip=client_ip(request),
        details={"brand": brand, "matches": len(matches)},
    )
    return {
        "asset_id": asset["_id"],
        "file_id": art["file_id"],
        "fingerprints": fp,
        "reference": bool(reference and brand),
        "brand": brand,
        "matches": matches,
    }


@router.post("/screenshot", summary="Upload a screenshot and find visually similar pages")
async def upload_screenshot(
    request: Request,
    file: UploadFile = File(...),
    threshold: float = Form(0.82, ge=0.5, le=1.0),
    user: CurrentUser = Depends(require(Permission.UPLOAD)),
    db=Depends(db_dep),
) -> dict[str, Any]:
    content = await _read(file)
    fmt = _image_format(content)
    fp = image_fingerprints(content)
    art = await ArtifactRepository(db, get_fs()).store_file(
        "upload_screenshot",
        content,
        filename=file.filename or "screenshot",
        content_type=f"image/{fmt.lower()}",
        metadata={"uploaded_by": user.username, **{k: fp.get(k) for k in ("phash", "dhash", "ahash")}},
    )
    cursor = (
        db[Collections.ASSETS]
        .find(
            {"fingerprints.screenshot_phash": {"$ne": None}},
            {
                "type": 1,
                "value": 1,
                "status": 1,
                "confidence": 1,
                "fingerprints.screenshot_phash": 1,
                "fingerprints.screenshot_dhash": 1,
            },
        )
        .limit(SCAN_LIMIT)
    )
    matches = []
    async for doc in cursor:
        f = doc.get("fingerprints") or {}
        sim = max(
            hash_similarity(fp.get("phash"), f.get("screenshot_phash")),
            hash_similarity(fp.get("dhash"), f.get("screenshot_dhash")),
        )
        if sim >= threshold:
            matches.append(_match(doc, sim, "screenshot"))
    matches.sort(key=lambda m: m["similarity"], reverse=True)
    await audit(
        "upload.screenshot",
        username=user.username,
        role=user.role,
        ip=client_ip(request),
        details={"matches": len(matches)},
    )
    return {"file_id": art["file_id"], "fingerprints": fp, "matches": matches[:MATCH_LIMIT]}


@router.post("/html", summary="Upload page HTML: extract fingerprints and pivot on trackers, title and structure")
async def upload_html(
    request: Request,
    file: UploadFile = File(...),
    page_url: str = Form("https://uploaded.local/", max_length=2048),
    brand: str | None = Form(None, max_length=128),
    user: CurrentUser = Depends(require(Permission.UPLOAD)),
    db=Depends(db_dep),
) -> dict[str, Any]:
    content = await _read(file)
    html = decode_body(content, file.content_type)
    if "<" not in html[:5000]:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "File does not look like HTML")
    fp = extract_website_fingerprints(html, page_url)
    art = await ArtifactRepository(db, get_fs()).store_file(
        "upload_html",
        content,
        filename=file.filename or "page.html",
        content_type="text/plain; charset=utf-8",
        metadata={"uploaded_by": user.username, "page_url": page_url},
    )
    verdict = classify_content(
        status_code=200,
        html=html,
        text=fp.get("text_excerpt"),
        title=fp.get("title"),
        word_count=fp.get("word_count"),
        has_login_form=bool(fp.get("has_login_form")),
    )
    host = page_url.split("//", 1)[-1].split("/", 1)[0] or "uploaded.local"
    brand_result = assess_brand(host, fp, brand=brand)
    matches: dict[str, dict[str, Any]] = {}
    if fp.get("tracking_ids"):
        async for doc in (
            db[Collections.ASSETS]
            .find(
                {"fingerprints.tracking_ids": {"$in": fp["tracking_ids"]}},
                {"type": 1, "value": 1, "status": 1, "confidence": 1, "fingerprints.tracking_ids": 1},
            )
            .limit(MATCH_LIMIT)
        ):
            shared = sorted(set(fp["tracking_ids"]) & set((doc.get("fingerprints") or {}).get("tracking_ids", [])))
            matches[doc["_id"]] = {**_match(doc, 1.0, "tracking_id"), "shared": shared}
    if fp.get("title_hash"):
        async for doc in (
            db[Collections.ASSETS]
            .find({"fingerprints.title_hash": fp["title_hash"]}, {"type": 1, "value": 1, "status": 1, "confidence": 1})
            .limit(MATCH_LIMIT)
        ):
            matches.setdefault(doc["_id"], _match(doc, 1.0, "title"))
    if fp.get("dom_simhash"):
        async for doc in (
            db[Collections.ASSETS]
            .find(
                {"fingerprints.html_simhash": {"$ne": None}},
                {"type": 1, "value": 1, "status": 1, "confidence": 1, "fingerprints.html_simhash": 1},
            )
            .limit(SCAN_LIMIT)
        ):
            sim = simhash_similarity(fp["dom_simhash"], (doc.get("fingerprints") or {}).get("html_simhash"))
            if sim >= 0.9:
                matches.setdefault(doc["_id"], _match(doc, sim, "html_structure"))
    await audit(
        "upload.html",
        username=user.username,
        role=user.role,
        ip=client_ip(request),
        details={"tracking_ids": fp.get("tracking_ids"), "matches": len(matches)},
    )
    return {
        "file_id": art["file_id"],
        "fingerprints": {
            k: fp.get(k)
            for k in (
                "title",
                "title_hash",
                "meta",
                "forms",
                "has_login_form",
                "password_fields",
                "external_form_actions",
                "trackers",
                "tracking_ids",
                "technologies",
                "logo_candidates",
                "dom_simhash",
                "text_simhash",
                "telegram_exfil",
                "crypto_wallets",
                "emails",
                "word_count",
            )
        },
        "content": verdict.to_dict(),
        "brand": brand_result.to_dict(),
        "matches": sorted(matches.values(), key=lambda m: m["similarity"], reverse=True)[:MATCH_LIMIT],
    }


@router.post(
    "/certificate", summary="Upload a PEM/DER certificate: fingerprint, match inventory, optionally investigate"
)
async def upload_certificate(
    request: Request,
    file: UploadFile = File(...),
    investigate: bool = Form(False),
    user: CurrentUser = Depends(require(Permission.UPLOAD)),
    runner: PipelineRunner = Depends(runner_dep),
    db=Depends(db_dep),
) -> dict[str, Any]:
    content = await _read(file)
    try:
        if b"-----BEGIN CERTIFICATE-----" in content:
            der = x509.load_pem_x509_certificate(content).public_bytes(serialization.Encoding.DER)
        else:
            der = x509.load_der_x509_certificate(content).public_bytes(serialization.Encoding.DER)
        cert = parse_certificate(der)
    except ValueError as exc:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Not a valid PEM or DER X.509 certificate") from exc
    asset = await AssetRepository(db).upsert(
        AssetType.CERTIFICATE,
        cert["sha256"],
        source="upload",
        attributes={
            k: cert.get(k)
            for k in (
                "sha1",
                "subject",
                "issuer",
                "issuer_org",
                "san",
                "not_before",
                "not_after",
                "self_signed",
                "key_type",
                "key_size",
            )
        },
        fingerprints={"cert_sha256": cert["sha256"], "cert_sha1": cert["sha1"], "spki_sha256": cert["spki_sha256"]},
    )
    using = (
        await db[Collections.ASSETS]
        .find(
            {
                "$or": [
                    {"fingerprints.cert_sha256": cert["sha256"]},
                    {"fingerprints.spki_sha256": cert["spki_sha256"]},
                ],
                "type": {"$in": ["domain", "ip"]},
            },
            {"type": 1, "value": 1, "status": 1, "confidence": 1},
        )
        .limit(MATCH_LIMIT)
        .to_list(length=MATCH_LIMIT)
    )
    investigation_id = None
    if investigate:
        doc = runner.new_document(cert["sha256"], InvestigationOptions(), created_by=user.username, tags=["upload"])
        await runner.submit(doc)
        investigation_id = doc["_id"]
    await audit(
        "upload.certificate",
        username=user.username,
        role=user.role,
        resource_type="asset",
        resource_id=asset["_id"],
        ip=client_ip(request),
        details={"sha256": cert["sha256"], "investigate": investigate},
    )
    return {
        "asset_id": asset["_id"],
        "certificate": {k: v for k, v in cert.items() if k != "pem"},
        "matches": [_match(d, 1.0, "certificate") for d in using],
        "investigation_id": investigation_id,
    }
