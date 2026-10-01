"""TLS certificate collection and X.509 parsing."""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from app.utils.ioc import is_ip


def _name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else None


def _key_info(cert: x509.Certificate) -> tuple[str, int | None]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC-{key.curve.name}", key.key_size
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(key).__name__, None


def parse_certificate(der: bytes) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = [n.lower() for n in san.get_values_for_type(x509.DNSName)]
        san_ips = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans, san_ips = [], []
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(UTC)
    key_type, key_size = _key_info(cert)
    pub_der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    try:
        sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:
        sig_alg = None
    return {
        "sha1": hashlib.sha1(der).hexdigest(),  # noqa: S324 - fingerprint, not security
        "sha256": hashlib.sha256(der).hexdigest(),
        "md5": hashlib.md5(der).hexdigest(),  # noqa: S324 - fingerprint, not security
        "spki_sha256": hashlib.sha256(pub_der).hexdigest(),
        "serial": format(cert.serial_number, "x"),
        "version": cert.version.name,
        "subject": cert.subject.rfc4514_string(),
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "subject_org": _name_attr(cert.subject, NameOID.ORGANIZATION_NAME),
        "issuer": cert.issuer.rfc4514_string(),
        "issuer_cn": _name_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "san": sorted(set(sans)),
        "san_ips": san_ips,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "validity_days": (not_after - not_before).days,
        "age_days": (now - not_before).days,
        "expired": now > not_after,
        "self_signed": cert.issuer == cert.subject,
        "wildcard": any(s.startswith("*.") for s in sans),
        "signature_algorithm": sig_alg,
        "key_type": key_type,
        "key_size": key_size,
        "pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    }


async def _handshake(
    host: str, port: int, server_name: str | None, verify: bool, timeout: float
) -> tuple[bytes | None, dict[str, Any]]:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=server_name), timeout=timeout
    )
    try:
        sslobj: ssl.SSLObject = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True) if sslobj else None
        cipher = sslobj.cipher() if sslobj else None
        meta = {
            "protocol": sslobj.version() if sslobj else None,
            "cipher": cipher[0] if cipher else None,
            "alpn": sslobj.selected_alpn_protocol() if sslobj else None,
            "peer_ip": (writer.get_extra_info("peername") or [None])[0],
        }
        return der, meta
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass


async def collect_tls(host: str, port: int = 443, timeout: float = 10.0) -> dict[str, Any]:
    """Fetch the leaf certificate (unverified) and separately test whether it validates."""
    server_name = None if is_ip(host) else host
    result: dict[str, Any] = {"host": host, "port": port}
    try:
        der, meta = await _handshake(host, port, server_name, verify=False, timeout=timeout)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        return result
    result.update(meta)
    if not der:
        result["error"] = "no peer certificate"
        return result
    try:
        result["certificate"] = parse_certificate(der)
    except ValueError as exc:
        result["error"] = f"certificate parse failed: {exc}"
        return result
    try:
        await _handshake(host, port, server_name, verify=True, timeout=timeout)
        result["trusted"] = True
        result["validation_error"] = None
    except ssl.SSLCertVerificationError as exc:
        result["trusted"] = False
        result["validation_error"] = exc.verify_message or str(exc)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        result["trusted"] = False
        result["validation_error"] = f"{type(exc).__name__}: {exc}"
    return result
