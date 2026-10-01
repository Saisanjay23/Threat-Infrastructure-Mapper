"""Image fingerprints: Shodan-style favicon MurmurHash3 and perceptual hashes."""

from __future__ import annotations

import base64
import hashlib
import io
from typing import Any

import imagehash
import mmh3
from PIL import Image, UnidentifiedImageError


def favicon_mmh3(content: bytes) -> str:
    """Shodan/FOFA compatible favicon hash: mmh3 of base64 with newline every 76 chars."""
    return str(mmh3.hash(base64.encodebytes(content)))


def perceptual_hashes(content: bytes) -> dict[str, str]:
    try:
        with Image.open(io.BytesIO(content)) as img:
            img.seek(0)
            frame = img.convert("RGBA")
            background = Image.new("RGBA", frame.size, (255, 255, 255, 255))
            rgb = Image.alpha_composite(background, frame).convert("RGB")
            return {
                "phash": str(imagehash.phash(rgb)),
                "ahash": str(imagehash.average_hash(rgb)),
                "dhash": str(imagehash.dhash(rgb)),
                "whash": str(imagehash.whash(rgb)),
            }
    except (UnidentifiedImageError, OSError, ValueError):
        return {}


def image_fingerprints(content: bytes) -> dict[str, Any]:
    return {
        "md5": hashlib.md5(content).hexdigest(),  # noqa: S324 - fingerprint, not security
        "sha256": hashlib.sha256(content).hexdigest(),
        "mmh3": favicon_mmh3(content),
        "size": len(content),
        **perceptual_hashes(content),
    }


def hamming(a: str, b: str) -> int:
    """Hamming distance between two hex-encoded image hashes of equal length."""
    return imagehash.hex_to_hash(a) - imagehash.hex_to_hash(b)


def hash_similarity(a: str | None, b: str | None) -> float:
    """0..1 similarity between two perceptual hashes (1 == identical)."""
    if not a or not b or len(a) != len(b):
        return 0.0
    bits = len(a) * 4
    return max(0.0, 1.0 - hamming(a, b) / bits)
