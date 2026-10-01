"""Correlation scoring configuration models."""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from app.models.common import ConfidenceLevel

DEFAULT_WEIGHTS: dict[str, int] = {
    "redirect": 35,
    "subdomain": 30,
    "analytics": 40,
    "gtm": 40,
    "pixel": 40,
    "tracking": 30,
    "favicon": 30,
    "certificate": 25,
    "logo": 25,
    "html": 20,
    "screenshot": 20,
    "title": 15,
    "ip": 10,
    "asn": 5,
    "nameserver": 5,
    "hosting": 5,
}

FEATURE_LABELS: dict[str, str] = {
    "redirect": "Same redirect chain",
    "subdomain": "Subdomain of a seed domain",
    "analytics": "Analytics ID match (UA / GA4)",
    "gtm": "Google Tag Manager container match",
    "pixel": "Advertising pixel match (Meta / LinkedIn / TikTok)",
    "tracking": "Other tracker match (AdSense, Hotjar, Clarity, Metrika)",
    "favicon": "Favicon hash match",
    "certificate": "TLS certificate match",
    "logo": "Logo perceptual-hash match",
    "html": "HTML structure similarity",
    "screenshot": "Visual (screenshot) similarity",
    "title": "Page title match",
    "ip": "Shared IP address",
    "asn": "Shared ASN",
    "nameserver": "Shared nameserver",
    "hosting": "Shared hosting provider",
}


class Thresholds(BaseModel):
    very_high: int = Field(default=90, ge=1, le=100)
    high: int = Field(default=70, ge=1, le=100)
    medium: int = Field(default=50, ge=1, le=100)
    low: int = Field(default=30, ge=1, le=100)
    cluster_min: int = Field(default=50, ge=1, le=100, description="Minimum confidence for cluster membership")

    @model_validator(mode="after")
    def _ordered(self) -> Thresholds:
        if not (self.very_high > self.high > self.medium > self.low):
            raise ValueError("thresholds must satisfy very_high > high > medium > low")
        return self

    def level(self, score: int | None) -> ConfidenceLevel:
        s = score or 0
        if s >= self.very_high:
            return ConfidenceLevel.VERY_HIGH
        if s >= self.high:
            return ConfidenceLevel.HIGH
        if s >= self.medium:
            return ConfidenceLevel.MEDIUM
        if s >= self.low:
            return ConfidenceLevel.LOW
        return ConfidenceLevel.INFORMATIONAL


class SimilarityThresholds(BaseModel):
    html: float = Field(default=0.9, ge=0.5, le=1.0)
    logo: float = Field(default=0.88, ge=0.5, le=1.0)
    screenshot: float = Field(default=0.9, ge=0.5, le=1.0)
    title: float = Field(default=0.85, ge=0.5, le=1.0)


class ScoringConfig(BaseModel):
    weights: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    thresholds: Thresholds = Field(default_factory=Thresholds)
    similarity: SimilarityThresholds = Field(default_factory=SimilarityThresholds)
    noisy_fingerprint_limit: int = Field(
        default=150,
        ge=5,
        le=100000,
        description="Fingerprints shared by more assets than this (CDN IPs, default favicons) count at 25% weight",
    )

    @model_validator(mode="after")
    def _known_weights(self) -> ScoringConfig:
        unknown = set(self.weights) - set(DEFAULT_WEIGHTS)
        if unknown:
            raise ValueError(f"unknown scoring features: {sorted(unknown)}")
        for k, v in self.weights.items():
            if not 0 <= v <= 100:
                raise ValueError(f"weight for {k} must be between 0 and 100")
        merged = dict(DEFAULT_WEIGHTS)
        merged.update(self.weights)
        self.weights = merged
        return self


class ScoringConfigOut(ScoringConfig):
    labels: dict[str, str] = Field(default_factory=lambda: dict(FEATURE_LABELS))
    defaults: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
