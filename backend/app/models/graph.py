"""Graph relationship vocabulary and models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RelationType(StrEnum):
    # Core relationships from the TIM specification
    USES_CERTIFICATE = "USES_CERTIFICATE"
    SHARES_FAVICON = "SHARES_FAVICON"
    SHARES_PIXEL = "SHARES_PIXEL"
    SHARES_ANALYTICS = "SHARES_ANALYTICS"
    HOSTED_ON = "HOSTED_ON"
    RESOLVES_TO = "RESOLVES_TO"
    USES_NAMESERVER = "USES_NAMESERVER"
    MEMBER_OF_CLUSTER = "MEMBER_OF_CLUSTER"
    # Extended relationships
    SHARES_TRACKING = "SHARES_TRACKING"
    SHARES_CERTIFICATE = "SHARES_CERTIFICATE"
    SHARES_LOGO = "SHARES_LOGO"
    SIMILAR_HTML = "SIMILAR_HTML"
    SIMILAR_TITLE = "SIMILAR_TITLE"
    SIMILAR_SCREENSHOT = "SIMILAR_SCREENSHOT"
    BELONGS_TO_ASN = "BELONGS_TO_ASN"
    REDIRECTS_TO = "REDIRECTS_TO"
    HAS_URL = "HAS_URL"
    SUBDOMAIN_OF = "SUBDOMAIN_OF"
    USES_MX = "USES_MX"
    CNAME_TO = "CNAME_TO"
    HISTORICAL_RESOLUTION = "HISTORICAL_RESOLUTION"
    OBSERVED_WITH = "OBSERVED_WITH"


class RelatedEntity(BaseModel):
    """An entity a provider/collector discovered, plus how it relates to the queried IOC."""

    type: str
    value: str
    relation: RelationType
    reverse: bool = Field(default=False, description="If true the edge points from the entity to the IOC")
    evidence: dict[str, Any] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)


class RelationshipOut(BaseModel):
    id: str
    source: str
    target: str
    type: RelationType
    weight: float = 1.0
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
