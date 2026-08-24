"""Core data models used across DRACXX engines."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class ScanProfile(str, Enum):
    PASSIVE = "PASSIVE"
    LIGHT = "LIGHT"
    STANDARD = "STANDARD"
    DEEP = "DEEP"
    CUSTOM = "CUSTOM"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    INFO = "INFO"
    POTENTIAL = "POTENTIAL"
    LIKELY = "LIKELY"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    CONFIRMED_NON_DESTRUCTIVE = "CONFIRMED_BY_NON_DESTRUCTIVE_DETECTION"


class Asset(BaseModel):
    id: Optional[int] = None
    target: str
    asset_type: str  # domain, subdomain, ip, url, cidr
    ip: Optional[str] = None
    asn: Optional[str] = None
    source: Optional[str] = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)


class Port(BaseModel):
    asset: str
    port: int
    protocol: str = "tcp"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    tls: bool = False
    banner: Optional[str] = None


class WebEndpoint(BaseModel):
    url: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    headers: dict = Field(default_factory=dict)
    source: Optional[str] = None


class CVEMatch(BaseModel):
    cve_id: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_version: Optional[str] = None
    epss_score: Optional[float] = None
    kev: bool = False
    match_status: str  # from MatchStatus
    cpe: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    public_exploit_known: bool = False  # intelligence only, never executed


class Finding(BaseModel):
    finding_id: str
    title: str
    severity: Severity
    confidence: Confidence
    target: str
    asset: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    technology: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    cves: List[CVEMatch] = Field(default_factory=list)
    cwe: Optional[str] = None
    evidence: Optional[str] = None
    scanner: str = "unknown"
    references: List[str] = Field(default_factory=list)
    remediation: Optional[str] = None
    risk_score: Optional[float] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ScopeConfig(BaseModel):
    allowed_domains: List[str] = Field(default_factory=list)
    allowed_cidrs: List[str] = Field(default_factory=list)
    exclusions: List[str] = Field(default_factory=list)
    confirmed: bool = False


class ScanSession(BaseModel):
    session_id: str
    target: str
    profile: ScanProfile
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    tool_versions: dict = Field(default_factory=dict)
