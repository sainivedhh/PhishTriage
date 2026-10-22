"""Core data models for PhishTriage pipeline."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HeaderAuthResult(BaseModel):
    spf: Optional[str] = None       # pass, fail, softfail, neutral, none, permerror, temperror
    dkim: Optional[str] = None      # pass, fail, none, etc.
    dmarc: Optional[str] = None     # pass, fail, none, etc.
    auth_results_raw: Optional[str] = None
    from_header: Optional[str] = None
    from_address: Optional[str] = None
    from_domain: Optional[str] = None
    return_path: Optional[str] = None
    return_path_domain: Optional[str] = None
    reply_to: Optional[str] = None
    reply_to_domain: Optional[str] = None
    mismatches: List[str] = Field(default_factory=list)
    received_hops: int = 0
    received_anomalies: List[str] = Field(default_factory=list)


class AttachmentMetadata(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    md5: str
    sha256: str
    is_macro_capable: bool = False
    has_double_extension: bool = False
    is_archive: bool = False
    has_nested_archive: bool = False
    archive_contents: List[str] = Field(default_factory=list)


class ExtractedURL(BaseModel):
    url: str
    display_text: Optional[str] = None
    domain: Optional[str] = None
    tld: Optional[str] = None
    is_ip_address: bool = False
    is_shortener: bool = False
    is_suspicious_tld: bool = False
    mismatch_with_text: bool = False


class ParsedEmail(BaseModel):
    message_id: Optional[str] = None
    date: Optional[datetime] = None
    subject: str = ""
    from_header: str = ""
    from_address: str = ""
    from_name: str = ""
    to_headers: List[str] = Field(default_factory=list)
    cc_headers: List[str] = Field(default_factory=list)
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    headers: Dict[str, List[str]] = Field(default_factory=dict)
    body_plain: str = ""
    body_html: str = ""
    urls: List[ExtractedURL] = Field(default_factory=list)
    attachments: List[AttachmentMetadata] = Field(default_factory=list)
    header_auth: Optional[HeaderAuthResult] = None
    raw_size_bytes: int = 0


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: FindingSeverity
    score_contribution: int = 0
    mitre_attack_id: Optional[str] = None
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class RiskScore(BaseModel):
    total_score: int = Field(ge=0, le=100)
    verdict: Verdict
    breakdown: List[Finding] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)


class LLMTriageResponse(BaseModel):
    summary: str
    executive_assessment: str
    recommended_actions: List[str]
    confidence: float = Field(ge=0.0, le=1.0)
    is_fallback: bool = True
    mitre_summary: List[str] = Field(default_factory=list)


class IncidentReport(BaseModel):
    incident_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    email_subject: str
    sender: str
    recipient: str
    verdict: Verdict
    score: int
    score_breakdown: List[Finding]
    mitre_techniques: List[str]
    iocs: Dict[str, List[str]] = Field(
        default_factory=lambda: {
            "domains": [],
            "ips": [],
            "urls": [],
            "hashes": [],
            "senders": [],
        }
    )
    llm_analysis: Optional[LLMTriageResponse] = None
    recommended_actions: List[str] = Field(default_factory=list)
