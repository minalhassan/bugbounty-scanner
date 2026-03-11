"""
core/models.py
==============
Shared data models and enumerations used across all modules.
"""

from __future__ import annotations
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
import uuid


# ── Enumerations ──────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class VulnType(str, Enum):
    SQLI           = "SQL Injection"
    XSS            = "Cross-Site Scripting"
    CMDI           = "Command Injection"
    IDOR           = "Insecure Direct Object Reference"
    AUTH           = "Broken Authentication"
    FILE_UPLOAD    = "File Upload Vulnerability"
    TRAVERSAL      = "Directory Traversal"
    API_MISCONFIG  = "API Misconfiguration"
    SSRF           = "Server-Side Request Forgery"
    OPEN_REDIRECT  = "Open Redirect"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    RECON          = "Reconnaissance Finding"


class ScanStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    PAUSED    = "paused"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


class HttpMethod(str, Enum):
    GET     = "GET"
    POST    = "POST"
    PUT     = "PUT"
    PATCH   = "PATCH"
    DELETE  = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD    = "HEAD"


# ── Core Data Classes ─────────────────────────────────────────────────────────

@dataclass
class ReconResult:
    """Results from the reconnaissance phase."""
    target: str
    subdomains: List[str]               = field(default_factory=list)
    ip_addresses: List[str]             = field(default_factory=list)
    open_ports: Dict[str, List[int]]    = field(default_factory=dict)
    dns_records: Dict[str, List[str]]   = field(default_factory=dict)
    whois_data: Dict[str, Any]          = field(default_factory=dict)
    technologies: List[str]             = field(default_factory=list)
    server_info: Dict[str, str]         = field(default_factory=dict)
    headers: Dict[str, str]             = field(default_factory=dict)
    timestamp: datetime                  = field(default_factory=datetime.utcnow)


@dataclass
class Endpoint:
    """Represents a discovered endpoint on the target."""
    url: str
    method: HttpMethod                  = HttpMethod.GET
    params: Dict[str, str]             = field(default_factory=dict)
    headers: Dict[str, str]            = field(default_factory=dict)
    body: Optional[str]                = None
    content_type: Optional[str]        = None
    status_code: Optional[int]         = None
    response_length: Optional[int]     = None
    forms: List[Dict]                  = field(default_factory=list)
    is_api: bool                       = False
    requires_auth: bool                = False
    discovered_at: datetime            = field(default_factory=datetime.utcnow)

    def __hash__(self):
        return hash((self.url, self.method))

    def __eq__(self, other):
        return isinstance(other, Endpoint) and self.url == other.url and self.method == other.method


@dataclass
class AttackVector:
    """Represents a potential attack path discovered by the AI engine."""
    vector_id: str                     = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str                          = ""
    description: str                   = ""
    endpoints: List[Endpoint]          = field(default_factory=list)
    steps: List[str]                   = field(default_factory=list)
    confidence: float                  = 0.0
    estimated_severity: Severity       = Severity.MEDIUM


@dataclass
class Vulnerability:
    """A confirmed or suspected vulnerability finding."""
    vuln_id: str                       = field(default_factory=lambda: str(uuid.uuid4()))
    vuln_type: VulnType                = VulnType.SQLI
    severity: Severity                 = Severity.MEDIUM
    title: str                         = ""
    description: str                   = ""
    url: str                           = ""
    method: HttpMethod                 = HttpMethod.GET
    parameter: Optional[str]          = None
    payload: Optional[str]            = None
    evidence: Optional[str]           = None
    request_dump: Optional[str]       = None
    response_dump: Optional[str]      = None
    cvss_score: float                  = 0.0
    cvss_vector: Optional[str]        = None
    confidence: float                  = 0.0
    remediation: str                   = ""
    references: List[str]             = field(default_factory=list)
    false_positive: bool               = False
    verified: bool                     = False
    discovered_at: datetime            = field(default_factory=datetime.utcnow)
    cwe_id: Optional[str]             = None
    owasp_category: Optional[str]     = None


@dataclass
class ScanResult:
    """Complete scan result aggregating all findings."""
    scan_id: str                       = field(default_factory=lambda: str(uuid.uuid4()))
    target: str                        = ""
    status: ScanStatus                 = ScanStatus.PENDING
    started_at: Optional[datetime]    = None
    completed_at: Optional[datetime]  = None
    duration_seconds: float            = 0.0
    recon: Optional[ReconResult]      = None
    endpoints: List[Endpoint]         = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    attack_vectors: List[AttackVector] = field(default_factory=list)
    stats: Dict[str, Any]             = field(default_factory=dict)
    error: Optional[str]              = None

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)

    @property
    def overall_risk(self) -> str:
        if self.critical_count > 0:
            return "CRITICAL"
        elif self.high_count > 0:
            return "HIGH"
        elif self.medium_count > 0:
            return "MEDIUM"
        elif self.low_count > 0:
            return "LOW"
        return "NONE"
