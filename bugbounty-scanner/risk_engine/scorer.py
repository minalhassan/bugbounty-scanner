"""
risk_engine/scorer.py
=====================
CVSS 3.1-based Risk Scoring Engine

Computes vulnerability severity scores based on:
- Attack Vector (Network, Adjacent, Local, Physical)
- Attack Complexity (Low, High)
- Privileges Required (None, Low, High)
- User Interaction (None, Required)
- Scope (Unchanged, Changed)
- Confidentiality / Integrity / Availability Impact
"""

import math
from typing import List
from loguru import logger

from core.models import Vulnerability, Severity, VulnType


# ── CVSS 3.1 Constants ────────────────────────────────────────────────────────

CVSS_PROFILES = {
    VulnType.SQLI: {
        "AV": 0.85,  # Network
        "AC": 0.77,  # Low
        "PR": 0.85,  # None
        "UI": 0.85,  # None
        "S":  1.0,   # Changed (scope change)
        "C":  0.56,  # High confidentiality impact
        "I":  0.56,  # High integrity impact
        "A":  0.56,  # High availability impact
        "base_score": 9.8,
    },
    VulnType.XSS: {
        "AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.62,
        "S":  1.0,  "C":  0.22, "I":  0.22, "A":  0.0,
        "base_score": 6.1,
    },
    VulnType.CMDI: {
        "AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.85,
        "S":  1.0,  "C":  0.56, "I":  0.56, "A":  0.56,
        "base_score": 9.8,
    },
    VulnType.IDOR: {
        "AV": 0.85, "AC": 0.77, "PR": 0.62, "UI": 0.85,
        "S":  0.0,  "C":  0.56, "I":  0.22, "A":  0.0,
        "base_score": 6.5,
    },
    VulnType.AUTH: {
        "AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.85,
        "S":  0.0,  "C":  0.56, "I":  0.56, "A":  0.56,
        "base_score": 8.8,
    },
    VulnType.FILE_UPLOAD: {
        "AV": 0.85, "AC": 0.77, "PR": 0.62, "UI": 0.62,
        "S":  1.0,  "C":  0.56, "I":  0.56, "A":  0.56,
        "base_score": 8.8,
    },
    VulnType.TRAVERSAL: {
        "AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.85,
        "S":  0.0,  "C":  0.56, "I":  0.22, "A":  0.0,
        "base_score": 7.5,
    },
    VulnType.API_MISCONFIG: {
        "AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.85,
        "S":  0.0,  "C":  0.22, "I":  0.22, "A":  0.0,
        "base_score": 5.3,
    },
}

SEVERITY_THRESHOLDS = {
    (9.0, 10.0): Severity.CRITICAL,
    (7.0, 8.9):  Severity.HIGH,
    (4.0, 6.9):  Severity.MEDIUM,
    (0.1, 3.9):  Severity.LOW,
    (0.0, 0.0):  Severity.INFO,
}

REMEDIATION_ADVICE = {
    VulnType.SQLI: (
        "Use parameterized queries or prepared statements. "
        "Implement input validation with allowlists. "
        "Apply least privilege on database accounts. "
        "Enable WAF with SQL injection rules."
    ),
    VulnType.XSS: (
        "Apply context-aware output encoding (HTML, JS, URL, CSS). "
        "Implement a strict Content Security Policy. "
        "Use frameworks with auto-escaping templates. "
        "Validate and sanitize all user input."
    ),
    VulnType.CMDI: (
        "Avoid passing user data to OS commands entirely. "
        "Use allowlists for permitted values. "
        "Apply sandboxing and least privilege. "
        "Use language-native APIs instead of shell commands."
    ),
    VulnType.IDOR: (
        "Implement object-level authorization on every sensitive action. "
        "Use indirect reference maps instead of direct IDs. "
        "Log all access attempts to sensitive objects. "
        "Perform authorization checks server-side, never client-side."
    ),
    VulnType.AUTH: (
        "Enforce strong password policies and MFA. "
        "Use secure session management with HttpOnly, Secure, SameSite cookies. "
        "Implement account lockout after failed attempts. "
        "Use industry-standard auth frameworks (OAuth 2.0, OpenID Connect)."
    ),
    VulnType.FILE_UPLOAD: (
        "Allowlist permitted file extensions and MIME types. "
        "Store uploads outside the web root. "
        "Rename all uploaded files server-side. "
        "Scan uploads with antivirus before processing."
    ),
    VulnType.TRAVERSAL: (
        "Validate and canonicalize all file paths. "
        "Implement a chroot jail or file access restrictions. "
        "Never concatenate user input directly into file paths. "
        "Apply least privilege on file system access."
    ),
    VulnType.API_MISCONFIG: (
        "Disable unused HTTP methods. "
        "Implement proper CORS configuration with strict allowlists. "
        "Require authentication on all sensitive API routes. "
        "Remove debug endpoints and verbose error messages in production."
    ),
}


class RiskScorer:
    """
    Assigns CVSS 3.1-based scores to vulnerabilities and
    adjusts severity based on context (confidence, depth, impact).
    """

    def score_all(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Score all vulnerabilities in a scan result."""
        scored = []
        for vuln in vulnerabilities:
            scored_vuln = self.score(vuln)
            scored.append(scored_vuln)

        # Sort by CVSS score descending
        scored.sort(key=lambda v: v.cvss_score, reverse=True)
        logger.info(f"[RISK] Scored {len(scored)} vulnerabilities")
        return scored

    def score(self, vuln: Vulnerability) -> Vulnerability:
        """Score a single vulnerability."""
        profile = CVSS_PROFILES.get(vuln.vuln_type, CVSS_PROFILES[VulnType.API_MISCONFIG])

        # Base CVSS score from profile
        base_score = profile.get("base_score", 5.0)

        # Adjust for confidence
        adjusted_score = base_score * (0.5 + vuln.confidence * 0.5)

        # Round to 1 decimal
        adjusted_score = round(min(10.0, max(0.0, adjusted_score)), 1)

        # Determine severity from score
        severity = self._score_to_severity(adjusted_score)

        # Generate CVSS vector string
        cvss_vector = self._build_cvss_vector(profile)

        # Enhance remediation if not already set
        if not vuln.remediation:
            vuln.remediation = REMEDIATION_ADVICE.get(vuln.vuln_type, "Apply security best practices.")

        vuln.cvss_score = adjusted_score
        vuln.cvss_vector = cvss_vector
        vuln.severity = severity

        return vuln

    def _score_to_severity(self, score: float) -> Severity:
        """Map CVSS score to severity enum."""
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0.0:
            return Severity.LOW
        return Severity.INFO

    def _build_cvss_vector(self, profile: dict) -> str:
        """Build CVSS v3.1 vector string from numeric profile values."""
        def av_str(v):
            if v >= 0.85: return "N"
            if v >= 0.62: return "A"
            if v >= 0.55: return "L"
            return "P"
        def impact_str(v):
            if v >= 0.56: return "H"
            if v >= 0.22: return "L"
            return "N"

        av = av_str(profile.get("AV", 0.85))
        ac = "L" if profile.get("AC", 0.77) >= 0.77 else "H"
        pr = av_str(profile.get("PR", 0.85))
        ui = "N" if profile.get("UI", 0.85) >= 0.85 else "R"
        sc = "C" if profile.get("S", 0) > 0 else "U"
        ci = impact_str(profile.get("C", 0.22))
        ii = impact_str(profile.get("I", 0.22))
        ai = impact_str(profile.get("A", 0.0))

        return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{sc}/C:{ci}/I:{ii}/A:{ai}"

    def generate_risk_summary(self, vulnerabilities: List[Vulnerability]) -> dict:
        """Generate a risk summary for reporting."""
        counts = {s.value: 0 for s in Severity}
        for v in vulnerabilities:
            counts[v.severity.value] += 1

        scores = [v.cvss_score for v in vulnerabilities if v.cvss_score > 0]
        max_score = max(scores) if scores else 0.0
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0

        return {
            "total": len(vulnerabilities),
            "by_severity": counts,
            "max_cvss": max_score,
            "avg_cvss": avg_score,
            "overall_risk": self._overall_risk(counts),
        }

    def _overall_risk(self, counts: dict) -> str:
        if counts.get("critical", 0) > 0:   return "CRITICAL"
        if counts.get("high", 0) > 0:        return "HIGH"
        if counts.get("medium", 0) > 0:      return "MEDIUM"
        if counts.get("low", 0) > 0:         return "LOW"
        return "NONE"
