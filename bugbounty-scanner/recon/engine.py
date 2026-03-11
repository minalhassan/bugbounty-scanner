"""
recon/engine.py
===============
Reconnaissance Engine — discovers subdomains, DNS records, IPs,
open ports, technologies, and server information.
"""

import asyncio
import socket
import re
from typing import List, Dict, Optional
from loguru import logger

from core.models import ReconResult
from core.config import ScanConfig
from core.session import ScanSession


class ReconEngine:
    """
    Performs multi-vector reconnaissance against a target domain.

    Techniques:
    - Passive subdomain enumeration (certificate transparency + wordlist)
    - DNS A/MX/TXT/NS/CNAME record enumeration
    - WHOIS data extraction
    - HTTP header fingerprinting
    - Technology stack detection (Wappalyzer-style patterns)
    - Port scanning (top 20 common web ports)
    """

    # Technology fingerprinting patterns
    TECH_SIGNATURES = {
        "WordPress":    [r"wp-content", r"wp-includes", r"WordPress"],
        "Drupal":       [r"Drupal", r"/sites/default/", r"drupal.js"],
        "Joomla":       [r"Joomla", r"/components/com_", r"/modules/mod_"],
        "Laravel":      [r"laravel_session", r"X-Powered-By: PHP"],
        "Django":       [r"csrfmiddlewaretoken", r"__django"],
        "React":        [r"__NEXT_DATA__", r"react-dom", r"_react"],
        "Angular":      [r"ng-version", r"angular.js", r"ng-app"],
        "Vue.js":       [r"vue\.min\.js", r"__VUE__"],
        "jQuery":       [r"jquery", r"jQuery"],
        "Bootstrap":    [r"bootstrap\.min\.css", r"bootstrap\.js"],
        "Nginx":        [r"nginx"],
        "Apache":       [r"Apache"],
        "Express.js":   [r"X-Powered-By: Express"],
        "ASP.NET":      [r"__VIEWSTATE", r"ASP.NET", r"\.aspx"],
        "PHP":          [r"\.php", r"X-Powered-By: PHP"],
        "Cloudflare":   [r"cf-ray", r"cloudflare"],
        "AWS":          [r"amazonaws\.com", r"awselb", r"x-amz"],
    }

    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging",
        "test", "beta", "blog", "shop", "store", "app", "mobile",
        "cdn", "static", "assets", "media", "images", "docs",
        "support", "help", "portal", "dashboard", "login", "vpn",
        "remote", "git", "gitlab", "jenkins", "jira", "confluence",
        "m", "ns1", "ns2", "smtp", "pop", "imap", "webmail",
        "secure", "internal", "intranet", "old", "new", "backup",
    ]

    COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000, 4443]

    def __init__(self, session: ScanSession, config: ScanConfig):
        self.session = session
        self.config = config

    async def run(self, target: str) -> ReconResult:
        """Run full reconnaissance pipeline."""
        domain = self._normalize_domain(target)
        logger.info(f"[RECON] Starting reconnaissance on {domain}")

        result = ReconResult(target=domain)

        # Run recon tasks concurrently
        tasks = [
            self._enumerate_subdomains(domain),
            self._get_dns_records(domain),
            self._get_whois(domain),
            self._fingerprint_http(target if target.startswith("http") else f"https://{domain}"),
        ]
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        subdomains, dns_records, whois_data, http_info = outcomes

        if isinstance(subdomains, list):
            result.subdomains = subdomains
        if isinstance(dns_records, dict):
            result.dns_records = dns_records
        if isinstance(whois_data, dict):
            result.whois_data = whois_data
        if isinstance(http_info, dict):
            result.headers     = http_info.get("headers", {})
            result.server_info = http_info.get("server_info", {})
            result.technologies = http_info.get("technologies", [])

        # Resolve IPs
        result.ip_addresses = await self._resolve_ips(domain, result.subdomains)

        logger.info(
            f"[RECON] Complete — "
            f"{len(result.subdomains)} subdomains, "
            f"{len(result.ip_addresses)} IPs, "
            f"{len(result.technologies)} technologies"
        )
        return result

    def _normalize_domain(self, target: str) -> str:
        """Strip protocol and path from target."""
        target = re.sub(r"^https?://", "", target)
        target = target.split("/")[0].split(":")[0]
        return target.lower().strip()

    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """
        Discover subdomains via:
        1. Certificate Transparency (crt.sh)
        2. Common subdomain wordlist bruteforce
        """
        found = set()

        # crt.sh Certificate Transparency
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = await self.session.get(url)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for entry in data:
                    names = entry.get("name_value", "")
                    for name in names.split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain) and name != domain:
                            found.add(name)
            logger.debug(f"[RECON] crt.sh found {len(found)} subdomains")
        except Exception as e:
            logger.warning(f"[RECON] crt.sh failed: {e}")

        # Wordlist bruteforce (async DNS resolution)
        tasks = [
            self._check_subdomain(f"{sub}.{domain}")
            for sub in self.COMMON_SUBDOMAINS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for sub_domain, is_valid in zip(
            [f"{s}.{domain}" for s in self.COMMON_SUBDOMAINS], results
        ):
            if is_valid is True:
                found.add(sub_domain)

        return sorted(found)

    async def _check_subdomain(self, hostname: str) -> bool:
        """Check if a subdomain resolves via async DNS."""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, socket.gethostbyname, hostname)
            return True
        except socket.gaierror:
            return False

    async def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Enumerate DNS records using dnspython."""
        records = {}
        try:
            import dns.resolver
            import dns.exception

            for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
                try:
                    answers = dns.resolver.resolve(domain, record_type, lifetime=5)
                    records[record_type] = [str(r) for r in answers]
                except (dns.exception.DNSException, Exception):
                    pass
        except ImportError:
            logger.warning("[RECON] dnspython not installed, skipping DNS enumeration")

            # Fallback: basic socket lookup
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
                records["A"] = [ip]
            except Exception:
                pass

        return records

    async def _get_whois(self, domain: str) -> Dict:
        """Perform WHOIS lookup."""
        try:
            import whois
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)
            return {
                "registrar":    str(w.registrar or ""),
                "creation_date": str(w.creation_date or ""),
                "expiration_date": str(w.expiration_date or ""),
                "name_servers": list(w.name_servers or []),
                "emails":       list(w.emails or []) if isinstance(w.emails, (list, set)) else [str(w.emails or "")],
                "org":          str(w.org or ""),
                "country":      str(w.country or ""),
            }
        except Exception as e:
            logger.warning(f"[RECON] WHOIS failed: {e}")
            return {}

    async def _fingerprint_http(self, url: str) -> Dict:
        """Fingerprint server via HTTP headers and page content."""
        info = {"headers": {}, "server_info": {}, "technologies": []}
        try:
            resp = await self.session.get(url, allow_redirects=True)
            if not resp:
                return info

            # Extract headers
            info["headers"] = dict(resp.headers)
            info["server_info"] = {
                "status_code":  resp.status,
                "server":       resp.headers.get("Server", ""),
                "x_powered_by": resp.headers.get("X-Powered-By", ""),
                "content_type": resp.headers.get("Content-Type", ""),
                "x_frame":      resp.headers.get("X-Frame-Options", "MISSING"),
                "hsts":         resp.headers.get("Strict-Transport-Security", "MISSING"),
                "csp":          resp.headers.get("Content-Security-Policy", "MISSING"),
            }

            # Technology detection
            body = await resp.text(errors="ignore")
            combined = body + " " + str(resp.headers)
            techs = []
            for tech, patterns in self.TECH_SIGNATURES.items():
                if any(re.search(pat, combined, re.IGNORECASE) for pat in patterns):
                    techs.append(tech)
            info["technologies"] = techs

        except Exception as e:
            logger.warning(f"[RECON] HTTP fingerprint failed for {url}: {e}")

        return info

    async def _resolve_ips(self, domain: str, subdomains: List[str]) -> List[str]:
        """Resolve all discovered subdomains to IP addresses."""
        all_domains = [domain] + subdomains
        tasks = [self._resolve_ip(d) for d in all_domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        ips = set()
        for ip in results:
            if isinstance(ip, str):
                ips.add(ip)
        return sorted(ips)

    async def _resolve_ip(self, hostname: str) -> Optional[str]:
        """Resolve a single hostname to IP."""
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, hostname)
            return ip
        except Exception:
            return None
