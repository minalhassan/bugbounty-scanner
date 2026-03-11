"""
crawler/engine.py
=================
AI-Powered Web Crawler — recursively discovers endpoints, forms,
API routes, parameters, and builds a complete attack surface map.
"""

import asyncio
import re
import json
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from typing import List, Set, Dict, Optional, Tuple
from bs4 import BeautifulSoup
from loguru import logger

from core.models import Endpoint, HttpMethod
from core.config import ScanConfig
from core.session import ScanSession


class CrawlerEngine:
    """
    Intelligent recursive web crawler that:
    - Follows links, forms, and redirects
    - Detects JavaScript-rendered routes
    - Extracts API endpoints from JS bundles
    - Discovers hidden parameters
    - Classifies endpoints by type (page, API, form, asset)
    - Builds complete attack surface map
    """

    # Regex patterns for endpoint discovery in JavaScript
    JS_API_PATTERNS = [
        r'["\'](/api/[^\s\'"]+)["\']',
        r'["\'](/v\d+/[^\s\'"]+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
        r'url\s*[:=]\s*["\']([^"\']+)["\']',
        r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
        r'href\s*=\s*["\']([^"\']+)["\']',
        r'action\s*=\s*["\']([^"\']+)["\']',
    ]

    # Extensions to skip (non-content)
    SKIP_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
        ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
        ".pdf", ".zip", ".tar", ".gz", ".exe", ".dmg",
    }

    # Interesting parameters worth testing
    INTERESTING_PARAMS = {
        "id", "user", "uid", "username", "email", "token", "session",
        "file", "path", "url", "redirect", "next", "return", "page",
        "order", "sort", "filter", "search", "q", "query", "cmd",
        "exec", "action", "type", "category", "product", "item",
        "ref", "from", "to", "data", "payload", "input", "output",
    }

    def __init__(self, session: ScanSession, config: ScanConfig):
        self.session = session
        self.config = config
        self.visited: Set[str] = set()
        self.endpoints: List[Endpoint] = []
        self.base_domain: str = ""
        self._endpoint_set: Set[str] = set()  # Dedup by url+method

    async def crawl(self, target: str) -> List[Endpoint]:
        """
        Entry point — start crawl from target URL.
        Returns list of all discovered endpoints.
        """
        start_url = target if target.startswith("http") else f"https://{target}"
        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc or target

        logger.info(f"[CRAWLER] Starting crawl of {start_url} (depth={self.config.depth})")

        # Seed with common directories
        seed_urls = self._generate_seed_urls(start_url)
        tasks = [self._crawl_url(url, depth=0) for url in seed_urls]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Sort by interesting-ness (APIs and parameterized URLs first)
        self.endpoints.sort(key=lambda e: (
            0 if e.is_api else 1,
            0 if e.params else 1,
            e.url
        ))

        logger.info(f"[CRAWLER] Complete — {len(self.endpoints)} endpoints discovered")
        return self.endpoints

    def _generate_seed_urls(self, base: str) -> List[str]:
        """Generate initial seed URLs to discover common paths."""
        common_paths = [
            "", "/robots.txt", "/sitemap.xml", "/api", "/api/v1",
            "/api/v2", "/admin", "/login", "/register", "/dashboard",
            "/.well-known/security.txt", "/swagger.json", "/openapi.json",
            "/api-docs", "/graphql", "/wp-json", "/wp-login.php",
        ]
        return [urljoin(base, path) for path in common_paths]

    async def _crawl_url(self, url: str, depth: int = 0):
        """Recursively crawl a URL up to max depth."""
        if depth > self.config.depth:
            return
        if url in self.visited:
            return
        if any(url.endswith(ext) for ext in self.SKIP_EXTENSIONS):
            return
        if not self._is_same_domain(url):
            return

        self.visited.add(url)

        try:
            resp = await self.session.get(url, allow_redirects=True)
            if not resp:
                return

            # Register this URL as an endpoint
            endpoint = Endpoint(
                url=url,
                method=HttpMethod.GET,
                status_code=resp.status,
                response_length=resp.content_length or 0,
                is_api=self._is_api_endpoint(url),
            )

            body = await resp.text(errors="ignore")
            content_type = resp.headers.get("Content-Type", "")

            # Extract parameters from query string
            parsed = urlparse(url)
            if parsed.query:
                endpoint.params = dict(parse_qs(parsed.query, keep_blank_values=True))
                # Flatten single-value lists
                endpoint.params = {k: v[0] if len(v) == 1 else v
                                   for k, v in endpoint.params.items()}

            # Parse HTML
            if "text/html" in content_type:
                soup = BeautifulSoup(body, "lxml")

                # Extract forms
                endpoint.forms = self._extract_forms(soup, url)

                # Discover new links
                new_links = self._extract_links(soup, url)

                # Extract API routes from JS
                js_endpoints = await self._extract_js_endpoints(soup, url)
                new_links.update(js_endpoints)

                # Queue new links for crawling
                tasks = [
                    self._crawl_url(link, depth + 1)
                    for link in new_links
                    if link not in self.visited
                ]
                if tasks:
                    await asyncio.gather(*tasks[:20], return_exceptions=True)

            elif "application/json" in content_type or endpoint.is_api:
                endpoint.is_api = True
                try:
                    json_data = json.loads(body)
                    endpoint.body = json.dumps(json_data, indent=2)[:500]
                except Exception:
                    pass

            self._add_endpoint(endpoint)

            # Also test POST for forms
            if endpoint.forms:
                for form in endpoint.forms:
                    form_endpoint = Endpoint(
                        url=form.get("action", url),
                        method=HttpMethod(form.get("method", "GET").upper()),
                        params=form.get("inputs", {}),
                        forms=[form],
                    )
                    self._add_endpoint(form_endpoint)

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug(f"[CRAWLER] Error crawling {url}: {e}")

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Set[str]:
        """Extract all links from HTML."""
        links = set()
        selectors = [
            ("a", "href"),
            ("link", "href"),
            ("form", "action"),
            ("script", "src"),
            ("iframe", "src"),
        ]
        for tag, attr in selectors:
            for element in soup.find_all(tag):
                href = element.get(attr)
                if href:
                    full_url = urljoin(base_url, href)
                    full_url = full_url.split("#")[0]  # Remove fragments
                    if self._is_same_domain(full_url):
                        links.add(full_url)
        return links

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract form details for testing."""
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", base_url)
            method = form.get("method", "GET").upper()
            inputs = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs[name] = inp.get("value", "") or inp.get("placeholder", "")
            forms.append({
                "action": urljoin(base_url, action),
                "method": method,
                "inputs": inputs,
                "enctype": form.get("enctype", "application/x-www-form-urlencoded"),
            })
        return forms

    async def _extract_js_endpoints(self, soup: BeautifulSoup, base_url: str) -> Set[str]:
        """Extract API endpoints from inline JavaScript and JS files."""
        endpoints = set()

        # Inline scripts
        for script in soup.find_all("script"):
            content = script.string or ""
            if content:
                for url in self._parse_js_for_endpoints(content, base_url):
                    endpoints.add(url)

        # External JS files
        js_srcs = [
            urljoin(base_url, s.get("src"))
            for s in soup.find_all("script", src=True)
            if s.get("src")
        ]

        for js_url in js_srcs[:5]:  # Limit to 5 external JS files
            if self._is_same_domain(js_url):
                try:
                    resp = await self.session.get(js_url)
                    if resp and resp.status == 200:
                        js_content = await resp.text(errors="ignore")
                        for url in self._parse_js_for_endpoints(js_content, base_url):
                            endpoints.add(url)
                except Exception:
                    pass

        return endpoints

    def _parse_js_for_endpoints(self, js: str, base_url: str) -> Set[str]:
        """Parse JavaScript source for API endpoint patterns."""
        endpoints = set()
        for pattern in self.JS_API_PATTERNS:
            for match in re.finditer(pattern, js):
                groups = [g for g in match.groups() if g and g.startswith("/")]
                for path in groups:
                    if len(path) < 200 and not any(path.endswith(e) for e in self.SKIP_EXTENSIONS):
                        full = urljoin(base_url, path)
                        if self._is_same_domain(full):
                            endpoints.add(full)
        return endpoints

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the target domain."""
        try:
            parsed = urlparse(url)
            return (
                parsed.scheme in ("http", "https")
                and self.base_domain in parsed.netloc
            )
        except Exception:
            return False

    def _is_api_endpoint(self, url: str) -> bool:
        """Heuristic: is this URL likely an API endpoint?"""
        api_patterns = ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql",
                        "/json", ".json", "/rpc", "/ws/"]
        return any(p in url.lower() for p in api_patterns)

    def _add_endpoint(self, endpoint: Endpoint):
        """Add endpoint if not already discovered."""
        key = f"{endpoint.method.value}:{endpoint.url}"
        if key not in self._endpoint_set:
            self._endpoint_set.add(key)
            self.endpoints.append(endpoint)
