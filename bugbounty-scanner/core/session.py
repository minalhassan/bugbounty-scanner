"""
core/session.py
===============
Manages HTTP sessions with rate limiting, retries, and fingerprint rotation.
"""

import asyncio
import random
import time
from typing import Optional, Dict, Any
from loguru import logger
import aiohttp
from tenacity import retry, stop_after_attempt, wait_exponential


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
]


class RateLimiter:
    """Token bucket rate limiter."""

    def __init__(self, rate: float = 10.0):
        self.rate = rate
        self._tokens = rate
        self._last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_update
            self._tokens = min(self.rate, self._tokens + elapsed * self.rate)
            self._last_update = now

            if self._tokens < 1:
                sleep_time = (1 - self._tokens) / self.rate
                await asyncio.sleep(sleep_time)
                self._tokens = 0
            else:
                self._tokens -= 1


class ScanSession:
    """
    Async HTTP session manager with:
    - Rate limiting
    - Automatic retries
    - User-agent rotation
    - Cookie/session management
    - Request logging
    """

    def __init__(
        self,
        rate_limit: float = 10.0,
        timeout: int = 30,
        verify_ssl: bool = False,
        proxy: Optional[str] = None,
        cookies: Optional[Dict] = None,
        extra_headers: Optional[Dict] = None,
        rotate_ua: bool = True,
    ):
        self.rate_limiter = RateLimiter(rate_limit)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.cookies = cookies or {}
        self.rotate_ua = rotate_ua
        self._session: Optional[aiohttp.ClientSession] = None
        self.request_count = 0
        self.error_count = 0

        self.default_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
        }
        if extra_headers:
            self.default_headers.update(extra_headers)

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=self.verify_ssl, limit=100)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            cookies=self.cookies,
            headers=self.default_headers,
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()

    def _get_headers(self, extra: Optional[Dict] = None) -> Dict:
        headers = dict(self.default_headers)
        if self.rotate_ua:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        if extra:
            headers.update(extra)
        return headers

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=5))
    async def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        allow_redirects: bool = True,
    ) -> Optional[aiohttp.ClientResponse]:
        """Perform a GET request with rate limiting."""
        await self.rate_limiter.acquire()
        try:
            resp = await self._session.get(
                url,
                params=params,
                headers=self._get_headers(headers),
                allow_redirects=allow_redirects,
                proxy=self.proxy,
            )
            self.request_count += 1
            logger.debug(f"GET {url} → {resp.status}")
            return resp
        except Exception as e:
            self.error_count += 1
            logger.warning(f"GET {url} failed: {e}")
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=5))
    async def post(
        self,
        url: str,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
    ) -> Optional[aiohttp.ClientResponse]:
        """Perform a POST request with rate limiting."""
        await self.rate_limiter.acquire()
        try:
            resp = await self._session.post(
                url,
                data=data,
                json=json,
                headers=self._get_headers(headers),
                proxy=self.proxy,
            )
            self.request_count += 1
            logger.debug(f"POST {url} → {resp.status}")
            return resp
        except Exception as e:
            self.error_count += 1
            logger.warning(f"POST {url} failed: {e}")
            raise

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Optional[aiohttp.ClientResponse]:
        """Generic request method."""
        await self.rate_limiter.acquire()
        headers = self._get_headers(kwargs.pop("headers", None))
        try:
            resp = await self._session.request(
                method, url, headers=headers, proxy=self.proxy, **kwargs
            )
            self.request_count += 1
            return resp
        except Exception as e:
            self.error_count += 1
            logger.warning(f"{method} {url} failed: {e}")
            return None
