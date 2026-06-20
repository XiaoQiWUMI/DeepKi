# (●°u°●)​ 」 DeepKi Base Scanner
# Every Xiao Qi paw inherits from here~

import asyncio
import time
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, AsyncIterator
from urllib.parse import urlparse

import httpx


@dataclass
class ScanResult:
    """One finding from a scanner module"""
    module: str
    title: str
    severity: str  # critical/high/medium/low/info
    url: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cve_id: str = ""
    request_dump: str = ""
    response_dump: str = ""

    def fingerprint(self) -> str:
        """Generate dedup key"""
        raw = f"{self.module}|{self.title}|{self.url}|{self.evidence}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]


class BaseScanner(ABC):
    """Xiao Qi's base scanner paw 🐾"""

    name: str = "base"
    icon: str = "🔧"
    description: str = ""

    def __init__(
        self,
        target_url: str,
        concurrent: int = 50,
        timeout: int = 10,
        user_agent: str = "Deepki/1.0",
        progress_callback: Optional[callable] = None,
        finding_callback: Optional[callable] = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.parsed = urlparse(self.target_url)
        self.base_domain = self.parsed.hostname or ""
        self.concurrent = concurrent
        self.timeout = timeout
        self.progress = progress_callback
        self.on_finding = finding_callback
        self._semaphore = asyncio.Semaphore(concurrent)
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("Scanner not started. Use async context manager.")
        return self._client

    async def __aenter__(self):
        limits = httpx.Limits(max_connections=self.concurrent, max_keepalive_connections=20)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            limits=limits,
            headers={"User-Agent": "Deepki/1.0 (Xiao Qi Scanner)"},
            follow_redirects=True,
            max_redirects=5,
            verify=False,  # allow self-signed certs for testing
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()
            self._client = None

    @abstractmethod
    async def run(self) -> list[ScanResult]:
        """Override: return list of findings"""
        ...

    async def _get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        """Safe GET with semaphore"""
        async with self._semaphore:
            try:
                return await self.client.get(url, **kwargs)
            except (httpx.TimeoutException, httpx.ConnectError,
                    httpx.RemoteProtocolError, Exception):
                return None

    async def _head(self, url: str, **kwargs) -> Optional[httpx.Response]:
        """Safe HEAD with semaphore"""
        async with self._semaphore:
            try:
                return await self.client.head(url, **kwargs)
            except Exception:
                return None

    async def _post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        """Safe POST with semaphore"""
        async with self._semaphore:
            try:
                return await self.client.post(url, **kwargs)
            except Exception:
                return None

    async def _report_progress(self, current: int, total: int, extra: dict = None):
        """Notify progress to callback"""
        if self.progress:
            await self.progress(self.name, current, total, extra or {})

    async def _report_finding(self, result: ScanResult):
        """Notify finding to callback"""
        if self.on_finding:
            await self.on_finding(result)

    def _url(self, path: str) -> str:
        """Build full URL from path"""
        if path.startswith("http"):
            return path
        return f"{self.target_url}/{path.lstrip('/')}"
