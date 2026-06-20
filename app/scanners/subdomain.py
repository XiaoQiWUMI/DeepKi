# (●°u°●)​ 」 Subdomain Scanner
# Xiao Qi sniffs for subdomains like a truffle pig~ ~_^

import asyncio
import socket
import ssl
from typing import Optional
from pathlib import Path

from .base import BaseScanner, ScanResult
from ..config import WORDLIST_DIR


class SubdomainScanner(BaseScanner):
    """Find subdomains via DNS resolution & certificate transparency"""

    name = "subdomain"
    icon = "🔍"
    description = "Subdomain enumeration via DNS + CT logs"

    def __init__(self, target_url: str, wordlist: str = None, **kwargs):
        super().__init__(target_url, **kwargs)
        self.wordlist_path = Path(wordlist) if wordlist else WORDLIST_DIR / "subdomains.txt"
        self._found: set[str] = set()

    async def run(self) -> list[ScanResult]:
        results = []
        subdomains = self._load_wordlist()

        total = len(subdomains) + 1  # +1 for CT log check
        await self._report_progress(0, total, {"found": 0})

        # Phase 1: DNS brute-force
        tasks = [self._resolve(sub) for sub in subdomains]
        resolved = await asyncio.gather(*tasks)
        for i, (sub, ips) in enumerate(zip(subdomains, resolved)):
            if ips:
                self._found.add(sub)
                results.append(ScanResult(
                    module=self.name,
                    title=f"Subdomain found: {sub}",
                    severity="info",
                    url=f"https://{sub}",
                    evidence=f"Resolved to: {', '.join(ips)}",
                ))
            if i % 10 == 0:
                await self._report_progress(i + 1, total, {"found": len(self._found)})

        # Phase 2: Certificate Transparency (crt.sh)
        ct_subdomains = await self._query_crtsh()
        for sub in ct_subdomains:
            if sub not in self._found:
                self._found.add(sub)
                results.append(ScanResult(
                    module=self.name,
                    title=f"Subdomain (CT): {sub}",
                    severity="info",
                    url=f"https://{sub}",
                    evidence="Found via crt.sh certificate transparency",
                ))

        await self._report_progress(total, total, {"found": len(self._found)})
        return results

    def _load_wordlist(self) -> list[str]:
        """Load subdomain wordlist, generate variants"""
        subs = []
        if self.wordlist_path.exists():
            with open(self.wordlist_path) as f:
                subs = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        # Always test these common ones
        common = ["www", "mail", "api", "admin", "dev", "test", "staging",
                   "vpn", "cdn", "blog", "docs", "shop", "app", "portal",
                   "login", "auth", "git", "jenkins", "kibana", "grafana"]
        for c in common:
            if c not in subs:
                subs.append(c)
        return subs

    async def _resolve(self, subdomain: str) -> tuple[str, list[str]]:
        """Resolve single subdomain"""
        fqdn = f"{subdomain}.{self.base_domain}"
        try:
            loop = asyncio.get_event_loop()
            ips = await loop.run_in_executor(None, lambda: socket.getaddrinfo(fqdn, None))
            return subdomain, list(set(ip[4][0] for ip in ips))
        except (socket.gaierror, OSError):
            return subdomain, []

    async def _query_crtsh(self) -> list[str]:
        """Query crt.sh for subdomains"""
        results = []
        try:
            url = f"https://crt.sh/?q=%.{self.base_domain}&output=json"
            resp = await self._get(url)
            if resp and resp.status_code == 200:
                data = resp.json()
                names = set()
                for entry in data[:200]:  # Limit
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lstrip("*.")
                        if n.endswith(f".{self.base_domain}") or n == self.base_domain:
                            names.add(n)
                results = sorted(names)
        except Exception:
            pass  # crt.sh might rate-limit, that's ok~
        return results
