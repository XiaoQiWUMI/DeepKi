# (●°u°●)​ 」 Directory Brute-Forcer
# Xiao Qi paws through directories looking for hidden treasures~ 📁

from pathlib import Path
from .base import BaseScanner, ScanResult
from ..config import WORDLIST_DIR


class DirectoryScanner(BaseScanner):
    """Brute-force directories & files"""

    name = "directory"
    icon = "📁"
    description = "Directory & file brute-force"

    INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

    def __init__(self, target_url: str, wordlist: str = None, **kwargs):
        super().__init__(target_url, **kwargs)
        self.wordlist_path = Path(wordlist) if wordlist else WORDLIST_DIR / "common_dirs.txt"
        self._seen: set[str] = set()

    async def run(self) -> list[ScanResult]:
        results = []
        paths = self._load_wordlist()
        total = len(paths)
        await self._report_progress(0, total, {"found": 0, "reqs": 0})

        found_count = 0
        for i, path in enumerate(paths):
            url = self._url(path)
            resp = await self._head(url)
            if resp is not None and resp.status_code in self.INTERESTING_CODES:
                found_count += 1
                result = self._classify(url, path, resp)
                results.append(result)
                await self._report_finding(result)

            if i % 20 == 0:
                await self._report_progress(
                    i + 1, total,
                    {"found": found_count, "reqs": i + 1}
                )

        await self._report_progress(total, total, {"found": found_count, "reqs": total})
        return results

    def _load_wordlist(self) -> list[str]:
        paths = []
        if self.wordlist_path.exists():
            with open(self.wordlist_path) as f:
                paths = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        # Always include these
        builtin = [
            "admin", "login", "wp-admin", "administrator",
            "api", "api/v1", "graphql", "swagger", "docs",
            "backup", "backups", "bak", "old", "test", "dev",
            ".git/HEAD", ".env", ".DS_Store", "robots.txt",
            "sitemap.xml", "crossdomain.xml", "phpinfo.php",
            "phpmyadmin", "pma", "mysql", "adminer.php",
            "console", "dashboard", "manager", "jenkins",
            "status", "health", "actuator", "metrics",
            "uploads", "static", "assets", "js", "css", "images",
            "config", "conf", "settings", "debug",
            "vendor", "node_modules", "storage", "logs",
            ".well-known/security.txt", ".well-known/openid-configuration",
            "wp-content", "wp-includes", "wp-json", "wp-login",
            "xmlrpc.php", "wp-config.php.bak", "wp-config.php~",
            "server-status", "server-info", ".htaccess",
        ]
        for b in builtin:
            if b not in paths:
                paths.append(b)
        return paths

    def _classify(self, url: str, path: str, resp) -> ScanResult:
        code = resp.status_code
        content_type = resp.headers.get("content-type", "")

        # Classify by status code & path patterns
        if path.endswith((".env", ".git/HEAD", "wp-config.php.bak", "wp-config.php~")):
            sev, title = "high", f"Sensitive file exposed: {path}"
        elif path in ("admin", "wp-admin", "administrator", "manager", "console"):
            sev, title = "medium", f"Admin panel found: {path}"
        elif path in ("phpinfo.php", "phpmyadmin", "adminer.php"):
            sev, title = "medium", f"Database tool exposed: {path}"
        elif path in ("backup", "backups", "bak") and code == 200:
            sev, title = "medium", f"Backup directory accessible: {path}"
        elif path in (".well-known/security.txt",):
            sev, title = "info", f"Security policy: {path}"
        elif code == 403:
            sev, title = "info", f"Forbidden (potential attack surface): {path}"
        elif code == 401:
            sev, title = "info", f"Auth required: {path}"
        elif "json" in content_type and path.startswith("api"):
            sev, title = "info", f"API endpoint: {path}"
        else:
            sev, title = "info", f"Path found [{code}]: {path}"

        return ScanResult(
            module=self.name,
            title=title,
            severity=sev,
            url=url,
            evidence=f"HTTP {code} | Content-Type: {content_type} | Size: {resp.headers.get('content-length', '?')}",
            description=f"Directory/file brute-force discovered: {url} (HTTP {code})",
        )
