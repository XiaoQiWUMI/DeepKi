# (●°u°●)​ 」 403 Bypass Tester
# Xiao Qi knocks creatively until the door opens~ 🚪

from .base import BaseScanner, ScanResult


class PortKnocker(BaseScanner):
    """Test 403/401 bypass techniques"""

    name = "port_knock"
    icon = "🚪"
    description = "403/401 bypass techniques"

    # Bypass techniques from the 403-bypass skill
    PATH_BYPASSES = [
        # Path obfuscation
        ("/{path}", "Normal"),
        ("/{path}/", "Trailing slash"),
        ("/{path};/", "Semicolon"),
        ("/{path}..;/", "Dot-dot-semicolon"),
        ("/{path}.json", "JSON extension"),
        ("/{path}.html", "HTML extension"),
        ("/{path}.xml", "XML extension"),
        ("/{path}.bak", "Backup extension"),
        ("//{path}", "Double slash"),
        ("/{path}/.", "Dot suffix"),
        ("/{path}/..;/..;/", "Double dot-dot-semicolon"),
        ("/./{path}", "Dot-slash prefix"),
        ("/%2e/{path}", "URL-encoded dot"),
        ("/{upper_path}", "Uppercase path"),
    ]

    HEADER_BYPASSES = [
        ({"X-Forwarded-For": "127.0.0.1"}, "X-Forwarded-For localhost"),
        ({"X-Forwarded-Host": "127.0.0.1"}, "X-Forwarded-Host localhost"),
        ({"X-Original-URL": "/admin"}, "X-Original-URL"),
        ({"X-Rewrite-URL": "/admin"}, "X-Rewrite-URL"),
        ({"X-Custom-IP-Authorization": "127.0.0.1"}, "X-Custom-IP-Authorization"),
        ({"X-Originating-IP": "127.0.0.1"}, "X-Originating-IP"),
        ({"X-Remote-IP": "127.0.0.1"}, "X-Remote-IP"),
        ({"X-Remote-Addr": "127.0.0.1"}, "X-Remote-Addr"),
        ({"X-Client-IP": "127.0.0.1"}, "X-Client-IP"),
        ({"X-Real-IP": "127.0.0.1"}, "X-Real-IP"),
        ({"X-ProxyUser-Ip": "127.0.0.1"}, "X-ProxyUser-Ip"),
        ({"Client-IP": "127.0.0.1"}, "Client-IP"),
        ({"True-Client-IP": "127.0.0.1"}, "True-Client-IP"),
        ({"Referer": "/admin"}, "Referer admin"),
    ]

    METHOD_BYPASSES = [
        ("GET", "GET"),
        ("POST", "POST"),
        ("HEAD", "HEAD"),
        ("OPTIONS", "OPTIONS"),
        ("PUT", "PUT"),
        ("PATCH", "PATCH"),
        ("TRACE", "TRACE"),
    ]

    def __init__(self, target_url: str, blocked_paths: list[str] = None, **kwargs):
        super().__init__(target_url, **kwargs)
        # Paths to try bypassing
        self.blocked_paths = blocked_paths or [
            "admin", "wp-admin", "administrator",
            "console", "manager", "dashboard",
            "config", "backup", "api",
        ]

    async def run(self) -> list[ScanResult]:
        results = []

        # First find which paths return 403
        blocked = []
        for path in self.blocked_paths:
            resp = await self._get(self._url(f"/{path}"))
            if resp and resp.status_code in (403, 401):
                blocked.append(path)

        if not blocked:
            # Test a few common blocked paths even if not found
            blocked = ["admin"]
            resp = await self._get(self._url("/admin"))
            if resp and resp.status_code not in (403, 401):
                return results  # Nothing blocked, skip

        total = len(blocked) * (len(self.PATH_BYPASSES) + len(self.HEADER_BYPASSES) + len(self.METHOD_BYPASSES))
        step = 0
        await self._report_progress(0, total, {"bypassed": 0, "tested": 0})

        bypass_count = 0
        for path in blocked:
            # Path bypasses
            for pattern, technique in self.PATH_BYPASSES:
                step += 1
                try:
                    test_path = pattern.format(
                        path=path,
                        upper_path=path.upper(),
                    )
                    resp = await self._get(self._url(test_path))
                    if resp and resp.status_code in (200, 301, 302):
                        bypass_count += 1
                        results.append(ScanResult(
                            module=self.name,
                            title=f"403 Bypass [{technique}]: {path}",
                            severity="medium",
                            url=self._url(test_path),
                            description=f"403 bypass via {technique}. Path '{test_path}' returned HTTP {resp.status_code}",
                            evidence=f"HTTP {resp.status_code}, size={len(resp.text or '')}",
                            remediation="Ensure consistent access control regardless of path format",
                        ))
                except Exception:
                    pass
                if step % 10 == 0:
                    await self._report_progress(step, total, {"bypassed": bypass_count, "tested": step})

            # Header bypasses
            for headers, technique in self.HEADER_BYPASSES:
                step += 1
                try:
                    resp = await self._get(self._url(f"/{path}"), headers=headers)
                    if resp and resp.status_code in (200, 301, 302):
                        bypass_count += 1
                        results.append(ScanResult(
                            module=self.name,
                            title=f"403 Bypass [{technique}]: {path}",
                            severity="medium",
                            url=self._url(f"/{path}"),
                            description=f"403 bypass via {technique}. HTTP {resp.status_code}",
                            evidence=f"HTTP {resp.status_code}, size={len(resp.text or '')}",
                            remediation="Validate access control against actual authentication, not IP headers",
                        ))
                except Exception:
                    pass
                if step % 10 == 0:
                    await self._report_progress(step, total, {"bypassed": bypass_count, "tested": step})

            # Method bypasses
            for method, mname in self.METHOD_BYPASSES:
                step += 1
                if method == "GET":
                    continue  # Already tested
                try:
                    resp = await self.client.request(method, self._url(f"/{path}"))
                    if resp and resp.status_code in (200, 301, 302):
                        bypass_count += 1
                        results.append(ScanResult(
                            module=self.name,
                            title=f"403 Bypass [Method {mname}]: {path}",
                            severity="medium",
                            url=self._url(f"/{path}"),
                            description=f"403 bypass via HTTP {mname} method. HTTP {resp.status_code}",
                            evidence=f"Method: {method}, HTTP {resp.status_code}",
                        ))
                except Exception:
                    pass

        await self._report_progress(total, total, {"bypassed": bypass_count, "tested": step})
        return results
