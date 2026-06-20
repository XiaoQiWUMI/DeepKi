# (●°u°●)​ 」 Security Header Auditor
# Xiao Qi checks if the website wears its safety helmet~ 📋

from .base import BaseScanner, ScanResult

# Expected security headers with their importance
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "title": "Missing HSTS Header",
        "desc": "HSTS (HTTP Strict-Transport-Security) not set. Users may access the site over plain HTTP.",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "X-Frame-Options": {
        "severity": "low",
        "title": "Missing X-Frame-Options",
        "desc": "Site can be framed by other pages, enabling clickjacking attacks.",
        "fix": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "title": "Missing X-Content-Type-Options",
        "desc": "Browser may MIME-sniff content, leading to XSS via uploaded files.",
        "fix": "Add: X-Content-Type-Options: nosniff",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "title": "Missing Content-Security-Policy",
        "desc": "No CSP header set. XSS and data injection attacks are easier without CSP.",
        "fix": "Add a restrictive CSP header (e.g., default-src 'self')",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "title": "Missing X-XSS-Protection",
        "desc": "Legacy XSS filter not enabled (deprecated but still useful for older browsers).",
        "fix": "Add: X-XSS-Protection: 1; mode=block",
    },
    "Referrer-Policy": {
        "severity": "info",
        "title": "Missing Referrer-Policy",
        "desc": "Referrer information may leak sensitive URLs to third parties.",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "info",
        "title": "Missing Permissions-Policy",
        "desc": "Browser features (camera, mic, etc.) are not restricted.",
        "fix": "Add Permissions-Policy header to limit browser features",
    },
}

COOKIE_FLAGS = {
    "HttpOnly": "Prevents JavaScript from reading the cookie (XSS protection)",
    "Secure": "Cookie only sent over HTTPS",
    "SameSite": "Prevents CSRF: should be Lax or Strict",
}


class HeaderAuditor(BaseScanner):
    """Audit security headers and cookie settings"""

    name = "header_audit"
    icon = "📋"
    description = "Security header & cookie audit"

    async def run(self) -> list[ScanResult]:
        results = []

        resp = await self._get(self.target_url)
        if resp is None:
            return [ScanResult(
                module=self.name, title="Target unreachable",
                severity="info", url=self.target_url,
                description="Could not connect for header audit",
            )]

        headers = {k.lower(): v for k, v in resp.headers.items()}
        set_cookies = resp.headers.get_all("set-cookie") if hasattr(resp.headers, 'get_all') \
            else [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]

        total = len(SECURITY_HEADERS) + len(set_cookies) + 3
        step = 0
        await self._report_progress(0, total, {"missing": 0, "cookie_issues": 0})

        # Check security headers
        missing = 0
        for header_name, info in SECURITY_HEADERS.items():
            step += 1
            if header_name.lower() not in headers:
                missing += 1
                results.append(ScanResult(
                    module=self.name,
                    title=info["title"],
                    severity=info["severity"],
                    url=self.target_url,
                    description=info["desc"],
                    remediation=info["fix"],
                    evidence=f"Header '{header_name}' not present in response",
                ))
            await self._report_progress(step, total, {"missing": missing, "cookie_issues": len(results) - missing})

        # Check cookie flags
        cookie_issues = 0
        for cookie in set_cookies:
            step += 1
            cookie_lower = cookie.lower()
            if "httponly" not in cookie_lower:
                cookie_issues += 1
                results.append(ScanResult(
                    module=self.name,
                    title="Cookie missing HttpOnly flag",
                    severity="low",
                    url=self.target_url,
                    description=COOKIE_FLAGS["HttpOnly"],
                    evidence=f"Set-Cookie: {cookie[:200]}",
                    remediation="Add HttpOnly flag to session cookies",
                ))
            if "secure" not in cookie_lower and self.target_url.startswith("https"):
                cookie_issues += 1
                results.append(ScanResult(
                    module=self.name,
                    title="Cookie missing Secure flag",
                    severity="low",
                    url=self.target_url,
                    description=COOKIE_FLAGS["Secure"],
                    evidence=f"Set-Cookie: {cookie[:200]}",
                    remediation="Add Secure flag to cookies (HTTPS-only)",
                ))
            if "samesite" not in cookie_lower:
                cookie_issues += 1
                results.append(ScanResult(
                    module=self.name,
                    title="Cookie missing SameSite attribute",
                    severity="low",
                    url=self.target_url,
                    description=COOKIE_FLAGS["SameSite"],
                    evidence=f"Set-Cookie: {cookie[:200]}",
                    remediation="Add SameSite=Lax or SameSite=Strict to cookies",
                ))

        # Check server header leak
        step += 1
        server = headers.get("server", "")
        if server:
            results.append(ScanResult(
                module=self.name,
                title=f"Server header leak: {server}",
                severity="info",
                url=self.target_url,
                description=f"Server header reveals: {server}. This helps attackers target version-specific exploits.",
                evidence=f"Server: {server}",
                remediation="Remove or mask the Server header",
            ))

        # Check X-Powered-By
        step += 1
        powered = headers.get("x-powered-by", "")
        if powered:
            results.append(ScanResult(
                module=self.name,
                title=f"X-Powered-By leak: {powered}",
                severity="info",
                url=self.target_url,
                description=f"Technology disclosure via X-Powered-By: {powered}",
                evidence=f"X-Powered-By: {powered}",
                remediation="Remove X-Powered-By header",
            ))

        await self._report_progress(total, total, {"missing": missing, "cookie_issues": cookie_issues})
        return results
