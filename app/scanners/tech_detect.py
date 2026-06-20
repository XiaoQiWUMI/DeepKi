# (●°u°●)​ 」 Technology Fingerprinter
# Xiao Qi sniffs what the website is made of~ 🖥️  ~_^

import re
from .base import BaseScanner, ScanResult
from ..config import VULN_SIGNATURES

# Technology fingerprints
FINGERPRINTS = {
    "frameworks": {
        "WordPress": [
            ("header", "x-powered-by", re.compile(r"WordPress", re.I)),
            ("body", None, re.compile(r"wp-content/|wordpress|wp-json", re.I)),
            ("path", "/wp-login.php", None),
        ],
        "Laravel": [
            ("cookie", None, re.compile(r"laravel_session", re.I)),
            ("header", "set-cookie", re.compile(r"laravel_session", re.I)),
        ],
        "Django": [
            ("cookie", None, re.compile(r"csrftoken|sessionid=", re.I)),
            ("body", None, re.compile(r"__django|django\.", re.I)),
        ],
        "Spring Boot": [
            ("body", None, re.compile(r"Whitelabel Error Page|spring-boot", re.I)),
            ("path", "/actuator/health", None),
        ],
        "Express": [
            ("header", "x-powered-by", re.compile(r"Express", re.I)),
        ],
        "Flask": [
            ("cookie", None, re.compile(r"flask-session", re.I)),
        ],
        "Ruby on Rails": [
            ("cookie", None, re.compile(r"_session.*=", re.I)),
        ],
        "ASP.NET": [
            ("header", "x-powered-by", re.compile(r"ASP\.NET", re.I)),
            ("header", "x-aspnet-version", re.compile(r".*")),
        ],
    },
    "servers": {
        "Nginx": [
            ("header", "server", re.compile(r"nginx", re.I)),
        ],
        "Apache": [
            ("header", "server", re.compile(r"Apache", re.I)),
        ],
        "IIS": [
            ("header", "server", re.compile(r"IIS|Microsoft-IIS", re.I)),
        ],
        "Cloudflare": [
            ("header", "cf-ray", re.compile(r".*")),
            ("header", "server", re.compile(r"cloudflare", re.I)),
        ],
    },
    "js_libs": {
        "jQuery": [("body", None, re.compile(r"jquery[.-](\d+\.\d+\.\d+)", re.I))],
        "React": [("body", None, re.compile(r"react(\d+\.\d+\.\d+)?\.\w+\.js|__REACT", re.I))],
        "Vue.js": [("body", None, re.compile(r"vue(\d+\.\d+\.\d+)?\.\w+\.js|__VUE", re.I))],
        "Bootstrap": [("body", None, re.compile(r"bootstrap(\d+\.\d+\.\d+)?\.\w+\.css", re.I))],
        "Angular": [("body", None, re.compile(r"angular(\d+\.\d+\.\d+)?\.\w+\.js|ng-app", re.I))],
    },
}


class TechDetector(BaseScanner):
    """Fingerprint technologies used by target"""

    name = "tech_detect"
    icon = "🖥️"
    description = "Technology stack fingerprinting"

    async def run(self) -> list[ScanResult]:
        results = []

        # Fetch homepage
        resp = await self._get(self.target_url)
        if resp is None:
            return [ScanResult(
                module=self.name, title="Target unreachable",
                severity="info", url=self.target_url,
                description=f"Could not connect to {self.target_url}",
            )]

        body = resp.text[:50000] if resp.text else ""
        headers = dict(resp.headers)
        await self._report_progress(1, 5, {"detected": 0})

        # Check fingerprints
        for category, techs in FINGERPRINTS.items():
            for tech_name, checks in techs.items():
                if self._match(checks, headers, body):
                    results.append(ScanResult(
                        module=self.name,
                        title=f"{category.upper()}: {tech_name}",
                        severity="info",
                        url=self.target_url,
                        description=f"Detected {tech_name} ({category})",
                        evidence=self._get_evidence(checks, headers, body),
                    ))

        await self._report_progress(3, 5, {"detected": len(results)})

        # Check special paths
        special_paths = {
            "/actuator/health": "Spring Boot Actuator",
            "/wp-json/wp/v2/users": "WordPress REST API",
            "/.env": "Environment file",
            "/swagger-ui.html": "Swagger UI",
            "/api-docs": "API Documentation",
            "/graphql": "GraphQL endpoint",
        }
        for path, label in special_paths.items():
            r = await self._head(self._url(path))
            if r and r.status_code in (200, 401, 403):
                results.append(ScanResult(
                    module=self.name,
                    title=f"Special endpoint: {label}",
                    severity="info" if r.status_code != 200 else "medium",
                    url=self._url(path),
                    description=f"{label} accessible at {path} (HTTP {r.status_code})",
                    evidence=f"HTTP {r.status_code} | {r.headers.get('content-type', '')}",
                ))

        await self._report_progress(5, 5, {"detected": len(results)})

        # Check sensitive files from signatures
        for fname in VULN_SIGNATURES["sensitive_files"]:
            r = await self._get(self._url(f"/{fname}"))
            if r and r.status_code == 200:
                results.append(ScanResult(
                    module=self.name,
                    title=f"Sensitive file exposed: {fname}",
                    severity="high",
                    url=self._url(f"/{fname}"),
                    evidence=f"HTTP 200, size={len(r.text) if r.text else 0}",
                ))

        return results

    def _match(self, checks, headers: dict, body: str) -> bool:
        for source, key, pattern in checks:
            if source == "header":
                if key:
                    val = headers.get(key, "")
                    if pattern and pattern.search(val):
                        return True
                else:
                    for v in headers.values():
                        if pattern and pattern.search(v):
                            return True
            elif source == "cookie":
                cookie = headers.get("set-cookie", "")
                if pattern and pattern.search(cookie):
                    return True
            elif source == "body":
                if pattern and pattern.search(body):
                    return True
            elif source == "path":
                # Path checks are done separately
                pass
        return False

    def _get_evidence(self, checks, headers: dict, body: str) -> str:
        """Extract matching evidence string"""
        for source, key, pattern in checks:
            if source == "header":
                if key and key in headers:
                    return f"Header {key}: {headers[key][:200]}"
            elif source == "body":
                m = pattern.search(body) if pattern else None
                if m:
                    return f"Body contains: {m.group()}"
        return "Pattern matched"
