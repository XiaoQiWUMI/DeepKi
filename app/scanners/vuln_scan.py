# (●°u°●)​ 」 Vulnerability Scanner
# Xiao Qi finds the juicy bugs~ 💉  ~_^

import re
from urllib.parse import urlparse, parse_qs
from .base import BaseScanner, ScanResult
from ..config import VULN_SIGNATURES


class VulnScanner(BaseScanner):
    """Signature-based vulnerability detection"""

    name = "vuln_scan"
    icon = "💉"
    description = "Vulnerability detection (SQLi, XSS, SSRF, SSTI, LFI, etc.)"

    # Payloads for each vulnerability type
    SQLI_PAYLOADS = [
        ("'", "SQL syntax|mysql_fetch|ORA-\\d{5}|PostgreSQL|unclosed quotation|syntax error"),
        ('"', "SQL syntax|mysql_fetch|syntax error"),
        ("' OR '1'='1", "SQL|mysql|syntax"),
        ("' OR 1=1--", "SQL|mysql|syntax"),
        ("1' AND '1'='1", "SQL|mysql|syntax"),
        ("1' ORDER BY 1--", "SQL|mysql|syntax"),
    ]

    XSS_PAYLOADS = [
        "<script>alert('XSS_TEST')</script>",
        '"><script>alert("XSS_TEST")</script>',
        "<img src=x onerror=alert('XSS_TEST')>",
        "javascript:alert('XSS_TEST')",
    ]

    SSTI_PAYLOADS = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("{{config}}", "Config|secret|SECRET_KEY"),
    ]

    LFI_PATHS = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd%00",
        "..\\..\\..\\windows\\win.ini",
        "php://filter/convert.base64-encode/resource=index",
    ]

    OPENREDIRECT_PARAMS = [
        "redirect", "redirect_uri", "redirect_url", "url", "return", "return_url",
        "next", "target", "dest", "destination", "callback", "callback_url",
        "continue", "goto", "redir", "forward",
    ]

    SSRF_PARAMS = [
        "url", "uri", "path", "file", "document", "folder", "root",
        "server", "domain", "src", "source", "href", "link", "web",
        "api", "endpoint", "host", "site", "proxy", "fetch",
    ]

    def __init__(self, target_url: str, **kwargs):
        super().__init__(target_url, **kwargs)
        self._findings: list[ScanResult] = []

    async def run(self) -> list[ScanResult]:
        self._findings = []

        # Phase 1: Get baseline
        resp = await self._get(self.target_url)
        if resp is None:
            return self._findings

        body = resp.text
        # Extract all links & forms for parameter discovery
        params = self._extract_params(body)

        total_steps = 1 + len(params) * 2 + 6
        step = 0
        await self._report_progress(step, total_steps, {"findings": 0})

        # Phase 2: SQLi test on each parameter
        for param in params[:20]:  # limit params to test
            await self._test_sqli(param)
            step += 1
            await self._report_progress(step, total_steps, {"findings": len(self._findings)})

        # Phase 3: XSS test on each parameter
        for param in params[:20]:
            await self._test_xss(param)
            step += 1
            await self._report_progress(step, total_steps, {"findings": len(self._findings)})

        # Phase 4: SSTI test
        await self._test_ssti(params)
        step += 1
        await self._report_progress(step, total_steps, {"findings": len(self._findings)})

        # Phase 5: LFI test
        await self._test_lfi()
        step += 1
        await self._report_progress(step, total_steps, {"findings": len(self._findings)})

        # Phase 6: Open redirect
        await self._test_openredirect(params)
        step += 1
        await self._report_progress(step, total_steps, {"findings": len(self._findings)})

        # Phase 7: SSRF
        await self._test_ssrf(params)
        step += 1
        await self._report_progress(step, total_steps, {"findings": len(self._findings)})

        # Phase 8: Common CVE checks
        await self._check_common_cves()
        step += 1
        await self._report_progress(step, total_steps, {"findings": len(self._findings)})

        # Phase 9: Security.txt / well-known
        await self._check_wellknown()
        step += 1
        await self._report_progress(step, total_steps, {"findings": len(self._findings)})

        await self._report_progress(total_steps, total_steps, {"findings": len(self._findings)})
        return self._findings

    def _extract_params(self, body: str) -> list[str]:
        """Extract query parameters from links and forms"""
        params = set()
        # Input names
        for m in re.finditer(r'name=["\'](\w+)["\']', body, re.I):
            params.add(m.group(1))
        # URL query params
        for m in re.finditer(r'href=["\']([^"\']+)["\']', body, re.I):
            try:
                parsed = urlparse(m.group(1))
                for k in parse_qs(parsed.query).keys():
                    params.add(k)
            except Exception:
                pass
        # JSON keys in script tags
        for m in re.finditer(r'["\'](\w{2,20})["\']\s*:', body):
            params.add(m.group(1))

        return list(params)[:30]

    async def _test_sqli(self, param: str):
        for payload, error_pattern in self.SQLI_PAYLOADS:
            url = f"{self.target_url}?{param}={payload}"
            resp = await self._get(url)
            if resp and resp.text:
                if re.search(error_pattern, resp.text, re.I):
                    self._add_finding(ScanResult(
                        module=self.name,
                        title=f"Potential SQL Injection: {param}",
                        severity="high",
                        url=url,
                        description=f"SQL error detected when injecting parameter '{param}' with payload: {payload}",
                        evidence=resp.text[:500],
                        remediation="Use parameterized queries / prepared statements",
                    ))
                    return  # One finding per param is enough

    async def _test_xss(self, param: str):
        payload = '"><img src=x onerror=alert("XSS_TEST")>'
        url = f"{self.target_url}?{param}={payload}"
        resp = await self._get(url)
        if resp and payload in resp.text:
            self._add_finding(ScanResult(
                module=self.name,
                title=f"Potential Reflected XSS: {param}",
                severity="medium",
                url=url,
                description=f"Payload reflected in response for parameter '{param}'",
                evidence=f"Payload '{payload}' found in response body",
                remediation="HTML-encode all user input before output",
            ))

    async def _test_ssti(self, params: list[str]):
        for payload, expected in self.SSTI_PAYLOADS:
            for param in params[:5]:
                url = f"{self.target_url}?{param}={payload}"
                resp = await self._get(url)
                if resp and expected in resp.text:
                    self._add_finding(ScanResult(
                        module=self.name,
                        title=f"Potential SSTI: {param}",
                        severity="high",
                        url=url,
                        description=f"Template expression '{payload}' evaluated: found '{expected}'",
                        evidence=f"Expected result '{expected}' found in response",
                    ))
                    return

    async def _test_lfi(self):
        for path in self.LFI_PATHS[:3]:
            url = f"{self.target_url}?file={path}"
            resp = await self._get(url)
            if resp and "root:" in resp.text:
                self._add_finding(ScanResult(
                    module=self.name,
                    title=f"Potential LFI (Local File Inclusion)",
                    severity="high",
                    url=url,
                    description=f"/etc/passwd content detected via path traversal: {path}",
                    evidence=resp.text[:500],
                ))
                return

    async def _test_openredirect(self, params: list[str]):
        for param in self.OPENREDIRECT_PARAMS:
            if param in params:
                test_url = "https://evil.com"
                url = f"{self.target_url}?{param}={test_url}"
                resp = await self._get(url)
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if test_url in location:
                        self._add_finding(ScanResult(
                            module=self.name,
                            title=f"Open Redirect: {param}",
                            severity="medium",
                            url=url,
                            description=f"Parameter '{param}' can redirect to arbitrary URLs",
                            evidence=f"Location header: {location}",
                        ))

    async def _test_ssrf(self, params: list[str]):
        for param in self.SSRF_PARAMS:
            if param in params:
                url = f"{self.target_url}?{param}=http://169.254.169.254/latest/meta-data/"
                resp = await self._get(url)
                if resp and resp.status_code == 200 and len(resp.text) > 50:
                    self._add_finding(ScanResult(
                        module=self.name,
                        title=f"Potential SSRF: {param}",
                        severity="high",
                        url=url,
                        description=f"Parameter '{param}' may allow SSRF to cloud metadata",
                        evidence=resp.text[:500],
                    ))

    async def _check_common_cves(self):
        """Check for common known vulnerabilities"""
        checks = [
            ("/api/log", "Log4j JNDI test header", {"X-Api-Version": "${jndi:ldap://test}"}),
            ("/struts2-showcase/", "Struts2 Showcase", {}),
            ("/.git/HEAD", "Git repo exposed", {}),
            ("/wp-content/debug.log", "WordPress debug log", {}),
            ("/console", "H2 Console", {}),
            ("/druid/index.html", "Druid Monitor", {}),
        ]
        for path, title, extra_headers in checks:
            resp = await self._get(self._url(path), headers=extra_headers)
            if resp and resp.status_code in (200, 403):
                sev = "high" if resp.status_code == 200 else "info"
                self._add_finding(ScanResult(
                    module=self.name,
                    title=title,
                    severity=sev,
                    url=self._url(path),
                    evidence=f"HTTP {resp.status_code}, size={len(resp.text or '')}",
                ))

    async def _check_wellknown(self):
        """Check .well-known paths"""
        paths = [
            "/.well-known/security.txt",
            "/.well-known/openid-configuration",
            "/.well-known/assetlinks.json",
        ]
        for path in paths:
            resp = await self._get(self._url(path))
            if resp and resp.status_code == 200:
                self._add_finding(ScanResult(
                    module=self.name,
                    title=f".well-known resource: {path}",
                    severity="info",
                    url=self._url(path),
                    evidence=resp.text[:300],
                ))

    def _add_finding(self, result: ScanResult):
        self._findings.append(result)
