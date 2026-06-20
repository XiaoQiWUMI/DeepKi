# (●°u°●)​ 」 CORS Tester
# Xiao Qi checks if the website plays nice with others~ 🌐

from .base import BaseScanner, ScanResult


class CORSTester(BaseScanner):
    """Test CORS misconfigurations"""

    name = "cors_test"
    icon = "🌐"
    description = "CORS misconfiguration testing"

    # Test origins for CORS
    TEST_ORIGINS = [
        ("null", "Null origin allowed"),
        ("https://evil.com", "Arbitrary origin reflected"),
        (f"https://attacker{''}.com.evil.com", "Prefix match bypass"),
        ("https://evil.com;https://trusted.com", "Origin list injection"),
    ]

    async def run(self) -> list[ScanResult]:
        results = []

        total = len(self.TEST_ORIGINS) + 3
        step = 0
        await self._report_progress(0, total, {"issues": 0})

        # First check if CORS is even present
        baseline = await self._get(self.target_url)
        if baseline is None:
            return []

        baseline_acao = baseline.headers.get("access-control-allow-origin", "")
        baseline_acac = baseline.headers.get("access-control-allow-credentials", "")

        if not baseline_acao:
            results.append(ScanResult(
                module=self.name,
                title="No CORS headers (safe default)",
                severity="info",
                url=self.target_url,
                description="No Access-Control-Allow-Origin header present. The site does not enable CORS.",
            ))
        step += 1
        await self._report_progress(step, total, {"issues": len(results)})

        # Test various origins
        for origin, title in self.TEST_ORIGINS:
            step += 1
            resp = await self._get(
                self.target_url,
                headers={"Origin": origin},
            )
            if resp is None:
                continue

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")
            acam = resp.headers.get("access-control-allow-methods", "")

            is_vuln = False
            evidence = ""

            # Check if origin is reflected
            if acao == origin:
                is_vuln = True
                evidence += f"Origin reflected: {acao}"
            elif acao == "*" and acac.lower() == "true":
                is_vuln = True
                evidence += "Wildcard origin with credentials=true"

            if is_vuln:
                res = ScanResult(
                    module=self.name,
                    title=f"CORS: {title}",
                    severity="medium" if acac.lower() == "true" else "low",
                    url=self.target_url,
                    description=f"CORS misconfiguration: {title}. ACAO={acao}, ACAC={acac}",
                    evidence=evidence or f"ACAO: {acao}, ACAC: {acac}, ACAM: {acam}",
                    remediation="Use a strict allowlist of origins. Never reflect Origin header blindly. Never use * with credentials.",
                )
                results.append(res)

            await self._report_progress(step, total, {"issues": len(results)})

        # Test preflight
        step += 1
        preflight = await self._get(
            self.target_url,
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        if preflight and preflight.status_code in (200, 204):
            acao = preflight.headers.get("access-control-allow-origin", "")
            if acao == "https://evil.com":
                results.append(ScanResult(
                    module=self.name,
                    title="CORS: Preflight allows arbitrary origin",
                    severity="medium",
                    url=self.target_url,
                    evidence=f"Preflight OK, ACAO={acao}",
                ))

        # Check for ACAH / ACAM with origin reflection
        step += 1
        acah = baseline.headers.get("access-control-allow-headers", "")
        if "authorization" in acah.lower() and baseline_acao:
            results.append(ScanResult(
                module=self.name,
                title="CORS: Authorization header allowed with CORS",
                severity="medium",
                url=self.target_url,
                description="Site allows Authorization header via CORS. Combined with origin reflection, this leaks credentials.",
                evidence=f"ACAH: {acah}",
            ))

        await self._report_progress(total, total, {"issues": len(results)})
        return results
