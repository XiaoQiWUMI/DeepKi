# (●°u°●)​ 」 Scan Orchestrator
# Xiao Qi's brain — coordinates all the paws!
# Uses the Deepki cute terminal/web progress format~

import asyncio
import time
from datetime import datetime, timezone
from typing import Optional, AsyncIterator
from dataclasses import dataclass, field

from .base import BaseScanner, ScanResult
from .subdomain import SubdomainScanner
from .portscan import PortScanner
from .directory import DirectoryScanner
from .tech_detect import TechDetector
from .vuln_scan import VulnScanner
from .header_audit import HeaderAuditor
from .cors_test import CORSTester
from .port_knock import PortKnocker
from ..models.database import Severity


@dataclass
class ModuleProgress:
    """Progress of one scan module"""
    module: str
    icon: str
    label: str
    current: int = 0
    total: int = 0
    status: str = "queued"  # queued | running | done
    extra: dict = field(default_factory=dict)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None

    @property
    def percent(self) -> int:
        if self.total == 0:
            return 0 if self.status == "running" else 100
        return min(100, int(self.current / self.total * 100))

    @property
    def elapsed(self) -> str:
        if self.started_at is None:
            return "0s"
        end = self.finished_at or time.time()
        secs = int(end - self.started_at)
        if secs < 60:
            return f"{secs}s"
        return f"{secs // 60}m{secs % 60}s"


@dataclass
class ScanProgress:
    """Overall scan progress"""
    target_url: str
    mode: str
    started_at: float
    modules: dict[str, ModuleProgress] = field(default_factory=dict)
    findings: list[ScanResult] = field(default_factory=list)
    phase: str = "info"  # info | vuln | verify | report
    overall_percent: int = 0
    status: str = "running"

    @property
    def severity_counts(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def formatted_time(self) -> str:
        return datetime.fromtimestamp(self.started_at).strftime("%H:%M:%S")


class ScanOrchestrator:
    """Orchestrates multiple scanners, manages progress, collects findings"""

    PHASES = [
        ("info", "信息收集", "(●°u°●)​ 」 Xiao Qi is sniffing..."),
        ("vuln", "漏洞扫描", ">_< digging deep..."),
        ("verify", "漏洞验证", "~_^ poking carefully..."),
        ("report", "报告生成", "^ - ^ Baking report..."),
    ]

    def __init__(
        self,
        target_url: str,
        mode: str = "full",
        modules: list[str] = None,
        progress_callback: Optional[callable] = None,
        finding_callback: Optional[callable] = None,
        **kwargs,
    ):
        self.target_url = target_url
        self.mode = mode
        self.enabled_modules = modules or list(self._all_modules().keys())
        self._progress_cb = progress_callback
        self._finding_cb = finding_callback
        self._scanner_kwargs = kwargs

        # Build progress tracker
        self.progress = ScanProgress(
            target_url=target_url,
            mode=mode,
            started_at=time.time(),
        )

    def _all_modules(self) -> dict:
        """All available scan modules"""
        return {
            "subdomain": {"class": SubdomainScanner, "icon": "🔍", "label": "子域名枚举", "phase": "info"},
            "portscan": {"class": PortScanner, "icon": "🔌", "label": "端口扫描", "phase": "info"},
            "directory": {"class": DirectoryScanner, "icon": "📁", "label": "目录爆破", "phase": "info"},
            "tech_detect": {"class": TechDetector, "icon": "🖥️", "label": "技术指纹", "phase": "info"},
            "vuln_scan": {"class": VulnScanner, "icon": "💉", "label": "漏洞扫描", "phase": "vuln"},
            "header_audit": {"class": HeaderAuditor, "icon": "📋", "label": "安全头审计", "phase": "info"},
            "cors_test": {"class": CORSTester, "icon": "🌐", "label": "CORS测试", "phase": "vuln"},
            "port_knock": {"class": PortKnocker, "icon": "🚪", "label": "403绕过", "phase": "vuln"},
        }

    async def run(self) -> ScanProgress:
        """Execute the full scan pipeline"""
        all_modules = self._all_modules()

        # Phase 1: Information Gathering (parallel)
        await self._emit_phase("info")
        info_modules = {k: v for k, v in all_modules.items()
                        if v["phase"] == "info" and k in self.enabled_modules}

        info_tasks = []
        for name, cfg in info_modules.items():
            task = self._run_module(name, cfg)
            info_tasks.append(task)

        if info_tasks:
            await asyncio.gather(*info_tasks)

        # Phase 2: Vulnerability Scanning (parallel)
        await self._emit_phase("vuln")
        vuln_modules = {k: v for k, v in all_modules.items()
                        if v["phase"] == "vuln" and k in self.enabled_modules}

        vuln_tasks = []
        for name, cfg in vuln_modules.items():
            task = self._run_module(name, cfg)
            vuln_tasks.append(task)

        if vuln_tasks:
            await asyncio.gather(*vuln_tasks)

        # Phase 3: Verification (for critical/high findings)
        await self._emit_phase("verify")
        await self._verify_findings()

        # Phase 4: Report generation
        await self._emit_phase("report")
        self.progress.overall_percent = 100
        self.progress.status = "completed"
        await self._notify_progress()

        return self.progress

    async def _run_module(self, name: str, cfg: dict):
        """Run one scanner module"""
        scanner_class = cfg["class"]

        # Init progress
        mp = ModuleProgress(
            module=name,
            icon=cfg["icon"],
            label=cfg["label"],
            status="running",
            started_at=time.time(),
        )
        self.progress.modules[name] = mp
        await self._notify_progress()

        try:
            async with scanner_class(
                self.target_url,
                progress_callback=self._module_progress_cb(name),
                finding_callback=self._module_finding_cb(name),
                **self._scanner_kwargs,
            ) as scanner:
                await scanner.run()

            mp.status = "done"
            mp.finished_at = time.time()

        except Exception as e:
            mp.status = "failed"
            mp.extra["error"] = str(e)
            mp.finished_at = time.time()

        await self._notify_progress()

    def _module_progress_cb(self, name: str):
        """Create progress callback for a module"""
        async def cb(module_name: str, current: int, total: int, extra: dict):
            if name in self.progress.modules:
                mp = self.progress.modules[name]
                mp.current = current
                mp.total = total
                mp.extra = extra
                await self._notify_progress()
        return cb

    def _module_finding_cb(self, name: str):
        """Create finding callback for a module"""
        async def cb(result: ScanResult):
            result.module = name
            self.progress.findings.append(result)
            if self._finding_cb:
                await self._finding_cb(result)
            await self._notify_progress()
        return cb

    async def _verify_findings(self):
        """Verify critical/high severity findings"""
        to_verify = [f for f in self.progress.findings
                     if f.severity in ("critical", "high")]

        if not to_verify:
            return

        verified = 0
        for i, finding in enumerate(to_verify):
            # Re-test the finding
            try:
                # Simple re-check: make the same request again
                async with BaseScanner(self.target_url) as scanner:
                    resp = await scanner._get(finding.url)
                    if resp and resp.status_code == 200:
                        finding.verified = True
                        finding.evidence += f"\n[Verified] Re-test returned HTTP {resp.status_code}"
                        verified += 1
            except Exception:
                pass

            if name := self.progress.modules.get("__verify__"):
                name.current = i + 1
                name.total = len(to_verify)
                name.extra["verified"] = verified
                name.extra["failed"] = (i + 1) - verified
            else:
                self.progress.modules["__verify__"] = ModuleProgress(
                    module="verify", icon="✅", label="漏洞验证",
                    current=i + 1, total=len(to_verify),
                    status="running", extra={"verified": verified, "failed": 0},
                )
            await self._notify_progress()

        if "__verify__" in self.progress.modules:
            self.progress.modules["__verify__"].status = "done"

    async def _emit_phase(self, phase_name: str):
        """Emit phase change"""
        for p in self.PHASES:
            if p[0] == phase_name:
                self.progress.phase = phase_name
                await self._notify_progress()
                return

    async def _notify_progress(self):
        """Call the progress callback with current state"""
        if self._progress_cb:
            await self._progress_cb(self.progress)

    @staticmethod
    def format_terminal(progress: ScanProgress) -> str:
        """Generate cute terminal progress output"""
        lines = []
        counts = progress.severity_counts
        elapsed = int(time.time() - progress.started_at)
        elapsed_str = f"{elapsed // 60}m{elapsed % 60}s" if elapsed >= 60 else f"{elapsed}s"

        lines.append(f"\n{'='*50}")
        lines.append(f"  目标: {progress.target_url}  模式: {progress.mode}  开始: {progress.formatted_time}")
        lines.append("")

        # Each phase
        for phase_key, phase_name, emoji_msg in ScanOrchestrator.PHASES:
            phase_modules = {k: v for k, v in progress.modules.items()
                             if v.module != "__verify__" or phase_key == "verify"}
            if phase_key == "verify":
                phase_modules = {k: v for k, v in progress.modules.items()
                                 if k == "__verify__"}

            relevant = False
            for mp in phase_modules.values():
                if mp.status in ("running", "done"):
                    relevant = True
                    break

            if not relevant and phase_key != progress.phase:
                continue

            # Build module summary
            summaries = []
            for mp in phase_modules.values():
                if mp.status == "done":
                    # Summary with stats
                    extra_str = ""
                    if mp.extra:
                        parts = []
                        for k, v in mp.extra.items():
                            parts.append(f"{k}:{v}")
                        extra_str = f"[{','.join(parts)}]"
                    summaries.append(f"[{mp.icon} {mp.label}{extra_str}]")
                elif mp.status == "running":
                    bar = ScanOrchestrator._progress_bar(mp.percent, 20)
                    summaries.append(f"[{mp.current}/{mp.total}] {bar} {mp.percent}%")

            if summaries:
                lines.append(f"▸ {phase_name}  {'  '.join(summaries)}")
                # Emoji message
                emoji = {"info": "(●°u°●)​ 」", "vuln": ">_<", "verify": "~_^", "report": "^ - ^"}
                lines.append(f"  {emoji.get(phase_key, '')}  {emoji_msg}  {elapsed_str}")
                lines.append("")

        # Real-time findings
        if progress.findings:
            lines.append("  实时漏洞:")
            for f in progress.findings[-10:]:  # Last 10
                sev_mark = {"critical": "💀", "high": "🔴", "medium": "🟡", "low": "🟢", "info": "🔵"}
                mark = sev_mark.get(f.severity, "⚪")
                verified = " ✓" if f.verified else ""
                lines.append(f"  [{f.severity.upper():7s}] {mark} {f.title[:50]}{verified}")

        # Completion
        if progress.status == "completed":
            lines.append(f"\n{'='*50}")
            lines.append(f"  扫描完成  ♪───Ｏ（≧∇≦）Ｏ────♪")
            lines.append(f"  漏洞: {len(progress.findings)}  "
                         f"(高危:{counts['high']} / 中危:{counts['medium']} / 低危:{counts['low']})")
            lines.append(f"  已验证: {sum(1 for f in progress.findings if f.verified)}  "
                         f"耗时: {elapsed_str}")
            lines.append(f"{'='*50}\n")

        return "\n".join(lines)

    @staticmethod
    def _progress_bar(percent: int, width: int = 20) -> str:
        """Make a cute progress bar"""
        filled = int(width * percent / 100)
        empty = width - filled
        return f"[{'█' * filled}{'░' * empty}]"
