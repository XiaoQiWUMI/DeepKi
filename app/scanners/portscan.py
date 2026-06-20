# (●°u°●)​ 」 Port Scanner
# Xiao Qi knocks on doors to see who's home~ 🔌

import asyncio
import socket

from .base import BaseScanner, ScanResult

# Common ports + service names
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    3000: "Grafana/Dev", 3306: "MySQL", 3389: "RDP", 5000: "Flask/Dev",
    5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC", 6379: "Redis",
    8000: "Dev HTTP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9000: "SonarQube", 9090: "Prometheus",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

DEFAULT_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090]


class PortScanner(BaseScanner):
    """TCP port scanner"""

    name = "portscan"
    icon = "🔌"
    description = "TCP connect scan on common ports"

    def __init__(self, target_url: str, ports: str = None, **kwargs):
        super().__init__(target_url, **kwargs)
        if ports:
            self.ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        else:
            self.ports = DEFAULT_PORTS
        # Auto-expand: if target is a subdomain, also scan the base
        self._hosts = [self.base_domain]

    async def run(self) -> list[ScanResult]:
        results = []
        total = len(self._hosts) * len(self.ports)
        await self._report_progress(0, total, {"open": 0})

        tasks = []
        for host in self._hosts:
            for port in self.ports:
                tasks.append(self._check_port(host, port))

        findings = await asyncio.gather(*tasks)
        open_count = 0
        for i, (host, port, is_open) in enumerate(findings):
            if is_open:
                open_count += 1
                service = PORT_SERVICES.get(port, "Unknown")
                results.append(ScanResult(
                    module=self.name,
                    title=f"Port {port}/tcp open ({service})",
                    severity="info",
                    url=f"{host}:{port}",
                    description=f"TCP port {port} ({service}) is open on {host}",
                    evidence=f"Connection to {host}:{port} succeeded",
                ))
            if i % 5 == 0:
                await self._report_progress(i + 1, total, {"open": open_count})

        await self._report_progress(total, total, {"open": open_count})
        return results

    async def _check_port(self, host: str, port: int) -> tuple[str, int, bool]:
        """TCP connect to check if port is open"""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=2.0,
            )
            writer.close()
            await writer.wait_closed()
            return host, port, True
        except (asyncio.TimeoutError, ConnectionRefusedError,
                OSError, asyncio.CancelledError):
            return host, port, False
