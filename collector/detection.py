from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from time import time
from typing import Iterable

from collector.netflow import Flow

# Reply-leg service ports: NetFlow also exports 1.1.1.1:53 → client:ephemeral
# which looks like a spray/vertical scan if counted.
DNS_REPLY_PORTS = {53, 853, 9953, 8853}

# Anycast resolvers only (not Cloudflare/Google CDN ranges).
PUBLIC_DNS_CIDRS = (
    # Cloudflare 1.1.1.1
    "1.1.1.1/32",
    "1.0.0.1/32",
    "1.1.1.2/32",
    "1.0.0.2/32",
    "1.1.1.3/32",
    "1.0.0.3/32",
    "2606:4700:4700::1111/128",
    "2606:4700:4700::1001/128",
    "2606:4700:4700::1112/128",
    "2606:4700:4700::1002/128",
    "2606:4700:4700::1113/128",
    "2606:4700:4700::1003/128",
    # Google 8.8.8.8
    "8.8.8.8/32",
    "8.8.4.4/32",
    "2001:4860:4860::8888/128",
    "2001:4860:4860::8844/128",
    # Quad9
    "9.9.9.9/32",
    "9.9.9.10/32",
    "9.9.9.11/32",
    "9.9.9.12/32",
    "149.112.112.112/32",
    "149.112.112.10/32",
    "149.112.112.11/32",
    "149.112.112.12/32",
    "2620:fe::fe/128",
    "2620:fe::9/128",
    "2620:fe::10/128",
    "2620:fe::11/128",
    "2620:fe::12/128",
    "2620:fe::fe:9/128",
    "2620:fe::fe:10/128",
    "2620:fe::fe:11/128",
    "2620:fe::fe:12/128",
    # OpenDNS
    "208.67.222.222/32",
    "208.67.220.220/32",
    "2620:119:35::35/128",
    "2620:119:53::53/128",
)


@dataclass
class Detection:
    src_ip: str
    kind: str
    score: int
    detail: dict


def _nets(cidrs: Iterable[str]) -> list:
    return [ip_network(item, strict=False) for item in cidrs if str(item).strip()]


class ScanDetector:
    """Sliding-window detector for vertical, horizontal, and spray port scans."""

    def __init__(
        self,
        window_sec: int = 30,
        vertical_ports: int = 40,
        horizontal_hosts: int = 40,
        unique_ports: int = 80,
        allowlist: Iterable[str] | None = None,
        public_dns: Iterable[str] | None = PUBLIC_DNS_CIDRS,
        ignore_dns_replies: bool = True,
    ) -> None:
        self.window_sec = window_sec
        self.vertical_ports = vertical_ports
        self.horizontal_hosts = horizontal_hosts
        self.unique_ports = unique_ports
        self.ignore_dns_replies = ignore_dns_replies
        self.public_dns = _nets(public_dns or [])
        self.allowlist = _nets(allowlist or [])
        # src_ip -> deque of (ts, dst_ip, dst_port, proto)
        self._events: dict[str, deque[tuple[float, str, int, int]]] = defaultdict(deque)

    def set_user_allowlist(self, cidrs: Iterable[str]) -> None:
        self.allowlist = _nets(cidrs)

    def is_allowed(self, ip: str) -> bool:
        try:
            addr = ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.allowlist) or any(
            addr in net for net in self.public_dns
        )

    def observe(self, flow: Flow) -> list[Detection]:
        if flow.src_ip in ("0.0.0.0", "::") or flow.dst_ip in ("0.0.0.0", "::"):
            return []
        if self.is_allowed(flow.src_ip):
            return []
        if self.ignore_dns_replies and flow.src_port in DNS_REPLY_PORTS:
            return []
        # ICMP / non-transport still counts as a dest "port" of 0; skip those for scan math
        if flow.proto not in (6, 17) or flow.dst_port == 0:
            return []

        now = time()
        q = self._events[flow.src_ip]
        q.append((now, flow.dst_ip, flow.dst_port, flow.proto))
        cutoff = now - self.window_sec
        while q and q[0][0] < cutoff:
            q.popleft()
        if not q:
            self._events.pop(flow.src_ip, None)
            return []

        dst_ips = {item[1] for item in q}
        dst_ports = {item[2] for item in q}
        per_host: dict[str, set[int]] = defaultdict(set)
        per_port: dict[int, set[str]] = defaultdict(set)
        for _ts, dst_ip, dst_port, _proto in q:
            per_host[dst_ip].add(dst_port)
            per_port[dst_port].add(dst_ip)

        detections: list[Detection] = []
        worst_host, worst_host_ports = max(per_host.items(), key=lambda kv: len(kv[1]))
        if len(worst_host_ports) >= self.vertical_ports:
            detections.append(
                Detection(
                    src_ip=flow.src_ip,
                    kind="vertical",
                    score=len(worst_host_ports),
                    detail={
                        "target": worst_host,
                        "unique_ports": len(worst_host_ports),
                        "sample_ports": sorted(worst_host_ports)[:12],
                        "window_sec": self.window_sec,
                        "flows": len(q),
                    },
                )
            )

        worst_port, worst_port_hosts = max(per_port.items(), key=lambda kv: len(kv[1]))
        if len(worst_port_hosts) >= self.horizontal_hosts:
            detections.append(
                Detection(
                    src_ip=flow.src_ip,
                    kind="horizontal",
                    score=len(worst_port_hosts),
                    detail={
                        "port": worst_port,
                        "unique_hosts": len(worst_port_hosts),
                        "sample_hosts": sorted(worst_port_hosts)[:8],
                        "window_sec": self.window_sec,
                        "flows": len(q),
                    },
                )
            )

        if len(dst_ports) >= self.unique_ports:
            detections.append(
                Detection(
                    src_ip=flow.src_ip,
                    kind="spray",
                    score=len(dst_ports),
                    detail={
                        "unique_ports": len(dst_ports),
                        "unique_hosts": len(dst_ips),
                        "window_sec": self.window_sec,
                        "flows": len(q),
                    },
                )
            )
        return detections

    def prune(self) -> None:
        cutoff = time() - self.window_sec
        dead = []
        for src, q in self._events.items():
            while q and q[0][0] < cutoff:
                q.popleft()
            if not q:
                dead.append(src)
        for src in dead:
            self._events.pop(src, None)

    def tracked_sources(self) -> int:
        return len(self._events)
