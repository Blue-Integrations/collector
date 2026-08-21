from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from time import time
from typing import Iterable

from collector.netflow import Flow, proto_name

# Server-originated reply legs: HTTPS/SSH/DNS from our hosts → attacker:ephemeral
# looks like a vertical scan if counted. Skip well-known SOURCE ports to high dest ports.
SERVER_REPLY_PORTS = {
    20,
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    465,
    587,
    853,
    993,
    995,
    1194,
    3306,
    5432,
    6379,
    8080,
    8443,
    8853,
    9953,
}

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
    """Sliding-window detector for port scans, ICMP floods, and oversized flows."""

    def __init__(
        self,
        window_sec: int = 30,
        vertical_ports: int = 40,
        horizontal_hosts: int = 40,
        unique_ports: int = 80,
        icmp_flood_threshold: int = 50,
        large_flow_min_bytes: int = 2048,
        large_flow_threshold: int = 20,
        allowlist: Iterable[str] | None = None,
        public_dns: Iterable[str] | None = PUBLIC_DNS_CIDRS,
        protected: Iterable[str] | None = None,
        ignore_dns_replies: bool = True,
    ) -> None:
        self.window_sec = window_sec
        self.vertical_ports = vertical_ports
        self.horizontal_hosts = horizontal_hosts
        self.unique_ports = unique_ports
        self.icmp_flood_threshold = icmp_flood_threshold
        self.large_flow_min_bytes = large_flow_min_bytes
        self.large_flow_threshold = large_flow_threshold
        self.ignore_dns_replies = ignore_dns_replies
        self.public_dns = _nets(public_dns or [])
        self.protected = _nets(protected or [])
        self.allowlist = _nets(allowlist or [])
        # src_ip -> deque of (ts, dst_ip, dst_port, proto, src_port)
        self._events: dict[str, deque[tuple[float, str, int, int, int]]] = defaultdict(deque)
        # src_ip -> deque of (ts, dst_ip, bytes, packets)
        self._icmp_events: dict[str, deque[tuple[float, str, int, int]]] = defaultdict(deque)
        # src_ip -> deque of (ts, dst_ip, bytes, proto)
        self._large_events: dict[str, deque[tuple[float, str, int, int]]] = defaultdict(deque)

    def set_user_allowlist(self, cidrs: Iterable[str]) -> None:
        self.allowlist = _nets(cidrs)

    def set_protected(self, cidrs: Iterable[str]) -> None:
        self.protected = _nets(cidrs)

    def is_allowed(self, ip: str) -> bool:
        try:
            addr = ip_address(ip)
        except ValueError:
            return False
        return (
            any(addr in net for net in self.allowlist)
            or any(addr in net for net in self.public_dns)
            or any(addr in net for net in self.protected)
        )

    def observe(self, flow: Flow) -> list[Detection]:
        if flow.src_ip in ("0.0.0.0", "::") or flow.dst_ip in ("0.0.0.0", "::"):
            return []
        if self.is_allowed(flow.src_ip):
            return []

        detections: list[Detection] = []
        reply_leg = (
            self.ignore_dns_replies
            and flow.proto in (6, 17)
            and flow.src_port in SERVER_REPLY_PORTS
            and flow.dst_port >= 1024
        )
        if not reply_leg and flow.bytes >= self.large_flow_min_bytes:
            detections.extend(self._observe_large(flow))
        if flow.proto in (1, 58):
            detections.extend(self._observe_icmp(flow))
            return detections

        if reply_leg:
            return detections
        if flow.proto not in (6, 17) or flow.dst_port == 0:
            return detections

        now = time()
        q = self._events[flow.src_ip]
        q.append((now, flow.dst_ip, flow.dst_port, flow.proto, flow.src_port))
        cutoff = now - self.window_sec
        while q and q[0][0] < cutoff:
            q.popleft()
        if not q:
            self._events.pop(flow.src_ip, None)
            return detections

        dst_ips = {item[1] for item in q}
        dst_ports = {item[2] for item in q}
        per_host: dict[str, set[int]] = defaultdict(set)
        per_port: dict[int, set[str]] = defaultdict(set)
        per_service: dict[tuple[str, int], set[int]] = defaultdict(set)
        for _ts, dst_ip, dst_port, _proto, src_port in q:
            per_host[dst_ip].add(dst_port)
            per_port[dst_port].add(dst_ip)
            per_service[(dst_ip, dst_port)].add(src_port)

        port_detections: list[Detection] = []
        worst_host, worst_host_ports = max(per_host.items(), key=lambda kv: len(kv[1]))
        if len(worst_host_ports) >= self.vertical_ports:
            port_detections.append(
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
            port_detections.append(
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
            port_detections.append(
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

        # Many source ports at one service (HTTPS flood) — not a dest-port scan,
        # so vertical/spray miss it and the reply leg used to blame the server.
        worst_svc, worst_src_ports = max(per_service.items(), key=lambda kv: len(kv[1]))
        if len(worst_src_ports) >= self.vertical_ports:
            target, port = worst_svc
            port_detections.append(
                Detection(
                    src_ip=flow.src_ip,
                    kind="connect-storm",
                    score=len(worst_src_ports),
                    detail={
                        "target": target,
                        "port": port,
                        "unique_src_ports": len(worst_src_ports),
                        "window_sec": self.window_sec,
                        "flows": len(q),
                    },
                )
            )
        return detections + port_detections

    def _observe_icmp(self, flow: Flow) -> list[Detection]:
        now = time()
        q = self._icmp_events[flow.src_ip]
        q.append((now, flow.dst_ip, flow.bytes, flow.packets))
        cutoff = now - self.window_sec
        while q and q[0][0] < cutoff:
            q.popleft()
        if not q:
            self._icmp_events.pop(flow.src_ip, None)
            return []
        if len(q) < self.icmp_flood_threshold:
            return []

        targets = {item[1] for item in q}
        total_bytes = sum(item[2] for item in q)
        max_bytes = max(item[2] for item in q)
        return [
            Detection(
                src_ip=flow.src_ip,
                kind="icmp-flood",
                score=len(q),
                detail={
                    "flows": len(q),
                    "unique_targets": len(targets),
                    "total_bytes": total_bytes,
                    "max_bytes": max_bytes,
                    "sample_targets": sorted(targets)[:8],
                    "proto": proto_name(flow.proto),
                    "window_sec": self.window_sec,
                },
            )
        ]

    def _observe_large(self, flow: Flow) -> list[Detection]:
        now = time()
        q = self._large_events[flow.src_ip]
        q.append((now, flow.dst_ip, flow.bytes, flow.proto))
        cutoff = now - self.window_sec
        while q and q[0][0] < cutoff:
            q.popleft()
        if not q:
            self._large_events.pop(flow.src_ip, None)
            return []
        if len(q) < self.large_flow_threshold:
            return []

        targets = {item[1] for item in q}
        max_bytes = max(item[2] for item in q)
        protos = {item[3] for item in q}
        return [
            Detection(
                src_ip=flow.src_ip,
                kind="large-flow",
                score=len(q),
                detail={
                    "flows": len(q),
                    "min_bytes": self.large_flow_min_bytes,
                    "max_bytes": max_bytes,
                    "unique_targets": len(targets),
                    "protos": sorted(proto_name(p) for p in protos),
                    "sample_targets": sorted(targets)[:8],
                    "window_sec": self.window_sec,
                },
            )
        ]

    def _prune_map(self, table: dict[str, deque], cutoff: float) -> None:
        dead = []
        for src, q in table.items():
            while q and q[0][0] < cutoff:
                q.popleft()
            if not q:
                dead.append(src)
        for src in dead:
            table.pop(src, None)

    def prune(self) -> None:
        cutoff = time() - self.window_sec
        self._prune_map(self._events, cutoff)
        self._prune_map(self._icmp_events, cutoff)
        self._prune_map(self._large_events, cutoff)

    def tracked_sources(self) -> int:
        return len(set(self._events) | set(self._icmp_events) | set(self._large_events))
