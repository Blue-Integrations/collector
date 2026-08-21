from __future__ import annotations

import asyncio
import time
from collections import deque

from collector.netflow import Flow, NetflowParser


class ProbeStats:
    WINDOW_SEC = 10

    def __init__(self) -> None:
        self.datagrams = 0
        self.parse_errors = 0
        self.flows = 0
        self.bytes = 0
        self.dropped = 0
        self.last_exporter = ""
        self.last_flow_at: float | None = None
        self._times: deque[float] = deque(maxlen=4000)
        self.started_at = time.time()

    def record(self, count: int, exporter: str) -> None:
        now = time.time()
        self.datagrams += 1
        self.flows += count
        self.last_exporter = exporter
        if count:
            self.last_flow_at = now
        for _ in range(count):
            self._times.append(now)

    def _window_count(self, window: float | None = None) -> int:
        window = self.WINDOW_SEC if window is None else window
        now = time.time()
        cutoff = now - window
        while self._times and self._times[0] < cutoff:
            self._times.popleft()
        return len(self._times)

    def flows_last_10s(self) -> int:
        return self._window_count()

    def flows_per_sec(self) -> float:
        count = self._window_count()
        if not count:
            return 0.0
        now = time.time()
        span = max(now - self._times[0], 1.0)
        return round(count / span, 1)

    def as_dict(self) -> dict:
        return {
            "datagrams": self.datagrams,
            "parse_errors": self.parse_errors,
            "flows": self.flows,
            "bytes_exported": self.bytes,
            "dropped": self.dropped,
            "last_exporter": self.last_exporter,
            "last_flow_at": self.last_flow_at,
            "flows_last_10s": self.flows_last_10s(),
            "flows_per_sec": self.flows_per_sec(),
            "uptime_sec": int(time.time() - self.started_at),
        }


class NetflowProtocol(asyncio.DatagramProtocol):
    def __init__(self, parser: NetflowParser, queue: asyncio.Queue[Flow], stats: ProbeStats) -> None:
        self.parser = parser
        self.queue = queue
        self.stats = stats

    def datagram_received(self, data: bytes, addr) -> None:
        exporter = addr[0]
        try:
            flows = self.parser.parse(data, exporter)
        except Exception:
            self.stats.parse_errors += 1
            return
        self.stats.record(len(flows), exporter)
        for flow in flows:
            self.stats.bytes += flow.bytes
            try:
                self.queue.put_nowait(flow)
            except asyncio.QueueFull:
                self.stats.dropped += 1


async def start_probe(
    host: str,
    port: int,
    parser: NetflowParser,
    queue: asyncio.Queue[Flow],
    stats: ProbeStats,
) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: NetflowProtocol(parser, queue, stats),
        local_addr=(host, port),
    )
    return transport
