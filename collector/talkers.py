from __future__ import annotations

import time
from collections import defaultdict
from typing import Any


class TalkerTracker:
    """In-memory byte/packet counters for top-talker dumps."""

    def __init__(self, max_hosts: int = 20000, max_pairs: int = 20000) -> None:
        self.max_hosts = max_hosts
        self.max_pairs = max_pairs
        self.started_at = time.time()
        self._src: dict[str, dict[str, float | int]] = defaultdict(self._blank)
        self._dst: dict[str, dict[str, float | int]] = defaultdict(self._blank)
        self._pairs: dict[tuple[str, str], dict[str, float | int]] = defaultdict(self._blank)

    @staticmethod
    def _blank() -> dict[str, float | int]:
        return {"bytes": 0, "packets": 0, "flows": 0, "last_seen": 0.0}

    def observe(self, src_ip: str, dst_ip: str, nbytes: int, packets: int) -> None:
        now = time.time()
        self._bump(self._src[src_ip], nbytes, packets, now)
        self._bump(self._dst[dst_ip], nbytes, packets, now)
        self._bump(self._pairs[(src_ip, dst_ip)], nbytes, packets, now)
        if len(self._src) + len(self._dst) > self.max_hosts * 2:
            self._prune(self._src)
            self._prune(self._dst)
        if len(self._pairs) > self.max_pairs:
            self._prune(self._pairs)

    @staticmethod
    def _bump(row: dict[str, float | int], nbytes: int, packets: int, now: float) -> None:
        row["bytes"] = int(row["bytes"]) + int(nbytes)
        row["packets"] = int(row["packets"]) + int(packets)
        row["flows"] = int(row["flows"]) + 1
        row["last_seen"] = now

    def _prune(self, table: dict, keep: int | None = None) -> None:
        keep = keep or (self.max_hosts if table is not self._pairs else self.max_pairs)
        if len(table) <= keep:
            return
        ranked = sorted(table.items(), key=lambda kv: int(kv[1]["bytes"]), reverse=True)
        for key, _row in ranked[keep:]:
            table.pop(key, None)

    def dump(self, limit: int = 50) -> dict[str, Any]:
        limit = max(1, min(int(limit), 500))
        now = time.time()
        return {
            "generated_at": now,
            "since": self.started_at,
            "window": "since_start",
            "top_sources": self._rank(self._src, limit, ip_key="ip"),
            "top_destinations": self._rank(self._dst, limit, ip_key="ip"),
            "top_pairs": self._rank_pairs(limit),
        }

    def _rank(self, table: dict[str, dict[str, float | int]], limit: int, ip_key: str) -> list[dict[str, Any]]:
        ranked = sorted(table.items(), key=lambda kv: int(kv[1]["bytes"]), reverse=True)[:limit]
        out = []
        for ip, row in ranked:
            out.append(
                {
                    ip_key: ip,
                    "bytes": int(row["bytes"]),
                    "packets": int(row["packets"]),
                    "flows": int(row["flows"]),
                    "last_seen": row["last_seen"],
                }
            )
        return out

    def _rank_pairs(self, limit: int) -> list[dict[str, Any]]:
        ranked = sorted(self._pairs.items(), key=lambda kv: int(kv[1]["bytes"]), reverse=True)[:limit]
        out = []
        for (src, dst), row in ranked:
            out.append(
                {
                    "src_ip": src,
                    "dst_ip": dst,
                    "bytes": int(row["bytes"]),
                    "packets": int(row["packets"]),
                    "flows": int(row["flows"]),
                    "last_seen": row["last_seen"],
                }
            )
        return out
