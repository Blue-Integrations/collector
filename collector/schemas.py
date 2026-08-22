from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from collector import __version__


class DatabaseOut(BaseModel):
    engine: str
    tables: dict[str, int] = Field(default_factory=dict)
    path: str | None = None
    host: str | None = None
    port: int | None = None
    database: str | None = None


class Health(BaseModel):
    ok: bool
    netflow_port: int
    flows: int
    flows_last_10s: int = 0
    flows_per_sec: float = 0
    version: str = __version__
    vendor: str = "mikrotik"
    router: bool | None = None
    mikrotik: bool | None = None
    database: DatabaseOut | None = None


class BlockedIP(BaseModel):
    ip: str
    reason: str = ""
    source: str = ""
    created_at: float | None = None
    timeout: str = "1d"
    on_router: bool | None = None


class BlockedDump(BaseModel):
    generated_at: float
    address_list: str
    count: int
    blocked: list[BlockedIP]
    vendor: str = "mikrotik"


class Talker(BaseModel):
    ip: str
    bytes: int
    packets: int
    flows: int
    last_seen: float


class TalkerPair(BaseModel):
    src_ip: str
    dst_ip: str
    bytes: int
    packets: int
    flows: int
    last_seen: float


class TalkersDump(BaseModel):
    generated_at: float
    since: float
    window: Literal["since_start"] = "since_start"
    top_sources: list[Talker]
    top_destinations: list[Talker]
    top_pairs: list[TalkerPair]


class ProbeStatsOut(BaseModel):
    datagrams: int = 0
    parse_errors: int = 0
    flows: int = 0
    bytes_exported: int = 0
    dropped: int = 0
    last_exporter: str = ""
    last_flow_at: float | None = None
    flows_last_10s: int = 0
    flows_per_sec: float = 0
    uptime_sec: int = 0


class FullDump(BlockedDump):
    talkers: TalkersDump
    stats: ProbeStatsOut
