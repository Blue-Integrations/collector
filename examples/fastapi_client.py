"""Drop this into another FastAPI app (or copy the router).

Env:
  COLLECTOR_URL=http://192.168.88.20:8080
  COLLECTOR_API_KEY=<collector SECRET_KEY>

    from examples.fastapi_client import router
    app.include_router(router)
"""

from __future__ import annotations

from typing import Any, Literal

import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    collector_url: str = "http://192.168.88.20:8080"
    collector_api_key: str = ""


settings = Settings()


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


class ProbeStats(BaseModel):
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
    stats: ProbeStats


class CollectorClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None) -> None:
        key = api_key if api_key is not None else settings.collector_api_key
        self._http = httpx.AsyncClient(
            base_url=(base_url or settings.collector_url).rstrip("/"),
            headers={"X-API-Key": key},
            timeout=8.0,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict:
        response = await self._http.get(path, params=params)
        if response.status_code == 401:
            raise HTTPException(status_code=401, detail="collector: invalid api key")
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail=response.text)
        return response.json()

    async def health(self) -> dict:
        response = await self._http.get("/api/health")
        response.raise_for_status()
        return response.json()

    async def dump(self, limit: int = 50) -> FullDump:
        return FullDump.model_validate(await self._get("/api/dump", {"limit": limit}))

    async def blocked(self) -> BlockedDump:
        return BlockedDump.model_validate(await self._get("/api/dump/blocked"))

    async def talkers(self, limit: int = 50) -> TalkersDump:
        return TalkersDump.model_validate(
            await self._get("/api/dump/talkers", {"limit": limit})
        )


client = CollectorClient()
router = APIRouter(prefix="/collector", tags=["collector"])


@router.get("/blocked", response_model=BlockedDump)
async def blocked_proxy():
    return await client.blocked()


@router.get("/talkers", response_model=TalkersDump)
async def talkers_proxy(limit: int = Query(50, ge=1, le=500)):
    return await client.talkers(limit=limit)


@router.get("/dump", response_model=FullDump)
async def dump_proxy(limit: int = Query(50, ge=1, le=500)):
    return await client.dump(limit=limit)
