from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import random
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from collector.config import Settings, get_settings
from collector.db import Database
from collector.detection import ScanDetector
from collector.mikrotik import MikroTikClient, MikroTikError
from collector.netflow import Flow, NetflowParser, proto_name
from collector.probe import ProbeStats, start_probe
from collector.schemas import BlockedDump, FullDump, Health, TalkersDump
from collector.talkers import TalkerTracker

STATIC = Path(__file__).parent / "static"
TEMPLATES = Path(__file__).parent / "templates"


class Runtime:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db = Database(settings.db_path)
        self.parser = NetflowParser()
        self.stats = ProbeStats()
        self.queue: asyncio.Queue[Flow] = asyncio.Queue(maxsize=20000)
        self.mikrotik = MikroTikClient(settings)
        self.detector = ScanDetector(
            window_sec=settings.scan_window_sec,
            vertical_ports=settings.vertical_port_threshold,
            horizontal_hosts=settings.horizontal_host_threshold,
            unique_ports=settings.unique_port_threshold,
            allowlist=settings.allowlist_cidrs(),
            protected=settings.protected_cidr_list(),
        )
        self.mikrotik_status: dict[str, Any] = {
            "connected": False,
            "host": settings.mikrotik_host,
            "port": settings.mikrotik_port,
            "identity": "",
            "version": "",
            "address_list": settings.mikrotik_address_list,
            "list_count": 0,
            "filter_ready": False,
            "last_error": "",
            "last_ok": None,
        }
        self.sample_counter = 0
        self.talkers = TalkerTracker()
        self.auto_block = _as_bool(self.db.get_kv("auto_block"), settings.auto_block)
        self._transport = None
        self._tasks: list[asyncio.Task] = []

    def apply_thresholds(self) -> None:
        s = self.settings
        self.detector.window_sec = int(self.db.get_kv("scan_window_sec", str(s.scan_window_sec)))
        self.detector.vertical_ports = int(
            self.db.get_kv("vertical_port_threshold", str(s.vertical_port_threshold))
        )
        self.detector.horizontal_hosts = int(
            self.db.get_kv("horizontal_host_threshold", str(s.horizontal_host_threshold))
        )
        self.detector.unique_ports = int(
            self.db.get_kv("unique_port_threshold", str(s.unique_port_threshold))
        )
        allow = self.db.get_kv("allowlist", s.allowlist)
        self.detector.set_user_allowlist(
            item.strip() for item in allow.split(",") if item.strip()
        )
        self.detector.set_protected(s.protected_cidr_list())
        self.auto_block = _as_bool(self.db.get_kv("auto_block"), s.auto_block)
        self.purge_ignored_detections()

    def purge_ignored_detections(self) -> None:
        removed = 0
        for ip in self.db.all_detection_ips():
            if self.detector.is_allowed(ip):
                removed += self.db.delete_detections_for_ip(ip)
        if removed:
            self.db.log(f"purged {removed} allowlisted DNS/LAN detection row(s)")


runtime: Runtime | None = None


def get_runtime() -> Runtime:
    if runtime is None:
        raise RuntimeError("runtime not started")
    return runtime


@asynccontextmanager
async def lifespan(app: FastAPI):
    global runtime
    settings = get_settings()
    runtime = Runtime(settings)
    runtime.apply_thresholds()
    runtime.db.log("collector started")
    try:
        runtime._transport = await start_probe(
            settings.netflow_host,
            settings.netflow_port,
            runtime.parser,
            runtime.queue,
            runtime.stats,
        )
        runtime.db.log(f"NetFlow probe listening on {settings.netflow_host}:{settings.netflow_port}")
    except OSError as exc:
        runtime.db.log(f"NetFlow probe failed to bind: {exc}", "error")

    runtime._tasks = [
        asyncio.create_task(_flow_worker(runtime), name="flow-worker"),
        asyncio.create_task(_housekeeping(runtime), name="housekeeping"),
        asyncio.create_task(_mikrotik_watch(runtime), name="mikrotik-watch"),
        asyncio.create_task(_unblock_allowlisted(runtime), name="unblock-dns"),
    ]
    if settings.demo:
        runtime._tasks.append(asyncio.create_task(_demo_loop(runtime), name="demo"))
        runtime.db.log("demo mode enabled — injecting synthetic scans")

    yield

    for task in runtime._tasks:
        task.cancel()
    await asyncio.gather(*runtime._tasks, return_exceptions=True)
    if runtime._transport is not None:
        runtime._transport.close()
    runtime.mikrotik.close()
    runtime.db.close()
    runtime = None


app = FastAPI(
    title="Collector",
    description=(
        "NetFlow probe and MikroTik scanner blocker. "
        "Machine JSON dumps live under `/api/dump`. "
        "Send header `X-API-Key` with the same value as `SECRET_KEY`."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "dump", "description": "Blocked IPs and top talkers. Auth: X-API-Key = SECRET_KEY."},
        {"name": "ops", "description": "Health check."},
    ],
)
app.add_middleware(
    SessionMiddleware,
    secret_key=get_settings().secret_key,
    session_cookie="collector",
    same_site="lax",
    https_only=False,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Secret-Key"],
)
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES))
templates.env.globals["proto_name"] = proto_name


def _logged_in(request: Request) -> bool:
    return bool(request.session.get("user"))


def require_login(request: Request) -> None:
    if not _logged_in(request):
        raise HTTPException(status_code=401, detail="auth required")


def _bearer_token(request: Request) -> str:
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return ""


def _provided_api_key(request: Request) -> str:
    return (
        request.headers.get("x-api-key")
        or request.headers.get("x-secret-key")
        or _bearer_token(request)
        or request.query_params.get("key")
        or request.query_params.get("api_key")
        or ""
    )


def _api_key_ok(provided: str, expected: str) -> bool:
    if not provided or not expected:
        return False
    left = hashlib.sha256(provided.encode("utf-8")).digest()
    right = hashlib.sha256(expected.encode("utf-8")).digest()
    return secrets.compare_digest(left, right)


API_KEY_HEADER = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
    description="Collector SECRET_KEY",
)


def require_api_key(
    request: Request,
    api_key: Annotated[str | None, Security(API_KEY_HEADER)] = None,
) -> None:
    provided = api_key or _provided_api_key(request)
    if not _api_key_ok(provided, get_settings().secret_key):
        raise HTTPException(status_code=401, detail="invalid api key")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if _logged_in(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", {"error": ""})


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    settings = get_settings()
    user_ok = secrets.compare_digest(username, settings.portal_user)
    pass_ok = secrets.compare_digest(password, settings.portal_password)
    if not (user_ok and pass_ok):
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid username or password"}, status_code=401
        )
    request.session["user"] = username
    return RedirectResponse("/", status_code=302)


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not _logged_in(request):
        return RedirectResponse("/login", status_code=302)
    rt = get_runtime()
    s = rt.settings
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": request.session.get("user"),
            "netflow_port": s.netflow_port,
            "mikrotik_host": s.mikrotik_host,
            "mikrotik_port": s.mikrotik_port,
            "weak_password": s.portal_password in {"changeme", "admin", "password"},
        },
    )


@app.get("/api/overview")
async def api_overview(request: Request, _: None = Depends(require_login)):
    rt = get_runtime()
    detections = [
        row for row in rt.db.detections(limit=80) if not rt.detector.is_allowed(row["src_ip"])
    ]
    blocks = rt.db.blocks(active_only=True)
    flows = rt.db.recent_flows(60)
    return {
        "stats": rt.stats.as_dict(),
        "mikrotik": rt.mikrotik_status,
        "auto_block": rt.auto_block,
        "thresholds": {
            "scan_window_sec": rt.detector.window_sec,
            "vertical_port_threshold": rt.detector.vertical_ports,
            "horizontal_host_threshold": rt.detector.horizontal_hosts,
            "unique_port_threshold": rt.detector.unique_ports,
            "allowlist": ",".join(str(n) for n in rt.detector.allowlist),
            "protected": [str(n) for n in rt.detector.protected],
            "public_dns": [str(n) for n in rt.detector.public_dns],
            "ignore_dns_replies": rt.detector.ignore_dns_replies,
        },
        "tracked_sources": rt.detector.tracked_sources(),
        "detections": detections,
        "blocks": blocks,
        "flows": flows,
        "events": rt.db.events(30),
        "now": time.time(),
    }


@app.post("/api/block")
async def api_block(request: Request, _: None = Depends(require_login)):
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    reason = (body.get("reason") or "manual").strip()
    _validate_ip(ip)
    rt = get_runtime()
    await _block_ip(rt, ip, reason, source="manual")
    return {"ok": True, "ip": ip}


@app.post("/api/unblock")
async def api_unblock(request: Request, _: None = Depends(require_login)):
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    _validate_ip(ip)
    rt = get_runtime()
    try:
        await asyncio.to_thread(rt.mikrotik.unblock, ip)
    except MikroTikError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    rt.db.deactivate_block(ip)
    rt.db.log(f"unblocked {ip}")
    return {"ok": True, "ip": ip}


@app.post("/api/settings")
async def api_settings(request: Request, _: None = Depends(require_login)):
    body = await request.json()
    rt = get_runtime()
    mapping = {
        "auto_block": body.get("auto_block"),
        "scan_window_sec": body.get("scan_window_sec"),
        "vertical_port_threshold": body.get("vertical_port_threshold"),
        "horizontal_host_threshold": body.get("horizontal_host_threshold"),
        "unique_port_threshold": body.get("unique_port_threshold"),
        "allowlist": body.get("allowlist"),
    }
    if mapping["auto_block"] is not None:
        rt.db.set_kv("auto_block", "true" if mapping["auto_block"] else "false")
    for key in (
        "scan_window_sec",
        "vertical_port_threshold",
        "horizontal_host_threshold",
        "unique_port_threshold",
        "allowlist",
    ):
        if mapping[key] is not None:
            rt.db.set_kv(key, str(mapping[key]).strip())
    rt.apply_thresholds()
    rt.db.log("settings updated")
    return {"ok": True, "auto_block": rt.auto_block}


@app.post("/api/mikrotik/test")
async def api_mikrotik_test(request: Request, _: None = Depends(require_login)):
    rt = get_runtime()
    status = await asyncio.to_thread(rt.mikrotik.probe)
    rt.mikrotik_status = status.__dict__
    if status.connected:
        rt.db.log(f"MikroTik reachable ({status.identity} {status.version})")
    else:
        rt.db.log(f"MikroTik check failed: {status.last_error}", "error")
    return rt.mikrotik_status


@app.get("/api/health", response_model=Health, tags=["ops"])
async def api_health():
    rt = get_runtime()
    return {
        "ok": True,
        "netflow_port": rt.settings.netflow_port,
        "flows": rt.stats.flows,
        "mikrotik": rt.mikrotik_status.get("connected"),
    }


def _blocked_dump(rt: Runtime, router_ips: list[str] | None) -> dict[str, Any]:
    local = rt.db.blocks(active_only=True)
    local_map = {row["ip"]: row for row in local}
    router_set = set(router_ips or [])
    ips = sorted(set(local_map) | router_set)
    blocked = []
    for ip in ips:
        row = local_map.get(ip, {})
        blocked.append(
            {
                "ip": ip,
                "reason": row.get("reason", ""),
                "source": row.get("source", "router" if ip in router_set else "local"),
                "created_at": row.get("created_at"),
                "timeout": row.get("timeout", rt.settings.mikrotik_block_timeout),
                "on_router": ip in router_set if router_ips is not None else None,
            }
        )
    return {
        "generated_at": time.time(),
        "address_list": rt.settings.mikrotik_address_list,
        "count": len(blocked),
        "blocked": blocked,
    }


@app.get("/api/dump", response_model=FullDump, tags=["dump"])
async def api_dump(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    _: None = Depends(require_api_key),
):
    rt = get_runtime()
    router_ips: list[str] | None = None
    try:
        router_ips = await asyncio.to_thread(rt.mikrotik.list_blocked)
    except MikroTikError:
        router_ips = None
    payload = _blocked_dump(rt, router_ips)
    payload["talkers"] = rt.talkers.dump(limit=limit)
    payload["stats"] = rt.stats.as_dict()
    return payload


@app.get("/api/dump/blocked", response_model=BlockedDump, tags=["dump"])
async def api_dump_blocked(request: Request, _: None = Depends(require_api_key)):
    rt = get_runtime()
    router_ips: list[str] | None = None
    try:
        router_ips = await asyncio.to_thread(rt.mikrotik.list_blocked)
    except MikroTikError:
        router_ips = None
    return _blocked_dump(rt, router_ips)


@app.get("/api/dump/talkers", response_model=TalkersDump, tags=["dump"])
async def api_dump_talkers(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    _: None = Depends(require_api_key),
):
    return get_runtime().talkers.dump(limit=limit)


def _validate_ip(ip: str) -> None:
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid IP address") from exc


async def _block_ip(rt: Runtime, ip: str, reason: str, source: str) -> None:
    if rt.detector.is_allowed(ip):
        raise HTTPException(status_code=400, detail=f"{ip} is on the allowlist")
    try:
        await asyncio.to_thread(rt.mikrotik.block, ip, f"collector:{reason}")
    except MikroTikError as exc:
        rt.db.log(f"block failed for {ip}: {exc}", "error")
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    rt.db.add_block(ip, reason, source, rt.settings.mikrotik_block_timeout)
    rt.db.log(f"blocked {ip} ({source}: {reason})")


async def _flow_worker(rt: Runtime) -> None:
    while True:
        flow = await rt.queue.get()
        try:
            detections = rt.detector.observe(flow)
            rt.talkers.observe(flow.src_ip, flow.dst_ip, flow.bytes, flow.packets)
            rt.sample_counter += 1
            if rt.sample_counter % 8 == 0:
                rt.db.insert_flow(flow.as_dict())
            for det in detections:
                already = rt.db.is_blocked(det.src_ip)
                auto = False
                if rt.auto_block and not already:
                    try:
                        await _block_ip(rt, det.src_ip, det.kind, source="auto")
                        auto = True
                    except HTTPException:
                        auto = False
                rt.db.upsert_detection(det.src_ip, det.kind, det.score, det.detail, auto_blocked=auto)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            rt.db.log(f"flow worker error: {exc}", "error")
        finally:
            rt.queue.task_done()


async def _housekeeping(rt: Runtime) -> None:
    while True:
        await asyncio.sleep(30)
        try:
            rt.detector.prune()
            rt.db.prune_flows()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            rt.db.log(f"housekeeping error: {exc}", "error")


async def _mikrotik_watch(rt: Runtime) -> None:
    await asyncio.sleep(1)
    while True:
        try:
            status = await asyncio.to_thread(rt.mikrotik.probe)
            rt.mikrotik_status = status.__dict__
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            rt.mikrotik_status["connected"] = False
            rt.mikrotik_status["last_error"] = str(exc)
        await asyncio.sleep(20)


async def _unblock_allowlisted(rt: Runtime) -> None:
    """Drop public DNS / LAN entries that were auto-blocked before the allowlist existed."""
    await asyncio.sleep(2)
    for row in rt.db.blocks(active_only=True):
        ip = row["ip"]
        if not rt.detector.is_allowed(ip):
            continue
        try:
            await asyncio.to_thread(rt.mikrotik.unblock, ip)
        except MikroTikError as exc:
            rt.db.log(f"could not unblock allowlisted {ip}: {exc}", "error")
            continue
        rt.db.deactivate_block(ip)
        rt.db.log(f"unblocked allowlisted {ip}")


async def _demo_loop(rt: Runtime) -> None:
    """Inject a noisy scanner plus background chatter so the portal has data."""
    scanner = "203.0.113.77"
    benign = ["10.0.0.12", "10.0.0.40", "10.0.0.88"]
    targets = [f"192.0.2.{i}" for i in range(10, 40)]
    await asyncio.sleep(1)
    while True:
        for host in benign:
            flow = Flow(
                    src_ip=host,
                    dst_ip="1.1.1.1",
                    src_port=random.randint(40000, 50000),
                    dst_port=443,
                    proto=6,
                    bytes=random.randint(200, 4000),
                    packets=random.randint(2, 20),
                    exporter="demo",
                    version=5,
            )
            rt.stats.record(1, "demo")
            await rt.queue.put(flow)
        for port in range(1, 90):
            flow = Flow(
                    src_ip=scanner,
                    dst_ip=random.choice(targets),
                    src_port=random.randint(40000, 60000),
                    dst_port=port,
                    proto=6,
                    bytes=40,
                    packets=1,
                    tcp_flags=2,
                    exporter="demo",
                    version=5,
            )
            rt.stats.record(1, "demo")
            await rt.queue.put(flow)
        await asyncio.sleep(8)


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401 and request.url.path.startswith("/api/"):
        return JSONResponse({"detail": exc.detail}, status_code=401)
    if exc.status_code == 401:
        return RedirectResponse("/login", status_code=302)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
