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

from collector.blocker import VENDORS, VENDOR_LABELS, RouterError, make_blocker, normalize_vendor
from collector.config import Settings, get_settings
from collector.db import Database
from collector.detection import Detection, ScanDetector
from collector.netflow import Flow, NetflowParser, proto_name
from collector.probe import ProbeStats, start_probe
from collector.schemas import BlockedDump, FullDump, Health, TalkersDump
from collector.upgrade import UpgradeError, check_upgrade, installed_version, run_upgrade
from collector.whois import WhoisError, lookup_ip
from collector.talkers import TalkerTracker
from collector.webhooks import (
    WebhookSettings,
    load_webhook_settings,
    notify_block,
    notify_detection,
    save_webhook_settings,
    send_test,
    validate_webhook_url,
    webhooks_as_dict,
)

STATIC = Path(__file__).parent / "static"
TEMPLATES = Path(__file__).parent / "templates"


class Runtime:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db = Database(settings.db_path)
        self.parser = NetflowParser()
        self.stats = ProbeStats()
        self.queue: asyncio.Queue[Flow] = asyncio.Queue(maxsize=20000)
        vendor = normalize_vendor(self.db.get_kv("blocker_vendor", settings.blocker_vendor))
        self.blocker = make_blocker(settings, vendor)
        self.detector = ScanDetector(
            window_sec=settings.scan_window_sec,
            vertical_ports=settings.vertical_port_threshold,
            horizontal_hosts=settings.horizontal_host_threshold,
            unique_ports=settings.unique_port_threshold,
            icmp_flood_threshold=settings.icmp_flood_threshold,
            large_flow_min_bytes=settings.large_flow_min_bytes,
            large_flow_threshold=settings.large_flow_threshold,
            allowlist=settings.allowlist_cidrs(),
            protected=settings.protected_cidr_list(),
        )
        self.mikrotik_status: dict[str, Any] = _status_dict(settings, vendor)
        self.router_blocked: set[str] = set()
        self.sample_counter = 0
        self.talkers = TalkerTracker()
        self.auto_block = _as_bool(self.db.get_kv("auto_block"), settings.auto_block)
        self.webhooks = self._default_webhooks()
        self._webhook_cooldown: dict[str, float] = {}
        self._transport = None
        self._tasks: list[asyncio.Task] = []

    def _default_webhooks(self) -> WebhookSettings:
        s = self.settings
        return WebhookSettings(
            slack_url=s.slack_webhook_url,
            discord_url=s.discord_webhook_url,
            notify_detections=s.webhook_notify_detections,
            notify_blocks=s.webhook_notify_blocks,
        )

    def apply_webhooks(self) -> None:
        self.webhooks = load_webhook_settings(self.db, self._default_webhooks())

    def _cooldown_ok(self, key: str, seconds: int = 300) -> bool:
        now = time.time()
        last = self._webhook_cooldown.get(key, 0.0)
        if now - last < seconds:
            return False
        self._webhook_cooldown[key] = now
        return True

    async def notify_detection_webhook(self, det: Detection, auto_blocked: bool = False) -> None:
        if not self.webhooks.notify_detections:
            return
        if not (self.webhooks.slack_url or self.webhooks.discord_url):
            return
        key = f"det:{det.src_ip}:{det.kind}"
        if not self._cooldown_ok(key):
            return
        try:
            await asyncio.to_thread(notify_detection, self.webhooks, det, auto_blocked)
        except Exception as exc:
            self.db.log(f"webhook detection notify failed: {exc}", "error")

    async def notify_block_webhook(self, ip: str, reason: str, source: str) -> None:
        if not self.webhooks.notify_blocks:
            return
        if not (self.webhooks.slack_url or self.webhooks.discord_url):
            return
        key = f"block:{ip}"
        if not self._cooldown_ok(key):
            return
        try:
            await asyncio.to_thread(notify_block, self.webhooks, ip, reason, source)
        except Exception as exc:
            self.db.log(f"webhook block notify failed: {exc}", "error")

    @property
    def vendor(self) -> str:
        return getattr(self.blocker, "vendor", "mikrotik")

    def set_vendor(self, vendor: str) -> str:
        chosen = normalize_vendor(vendor)
        if chosen not in VENDORS:
            raise HTTPException(status_code=400, detail="vendor must be mikrotik, cisco, or juniper")
        profile = self.settings.vendor_profile(chosen)
        if not profile["configured"]:
            missing = ", ".join(profile["missing"]) or "required .env settings"
            raise HTTPException(
                status_code=400,
                detail=f"{profile['label']} is not configured in .env ({missing}). Edit .env and restart the collector.",
            )
        self.db.set_kv("blocker_vendor", chosen)
        if self.vendor != chosen:
            self.blocker.close()
            self.blocker = make_blocker(self.settings, chosen)
            self.mikrotik_status = _status_dict(self.settings, chosen)
            self.router_blocked = set()
        return chosen

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
        self.detector.icmp_flood_threshold = int(
            self.db.get_kv("icmp_flood_threshold", str(s.icmp_flood_threshold))
        )
        self.detector.large_flow_min_bytes = int(
            self.db.get_kv("large_flow_min_bytes", str(s.large_flow_min_bytes))
        )
        self.detector.large_flow_threshold = int(
            self.db.get_kv("large_flow_threshold", str(s.large_flow_threshold))
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
    runtime.apply_webhooks()
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
        asyncio.create_task(_router_watch(runtime), name="router-watch"),
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
    runtime.blocker.close()
    runtime.db.close()
    runtime = None


app = FastAPI(
    title="Collector",
    description=(
        "NetFlow probe and scanner blocker (MikroTik, Cisco, or Juniper). "
        "Machine JSON dumps live under `/api/dump`. "
        "Send header `X-API-Key` with the same value as `SECRET_KEY`."
    ),
    version=installed_version(),
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
    host, port, _acl = s.blocker_endpoint(rt.vendor)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": request.session.get("user"),
            "netflow_port": s.netflow_port,
            "router_host": host,
            "router_port": port,
            "vendor": rt.vendor,
            "vendors": VENDORS,
            "vendor_labels": VENDOR_LABELS,
            "weak_password": s.portal_password in {"changeme", "admin", "password"},
        },
    )


@app.get("/api/overview")
async def api_overview(request: Request, _: None = Depends(require_login)):
    rt = get_runtime()
    detections = rt.db.detections(limit=80)
    blocks = rt.db.blocks(active_only=True)
    flows = rt.db.recent_flows(60)
    return {
        "stats": rt.stats.as_dict(),
        "mikrotik": rt.mikrotik_status,
        "router": rt.mikrotik_status,
        "vendor": rt.vendor,
        "vendors": [{"id": key, "label": VENDOR_LABELS[key]} for key in VENDORS],
        "router_profiles": rt.settings.router_profiles(),
        "auto_block": rt.auto_block,
        "thresholds": {
            "scan_window_sec": rt.detector.window_sec,
            "vertical_port_threshold": rt.detector.vertical_ports,
            "horizontal_host_threshold": rt.detector.horizontal_hosts,
            "unique_port_threshold": rt.detector.unique_ports,
            "icmp_flood_threshold": rt.detector.icmp_flood_threshold,
            "large_flow_min_bytes": rt.detector.large_flow_min_bytes,
            "large_flow_threshold": rt.detector.large_flow_threshold,
            "allowlist": ",".join(str(n) for n in rt.detector.allowlist),
            "protected": [str(n) for n in rt.detector.protected],
            "public_dns": [str(n) for n in rt.detector.public_dns],
            "ignore_dns_replies": rt.detector.ignore_dns_replies,
        },
        "tracked_sources": rt.detector.tracked_sources(),
        "detections": detections,
        "blocked_ips": sorted(rt.router_blocked),
        "blocks": blocks,
        "flows": flows,
        "events": rt.db.events(30),
        "webhooks": webhooks_as_dict(rt.webhooks),
        "now": time.time(),
        "version": installed_version(),
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
        await asyncio.to_thread(rt.blocker.unblock, ip)
    except RouterError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    rt.db.deactivate_block(ip)
    rt.router_blocked.discard(ip)
    rt.db.log(f"unblocked {ip}")
    return {"ok": True, "ip": ip}


@app.get("/api/whois/{ip}")
async def api_whois(ip: str, request: Request, _: None = Depends(require_login)):
    _validate_ip(ip)
    try:
        record = await asyncio.to_thread(lookup_ip, ip)
    except WhoisError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {
        "ip": record.ip,
        "network": record.network,
        "cidr": record.cidr,
        "country": record.country,
        "org": record.org,
        "abuse": record.abuse,
        "rir": record.rir,
        "handle": record.raw_handle,
        "fetched_at": record.fetched_at,
    }


@app.post("/api/settings")
async def api_settings(request: Request, _: None = Depends(require_login)):
    body = await request.json()
    rt = get_runtime()
    mapping = {
        "auto_block": body.get("auto_block"),
        "blocker_vendor": body.get("blocker_vendor") or body.get("vendor"),
        "scan_window_sec": body.get("scan_window_sec"),
        "vertical_port_threshold": body.get("vertical_port_threshold"),
        "horizontal_host_threshold": body.get("horizontal_host_threshold"),
        "unique_port_threshold": body.get("unique_port_threshold"),
        "icmp_flood_threshold": body.get("icmp_flood_threshold"),
        "large_flow_min_bytes": body.get("large_flow_min_bytes"),
        "large_flow_threshold": body.get("large_flow_threshold"),
        "allowlist": body.get("allowlist"),
    }
    if mapping["auto_block"] is not None:
        rt.db.set_kv("auto_block", "true" if mapping["auto_block"] else "false")
    if mapping.get("blocker_vendor"):
        rt.set_vendor(str(mapping["blocker_vendor"]))
    for key in (
        "scan_window_sec",
        "vertical_port_threshold",
        "horizontal_host_threshold",
        "unique_port_threshold",
        "icmp_flood_threshold",
        "large_flow_min_bytes",
        "large_flow_threshold",
        "allowlist",
    ):
        if mapping[key] is not None:
            rt.db.set_kv(key, str(mapping[key]).strip())
    rt.apply_thresholds()
    rt.db.log("settings updated")
    return {"ok": True, "auto_block": rt.auto_block, "vendor": rt.vendor}


@app.post("/api/webhooks")
async def api_webhooks_save(request: Request, _: None = Depends(require_login)):
    body = await request.json()
    rt = get_runtime()
    try:
        rt.webhooks = save_webhook_settings(rt.db, body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    rt.db.log("webhook settings updated")
    return {"ok": True, "webhooks": webhooks_as_dict(rt.webhooks)}


@app.post("/api/webhooks/test")
async def api_webhooks_test(request: Request, _: None = Depends(require_login)):
    body = await request.json()
    channel = (body.get("channel") or "").strip().lower()
    if channel not in {"slack", "discord"}:
        raise HTTPException(status_code=400, detail="channel must be slack or discord")
    rt = get_runtime()
    if channel == "slack":
        raw = body.get("slack_webhook_url", rt.webhooks.slack_url)
        try:
            url = validate_webhook_url(str(raw or ""), "slack")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    else:
        raw = body.get("discord_webhook_url", rt.webhooks.discord_url)
        try:
            url = validate_webhook_url(str(raw or ""), "discord")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not url:
        raise HTTPException(status_code=400, detail=f"{channel} webhook URL is not configured")
    try:
        await asyncio.to_thread(send_test, url, channel)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"ok": True, "channel": channel}


@app.post("/api/router/test")
@app.post("/api/mikrotik/test")
async def api_router_test(request: Request, _: None = Depends(require_login)):
    rt = get_runtime()
    label = VENDOR_LABELS.get(rt.vendor, rt.vendor)
    status = await asyncio.to_thread(rt.blocker.probe)
    rt.mikrotik_status = status.__dict__
    if status.connected:
        await _refresh_router_blocked(rt)
        rt.db.log(f"{label} reachable ({status.identity} {status.version})")
    else:
        rt.db.log(f"{label} check failed: {status.last_error}", "error")
    return rt.mikrotik_status


@app.get("/api/upgrade/status")
async def api_upgrade_status(request: Request, _: None = Depends(require_login)):
    rt = get_runtime()
    if not rt.settings.upgrade_allow_api:
        raise HTTPException(status_code=403, detail="upgrade API disabled in .env")
    status = await asyncio.to_thread(
        check_upgrade,
        rt.settings.upgrade_git_remote,
        rt.settings.upgrade_git_branch,
        True,
    )
    return status.__dict__


@app.post("/api/upgrade")
async def api_upgrade_run(request: Request, _: None = Depends(require_login)):
    rt = get_runtime()
    if not rt.settings.upgrade_allow_api:
        raise HTTPException(status_code=403, detail="upgrade API disabled in .env")
    body: dict[str, Any] = {}
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.json()
    restart = bool(body.get("restart"))
    restart_cmd = rt.settings.upgrade_restart_cmd if restart else ""
    try:
        result = await asyncio.to_thread(
            run_upgrade,
            remote=rt.settings.upgrade_git_remote,
            branch=rt.settings.upgrade_git_branch,
            restart_cmd=restart_cmd,
            use_git=body.get("git", True),
            install_deps=body.get("install", True),
        )
    except UpgradeError as exc:
        rt.db.log(f"upgrade failed: {exc}", "error")
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    rt.db.log(
        f"upgraded {result.previous_version} -> {result.installed_version}"
        + (f" ({result.previous_commit}->{result.new_commit})" if result.new_commit else "")
    )
    return result.__dict__


@app.get("/api/health", response_model=Health, tags=["ops"])
async def api_health():
    rt = get_runtime()
    return {
        "ok": True,
        "netflow_port": rt.settings.netflow_port,
        "flows": rt.stats.flows,
        "flows_last_10s": rt.stats.flows_last_10s(),
        "flows_per_sec": rt.stats.flows_per_sec(),
        "version": installed_version(),
        "mikrotik": rt.mikrotik_status.get("connected"),
        "router": rt.mikrotik_status.get("connected"),
        "vendor": rt.vendor,
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
    host, _port, acl = rt.settings.blocker_endpoint(rt.vendor)
    return {
        "generated_at": time.time(),
        "address_list": rt.mikrotik_status.get("address_list") or acl,
        "vendor": rt.vendor,
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
        router_ips = await asyncio.to_thread(rt.blocker.list_blocked)
    except RouterError:
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
        router_ips = await asyncio.to_thread(rt.blocker.list_blocked)
    except RouterError:
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


def visible_detections(
    rows: list[dict[str, Any]],
    router_blocked: set[str],
    is_allowed,
) -> list[dict[str, Any]]:
    """Drop allowlisted sources and IPs already on the router access list."""
    return [
        row
        for row in rows
        if not is_allowed(row["src_ip"]) and row["src_ip"] not in router_blocked
    ]


async def _refresh_router_blocked(rt: Runtime) -> None:
    try:
        listed = await asyncio.to_thread(rt.blocker.list_blocked)
    except RouterError:
        return
    rt.router_blocked = set(listed)


async def _block_ip(rt: Runtime, ip: str, reason: str, source: str) -> None:
    if rt.detector.is_allowed(ip):
        raise HTTPException(status_code=400, detail=f"{ip} is on the allowlist")
    try:
        await asyncio.to_thread(rt.blocker.block, ip, f"collector:{reason}")
    except RouterError as exc:
        rt.db.log(f"block failed for {ip}: {exc}", "error")
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    rt.db.add_block(ip, reason, source, rt.settings.mikrotik_block_timeout)
    rt.router_blocked.add(ip)
    rt.db.log(f"blocked {ip} ({source}: {reason})")
    await rt.notify_block_webhook(ip, reason, source)


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
                await rt.notify_detection_webhook(det, auto_blocked=auto)
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


async def _router_watch(rt: Runtime) -> None:
    await asyncio.sleep(1)
    while True:
        try:
            status = await asyncio.to_thread(rt.blocker.probe)
            rt.mikrotik_status = status.__dict__
            if status.connected:
                await _refresh_router_blocked(rt)
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
            await asyncio.to_thread(rt.blocker.unblock, ip)
        except RouterError as exc:
            rt.db.log(f"could not unblock allowlisted {ip}: {exc}", "error")
            continue
        rt.db.deactivate_block(ip)
        rt.router_blocked.discard(ip)
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


def _status_dict(settings: Settings, vendor: str) -> dict[str, Any]:
    host, port, acl = settings.blocker_endpoint(vendor)
    return {
        "connected": False,
        "host": host,
        "port": port,
        "vendor": vendor,
        "identity": "",
        "version": "",
        "address_list": acl,
        "list_count": 0,
        "filter_ready": False,
        "last_error": "",
        "last_ok": None,
    }


@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401 and request.url.path.startswith("/api/"):
        return JSONResponse({"detail": exc.detail}, status_code=401)
    if exc.status_code == 401:
        return RedirectResponse("/login", status_code=302)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
