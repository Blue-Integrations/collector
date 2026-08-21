from __future__ import annotations

import ipaddress
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field


class WhoisError(Exception):
    pass


@dataclass
class WhoisRecord:
    ip: str
    network: str = ""
    cidr: str = ""
    country: str = ""
    org: str = ""
    abuse: str = ""
    rir: str = ""
    fetched_at: float = field(default_factory=time.time)
    raw_handle: str = ""


_CACHE: dict[str, tuple[float, WhoisRecord]] = {}
_CACHE_TTL = 3600.0


def lookup_ip(ip: str, *, cache: bool = True) -> WhoisRecord:
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise WhoisError("invalid IP address") from exc

    if cache:
        hit = _CACHE.get(ip)
        if hit and time.time() - hit[0] < _CACHE_TTL:
            return hit[1]

    url = f"https://rdap.org/ip/{ip}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        raise WhoisError(f"RDAP lookup failed ({exc.code})") from exc
    except urllib.error.URLError as exc:
        raise WhoisError(f"RDAP unreachable: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise WhoisError("RDAP returned invalid JSON") from exc

    record = _parse_rdap(ip, payload)
    if cache:
        _CACHE[ip] = (time.time(), record)
    return record


def _parse_rdap(ip: str, data: dict) -> WhoisRecord:
    record = WhoisRecord(
        ip=ip,
        network=str(data.get("name") or ""),
        country=str(data.get("country") or ""),
        rir=_rir_from_links(data.get("links") or []),
        raw_handle=str(data.get("handle") or ""),
    )
    start = data.get("startAddress") or ""
    end = data.get("endAddress") or ""
    if start and end:
        record.cidr = f"{start} – {end}"
    elif data.get("cidr0_cidr"):
        record.cidr = str(data["cidr0_cidr"])

    for entity in data.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        roles = {str(r).lower() for r in entity.get("roles") or []}
        label = _entity_label(entity)
        if not record.org and roles & {"registrant", "technical", "administrative"}:
            record.org = label
        if not record.abuse and "abuse" in roles:
            record.abuse = label
    if not record.org:
        record.org = _entity_label((data.get("entities") or [{}])[0] if data.get("entities") else {})
    return record


def _rir_from_links(links: list) -> str:
    for link in links:
        if not isinstance(link, dict):
            continue
        href = str(link.get("href") or "")
        for tag in ("arin", "ripe", "apnic", "lacnic", "afrinic"):
            if tag in href.lower():
                return tag.upper()
    return ""


def _entity_label(entity: dict) -> str:
    if not entity:
        return ""
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) > 1:
        for row in vcard[1]:
            if not isinstance(row, list) or len(row) < 4:
                continue
            kind, _params, val_type, value = row[0], row[1], row[2], row[3]
            if kind == "fn" and value:
                return str(value)
            if kind == "org" and value:
                return str(value)
            if val_type == "text" and kind in {"email", "tel"} and value:
                return str(value)
    return str(entity.get("handle") or "")
