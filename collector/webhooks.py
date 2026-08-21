from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from collector.detection import Detection


@dataclass
class WebhookSettings:
    slack_url: str = ""
    discord_url: str = ""
    notify_detections: bool = True
    notify_blocks: bool = True


def load_webhook_settings(db, defaults: WebhookSettings) -> WebhookSettings:
    return WebhookSettings(
        slack_url=(db.get_kv("slack_webhook_url", defaults.slack_url) or "").strip(),
        discord_url=(db.get_kv("discord_webhook_url", defaults.discord_url) or "").strip(),
        notify_detections=_as_bool(db.get_kv("webhook_notify_detections"), defaults.notify_detections),
        notify_blocks=_as_bool(db.get_kv("webhook_notify_blocks"), defaults.notify_blocks),
    )


def save_webhook_settings(db, payload: dict[str, Any]) -> WebhookSettings:
    if "slack_webhook_url" in payload:
        db.set_kv("slack_webhook_url", validate_webhook_url(str(payload["slack_webhook_url"]), "slack"))
    if "discord_webhook_url" in payload:
        db.set_kv("discord_webhook_url", validate_webhook_url(str(payload["discord_webhook_url"]), "discord"))
    if payload.get("webhook_notify_detections") is not None:
        db.set_kv(
            "webhook_notify_detections",
            "true" if payload["webhook_notify_detections"] else "false",
        )
    if payload.get("webhook_notify_blocks") is not None:
        db.set_kv(
            "webhook_notify_blocks",
            "true" if payload["webhook_notify_blocks"] else "false",
        )
    return WebhookSettings(
        slack_url=db.get_kv("slack_webhook_url", "") or "",
        discord_url=db.get_kv("discord_webhook_url", "") or "",
        notify_detections=_as_bool(db.get_kv("webhook_notify_detections"), True),
        notify_blocks=_as_bool(db.get_kv("webhook_notify_blocks"), True),
    )


def validate_webhook_url(url: str, kind: str) -> str:
    cleaned = url.strip()
    if not cleaned:
        return ""
    if kind == "slack" and not cleaned.startswith("https://hooks.slack.com/"):
        raise ValueError("Slack webhook must start with https://hooks.slack.com/")
    if kind == "discord" and not cleaned.startswith("https://discord.com/api/webhooks/"):
        raise ValueError("Discord webhook must start with https://discord.com/api/webhooks/")
    return cleaned


def webhooks_as_dict(settings: WebhookSettings) -> dict[str, Any]:
    return {
        "slack_webhook_url": settings.slack_url,
        "discord_webhook_url": settings.discord_url,
        "webhook_notify_detections": settings.notify_detections,
        "webhook_notify_blocks": settings.notify_blocks,
        "slack_configured": bool(settings.slack_url),
        "discord_configured": bool(settings.discord_url),
    }


def _as_bool(raw: str | None, default: bool) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _post_json(url: str, payload: dict[str, Any]) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "netflow-collector/0.1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            if resp.status >= 400:
                raise RuntimeError(f"webhook HTTP {resp.status}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:200]
        raise RuntimeError(f"webhook HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc


def format_detection_message(det: Detection, auto_blocked: bool = False) -> str:
    detail = det.detail or {}
    lines = [
        f"Detection: {det.kind}",
        f"Source: {det.src_ip}",
        f"Score: {det.score}",
    ]
    if detail.get("target"):
        lines.append(f"Target: {detail['target']}")
    if detail.get("port") is not None:
        lines.append(f"Port: {detail['port']}")
    if detail.get("max_bytes") is not None:
        lines.append(f"Max bytes: {detail['max_bytes']}")
    if detail.get("flows") is not None:
        lines.append(f"Flows in window: {detail['flows']}")
    if auto_blocked:
        lines.append("Action: auto-blocked on router")
    return "\n".join(lines)


def format_block_message(ip: str, reason: str, source: str) -> str:
    return "\n".join(
        [
            "IP blocked on router",
            f"IP: {ip}",
            f"Reason: {reason}",
            f"Source: {source}",
        ]
    )


def send_slack(url: str, text: str) -> None:
    if not url:
        raise ValueError("Slack webhook URL is not configured")
    _post_json(url, {"text": text})


def send_discord(url: str, text: str) -> None:
    if not url:
        raise ValueError("Discord webhook URL is not configured")
    _post_json(
        url,
        {
            "content": text,
            "allowed_mentions": {"parse": []},
        },
    )


def send_test(url: str, channel: str) -> None:
    label = "Slack" if channel == "slack" else "Discord"
    text = f"Collector webhook test ({label}) — notifications are configured."
    if channel == "slack":
        send_slack(url, text)
    elif channel == "discord":
        send_discord(url, text)
    else:
        raise ValueError("channel must be slack or discord")


def notify_detection(settings: WebhookSettings, det: Detection, auto_blocked: bool = False) -> list[str]:
    if not settings.notify_detections:
        return []
    text = format_detection_message(det, auto_blocked=auto_blocked)
    return _notify_both(settings, text)


def notify_block(settings: WebhookSettings, ip: str, reason: str, source: str) -> list[str]:
    if not settings.notify_blocks:
        return []
    text = format_block_message(ip, reason, source)
    return _notify_both(settings, text)


def _notify_both(settings: WebhookSettings, text: str) -> list[str]:
    sent: list[str] = []
    errors: list[str] = []
    if settings.slack_url:
        try:
            send_slack(settings.slack_url, text)
            sent.append("slack")
        except Exception as exc:
            errors.append(f"slack: {exc}")
    if settings.discord_url:
        try:
            send_discord(settings.discord_url, text)
            sent.append("discord")
        except Exception as exc:
            errors.append(f"discord: {exc}")
    if errors and not sent:
        raise RuntimeError("; ".join(errors))
    if errors:
        return sent + [f"partial: {'; '.join(errors)}"]
    if not sent:
        raise RuntimeError("no webhook URLs configured")
    return sent
