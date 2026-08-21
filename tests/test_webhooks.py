from collector.detection import Detection
from collector.webhooks import (
    format_block_message,
    format_detection_message,
    validate_webhook_url,
    webhooks_as_dict,
    WebhookSettings,
)


def test_validate_slack_url():
    url = validate_webhook_url("https://hooks.slack.com/services/T/B/x", "slack")
    assert url.startswith("https://hooks.slack.com/")


def test_validate_discord_url():
    url = validate_webhook_url("https://discord.com/api/webhooks/1/token", "discord")
    assert "/api/webhooks/" in url


def test_reject_bad_slack_url():
    try:
        validate_webhook_url("https://example.com/hook", "slack")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "Slack" in str(exc)


def test_format_detection_message():
    text = format_detection_message(
        Detection(
            src_ip="203.0.113.1",
            kind="icmp-flood",
            score=55,
            detail={"flows": 55, "max_bytes": 4126, "target": "192.0.2.1"},
        ),
        auto_blocked=True,
    )
    assert "icmp-flood" in text
    assert "4126" in text
    assert "auto-blocked" in text


def test_format_block_message():
    text = format_block_message("203.0.113.1", "manual", "manual")
    assert "203.0.113.1" in text
    assert "manual" in text


def test_webhooks_as_dict():
    payload = webhooks_as_dict(
        WebhookSettings(
            slack_url="https://hooks.slack.com/services/T/B/x",
            discord_url="",
            notify_detections=True,
            notify_blocks=False,
        )
    )
    assert payload["slack_configured"] is True
    assert payload["discord_configured"] is False
    assert payload["webhook_notify_blocks"] is False
