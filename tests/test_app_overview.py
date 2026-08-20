from collector.app import visible_detections


def test_visible_detections_hides_router_listed_ips():
    rows = [
        {"src_ip": "203.0.113.1", "kind": "spray"},
        {"src_ip": "203.0.113.2", "kind": "vertical"},
        {"src_ip": "192.168.88.50", "kind": "horizontal"},
    ]
    out = visible_detections(
        rows,
        router_blocked={"203.0.113.2"},
        is_allowed=lambda ip: ip.startswith("192.168."),
    )
    assert [row["src_ip"] for row in out] == ["203.0.113.1"]


def test_visible_detections_empty_when_all_blocked_or_allowlisted():
    rows = [{"src_ip": "1.1.1.1", "kind": "spray"}]
    assert visible_detections(rows, {"1.1.1.1"}, lambda _ip: False) == []
    assert visible_detections(rows, set(), lambda ip: ip == "1.1.1.1") == []
