from collector.detection import ScanDetector
from collector.netflow import Flow


def _flow(src: str, dst: str, port: int) -> Flow:
    return Flow(src_ip=src, dst_ip=dst, src_port=40000, dst_port=port, proto=6, bytes=40, packets=1)


def test_public_dns_replies_ignored():
    det = ScanDetector(window_sec=30, vertical_ports=5, unique_ports=5, allowlist=[])
    hits = []
    for port in range(40000, 40050):
        hits.extend(
            det.observe(
                Flow(
                    src_ip="1.1.1.1",
                    dst_ip="192.0.2.8",
                    src_port=53,
                    dst_port=port,
                    proto=17,
                    bytes=80,
                    packets=1,
                )
            )
        )
    assert hits == []
    assert det.is_allowed("8.8.8.8")
    assert det.is_allowed("9.9.9.9")
    assert det.is_allowed("1.0.0.1")
    assert not det.is_allowed("203.0.113.50")


def test_dns_reply_port_ignored_for_unknown_resolver():
    det = ScanDetector(window_sec=30, vertical_ports=5, unique_ports=5, allowlist=[])
    hits = []
    for port in range(40000, 40020):
        hits.extend(
            det.observe(
                Flow(
                    src_ip="203.0.113.53",
                    dst_ip="192.0.2.8",
                    src_port=53,
                    dst_port=port,
                    proto=17,
                    bytes=80,
                    packets=1,
                )
            )
        )
    assert hits == []


def test_allowlist_skips_lan():
    det = ScanDetector(window_sec=30, vertical_ports=5, allowlist=["192.168.88.0/24"])
    hits = []
    for port in range(1, 40):
        hits.extend(det.observe(_flow("192.168.88.10", "1.1.1.1", port)))
    assert hits == []


def test_vertical_scan():
    det = ScanDetector(window_sec=30, vertical_ports=8, horizontal_hosts=999, unique_ports=999)
    detections = []
    for port in range(1, 12):
        detections.extend(det.observe(_flow("203.0.113.50", "192.0.2.8", port)))
    kinds = {d.kind for d in detections}
    assert "vertical" in kinds
    vertical = [d for d in detections if d.kind == "vertical"][-1]
    assert vertical.score >= 8
    assert vertical.detail["target"] == "192.0.2.8"


def test_https_reply_leg_ignored():
    det = ScanDetector(window_sec=30, vertical_ports=5, unique_ports=5, allowlist=[])
    hits = []
    for port in range(40000, 40050):
        hits.extend(
            det.observe(
                Flow(
                    src_ip="151.244.12.5",
                    dst_ip="45.148.10.238",
                    src_port=443,
                    dst_port=port,
                    proto=6,
                    bytes=4000,
                    packets=8,
                )
            )
        )
    assert hits == []


def test_protected_wan_not_scored():
    det = ScanDetector(
        window_sec=30,
        vertical_ports=5,
        unique_ports=5,
        allowlist=[],
        protected=["151.244.12.0/27"],
    )
    hits = []
    for port in range(1, 20):
        hits.extend(det.observe(_flow("151.244.12.5", "203.0.113.9", port)))
    assert hits == []
    assert det.is_allowed("151.244.12.10")


def test_connect_storm_many_src_ports_one_service():
    det = ScanDetector(window_sec=30, vertical_ports=8, horizontal_hosts=999, unique_ports=999)
    detections = []
    for src_port in range(40000, 40020):
        detections.extend(
            det.observe(
                Flow(
                    src_ip="45.148.10.238",
                    dst_ip="151.244.12.5",
                    src_port=src_port,
                    dst_port=443,
                    proto=6,
                    bytes=76,
                    packets=1,
                )
            )
        )
    storms = [d for d in detections if d.kind == "connect-storm"]
    assert storms
    assert storms[-1].detail["target"] == "151.244.12.5"
    assert storms[-1].detail["port"] == 443
    assert not any(d.kind == "vertical" for d in detections)


def test_horizontal_scan():
    det = ScanDetector(window_sec=30, vertical_ports=999, horizontal_hosts=8, unique_ports=999)
    detections = []
    for i in range(1, 12):
        detections.extend(det.observe(_flow("203.0.113.50", f"192.0.2.{i}", 22)))
    assert any(d.kind == "horizontal" for d in detections)


def _icmp(src: str, dst: str, nbytes: int = 4126) -> Flow:
    return Flow(src_ip=src, dst_ip=dst, src_port=0, dst_port=0, proto=1, bytes=nbytes, packets=1)


def test_icmp_flood():
    det = ScanDetector(window_sec=30, icmp_flood_threshold=10, large_flow_threshold=999)
    detections = []
    for i in range(12):
        detections.extend(det.observe(_icmp("203.0.113.77", f"192.0.2.{i % 4 + 1}")))
    floods = [d for d in detections if d.kind == "icmp-flood"]
    assert floods
    assert floods[-1].score >= 10
    assert floods[-1].detail["max_bytes"] == 4126


def test_large_flow():
    det = ScanDetector(
        window_sec=30,
        icmp_flood_threshold=999,
        large_flow_min_bytes=2048,
        large_flow_threshold=5,
    )
    detections = []
    for i in range(6):
        detections.extend(
            det.observe(
                Flow(
                    src_ip="203.0.113.88",
                    dst_ip="192.0.2.8",
                    src_port=40000 + i,
                    dst_port=443,
                    proto=6,
                    bytes=4126,
                    packets=3,
                )
            )
        )
    large = [d for d in detections if d.kind == "large-flow"]
    assert large
    assert large[-1].detail["max_bytes"] == 4126
    assert "TCP" in large[-1].detail["protos"]
