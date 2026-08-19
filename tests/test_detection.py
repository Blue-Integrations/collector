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


def test_horizontal_scan():
    det = ScanDetector(window_sec=30, vertical_ports=999, horizontal_hosts=8, unique_ports=999)
    detections = []
    for i in range(1, 12):
        detections.extend(det.observe(_flow("203.0.113.50", f"192.0.2.{i}", 22)))
    assert any(d.kind == "horizontal" for d in detections)
