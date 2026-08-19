from __future__ import annotations

import struct
import time

from collector.netflow import NetflowParser


def _ipv4(octet: str) -> int:
    a, b, c, d = (int(p) for p in octet.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def test_parse_netflow_v5():
    header = struct.pack("!HHIIIIBBH", 5, 1, 1000, int(time.time()), 0, 1, 0, 0, 0)
    record = struct.pack(
        "!IIIHHIIIIHHBBBBHHBBH",
        _ipv4("203.0.113.10"),
        _ipv4("192.0.2.5"),
        0,
        1,
        2,
        4,
        320,
        0,
        10,
        54321,
        22,
        0,
        2,
        6,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    flows = NetflowParser().parse(header + record, "192.168.88.3")
    assert len(flows) == 1
    flow = flows[0]
    assert flow.src_ip == "203.0.113.10"
    assert flow.dst_ip == "192.0.2.5"
    assert flow.src_port == 54321
    assert flow.dst_port == 22
    assert flow.proto == 6
    assert flow.bytes == 320
    assert flow.packets == 4
    assert flow.version == 5


def test_parse_netflow_v9_with_template():
    # header: version, count=2 sets, uptime, unix, seq, source_id
    header = struct.pack("!HHIIII", 9, 2, 0, int(time.time()), 1, 7)
    fields = [
        (8, 4),   # src
        (12, 4),  # dst
        (7, 2),   # sport
        (11, 2),  # dport
        (4, 1),   # proto
        (1, 4),   # bytes
        (2, 4),   # packets
    ]
    tmpl_payload = struct.pack("!HH", 256, len(fields))
    for ftype, flen in fields:
        tmpl_payload += struct.pack("!HH", ftype, flen)
    tmpl_set = struct.pack("!HH", 0, 4 + len(tmpl_payload)) + tmpl_payload

    record = (
        struct.pack("!I", _ipv4("198.51.100.9"))
        + struct.pack("!I", _ipv4("192.0.2.80"))
        + struct.pack("!H", 4000)
        + struct.pack("!H", 443)
        + struct.pack("!B", 6)
        + struct.pack("!I", 1500)
        + struct.pack("!I", 10)
    )
    padding = b"\x00" * ((4 - (len(record) % 4)) % 4)
    data_set = struct.pack("!HH", 256, 4 + len(record) + len(padding)) + record + padding

    flows = NetflowParser().parse(header + tmpl_set + data_set, "192.168.88.3")
    assert len(flows) == 1
    flow = flows[0]
    assert flow.src_ip == "198.51.100.9"
    assert flow.dst_ip == "192.0.2.80"
    assert flow.dst_port == 443
    assert flow.proto == 6
    assert flow.bytes == 1500
    assert flow.version == 9
