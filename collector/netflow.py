from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from ipaddress import ip_address


# NetFlow v9 / IPFIX information element IDs we care about
IN_BYTES = 1
IN_PKTS = 2
PROTOCOL = 4
TCP_FLAGS = 6
L4_SRC_PORT = 7
IPV4_SRC_ADDR = 8
L4_DST_PORT = 11
IPV4_DST_ADDR = 12
IPV6_SRC_ADDR = 27
IPV6_DST_ADDR = 28
IP_PROTOCOL_VERSION = 60
SRC_TRANSPORT_PORT = 227  # some exporters
DST_TRANSPORT_PORT = 228

PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    58: "ICMPv6",
}


def proto_name(number: int) -> str:
    return PROTO_NAMES.get(number, str(number))


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    proto: int = 0
    bytes: int = 0
    packets: int = 0
    tcp_flags: int = 0
    exporter: str = ""
    version: int = 0

    def as_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "proto_name": proto_name(self.proto),
            "bytes": self.bytes,
            "packets": self.packets,
            "tcp_flags": self.tcp_flags,
            "exporter": self.exporter,
            "version": self.version,
        }


@dataclass
class _Field:
    type: int
    length: int
    enterprise: int | None = None


@dataclass
class _Template:
    template_id: int
    fields: list[_Field] = field(default_factory=list)

    @property
    def size(self) -> int:
        return sum(f.length for f in self.fields)


class NetflowParser:
    """Stateful parser for NetFlow v5, v9, and IPFIX (v10)."""

    def __init__(self) -> None:
        # (exporter, observation_domain, template_id) -> template
        self.templates: dict[tuple[str, int, int], _Template] = {}

    def parse(self, data: bytes, exporter: str) -> list[Flow]:
        if len(data) < 20:
            return []
        version = struct.unpack_from("!H", data, 0)[0]
        if version == 5:
            return self._parse_v5(data, exporter)
        if version == 9:
            return self._parse_v9(data, exporter)
        if version == 10:
            return self._parse_ipfix(data, exporter)
        return []

    def _parse_v5(self, data: bytes, exporter: str) -> list[Flow]:
        if len(data) < 24:
            return []
        _version, count = struct.unpack_from("!HH", data, 0)
        flows: list[Flow] = []
        offset = 24
        record_size = 48
        for _ in range(count):
            if offset + record_size > len(data):
                break
            src, dst, _nexthop, _inp, _out, pkts, octets, _first, _last, sport, dport, _pad, flags, proto, *_rest = (
                struct.unpack_from("!IIIHHIIIIHHBBBBHHBBH", data, offset)
            )
            flows.append(
                Flow(
                    src_ip=_ipv4(src),
                    dst_ip=_ipv4(dst),
                    src_port=sport,
                    dst_port=dport,
                    proto=proto,
                    bytes=octets,
                    packets=pkts,
                    tcp_flags=flags,
                    exporter=exporter,
                    version=5,
                )
            )
            offset += record_size
        return flows

    def _parse_v9(self, data: bytes, exporter: str) -> list[Flow]:
        if len(data) < 20:
            return []
        _ver, count, _uptime, _secs, _seq, source_id = struct.unpack_from("!HHIIII", data, 0)
        return self._parse_sets(
            data,
            offset=20,
            end=len(data),
            exporter=exporter,
            domain=source_id,
            version=9,
            set_count=count,
        )

    def _parse_ipfix(self, data: bytes, exporter: str) -> list[Flow]:
        if len(data) < 16:
            return []
        _ver, length, _export_time, _seq, domain = struct.unpack_from("!HHIII", data, 0)
        end = min(length, len(data))
        return self._parse_sets(
            data,
            offset=16,
            end=end,
            exporter=exporter,
            domain=domain,
            version=10,
            set_count=None,
        )

    def _parse_sets(
        self,
        data: bytes,
        offset: int,
        end: int,
        exporter: str,
        domain: int,
        version: int,
        set_count: int | None,
    ) -> list[Flow]:
        flows: list[Flow] = []
        sets_seen = 0
        while offset + 4 <= end:
            if set_count is not None and sets_seen >= set_count:
                break
            set_id, set_len = struct.unpack_from("!HH", data, offset)
            if set_len < 4 or offset + set_len > end:
                break
            payload = data[offset + 4 : offset + set_len]
            if set_id in (0, 2):  # v9 template / IPFIX template
                self._read_templates(payload, exporter, domain, ipfix=(set_id == 2))
            elif set_id not in (1, 3):  # skip options templates
                tmpl = self.templates.get((exporter, domain, set_id))
                if tmpl and tmpl.size:
                    flows.extend(self._read_data(payload, tmpl, exporter, version))
            offset += set_len
            # v9 set lengths are 4-byte aligned already in the length field
            sets_seen += 1
        return flows

    def _read_templates(self, payload: bytes, exporter: str, domain: int, ipfix: bool) -> None:
        pos = 0
        while pos + 4 <= len(payload):
            template_id, field_count = struct.unpack_from("!HH", payload, pos)
            pos += 4
            fields: list[_Field] = []
            ok = True
            for _ in range(field_count):
                if pos + 4 > len(payload):
                    ok = False
                    break
                ftype, flen = struct.unpack_from("!HH", payload, pos)
                pos += 4
                enterprise = None
                if ipfix and ftype & 0x8000:
                    if pos + 4 > len(payload):
                        ok = False
                        break
                    enterprise = struct.unpack_from("!I", payload, pos)[0]
                    pos += 4
                    ftype = ftype & 0x7FFF
                fields.append(_Field(type=ftype, length=flen, enterprise=enterprise))
            if ok and template_id >= 256:
                self.templates[(exporter, domain, template_id)] = _Template(template_id, fields)

    def _read_data(self, payload: bytes, tmpl: _Template, exporter: str, version: int) -> list[Flow]:
        flows: list[Flow] = []
        pos = 0
        rec_size = tmpl.size
        if rec_size <= 0:
            return flows
        while pos + rec_size <= len(payload):
            values: dict[int, bytes] = {}
            cursor = pos
            for fld in tmpl.fields:
                values[fld.type] = payload[cursor : cursor + fld.length]
                cursor += fld.length
            flow = self._flow_from_fields(values, exporter, version)
            if flow is not None:
                flows.append(flow)
            pos += rec_size
        return flows

    def _flow_from_fields(self, values: dict[int, bytes], exporter: str, version: int) -> Flow | None:
        src = _addr_from_fields(values, IPV4_SRC_ADDR, IPV6_SRC_ADDR)
        dst = _addr_from_fields(values, IPV4_DST_ADDR, IPV6_DST_ADDR)
        if not src or not dst:
            return None
        return Flow(
            src_ip=src,
            dst_ip=dst,
            src_port=_uint(values.get(L4_SRC_PORT) or values.get(SRC_TRANSPORT_PORT)),
            dst_port=_uint(values.get(L4_DST_PORT) or values.get(DST_TRANSPORT_PORT)),
            proto=_uint(values.get(PROTOCOL)),
            bytes=_uint(values.get(IN_BYTES)),
            packets=_uint(values.get(IN_PKTS)),
            tcp_flags=_uint(values.get(TCP_FLAGS)),
            exporter=exporter,
            version=version,
        )


def _ipv4(value: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", value))


def _addr_from_fields(values: dict[int, bytes], v4: int, v6: int) -> str | None:
    raw = values.get(v4) or values.get(v6)
    if not raw:
        return None
    try:
        if len(raw) == 4:
            return socket.inet_ntoa(raw)
        if len(raw) == 16:
            return str(ip_address(raw))
    except (OSError, ValueError):
        return None
    return None


def _uint(raw: bytes | None) -> int:
    if not raw:
        return 0
    return int.from_bytes(raw, "big", signed=False)
