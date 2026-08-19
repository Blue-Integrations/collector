from collector.blocker import make_blocker, normalize_vendor
from collector.cisco import parse_object_group
from collector.config import Settings
from collector.juniper import parse_prefix_list
from collector.mikrotik import MikroTikClient


def test_normalize_vendor_aliases():
    assert normalize_vendor("IOS-XE") == "cisco"
    assert normalize_vendor("junos") == "juniper"
    assert normalize_vendor("RouterOS") == "mikrotik"
    assert normalize_vendor("nope") == "mikrotik"


def test_parse_cisco_object_group():
    text = """
Network object group blocked-scanners
 host 91.92.47.82
 host 174.239.149.22
 10.1.1.1
"""
    assert parse_object_group(text) == ["10.1.1.1", "174.239.149.22", "91.92.47.82"]


def test_parse_junos_prefix_list_set():
    text = """
set policy-options prefix-list blocked-scanners 1.2.3.4/32
set policy-options prefix-list blocked-scanners 8.8.8.8/32
"""
    assert parse_prefix_list(text) == ["1.2.3.4", "8.8.8.8"]


def test_parse_junos_prefix_list_curly():
    text = """
prefix-list blocked-scanners {
    203.0.113.10/32;
    2001:db8::1/128;
}
"""
    assert parse_prefix_list(text) == ["2001:db8::1", "203.0.113.10"]


def test_make_blocker_default_is_mikrotik():
    settings = Settings(mikrotik_password="x")
    blocker = make_blocker(settings, "mikrotik")
    assert isinstance(blocker, MikroTikClient)
    assert blocker.vendor == "mikrotik"


def test_make_blocker_cisco_and_juniper():
    from collector.cisco import CiscoClient
    from collector.juniper import JuniperClient

    settings = Settings()
    assert isinstance(make_blocker(settings, "cisco"), CiscoClient)
    assert isinstance(make_blocker(settings, "juniper"), JuniperClient)
