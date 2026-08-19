import re

from collector.mikrotik import _count, _is_missing_menu


def test_count_only_integer():
    assert _count("0") == 0
    assert _count("14\n") == 14


def test_count_ignores_line_1_error():
    err = "no such item (/ipv6/firewall/filter/add; line 1)"
    assert _count(err) == 0
    assert _is_missing_menu(err)


def test_connection_regex_escapes_dots():
    assert re.escape("174.239.149.22") == r"174\.239\.149\.22"
