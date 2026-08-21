from collector.config import Settings


def test_cisco_profile_missing_host():
    s = Settings(cisco_host="", cisco_password="secret")
    profile = s.vendor_profile("cisco")
    assert profile["configured"] is False
    assert "CISCO_HOST" in profile["missing"]


def test_cisco_profile_ready():
    s = Settings(cisco_host="192.0.2.1", cisco_password="secret")
    profile = s.vendor_profile("cisco")
    assert profile["configured"] is True
    assert profile["missing"] == []


def test_mikrotik_profile_needs_auth():
    s = Settings(mikrotik_password="", mikrotik_key_path="")
    profile = s.vendor_profile("mikrotik")
    assert profile["configured"] is False
    assert "MIKROTIK_PASSWORD or MIKROTIK_KEY_PATH" in profile["missing"]
