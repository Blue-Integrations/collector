from collector.schemas import BlockedDump, TalkersDump


def test_blocked_dump_schema():
    parsed = BlockedDump.model_validate(
        {
            "generated_at": 1.0,
            "address_list": "blocked-scanners",
            "count": 1,
            "blocked": [
                {
                    "ip": "203.0.113.77",
                    "reason": "spray",
                    "source": "auto",
                    "created_at": 1.0,
                    "timeout": "1d",
                    "on_router": True,
                }
            ],
        }
    )
    assert parsed.blocked[0].ip == "203.0.113.77"


def test_talkers_dump_schema():
    parsed = TalkersDump.model_validate(
        {
            "generated_at": 2.0,
            "since": 1.0,
            "window": "since_start",
            "top_sources": [
                {"ip": "10.0.0.1", "bytes": 9, "packets": 2, "flows": 1, "last_seen": 2.0}
            ],
            "top_destinations": [],
            "top_pairs": [],
        }
    )
    assert parsed.top_sources[0].bytes == 9
