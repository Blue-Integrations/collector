from collector.talkers import TalkerTracker


def test_top_talkers_rank_by_bytes():
    t = TalkerTracker()
    t.observe("203.0.113.1", "192.0.2.1", 100, 1)
    t.observe("203.0.113.1", "192.0.2.2", 50, 1)
    t.observe("198.51.100.9", "192.0.2.1", 1000, 4)
    dump = t.dump(limit=10)
    assert dump["top_sources"][0]["ip"] == "198.51.100.9"
    assert dump["top_sources"][0]["bytes"] == 1000
    assert dump["top_sources"][1]["ip"] == "203.0.113.1"
    assert dump["top_sources"][1]["bytes"] == 150
    assert dump["top_pairs"][0]["src_ip"] == "198.51.100.9"
    assert dump["top_destinations"][0]["ip"] == "192.0.2.1"
