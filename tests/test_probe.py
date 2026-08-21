import time

from collector.probe import ProbeStats


def test_flows_last_10s_counts_records_in_window():
    stats = ProbeStats()
    stats.record(3, "10.0.0.1")
    assert stats.flows_last_10s() == 3
    assert stats.flows_per_sec() == 3.0


def test_flows_last_10s_prunes_old_records():
    stats = ProbeStats()
    old = time.time() - 15
    stats._times.append(old)
    stats._times.append(old)
    stats.record(1, "10.0.0.1")
    assert stats.flows_last_10s() == 1
