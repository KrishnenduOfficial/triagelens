"""Adversarial and extreme edge-case stress tests for the Timeline Builder engine."""

from datetime import datetime, timedelta, timezone
import random
import time
import pytest

from src.engine.timeline import TimelineBuilder
from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.timeline import ThreatTimeline


@pytest.fixture
def builder():
    """Returns a fresh instance of TimelineBuilder."""
    return TimelineBuilder()


# ---------------------------------------------------------------------------
# 1. Volume Stress: 50,000 Alerts
# ---------------------------------------------------------------------------

def test_volume_stress_50k_alerts(builder):
    """50,000 alerts with shuffled timestamps must sort and correlate in under 3.0s without memory issues."""
    base_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    n_alerts = 50_000

    # Deterministic shuffle of timestamp offsets
    offsets = list(range(n_alerts))
    rng = random.Random(42)
    rng.shuffle(offsets)

    alerts = [
        NormalizedAlert(
            source_dataset="HighThroughput-SOC",
            source_file="batch.json",
            event_type="LogonEvent",
            original_record={"idx": i},
            timestamp=base_time + timedelta(seconds=off),
        )
        for i, off in enumerate(offsets)
    ]

    start = time.time()
    timelines = builder.build_timelines(alerts, group_by="source_dataset")
    duration = time.time() - start

    assert duration < 3.0, f"50,000 alert correlation took {duration:.2f}s (exceeded 3.0s limit)"
    assert len(timelines) == 1
    timeline = timelines[0]

    assert timeline.total_events == n_alerts
    assert timeline.grouping_key == "HighThroughput-SOC"
    assert timeline.start_time == base_time
    assert timeline.end_time == base_time + timedelta(seconds=n_alerts - 1)

    # Verify strictly ascending order throughout all 50,000 events
    for i in range(len(timeline.alerts) - 1):
        assert timeline.alerts[i].timestamp <= timeline.alerts[i + 1].timestamp


# ---------------------------------------------------------------------------
# 2. Clock Skew, Out-of-Order, and Missing Timestamps
# ---------------------------------------------------------------------------

def test_clock_skew_and_out_of_order(builder):
    """Sort alerts across negative epochs, far-future dates, identical timestamps, mixed timezones, and None."""
    t_neg = datetime(1969, 12, 31, 23, 0, 0, tzinfo=timezone.utc)
    t_1970 = datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    t_identical = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)
    t_future = datetime(3000, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    t_naive = datetime(2026, 6, 1, 12, 0, 0)  # Naive datetime

    alerts = [
        NormalizedAlert(source_dataset="SkewTest", source_file="1.json", event_type="E1", original_record={}, timestamp=t_future),
        NormalizedAlert(source_dataset="SkewTest", source_file="2.json", event_type="E2", original_record={}, timestamp=None),
        NormalizedAlert(source_dataset="SkewTest", source_file="3.json", event_type="E3", original_record={}, timestamp=t_identical),
        NormalizedAlert(source_dataset="SkewTest", source_file="4.json", event_type="E4", original_record={}, timestamp=t_neg),
        NormalizedAlert(source_dataset="SkewTest", source_file="5.json", event_type="E5", original_record={}, timestamp=t_identical),
        NormalizedAlert(source_dataset="SkewTest", source_file="6.json", event_type="E6", original_record={}, timestamp=None),
        NormalizedAlert(source_dataset="SkewTest", source_file="7.json", event_type="E7", original_record={}, timestamp=t_naive),
        NormalizedAlert(source_dataset="SkewTest", source_file="8.json", event_type="E8", original_record={}, timestamp=t_1970),
    ]

    timelines = builder.build_timelines(alerts, group_by="source_dataset")
    assert len(timelines) == 1
    sorted_alerts = timelines[0].alerts

    # Verify negative epoch is first
    assert sorted_alerts[0].timestamp == t_neg

    # Verify 1970 is second
    assert sorted_alerts[1].timestamp == t_1970

    # Verify None timestamps are sorted to the end
    assert sorted_alerts[-2].timestamp is None
    assert sorted_alerts[-1].timestamp is None

    # Verify start_time and end_time calculations
    assert timelines[0].start_time == t_neg
    assert timelines[0].end_time == t_future
    assert timelines[0].total_events == 8


# ---------------------------------------------------------------------------
# 3. Cross-Pollination Defense (50 Independent Datasets)
# ---------------------------------------------------------------------------

def test_cross_pollination_defense_50_groups(builder):
    """50 different datasets mixed together must isolate into 50 clean timelines with zero alert/enrichment leakage."""
    n_groups = 50
    alerts_per_group = 20
    base_time = datetime(2026, 11, 5, 0, 0, 0, tzinfo=timezone.utc)

    mixed_alerts = []
    enrichment_data = []

    for g_idx in range(n_groups):
        group_name = f"dataset_shard_{g_idx:02d}"
        ind_ip = f"198.51.100.{g_idx}"

        # Create enrichment result uniquely tied to this group's indicator
        enrichment_data.append(
            EnrichmentResult(
                indicator=ind_ip,
                indicator_type="ip",
                provider="VirusTotal",
                is_malicious=(g_idx % 2 == 0),
                raw_response={"shard": g_idx},
            )
        )

        for a_idx in range(alerts_per_group):
            mixed_alerts.append(
                NormalizedAlert(
                    source_dataset=group_name,
                    source_file=f"{group_name}.json",
                    event_type=f"Action_{a_idx}",
                    original_record={"shard": g_idx, "seq": a_idx},
                    extracted_indicators=[ind_ip],
                    timestamp=base_time + timedelta(minutes=a_idx),
                )
            )

    # Thoroughly shuffle the mixed alerts
    rng = random.Random(1337)
    rng.shuffle(mixed_alerts)

    # Build timelines
    timelines = builder.build_timelines(mixed_alerts, enrichment_data, group_by="source_dataset")

    assert len(timelines) == n_groups

    # Verify perfect isolation across all 50 groups
    for timeline in timelines:
        group_id = timeline.grouping_key
        assert timeline.total_events == alerts_per_group

        # Every alert in this timeline must belong exclusively to this grouping key
        for alert in timeline.alerts:
            assert alert.source_dataset == group_id

        # Verification of enrichment data isolation:
        # Must only contain the single enrichment corresponding to this group
        assert len(timeline.enrichment_data) == 1
        expected_ip = f"198.51.100.{int(group_id.split('_')[-1])}"
        assert timeline.enrichment_data[0].indicator == expected_ip


# ---------------------------------------------------------------------------
# 4. Grouping by original_record Attributes
# ---------------------------------------------------------------------------

def test_custom_group_by_original_record_host(builder):
    """Group by a nested key in original_record (e.g., 'host'), handling missing keys."""
    alerts = [
        NormalizedAlert(source_dataset="EVTX", source_file="1.json", event_type="Logon", original_record={"host": "DC-PRIMARY"}),
        NormalizedAlert(source_dataset="EVTX", source_file="2.json", event_type="Logon", original_record={"Host": "DC-PRIMARY"}),
        NormalizedAlert(source_dataset="EVTX", source_file="3.json", event_type="Process", original_record={"host": "WORKSTATION-01"}),
        NormalizedAlert(source_dataset="EVTX", source_file="4.json", event_type="Network", original_record={}),  # Missing host
    ]

    timelines = builder.build_timelines(alerts, group_by="host")

    # Expect 3 groups: 'DC-PRIMARY', 'WORKSTATION-01', and 'ungrouped'
    keys = {t.grouping_key for t in timelines}
    assert keys == {"DC-PRIMARY", "WORKSTATION-01", "ungrouped"}

    dc_timeline = next(t for t in timelines if t.grouping_key == "DC-PRIMARY")
    assert dc_timeline.total_events == 2


# ---------------------------------------------------------------------------
# 5. Empty and All-None Edge Cases
# ---------------------------------------------------------------------------

def test_empty_alerts_and_all_none_timestamps(builder):
    """Handle empty inputs and groups where every alert has None timestamp."""
    assert builder.build_timelines([]) == []

    all_none_alerts = [
        NormalizedAlert(source_dataset="MissingTime", source_file="1.json", event_type="E1", original_record={}, timestamp=None),
        NormalizedAlert(source_dataset="MissingTime", source_file="2.json", event_type="E2", original_record={}, timestamp=None),
    ]

    timelines = builder.build_timelines(all_none_alerts)
    assert len(timelines) == 1
    assert timelines[0].total_events == 2
    assert timelines[0].start_time is None
    assert timelines[0].end_time is None

