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


# ---------------------------------------------------------------------------
# 6. Time Windowing, Event Capping, and Correlation Confidence (Task F4)
# ---------------------------------------------------------------------------

def test_alerts_spaced_days_apart_split_into_multiple_timelines(builder):
    """Verify alerts on same host/user spaced days apart split into distinct timelines."""
    t1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 1, 10, 10, 0, 0, tzinfo=timezone.utc)  # 9 days later
    t3 = datetime(2026, 1, 30, 10, 0, 0, tzinfo=timezone.utc)  # 20 days later

    alerts = [
        NormalizedAlert(
            source_dataset="BendeDataset",
            source_file="auth.log",
            event_type="Logon",
            original_record={"host": "SRV-APP-01", "user": "admin"},
            timestamp=t1,
        ),
        NormalizedAlert(
            source_dataset="BendeDataset",
            source_file="auth.log",
            event_type="Process",
            original_record={"host": "SRV-APP-01", "user": "admin"},
            timestamp=t2,
        ),
        NormalizedAlert(
            source_dataset="BendeDataset",
            source_file="auth.log",
            event_type="Network",
            original_record={"host": "SRV-APP-01", "user": "admin"},
            timestamp=t3,
        ),
    ]

    timelines = builder.build_timelines(alerts)
    # Alerts spaced days apart must split into 3 distinct timelines (1 per session)
    assert len(timelines) == 3
    assert all(t.total_events == 1 for t in timelines)
    assert all(t.correlation_type == "confirmed" for t in timelines)
    assert [t.start_time for t in timelines] == [t1, t2, t3]


def test_timeline_time_gap_splitting(builder):
    """Verify alerts split when consecutive gap exceeds time_gap_minutes (30 min)."""
    t1 = datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 2, 1, 10, 15, 0, tzinfo=timezone.utc)  # 15 min gap (same session)
    t3 = datetime(2026, 2, 1, 11, 0, 0, tzinfo=timezone.utc)   # 45 min gap (> 30 min -> new session)
    t4 = datetime(2026, 2, 1, 11, 10, 0, tzinfo=timezone.utc)  # 10 min gap (same 2nd session)

    alerts = [
        NormalizedAlert(
            source_dataset="EVTX",
            source_file="events.json",
            event_type="Logon",
            original_record={"host": "WKSTN-01", "user": "alice"},
            timestamp=t1,
        ),
        NormalizedAlert(
            source_dataset="EVTX",
            source_file="events.json",
            event_type="ProcessCreate",
            original_record={"host": "WKSTN-01", "user": "alice"},
            timestamp=t2,
        ),
        NormalizedAlert(
            source_dataset="EVTX",
            source_file="events.json",
            event_type="FileAccess",
            original_record={"host": "WKSTN-01", "user": "alice"},
            timestamp=t3,
        ),
        NormalizedAlert(
            source_dataset="EVTX",
            source_file="events.json",
            event_type="NetworkConnect",
            original_record={"host": "WKSTN-01", "user": "alice"},
            timestamp=t4,
        ),
    ]

    timelines = builder.build_timelines(alerts, time_gap_minutes=30)
    assert len(timelines) == 2

    # Session 1: 10:00 and 10:15
    assert timelines[0].total_events == 2
    assert timelines[0].start_time == t1
    assert timelines[0].end_time == t2
    assert timelines[0].correlation_type == "confirmed"

    # Session 2: 11:00 and 11:10
    assert timelines[1].total_events == 2
    assert timelines[1].start_time == t3
    assert timelines[1].end_time == t4
    assert timelines[1].correlation_type == "confirmed"


def test_timeline_event_capping(builder):
    """Verify timelines exceeding max_events_per_timeline are chunked sequentially."""
    base_time = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
    alerts = [
        NormalizedAlert(
            source_dataset="Suricata",
            source_file="eve.json",
            event_type="Flow",
            original_record={"host": "FIREWALL-01", "user": "system"},
            timestamp=base_time + timedelta(minutes=i),
        )
        for i in range(25)
    ]

    timelines = builder.build_timelines(alerts, max_events_per_timeline=10)
    # 25 events capped at 10 per timeline -> 3 timelines (10, 10, 5)
    assert len(timelines) == 3
    assert [t.total_events for t in timelines] == [10, 10, 5]
    assert all(t.correlation_type == "confirmed" for t in timelines)
    assert all("FIREWALL-01" in t.grouping_key for t in timelines)


def test_correlation_type_confirmed_vs_potential(builder):
    """Verify shared hard identifiers yield 'confirmed' and unassociated yield 'potential'."""
    t = datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
    confirmed_alert = NormalizedAlert(
        source_dataset="DatasetA",
        source_file="log.json",
        event_type="Auth",
        original_record={"host": "PROD-DB-01", "user": "oracle"},
        timestamp=t,
    )
    potential_alert = NormalizedAlert(
        source_dataset="DatasetB",
        source_file="raw.json",
        event_type="GenericPing",
        original_record={"noise": "unstructured"},
        timestamp=t,
    )

    timelines = builder.build_timelines([confirmed_alert, potential_alert])
    assert len(timelines) == 2

    confirmed_tl = next(tl for tl in timelines if "PROD-DB-01" in tl.grouping_key)
    assert confirmed_tl.correlation_type == "confirmed"
    assert confirmed_tl.correlation_reason is not None

    potential_tl = next(tl for tl in timelines if tl.grouping_key == "ungrouped")
    assert potential_tl.correlation_type == "potential"
    assert potential_tl.correlation_reason == "time_proximity_fallback"


def test_naive_timestamp_treated_as_utc(builder):
    """Verify naive datetimes from logs are treated as UTC for sorting and windowing."""
    naive_t1 = datetime(2026, 5, 1, 10, 0, 0)  # Naive
    aware_t2 = datetime(2026, 5, 1, 10, 20, 0, tzinfo=timezone.utc)  # 20 min later in UTC

    alerts = [
        NormalizedAlert(
            source_dataset="WinSys",
            source_file="evtx.json",
            event_type="Logon",
            original_record={"host": "FS01", "user": "bob"},
            timestamp=aware_t2,
        ),
        NormalizedAlert(
            source_dataset="WinSys",
            source_file="evtx.json",
            event_type="Process",
            original_record={"host": "FS01", "user": "bob"},
            timestamp=naive_t1,
        ),
    ]

    timelines = builder.build_timelines(alerts)
    # Sorted order should have naive_t1 first, then aware_t2
    assert len(timelines) == 1
    assert timelines[0].total_events == 2
    assert timelines[0].alerts[0].timestamp == naive_t1
    assert timelines[0].alerts[1].timestamp == aware_t2
    assert timelines[0].start_time == naive_t1
    assert timelines[0].end_time == aware_t2




