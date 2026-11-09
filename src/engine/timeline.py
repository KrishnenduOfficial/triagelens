"""Incident timeline builder and security event correlation engine.

Assumptions & Design Rules:
1. Naive Timestamps: Naive datetime objects from security logs are normalized
   and treated as UTC (timezone.utc) to guarantee timezone-safe chronological
   sorting and correlation across diverse log sources without comparison TypeErrors.
2. Correlation Confidence:
   - 'confirmed': Shared deterministic entity identifiers (host + user, host, user,
     or indicator).
   - 'potential': Heuristic or time-proximity fallback ('ungrouped' or coarse dataset partition).
3. Windowing & Capping:
   - Groups are split into distinct timeline sessions when the time gap between consecutive
     events exceeds a configurable threshold (default: 30 minutes).
   - Groups exceeding a maximum event cap (default: 100 events) are chunked to prevent
     oversized timelines and LLM prompt inflation.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple

from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.timeline import ThreatTimeline
from src.engine.fields import FIELD_MAPPINGS, resolve_field

logger = logging.getLogger(__name__)


class TimelineBuilder:
    """Correlates security alerts and enrichment records into chronological threat timelines."""

    DEFAULT_TIME_GAP_MINUTES: int = 30
    DEFAULT_MAX_EVENTS_PER_TIMELINE: int = 100

    @staticmethod
    def _alert_sort_key(alert: NormalizedAlert):
        """Constructs a deterministic sort key that safely handles None and mixed timezones."""
        ts = alert.timestamp
        if ts is None:
            # Place None timestamps at the end, deterministically sorted by internal_id
            return (1, datetime.max.replace(tzinfo=timezone.utc), str(alert.internal_id))

        # Normalize naive timestamps to UTC to avoid naive vs aware comparison TypeError
        if ts.tzinfo is None:
            norm_ts = ts.replace(tzinfo=timezone.utc)
        else:
            norm_ts = ts.astimezone(timezone.utc)

        return (0, norm_ts, str(alert.internal_id))

    def _extract_auto_grouping(self, alert: NormalizedAlert) -> Tuple[str, str, str]:
        """Extracts documented entity correlation info: (grouping_key, correlation_type, correlation_reason)."""
        host_value = resolve_field(alert.original_record, "device.hostname")
        user_value = resolve_field(alert.original_record, "user.name")
        host = host_value.strip() if isinstance(host_value, str) else None
        user = user_value.strip() if isinstance(user_value, str) else None

        if host and user:
            return (f"{host}:{user}", "confirmed", "shared_host_and_user")
        if host:
            return (f"host:{host}", "confirmed", "shared_host")
        if user:
            return (f"user:{user}", "confirmed", "shared_user")

        if alert.extracted_indicators:
            return (f"indicator:{alert.extracted_indicators[0]}", "confirmed", "shared_indicator")

        return ("ungrouped", "potential", "time_proximity_fallback")

    def _get_alert_grouping_key(self, alert: NormalizedAlert, group_by: str) -> str:
        """Extracts the correlation grouping key from an alert attribute or original record."""
        if group_by.lower() in FIELD_MAPPINGS:
            value = resolve_field(alert.original_record, group_by)
            return str(value).strip() if value is not None else "ungrouped"

        # 1. Direct attribute on NormalizedAlert
        if hasattr(alert, group_by):
            val = getattr(alert, group_by)
            if val is not None:
                s = str(val).strip()
                if s:
                    return s

        # 2. Key inside original_record dictionary
        if isinstance(alert.original_record, dict):
            if group_by in alert.original_record:
                val = alert.original_record[group_by]
                if val is not None:
                    s = str(val).strip()
                    if s:
                        return s

            # Case-insensitive lookup in original_record
            lower_target = group_by.lower()
            for k, v in alert.original_record.items():
                if str(k).lower() == lower_target and v is not None:
                    s = str(v).strip()
                    if s:
                        return s

        return "ungrouped"

    def _resolve_alert_grouping(
        self, alert: NormalizedAlert, group_by: str
    ) -> Tuple[str, str, str]:
        """Resolves (grouping_key, correlation_type, correlation_reason) based on group_by strategy."""
        if group_by == "auto":
            return self._extract_auto_grouping(alert)

        raw_key = self._get_alert_grouping_key(alert, group_by)
        if raw_key == "ungrouped":
            return ("ungrouped", "potential", "time_proximity_fallback")

        if group_by == "source_dataset":
            return (raw_key, "potential", "shared_dataset_provenance")

        return (raw_key, "confirmed", f"shared_{group_by}")

    def build_timelines(
        self,
        alerts: List[NormalizedAlert],
        enrichment_data: Optional[List[EnrichmentResult]] = None,
        group_by: str = "auto",
        time_gap_minutes: Optional[int] = DEFAULT_TIME_GAP_MINUTES,
        max_events_per_timeline: Optional[int] = DEFAULT_MAX_EVENTS_PER_TIMELINE,
    ) -> List[ThreatTimeline]:
        """Groups alerts by a key, applies time-windowing and event capping, and constructs ThreatTimeline objects.

        Args:
            alerts: List of NormalizedAlert instances to correlate.
            enrichment_data: Optional threat intelligence results to map to timelines.
            group_by: Correlation strategy: 'auto' (host+user correlation),
                or specific attribute/key (e.g. 'host', 'source_dataset').
            time_gap_minutes: Inactivity threshold in minutes to split sessions (default: 30).
            max_events_per_timeline: Maximum alerts allowed per timeline chunk (default: 100).

        Returns:
            A chronologically sorted list of ThreatTimeline instances.
        """
        if not alerts:
            return []

        logger.info(
            "Building timelines for %d alerts (strategy: '%s', time_gap: %s min, max_events: %s)",
            len(alerts),
            group_by,
            time_gap_minutes,
            max_events_per_timeline,
        )

        # 1. Group alerts by correlation key and capture metadata
        groups: Dict[str, List[NormalizedAlert]] = defaultdict(list)
        meta_by_group: Dict[str, Tuple[str, str]] = {}

        for alert in alerts:
            key, corr_type, corr_reason = self._resolve_alert_grouping(alert, group_by)
            groups[key].append(alert)
            if key not in meta_by_group:
                meta_by_group[key] = (corr_type, corr_reason)

        # 2. Build fast indicator-to-enrichment index for O(1) matching
        enrichment_index: Dict[str, List[EnrichmentResult]] = defaultdict(list)
        if enrichment_data:
            for item in enrichment_data:
                ind_key = item.indicator.strip().lower()
                enrichment_index[ind_key].append(item)

        timelines: List[ThreatTimeline] = []

        # Determine whether time-gap splitting and event capping apply
        # For legacy raw dataset partitions (group_by='source_dataset'), preserve unpartitioned behavior
        # unless caller explicitly requested non-default parameters
        is_legacy_dataset = (group_by == "source_dataset")
        active_gap = None if is_legacy_dataset else time_gap_minutes
        active_cap = None if is_legacy_dataset else max_events_per_timeline

        # 3. Process each group
        for group_key, group_alerts in groups.items():
            corr_type, corr_reason = meta_by_group.get(group_key, ("confirmed", "correlated"))

            # Sort chronologically ascending (None timestamps placed deterministically at the end)
            sorted_alerts = sorted(group_alerts, key=self._alert_sort_key)

            # Split by time gap if active
            time_windows: List[List[NormalizedAlert]] = []
            if active_gap is not None and active_gap > 0:
                max_delta = timedelta(minutes=active_gap)
                current_window: List[NormalizedAlert] = []
                last_norm_ts: Optional[datetime] = None

                for alert in sorted_alerts:
                    if alert.timestamp is None:
                        current_window.append(alert)
                        continue

                    norm_ts = (
                        alert.timestamp.replace(tzinfo=timezone.utc)
                        if alert.timestamp.tzinfo is None
                        else alert.timestamp.astimezone(timezone.utc)
                    )

                    if last_norm_ts is not None and (norm_ts - last_norm_ts) > max_delta:
                        if current_window:
                            time_windows.append(current_window)
                            current_window = []

                    current_window.append(alert)
                    last_norm_ts = norm_ts

                if current_window:
                    time_windows.append(current_window)
            else:
                time_windows = [sorted_alerts]

            # Split by event cap if active
            final_chunks: List[List[NormalizedAlert]] = []
            for window in time_windows:
                if active_cap is not None and active_cap > 0 and len(window) > active_cap:
                    for i in range(0, len(window), active_cap):
                        final_chunks.append(window[i : i + active_cap])
                else:
                    final_chunks.append(window)

            # Construct ThreatTimeline for each chunk
            for chunk in final_chunks:
                timed_alerts = [a.timestamp for a in chunk if a.timestamp is not None]
                start_time = timed_alerts[0] if timed_alerts else None
                end_time = timed_alerts[-1] if timed_alerts else None

                # Associate threat intelligence relevant to this chunk's alerts
                timeline_enrichments: List[EnrichmentResult] = []
                seen_enrichments = set()

                for alert in chunk:
                    for ind in alert.extracted_indicators:
                        ind_key = ind.strip().lower()
                        if ind_key in enrichment_index:
                            for enr in enrichment_index[ind_key]:
                                enr_id = (enr.provider, enr.indicator_type, enr.indicator)
                                if enr_id not in seen_enrichments:
                                    seen_enrichments.add(enr_id)
                                    timeline_enrichments.append(enr)

                timeline = ThreatTimeline(
                    grouping_key=group_key,
                    alerts=chunk,
                    enrichment_data=timeline_enrichments,
                    start_time=start_time,
                    end_time=end_time,
                    total_events=len(chunk),
                    correlation_type=corr_type,
                    correlation_reason=corr_reason,
                )
                timelines.append(timeline)

        # Deterministic chronological sort by start_time ascending, then by grouping_key
        def timeline_sort_key(t: ThreatTimeline):
            if t.start_time is None:
                return (1, datetime.max.replace(tzinfo=timezone.utc), t.grouping_key)
            norm_st = (
                t.start_time.replace(tzinfo=timezone.utc)
                if t.start_time.tzinfo is None
                else t.start_time.astimezone(timezone.utc)
            )
            return (0, norm_st, t.grouping_key)

        timelines.sort(key=timeline_sort_key)
        return timelines
