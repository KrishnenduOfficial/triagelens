"""Incident timeline builder and security event correlation engine."""

from collections import defaultdict
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.timeline import ThreatTimeline

logger = logging.getLogger(__name__)


class TimelineBuilder:
    """Correlates security alerts and enrichment records into chronological threat timelines."""

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

    def _get_alert_grouping_key(self, alert: NormalizedAlert, group_by: str) -> str:
        """Extracts the correlation grouping key from an alert attribute or original record."""
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

    def build_timelines(
        self,
        alerts: List[NormalizedAlert],
        enrichment_data: Optional[List[EnrichmentResult]] = None,
        group_by: str = "source_dataset",
    ) -> List[ThreatTimeline]:
        """Groups alerts by a key, sorts chronologically, and constructs ThreatTimeline objects.

        Args:
            alerts: List of NormalizedAlert instances to correlate.
            enrichment_data: Optional threat intelligence results to map to timelines.
            group_by: Attribute or original_record key to group by (default: 'source_dataset').

        Returns:
            A list of ThreatTimeline instances sorted by grouping key.
        """
        if not alerts:
            return []

        logger.info(
            "Building timelines for %d alerts (grouped by '%s')", len(alerts), group_by
        )

        # 1. Group alerts by correlation key
        groups: Dict[str, List[NormalizedAlert]] = defaultdict(list)
        for alert in alerts:
            key = self._get_alert_grouping_key(alert, group_by)
            groups[key].append(alert)

        # 2. Build fast indicator-to-enrichment index for O(1) matching
        enrichment_index: Dict[str, List[EnrichmentResult]] = defaultdict(list)
        if enrichment_data:
            for item in enrichment_data:
                ind_key = item.indicator.strip().lower()
                enrichment_index[ind_key].append(item)

        timelines: List[ThreatTimeline] = []

        # 3. Process each group independently
        for group_key, group_alerts in groups.items():
            # Sort chronologically ascending (None timestamps placed at the end)
            sorted_alerts = sorted(group_alerts, key=self._alert_sort_key)

            # Calculate accurate start_time and end_time
            timed_alerts = [a.timestamp for a in sorted_alerts if a.timestamp is not None]
            start_time = timed_alerts[0] if timed_alerts else None
            end_time = timed_alerts[-1] if timed_alerts else None

            # Associate threat intelligence relevant to this timeline
            timeline_enrichments: List[EnrichmentResult] = []
            seen_enrichments = set()

            for alert in sorted_alerts:
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
                alerts=sorted_alerts,
                enrichment_data=timeline_enrichments,
                start_time=start_time,
                end_time=end_time,
                total_events=len(sorted_alerts),
            )
            timelines.append(timeline)

        # Sort timelines deterministically by grouping key
        timelines.sort(key=lambda t: t.grouping_key)
        return timelines

