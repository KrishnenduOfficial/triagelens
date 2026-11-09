"""Offline descriptive audit of class-associated format artifacts.

Call ``check_shortcuts`` on independently mapped alerts from both classes, or
``check_source_shortcuts`` on source groups without assigning event labels.
Results contain aggregate counts only, never paths, field names or event values.
Perfect separation is a warning about the observed sample, not a proof about
the population. Failure to detect separation is not proof of its absence.
"""

from collections import Counter
from datetime import timezone
from pathlib import PureWindowsPath
import re
from typing import Iterable, Iterator

from src.models.alert import NormalizedAlert


def _variation(left: Counter, right: Counter) -> float:
    a, b = sum(left.values()), sum(right.values())
    return round(sum(abs(left[k] / a - right[k] / b) for k in left.keys() | right.keys()) / 2, 4)


def check_shortcuts(alerts: Iterable[NormalizedAlert]) -> dict:
    """Compare mapped benign/malicious events; omit unknown or conflicting truth."""
    def tagged() -> Iterator[tuple[str | None, NormalizedAlert]]:
        for alert in alerts:
            truth = alert.ground_truth_metadata
            label = alert.ground_truth_label
            yield (label if truth is not None and truth.status == "mapped" else None), alert

    return _check_tagged(tagged(), ("benign", "malicious"), "excluded_unmapped")


def check_source_shortcuts(baseline: Iterable[NormalizedAlert],
                           attack_associated: Iterable[NormalizedAlert]) -> dict:
    """Compare source groups only; this does not assign or verify event labels."""
    def tagged() -> Iterator[tuple[str, NormalizedAlert]]:
        for alert in baseline:
            yield "baseline", alert
        for alert in attack_associated:
            yield "attack_associated", alert

    return _check_tagged(tagged(), ("baseline", "attack_associated"), None)


def _check_tagged(alerts: Iterable[tuple[str | None, NormalizedAlert]],
                  labels: tuple[str, str], excluded_key: str | None) -> dict:
    groups = {label: {"count": 0, "channels": Counter(), "fields": Counter(),
                      "names": Counter(), "suffixes": Counter(), "tokens": Counter(),
                      "first_time": None, "last_time": None, "missing_time": 0}
              for label in labels}
    excluded = 0
    for label, alert in alerts:
        if label not in groups:
            excluded += 1
            continue
        group = groups[label]
        group["count"] += 1
        record = alert.original_record
        group["channels"][str(record.get("Channel") or "<missing>")] += 1
        fields = {key for key, value in record.items()
                  if key not in ("raw_xml", "Details") and value is not None}
        details = record.get("Details")
        if isinstance(details, dict):
            fields.update("Details." + str(key) for key, value in details.items() if value is not None)
        group["fields"].update(fields)
        name = PureWindowsPath(alert.source_file).name.casefold()
        group["names"][name] += 1
        group["suffixes"][PureWindowsPath(name).suffix] += 1
        group["tokens"].update(set(re.findall(r"[a-z]+|\d+", PureWindowsPath(name).stem)))
        stamp = alert.timestamp
        if stamp is None or stamp.utcoffset() is None:
            group["missing_time"] += 1
        else:
            stamp = stamp.astimezone(timezone.utc)
            group["first_time"] = min(group["first_time"], stamp) if group["first_time"] else stamp
            group["last_time"] = max(group["last_time"], stamp) if group["last_time"] else stamp

    counts = {label: group["count"] for label, group in groups.items()}
    result = {"counts": counts, "checks": {}}
    if excluded_key:
        result[excluded_key] = excluded
    if not all(counts.values()):
        result["status"] = "insufficient_classes"
        return result
    a, b = groups[labels[0]], groups[labels[1]]
    checks = result["checks"]
    for name, feature in (("channel", "channels"), ("filename", "names"), ("extension", "suffixes")):
        left, right = a[feature], b[feature]
        checks[name] = {"perfect_separation": not bool(left.keys() & right.keys()),
                        "total_variation": _variation(left, right)}
    for name, feature in (("field_presence", "fields"), ("filename_token", "tokens")):
        left, right = a[feature], b[feature]
        separating = sum((left[key] == a["count"] and right[key] == 0)
                         or (right[key] == b["count"] and left[key] == 0)
                         for key in left.keys() | right.keys())
        checks[name] = {"perfect_separation": separating > 0, "separating_features": separating}
    if a["missing_time"] or b["missing_time"]:
        checks["time_range"] = {"status": "incomplete", "missing": {
            labels[0]: a["missing_time"], labels[1]: b["missing_time"]}}
    else:
        checks["time_range"] = {"status": "checked", "perfect_separation":
            a["last_time"] < b["first_time"] or b["last_time"] < a["first_time"]}
    result["status"] = "checked"
    return result
