"""Serve an isolated, synthetic dashboard database for browser smoke tests."""
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
temporary = tempfile.TemporaryDirectory(prefix="triagelens-smoke-")
os.environ["DATABASE_PATH"] = str(Path(temporary.name) / "smoke.sqlite")
os.environ["ALLOWED_ORIGINS"] = "http://127.0.0.1:18742"

import uvicorn
from src.api.main import app
from src.engine.yara import Limits, Match, ScanResult
from src.models.alert import NormalizedAlert
from src.models.enrichment import EnrichmentResult
from src.models.timeline import ThreatTimeline
from src.models.triage import TriageVerdict

db = app.state.db
stamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
alert = NormalizedAlert(source_dataset="synthetic-smoke", source_file="fixture.evtx",
    event_type="ProcessCreate", timestamp=stamp,
    original_record={"hostname": "fixture-host", "CommandLine": "example process"})
timeline = ThreatTimeline(grouping_key="synthetic-incident", alerts=[alert], total_events=1)
db.insert_timeline(timeline)
db.insert_verdict(TriageVerdict(timeline_id=timeline.timeline_id, severity="HIGH",
    confidence_score=0.8, summary="Synthetic advisory verdict", reasoning=["Review the event"],
    recommended_actions=["Preserve evidence"], raw_llm_response="{}"))
db.insert_detection("synthetic-rule", "sigma", [alert.internal_id], stamp, ["T1082"])
match = Match(namespace="fixture", rule="synthetic_yara", source_digest="a" * 64,
    metadata={"id": "fixture", "license": "MIT"}, occurrences=[], technique_ids=["T1082"])
db.save_yara_scan(ScanResult("00000000-0000-4000-8000-000000000001", "match", "b" * 64, 8,
    stamp.isoformat(), stamp.isoformat(), "fixture", "1", "c" * 64, Limits(), (), (match,)))
db.insert_enrichment(EnrichmentResult(indicator="example.invalid", indicator_type="domain",
    provider="fixture-provider", is_malicious=False, raw_response={}, lookup_status="error"))

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=18741, log_level="warning")
