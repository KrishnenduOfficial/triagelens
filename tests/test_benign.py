"""Offline tests for explicitly reviewed baseline intake."""

import pytest

from src.engine.benign import BenignEvtxAdapter
from test_evtx import Parser, record


@pytest.mark.parametrize("source", ["local", "public"])
def test_reviewed_sources_reuse_evtx_and_keep_truth_out_of_telemetry(tmp_path, source):
    path = tmp_path / "reviewed.evtx"
    path.touch()
    adapter = BenignEvtxAdapter(tmp_path, source=source, reviewed_files={path.name: True},
                                parser_factory=lambda stream: Parser([record(), record()]))
    batches = list(adapter.ingest(path.name, batch_size=1))
    assert [len(batch) for batch in batches] == [1, 1]
    alert = batches[0][0]
    assert alert.ground_truth_label == "benign"
    assert alert.ground_truth_metadata.status == "mapped"
    assert "benign" not in str(alert.original_record).lower()
    assert adapter.engine.stats.alerts_emitted == 2


@pytest.mark.parametrize("files", [{}, {"sample.evtx": False}, {"sample.evtx": 1}, {"../escape.evtx": True}])
def test_requires_explicit_safe_review(tmp_path, files):
    with pytest.raises(ValueError):
        BenignEvtxAdapter(tmp_path, source="local", reviewed_files=files)


def test_rejects_unreviewed_file_and_source(tmp_path):
    with pytest.raises(ValueError):
        BenignEvtxAdapter(tmp_path, source="other", reviewed_files={"file.evtx": True})
    adapter = BenignEvtxAdapter(tmp_path, source="public", reviewed_files={"file.evtx": True})
    with pytest.raises(ValueError):
        list(adapter.ingest("other.evtx"))
