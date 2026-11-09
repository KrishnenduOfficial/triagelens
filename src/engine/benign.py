"""Opt-in intake for independently reviewed benign Windows EVTX files.

Both local Windows exports and a public baseline use the same parser. A review
of a whole file is required: its label applies to every event in that file.
No data is downloaded and an unreviewed file is never labelled benign.

Example for each independently reviewed source root::

    adapter = BenignEvtxAdapter(root, source="local", reviewed_files={"export.evtx": True})
    for batch in adapter.ingest("export.evtx"):
        ...  # retain locally, or pass alerts to the shortcut audit

Use ``source="public"`` for a separately reviewed public baseline. Pass alerts
from both adapters and independently mapped attack alerts to
``src.engine.shortcut_check.check_shortcuts``; the audit consumes an iterable.
"""

from pathlib import Path
from typing import BinaryIO, Callable, Iterator, Literal, Mapping

from src.engine.evtx import EvtxIntakeEngine, RecordParser, _native_parser
from src.engine.ground_truth import DatasetGroundTruthMapper
from src.models.alert import NormalizedAlert


class BenignEvtxAdapter:
    """Stream explicitly reviewed files from one local or public source root."""

    def __init__(
        self, root: str | Path, *, source: Literal["local", "public"],
        reviewed_files: Mapping[str, bool],
        parser_factory: Callable[[BinaryIO], RecordParser] = _native_parser,
    ) -> None:
        if source not in ("local", "public"):
            raise ValueError("source must be local or public")
        if not reviewed_files or any(value is not True for value in reviewed_files.values()):
            raise ValueError("Each file must have an explicit whole-file benign review")
        self.root = Path(root).resolve()
        self.mapper = DatasetGroundTruthMapper(
            self.root, dataset_name=f"reviewed {source} Windows baseline",
            file_labels={key: "benign" for key in reviewed_files},
        )
        self.engine = EvtxIntakeEngine(parser_factory, ground_truth_mapper=self.mapper)

    def ingest(self, relative_path: str, batch_size: int = 100) -> Iterator[list[NormalizedAlert]]:
        """Yield normalized batches for one reviewed, root-relative EVTX file."""
        key = relative_path.replace("\\", "/")
        if key not in self.mapper.file_labels or Path(key).suffix.lower() != ".evtx":
            raise ValueError("File must be a reviewed EVTX path")
        path = (self.root / key).resolve()
        if not path.is_relative_to(self.root):
            raise ValueError("File must be inside the source root")
        yield from self.engine.ingest_evtx(path, batch_size=batch_size)
