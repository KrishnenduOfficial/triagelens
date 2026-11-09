"""Explicit, offline dataset mapping isolated from observable event telemetry.

No files are read here. Callers supply trusted annotations and exact root-relative
folder/file label rules. ATT&CK names/IDs alone never establish binary truth.

Usage (only after reviewing the independent annotation):
    mapper = DatasetGroundTruthMapper(root, file_labels={"reviewed/sample.evtx": "malicious"})
    intake = AlertIntakeEngine(ground_truth_mapper=mapper)  # src.engine.intake
    batches = intake.ingest_directory(Path(root) / "reviewed")
Metadata is supplied as ``metadata={relative_path: GroundTruthAnnotation(...)}``.
There is no automatic dataset-wide labelling or metadata file reader.
"""

from pathlib import Path, PurePosixPath
import re
from typing import Literal, Mapping

from src.models.alert import GroundTruthAnnotation, GroundTruthMetadata, NormalizedAlert

Label = Literal["malicious", "benign"]
_TECHNIQUE = re.compile(r"(?<![a-z0-9])T[0-9]{4}(?:\.[0-9]{3})?(?![a-z0-9]|\.[0-9])", re.I)


def _relative_key(value: str) -> str:
    path = PurePosixPath(value.replace("\\", "/"))
    if not path.parts or path.is_absolute() or ".." in path.parts or ":" in str(path):
        raise ValueError("Mapping keys must be dataset-relative paths")
    return path.as_posix()


class DatasetGroundTruthMapper:
    """Apply operator-reviewed labels without reading dataset file contents.

    ``file_labels`` and ``metadata`` use exact root-relative file paths;
    ``folder_labels`` match complete root-relative ancestor paths. All matching
    sources must agree. Unmapped and conflicting binary labels remain unknown.
    The EVTX-ATTACK-SAMPLES README describes attack-associated files, not per-event
    binary truth: no folder or technique implies maliciousness by default.
    File/folder labels apply to every event in those files; the operator must
    independently verify that scope before configuring a binary label.
    """

    def __init__(
        self, root: str | Path, *, dataset_name: str = "EVTX-ATTACK-SAMPLES",
        folder_labels: Mapping[str, Label] | None = None,
        file_labels: Mapping[str, Label] | None = None,
        metadata: Mapping[str, GroundTruthAnnotation | dict] | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.dataset_name = dataset_name
        self.folder_labels = self._labels(folder_labels or {})
        self.file_labels = self._labels(file_labels or {})
        self.metadata = {
            _relative_key(key): GroundTruthAnnotation.model_validate(value).model_copy(deep=True)
            for key, value in (metadata or {}).items()
        }
        for annotation in self.metadata.values():
            if any(not re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", value, re.I)
                   for value in annotation.technique_ids):
                raise ValueError("Invalid dataset technique ID")

    @staticmethod
    def _labels(values: Mapping[str, Label]) -> dict[str, Label]:
        if any(label not in ("malicious", "benign") for label in values.values()):
            raise ValueError("Dataset labels must be malicious or benign")
        return {_relative_key(key): label for key, label in values.items()}

    def map_alert(self, alert: NormalizedAlert) -> NormalizedAlert:
        """Return a mapped alert; leave the input, telemetry and indicators intact."""
        try:
            relative = Path(alert.source_file).resolve().relative_to(self.root)
        except ValueError:
            raise ValueError("Alert source is outside the configured dataset root") from None
        key = relative.as_posix()
        sources: dict[str, Label] = {}
        for folder, label in self.folder_labels.items():
            if PurePosixPath(folder) in PurePosixPath(key).parents:
                sources[f"folder:{folder}"] = label
        if key in self.file_labels:
            sources[f"file:{key}"] = self.file_labels[key]
        annotation = self.metadata.get(key, GroundTruthAnnotation())
        if annotation.label is not None:
            sources[f"metadata:{key}"] = annotation.label
        if alert.ground_truth_label is not None:
            if alert.ground_truth_label not in ("malicious", "benign"):
                raise ValueError("Existing dataset label must be malicious or benign")
            sources["existing_label"] = alert.ground_truth_label
        labels = set(sources.values())
        status = "conflict" if len(labels) > 1 else "mapped" if labels else "unknown"
        techniques = {match.group().upper() for match in _TECHNIQUE.finditer(key)}
        techniques.update(value.upper() for value in annotation.technique_ids)
        truth = GroundTruthMetadata(
            relative_path=key, status=status, label_sources=sources,
            technique_ids=sorted(techniques),
            severity=annotation.severity if status != "conflict" else None,
        )
        return alert.model_copy(update={
            "source_dataset": self.dataset_name,
            "ground_truth_label": next(iter(labels)) if len(labels) == 1 else None,
            "ground_truth_metadata": truth,
        })
