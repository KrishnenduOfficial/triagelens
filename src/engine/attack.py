"""Offline ATT&CK 17.1 catalog, technique comparison and Navigator export.

Example: ``evaluate_techniques(['T1059.001'], ['T1059'])`` returns separate
exact, parent-family and tactic set comparisons. None means not recorded; an
empty list is a recorded empty set. Counts are set-level, not binary incident
classification metrics. A shared tactic is not evidence of a correct technique.

``rule_techniques`` extracts Sigma attack.tNNNN[.NNN] tags or YARA metadata
values; unrecognized IDs are returned as diagnostics. ``coverage_matrix`` and
``navigator_layer`` accept explicitly named sources and never merge their data.
For example, serialize a layer with ``json.dumps(navigator_layer('Sigma', ids))``;
pass ``rule_techniques('sigma', match.tags)[0]`` as ``technique_ids`` when
persisting a detection. Check the accompanying invalid-ID list before doing so.
The snapshot includes only active Enterprise techniques in v17.1, not revoked,
deprecated, Mobile or ICS techniques. Coverage is annotation coverage, not
measured detection effectiveness. No network access or semantic inference occurs.
"""

from functools import lru_cache
import json
from pathlib import Path
import re
from typing import Iterable, Mapping


_PATH = Path(__file__).resolve().parents[2] / 'data' / 'attack' / 'enterprise-17.1.json'
_ID = re.compile(r'^T\d{4}(?:\.\d{3})?$')


@lru_cache(maxsize=1)
def _catalog():
    payload = json.loads(_PATH.read_text(encoding='utf-8'))
    if payload['version'] != '17.1':
        raise ValueError('Unexpected ATT&CK catalog version')
    entries = {item['id']: item for item in payload['techniques']}
    if len(entries) != len(payload['techniques']):
        raise ValueError('Duplicate ATT&CK technique')
    for key, value in entries.items():
        if not _ID.fullmatch(key) or (value['parent'] and value['parent'] not in entries):
            raise ValueError('Invalid ATT&CK catalog')
    return entries


def validate_techniques(values: Iterable[str]) -> tuple[list[str], list[str]]:
    """Return deduplicated valid IDs and invalid values; never infer a replacement."""
    if isinstance(values, (str, bytes)):
        raise ValueError('Technique IDs must be a collection')
    valid, invalid = set(), set()
    for value in values:
        if not isinstance(value, str):
            raise ValueError('Technique ID must be text')
        normalized = value.strip().upper()
        (valid if normalized in _catalog() else invalid).add(normalized)
    return sorted(valid), sorted(invalid)


def rule_techniques(source: str, metadata: Iterable[str]) -> tuple[list[str], list[str]]:
    """Map Sigma tags or YARA ATT&CK metadata; unknown IDs remain diagnostics."""
    if source not in ('sigma', 'yara'):
        raise ValueError('Expected sigma or yara')
    if isinstance(metadata, (str, bytes)):
        raise ValueError('Rule metadata must be a collection')
    values = []
    for raw in metadata:
        if not isinstance(raw, str):
            raise ValueError('Rule metadata must be text')
        value = raw.strip()
        if source == 'sigma':
            if not re.fullmatch(r'attack\.t\d{4}(?:\.\d{3})?', value, re.I):
                continue  # Includes tactic and unrelated Sigma tags.
            value = value[7:]
        values.append(value)
    return validate_techniques(values)


def _checked(values):
    if values is None:
        return None
    valid, invalid = validate_techniques(values)
    if invalid:
        raise ValueError('Unknown ATT&CK technique IDs: ' + ', '.join(invalid))
    return set(valid)


def _score(truth, prediction):
    match = len(truth & prediction)
    return {'matched': match, 'truth': len(truth), 'predicted': len(prediction),
            'precision': match / len(prediction) if prediction else None,
            'recall': match / len(truth) if truth else None}


def evaluate_techniques(ground_truth, ai_predictions):
    """Compare independently recorded sets; missing input yields unavailable."""
    truth, pred = _checked(ground_truth), _checked(ai_predictions)
    if truth is None or pred is None:
        return {'status': 'unavailable', 'exact': None, 'parent': None, 'tactic': None}
    catalog = _catalog()
    parents = lambda ids: {catalog[i]['parent'] or i for i in ids}
    tactics = lambda ids: {t for i in ids for t in catalog[i]['tactics']}
    return {'status': 'scored', 'exact': _score(truth, pred),
            'parent': _score(parents(truth), parents(pred)),
            'tactic': _score(tactics(truth), tactics(pred))}


def evaluate_timeline(timeline, verdict):
    """Compare supplied dataset annotations with AI predictions for one timeline.

    Missing/empty dataset annotations do not establish a reviewed empty truth set.
    Unknown catalog IDs are reported and withhold scoring, rather than silently
    dropping labels. Explicit reviewed empty sets can use evaluate_techniques.
    """
    recorded = [alert.ground_truth_metadata for alert in timeline.alerts]
    ids = [ident for metadata in recorded if metadata for ident in metadata.technique_ids]
    valid, invalid = validate_techniques(ids)
    predictions = verdict.predicted_techniques if verdict is not None else None
    result = evaluate_techniques(valid if valid and not invalid else None, predictions)
    result['unknown_ground_truth_ids'] = invalid
    result['ground_truth_complete'] = bool(recorded) and all(
        metadata is not None and metadata.technique_ids for metadata in recorded)
    if not result['ground_truth_complete']:
        result.update(status='unavailable', exact=None, parent=None, tactic=None)
    return result


def summarize_comparisons(comparisons):
    """Micro-average set counts by level across scored, independent timelines."""
    comparisons = list(comparisons)
    scored = [item for item in comparisons if item['status'] == 'scored']
    levels = {}
    for level in ('exact', 'parent', 'tactic'):
        totals = {key: sum(item[level][key] for item in scored)
                  for key in ('matched', 'truth', 'predicted')}
        totals['precision'] = totals['matched'] / totals['predicted'] if totals['predicted'] else None
        totals['recall'] = totals['matched'] / totals['truth'] if totals['truth'] else None
        levels[level] = totals
    return {'total_timelines': len(comparisons), 'scored_timelines': len(scored),
            'unavailable_timelines': len(comparisons) - len(scored), **levels}


def coverage_matrix(sources: Mapping[str, Iterable[str] | None]):
    """Return tactic/technique rows with separate, nullable source membership."""
    checked = {name: _checked(ids) for name, ids in sources.items()}
    return [{'tactic': tactic, 'technique_id': item['id'], 'name': item['name'],
             'parent': item['parent'],
             'sources': {name: (item['id'] in ids if ids is not None else None)
                         for name, ids in checked.items()}}
            for item in _catalog().values() for tactic in item['tactics']]


def navigator_layer(source: str, ids: Iterable[str]):
    """Build a Navigator 4.5 layer for exactly one labelled source."""
    selected = _checked(ids)
    if selected is None:
        raise ValueError('Unavailable source cannot be exported as empty coverage')
    return {'name': f'TriageLens: {source}', 'domain': 'enterprise-attack',
            'description': 'Recorded technique annotations; not detection effectiveness.',
            'versions': {'attack': '17.1', 'navigator': '4.9.0', 'layer': '4.5'},
            'techniques': [{'techniqueID': ident, 'score': 1} for ident in sorted(selected)]}
