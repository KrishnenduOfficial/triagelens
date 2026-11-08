"""Run lineage and acquisition origin; history metrics remain evaluation-row based."""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
import hashlib
import json
import logging
from typing import Callable, Optional

from src.models.triage import TriageVerdict

logger = logging.getLogger(__name__)
_ACQUISITION = ContextVar('triage_acquisition', default=None)


@dataclass(frozen=True)
class AcquisitionOutcome:
    verdict: Optional[TriageVerdict]
    origin: str = 'unknown'
    failure_category: Optional[str] = None


def note_acquisition(origin: str) -> None:
    """Called at actual cache-return/send boundaries, once per logical acquisition."""
    trace = _ACQUISITION.get()
    if trace is not None and trace['origin'] != origin:
        if trace['origin'] != 'unknown':
            raise ValueError('Acquisition origin conflict')
        trace['callback'](origin)  # storage failure prevents the send
        trace['origin'] = origin


def traced_acquisition(analyze: Callable, timeline, callback: Callable[[str], None]) -> AcquisitionOutcome:
    trace = {'origin':'unknown','callback':callback}
    token = _ACQUISITION.set(trace)
    try:
        try:
            verdict = analyze(timeline)
        except AcquisitionPersistenceError:
            raise
        except Exception:
            return AcquisitionOutcome(None, trace['origin'], 'engine_error')
        return AcquisitionOutcome(verdict, trace['origin'], None if verdict is not None else 'no_verdict')
    finally:
        _ACQUISITION.reset(token)


class AcquisitionPersistenceError(RuntimeError):
    """Fail acquisition rather than misclassifying failed provenance storage."""


def acquire_triage(engine, timeline, callback) -> AcquisitionOutcome:
    observed = None

    def persist_origin(origin):
        nonlocal observed
        try:
            callback(origin)
            observed = origin
        except Exception as exc:
            raise AcquisitionPersistenceError('Acquisition provenance could not be saved') from exc

    acquire = getattr(engine, 'acquire_timeline', None)
    if callable(acquire):
        result = acquire(timeline, on_acquisition=persist_origin)
        if not isinstance(result, AcquisitionOutcome):
            raise TypeError('Acquisition provider must return AcquisitionOutcome')
        if result.origin not in ('fresh','cache','unknown'):
            raise ValueError('Invalid acquisition origin')
        if observed is None and result.origin == 'unknown':
            persist_origin('unknown')
        elif observed != result.origin:
            raise ValueError('Provider must report acquisition origin before doing work')
        return result
    # Opaque providers may cache internally; never infer fresh origin from an ID.
    persist_origin('unknown')
    try:
        verdict = engine.analyze_timeline(timeline)
    except Exception:
        return AcquisitionOutcome(None, 'unknown', 'engine_error')
    return AcquisitionOutcome(verdict, 'unknown', None if verdict is not None else 'no_verdict')


def _fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('utf-8')).hexdigest()


class RunRecorder:
    def __init__(self, db, entrypoint):
        self.db = db
        self.run_id = db.create_evaluation_run(entrypoint)

    def observe(self, timeline, ordinal):
        return self.db.start_observation(self.run_id, ordinal, timeline.timeline_id)

    def acquire(self, engine, timeline, observation_id):
        return acquire_triage(engine, timeline,
                              lambda origin:self.db.mark_observation_acquisition(observation_id, origin))

    def complete(self, observation_id, result, timeline, tracker, verdict=None, failure_category=None):
        # Independent label/policy metadata stays exclusively in the evaluation layer.
        policies = []
        for alert in timeline.alerts:
            policy = asdict(tracker._get_config(alert.source_dataset))
            policy = {key:sorted(value) if isinstance(value,set) else value for key,value in policy.items()}
            if policy not in policies:
                policies.append(policy)
        context = _fingerprint({'version':1,'evaluator':'AccuracyTracker-v1',
                                'binary_label':result.ground_truth,'severity_label':result.severity_ground_truth,
                                'policies':sorted(policies,key=lambda policy:json.dumps(policy,sort_keys=True))})
        run = self.db.get_evaluation_run(self.run_id)
        snapshot = result.model_copy(update={'evaluation_context_hash':context,'quality_cohort_hash':run['quality_cohort_hash']})
        return self.db.finalize_observation(observation_id,snapshot,verdict=verdict,failure_category=failure_category)


@contextmanager
def evaluation_run(db, entrypoint):
    try:
        db.init_db()
        run = RunRecorder(db, entrypoint)
        try:
            yield run
            db.finish_evaluation_run(run.run_id)
        except BaseException:
            try:
                db.fail_evaluation_run(run.run_id)
            except Exception:
                logger.error('Run failure state could not be persisted; incomplete work remains unverified.')
            raise
    finally:
        db.close()
