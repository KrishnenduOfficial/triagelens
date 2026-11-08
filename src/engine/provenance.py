"""Run lineage and acquisition origin; history metrics remain evaluation-row based."""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
import hashlib
import json
import logging
from typing import Callable, Optional

from src.models.triage import TriageVerdict
from src.engine.verdict_cache import CacheContract, CacheProvenance

logger = logging.getLogger(__name__)
_ACQUISITION = ContextVar('triage_acquisition', default=None)


@dataclass(frozen=True)
class AcquisitionOutcome:
    verdict: Optional[TriageVerdict]
    origin: str = 'unknown'
    failure_category: Optional[str] = None
    cache_provenance: Optional[CacheProvenance] = None
    cache_validation: str = 'unverified'
    cache_contract: Optional[CacheContract] = None


def acquisition_trace():
    return _ACQUISITION.get()


def note_cache_state(validation, contract, provenance=None):
    trace = _ACQUISITION.get()
    if trace is not None:
        trace.update(cache_validation=validation,cache_contract=contract,cache_provenance=provenance)


def note_acquisition(origin: str) -> None:
    """Called at actual cache-return/send boundaries, once per logical acquisition."""
    trace = _ACQUISITION.get()
    if trace is not None and trace['origin'] != origin:
        if trace['origin'] != 'unknown':
            raise ValueError('Acquisition origin conflict')
        trace['callback'](origin)  # storage failure prevents the send
        trace['origin'] = origin


def traced_acquisition(analyze: Callable, timeline, callback: Callable[[str], None], persistent_cache=None) -> AcquisitionOutcome:
    trace = {'origin':'unknown','callback':callback,'persistent_cache':persistent_cache,
             'cache_validation':'unverified','cache_contract':None,'cache_provenance':None}
    token = _ACQUISITION.set(trace)
    try:
        try:
            verdict = analyze(timeline)
        except AcquisitionPersistenceError:
            raise
        except Exception:
            return AcquisitionOutcome(None,trace['origin'],'engine_error',None,
                                      trace['cache_validation'],trace['cache_contract'])
        return AcquisitionOutcome(verdict,trace['origin'],None if verdict is not None else 'no_verdict',
                                  trace['cache_provenance'],trace['cache_validation'],trace['cache_contract'])
    finally:
        _ACQUISITION.reset(token)


class AcquisitionPersistenceError(RuntimeError):
    """Fail acquisition rather than misclassifying failed provenance storage."""


def acquire_triage(engine, timeline, callback, persistent_cache=None) -> AcquisitionOutcome:
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
        kwargs = {'on_acquisition':persist_origin}
        if getattr(engine,'supports_persistent_cache',False) is True:
            kwargs['persistent_cache']=persistent_cache
        result = acquire(timeline, **kwargs)
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
    def __init__(self, db, entrypoint, cohort_id=None):
        self.db = db
        self.run_id = (db.create_evaluation_run(entrypoint) if cohort_id is None else
                       db.create_evaluation_run(entrypoint, cohort_id=cohort_id))
        self._acquisitions = {}

    def observe(self, timeline, ordinal):
        return self.db.start_observation(self.run_id, ordinal, timeline.timeline_id)

    def acquire(self, engine, timeline, observation_id):
        def record(origin):
            trace = acquisition_trace() or {}
            self.db.mark_observation_acquisition(observation_id,origin,
                cache_validation=trace.get('cache_validation','unverified'),contract=trace.get('cache_contract'))
        outcome = acquire_triage(engine,timeline,record,persistent_cache=self.db)
        self._acquisitions[observation_id]=outcome
        return outcome

    def complete(self, observation_id, result, timeline, tracker, verdict=None, failure_category=None):
        # Independent label/policy metadata stays exclusively in the evaluation layer.
        policies = []
        for alert in timeline.alerts:
            policy = asdict(tracker._get_config(alert.source_dataset))
            policy = {key:sorted(value) if isinstance(value,set) else value for key,value in policy.items()}
            if policy not in policies:
                policies.append(policy)
        evaluator = ('AccuracyTracker-disposition-v1' if result.prediction_basis == 'explicit_disposition_v1'
                     else 'AccuracyTracker-v1')
        context = _fingerprint({'version':1,'evaluator':evaluator,
                                'binary_label':result.ground_truth,'severity_label':result.severity_ground_truth,
                                'policies':sorted(policies,key=lambda policy:json.dumps(policy,sort_keys=True))})
        run = self.db.get_evaluation_run(self.run_id)
        snapshot = result.model_copy(update={'evaluation_context_hash':context,'quality_cohort_hash':run['quality_cohort_hash']})
        acquisition = self._acquisitions.get(observation_id)
        return self.db.finalize_observation(observation_id,snapshot,verdict=verdict,failure_category=failure_category,
                                            cache_provenance=acquisition.cache_provenance if acquisition else None)


@contextmanager
def evaluation_run(db, entrypoint, cohort_id=None):
    try:
        db.init_db()
        run = RunRecorder(db, entrypoint, cohort_id=cohort_id)
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
