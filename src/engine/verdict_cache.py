"""Versioned cache contracts and validated immutable verdict provenance."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
from typing import Optional

from src.models.triage import TriageVerdict

CACHE_FORMAT_VERSION = 1


def fingerprint(value) -> str:
    encoded = json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
    return hashlib.sha256(encoded.encode('utf-8')).hexdigest()


def utc_timestamp(value: str) -> float:
    instant = datetime.fromisoformat(value)
    if instant.tzinfo is None:
        raise ValueError('Cache dates must be timezone-aware')
    return instant.timestamp()


def utc_text(value: float) -> str:
    return datetime.fromtimestamp(value,timezone.utc).isoformat()


@dataclass(frozen=True)
class CacheContract:
    timeline_id: str
    evidence_hash: str
    inference_policy_hash: str
    allowed_models: tuple
    ttl_seconds: float

    @property
    def key(self):
        return fingerprint({'timeline':self.timeline_id,'evidence':self.evidence_hash,
                            'policy':self.inference_policy_hash})


@dataclass(frozen=True)
class CacheProvenance:
    evidence_hash: str
    inference_policy_hash: str
    generated_at: float
    expires_at: float
    verdict_hash: str
    version: int = CACHE_FORMAT_VERSION

    @classmethod
    def create(cls, contract, verdict, now):
        if not math.isfinite(now):
            raise ValueError('Cache clock must be finite')
        now = utc_timestamp(utc_text(now))
        return cls(contract.evidence_hash,contract.inference_policy_hash,now,
                   utc_timestamp(utc_text(now+contract.ttl_seconds)),fingerprint(verdict.model_dump(mode='json')))

    @classmethod
    def from_record(cls, row):
        return cls(row['evidence_hash'],row['inference_policy_hash'],
                   utc_timestamp(row['cache_generated_at']),utc_timestamp(row['cache_expires_at']),
                   row['cache_verdict_hash'],row['cache_provenance_version'])

    def as_record(self):
        return {'evidence_hash':self.evidence_hash,'inference_policy_hash':self.inference_policy_hash,
                'cache_generated_at':utc_text(self.generated_at),'cache_expires_at':utc_text(self.expires_at),
                'cache_verdict_hash':self.verdict_hash,'cache_provenance_version':self.version}


def validated_candidate(snapshot, provenance, contract, now) -> Optional[TriageVerdict]:
    """Reject unknown, expired, altered, incompatible, or malformed candidates."""
    try:
        if not isinstance(provenance,CacheProvenance) or type(provenance.version) is not int or provenance.version != CACHE_FORMAT_VERSION:
            return None
        if provenance.evidence_hash != contract.evidence_hash or provenance.inference_policy_hash != contract.inference_policy_hash:
            return None
        if not all(math.isfinite(value) for value in (now,provenance.generated_at,provenance.expires_at)):
            return None
        if provenance.generated_at>now or provenance.expires_at<=provenance.generated_at:
            return None
        if now>=min(provenance.expires_at,provenance.generated_at+contract.ttl_seconds):
            return None
        data = snapshot.model_dump(mode='json') if isinstance(snapshot,TriageVerdict) else dict(snapshot)
        if 'id' in data:
            data['verdict_id']=data['id']
            for name in ('reasoning','recommended_actions','missing_information','evidence_basis','evidence_context'):
                if data.get(name) is not None:
                    data[name]=json.loads(data[name])
        if 'verdict_id' not in data or 'timeline_id' not in data:
            return None
        verdict = TriageVerdict.model_validate(data)
        if str(verdict.timeline_id)!=contract.timeline_id or verdict.model_name not in contract.allowed_models:
            return None
        if fingerprint(verdict.model_dump(mode='json'))!=provenance.verdict_hash:
            return None
        return verdict
    except (ValueError,TypeError,KeyError,OverflowError):
        return None
