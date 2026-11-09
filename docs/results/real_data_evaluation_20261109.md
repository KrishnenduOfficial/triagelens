# Real-data evaluation status - 2026-11-09

**Status: partial.** No independently reviewed, labelled real-EVTX cohort has
been scored end to end. Real-data accuracy, confidence intervals, per-technique
performance and false-positive/false-negative analysis are not available. The
observations below are historical records summarized from [TASKS.md](../../TASKS.md),
not a new run; the underlying command output is not reproduced there.

## Real EVTX intake and source comparisons

- The recorded bounded public attack-dataset clone check selected three 68 KiB
  files from three tactic folders, capped at 200 events per file. It parsed
  1, 8 and 1 events, respectively, with no reported parser, normalization,
  timestamp or file errors. All 10 binary labels remained unknown; one event
  received a filename-derived technique annotation. No indicators were emitted,
  so this did not verify real-data enrichment dispatch or binary label accuracy.
  Intercepted prompts and logs and cache comparisons checked metadata isolation;
  these checks do not establish model accuracy.
- A separate recorded offline comparison sampled 200 public-baseline events from
  two files and 92 attack-associated events from three files, at most 100 events
  per file. Filename and time range completely separated these sampled source
  groups; channels overlapped, and no single tested field-presence or filename-token
  feature perfectly separated them. These groups are not independently verified
  event labels. The small, nonrepresentative sample cannot establish absence of
  shortcuts in a future cohort.

Public dataset origin and source categories alone do not establish whether each
event is malicious or benign. The selected mixed benign cohort also needs reviewed
local Windows logs. Small classes and correlated events can make estimates unstable;
no real-data class counts, Wilson intervals or model error rates are claimed here.

## Evaluation readiness and outstanding work

The [T1.4 status](../../TASKS.md) and [ADR-062](../../DECISIONS.md#adr-062-fixed-offline-first-evaluation-protocol)
describe an offline protocol with fixed source/duplicate-event grouping, persisted
split and freeze checks, repeated fresh inference and per-run metrics. Reviewed
real cohorts, an independently reviewed 14-event local prefix sample, a separately
approved live run and analyst review of every false positive and false negative
remain outstanding. The implementation uses precomputed or disabled enrichment;
end-to-end enrichment and latency are not established. Request estimates are not
enforced token caps. Development/test tuning discipline is procedural.

Once those prerequisites are met, report input and scored class balance, split
and grouping, run identities and repetitions, availability and abstentions,
confusion counts, Wilson 95% intervals with denominators, per-technique results,
latency scope and every FP/FN review. Avoid treating repeated observations as
independent cases or inferring labels from source names or predictions. Analysts
retain final authority.

## Synthetic results are separate

The earlier [six-case Groq check](groq_evaluation_report.md) used selected synthetic
cases: 6/6 binary matches, Wilson 95% interval 60.97%-100%, and severity agreement
1/6. The later [triage-v1 development check](triage_v1_live_check_20261108.md)
used a different synthetic sample: 4/5 labelled binary matches, Wilson interval
37.55%-96.38%, plus one unlabelled abstention. Both are small selected samples;
neither is a real-EVTX result or evidence of general performance. The current
`triage-v2` policy has not been evaluated on a reviewed real-data cohort.

No live requests or new data processing were performed for this report.
