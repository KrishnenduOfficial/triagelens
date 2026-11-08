import React from "react";
import type { EvidenceBasis, EvidenceReference, TriageVerdict } from "../api/apiService";

const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const nonblank = (value: unknown): value is string => typeof value === "string" && value.trim().length > 0;
const refs = (value: unknown): value is EvidenceReference[] => Array.isArray(value) && value.every(ref =>
  object(ref) && nonblank(ref.evidence_id) && Array.isArray(ref.field_path) &&
  ref.field_path.length > 0 && ref.field_path.every(nonblank));

function basisShape(value: unknown): value is EvidenceBasis {
  if (!object(value) || !["malicious_support", "benign_support", "insufficient_evidence"].includes(String(value.kind)) ||
      !refs(value.decision_refs)) return false;
  for (const key of ["observations", "hypotheses"]) {
    const items = value[key];
    if (!Array.isArray(items) || !items.every(item => object(item) && nonblank(item.statement) && refs(item.refs))) return false;
  }
  return Array.isArray(value.gaps) && value.gaps.every(gap => object(gap) && nonblank(gap.category) &&
    nonblank(gap.description) && nonblank(gap.required_evidence) && typeof gap.blocks_disposition === "boolean");
}

function resolve(context: unknown, ref: EvidenceReference): { value: unknown } | null {
  if (!object(context) || !/^[EI][1-9][0-9]*$/.test(ref.evidence_id) ||
      !Object.hasOwn(context, ref.evidence_id) || ref.field_path[0] === "evidence_id") return null;
  let value: unknown = context[ref.evidence_id];
  if (!object(value) || value.evidence_id !== ref.evidence_id) return null;
  for (const token of ref.field_path) {
    if (object(value) && Object.hasOwn(value, token)) value = value[token];
    else if (Array.isArray(value) && /^(0|[1-9][0-9]*)$/.test(token) &&
      Number.isSafeInteger(Number(token)) && Number(token) < value.length) value = value[Number(token)];
    else return null;
  }
  return nonblank(value) || typeof value === "boolean" || typeof value === "number" && Number.isFinite(value) ? { value } : null;
}

/** Model qualifications, resolved only against the immutable sanitized snapshot. */
export const VerdictQualifications: React.FC<{ verdict: TriageVerdict }> = ({ verdict }) => {
  const gaps = verdict.missing_information;
  const validGaps = Array.isArray(gaps) && gaps.every(nonblank);
  const flag = verdict.missing_information_recorded;
  const malformed = (gaps != null && !validGaps) || (flag !== undefined && typeof flag !== "boolean") ||
    (flag === true && !validGaps) || (flag === false && validGaps && gaps.length > 0);
  const cite = (references: EvidenceReference[]) => <ul className="styled-list">
    {references.map((ref, index) => {
      const resolved = resolve(verdict.evidence_context, ref);
      return <li key={index}><code>{ref.evidence_id} / {ref.field_path.join(" / ")}</code>: {resolved
        ? <span>{JSON.stringify(resolved.value)}</span>
        : <span role="alert">Evidence reference unavailable or invalid in saved snapshot</span>}</li>;
    })}
  </ul>;
  const basis = verdict.evidence_basis;
  const basisValid = basisShape(basis);
  return <section className="verdict-block" aria-label="Assessment qualifications">
    <h4 className="block-title">Uncertainty and missing information</h4>
    <p>{["LOW", "MEDIUM", "HIGH"].includes(String(verdict.uncertainty_level))
      ? `Uncertainty: ${verdict.uncertainty_level}` : "Uncertainty not recorded"}</p>
    {malformed && <p role="alert">Data-quality warning: missing-information values or presence metadata are inconsistent.</p>}
    {validGaps && gaps.length > 0 ? <ul className="styled-list">{gaps.map((gap, index) => <li key={index}>{gap}</li>)}</ul>
      : validGaps && flag === true ? <p>No gaps reported by the model. This is not proof of completeness.</p>
        : <p>Missing-information assessment not recorded</p>}
    <h4 className="block-title">Evidence basis — model-authored analysis</h4>
    {!basisValid || verdict.evidence_contract_version !== "evidence-basis-v1" ?
      (basis == null && verdict.policy_version !== "triage-v2"
        ? <p>Evidence basis not recorded for this policy</p>
        : <p role="alert">Data-quality warning: evidence basis or contract version is missing or invalid.</p>)
      : <>
        <p>Declared basis: {basis.kind}</p>
        <p>References identify saved supplied values; they do not certify conclusions or action safety.</p>
        <h5>Decision references</h5>{cite(basis.decision_refs)}
        <h5>Observations</h5>
        {basis.observations.length === 0 && <p>No observations declared.</p>}
        {basis.observations.map((item, index) => <div key={index}><p>{item.statement}</p>{cite(item.refs)}</div>)}
        <h5>Hypotheses</h5>
        {basis.hypotheses.length === 0 && <p>No hypotheses declared.</p>}
        {basis.hypotheses.map((item, index) => <div key={index}><p>{item.statement}</p>{cite(item.refs)}</div>)}
        <h5>Structured gaps</h5>
        {basis.gaps.map((gap, index) => <div key={index}>
          <p>{gap.blocks_disposition ? "Blocking gap" : "Nonblocking gap"} ({gap.category}): {gap.description}</p>
          <p>Required evidence: {gap.required_evidence}</p>
        </div>)}
      </>}
  </section>;
};
