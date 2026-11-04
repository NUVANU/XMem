import { createHash } from 'node:crypto';
import { validateEvidence, validateSnapshot, type Evidence, type Snapshot, type Applicability } from './contracts.js';

export const EVIDENCE_POLICY = 'declared-inputs-v1';
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map(key => `${JSON.stringify(key)}:${canonical(object[key])}`).join(',')}}`;
}
export function contentHash(value: unknown): string { return createHash('sha256').update(canonical(value)).digest('hex'); }

/** Configured collector capability, never populated from a caller's trusted boolean.
 * The adapter must resolve a separately observed record and verify its report bytes.
 * Local callers can implement adapters: this is not authentication against malicious code.
 */
export interface ExecutionProvenance {
  resolve(evidenceId: string): { evidence: Evidence; snapshot: Snapshot; artifact: Uint8Array } | undefined;
}
export interface EvidenceDecision {
  applicability: Applicability; reusable_pass: boolean; reason_codes: string[];
  evidence_id: string; target_snapshot_id: string; target_fingerprint: string;
  policy_version: string; result: Evidence['result'];
}
export function verifyEvidence(input: Evidence, targetInput: Snapshot, policy: string, provenance?: ExecutionProvenance): EvidenceDecision {
  const evidence = validateEvidence(input);
  const target = validateSnapshot(targetInput);
  const decide = (applicability: Applicability, ...reason_codes: string[]): EvidenceDecision => ({
    applicability, reusable_pass: applicability === 'EXACT' && evidence.result === 'PASS',
    reason_codes, evidence_id: evidence.evidence_id, target_snapshot_id: target.snapshot_id,
    target_fingerprint: contentHash(target), policy_version: policy, result: evidence.result,
  });
  if (policy !== EVIDENCE_POLICY) return decide('UNKNOWN', 'UNSUPPORTED_POLICY');
  if (!provenance) return decide('UNKNOWN', 'UNTRUSTED_SOURCE');
  try {
    const observed = provenance.resolve(evidence.evidence_id);
    if (!observed) return decide('UNKNOWN', 'SOURCE_MISSING');
    validateEvidence(observed.evidence); validateSnapshot(observed.snapshot);
    if (canonical(observed.evidence) !== canonical(evidence)) return decide('UNKNOWN', 'PROVENANCE_MISMATCH');
    if (evidence.source.kind !== 'executor') return decide('UNKNOWN', 'UNTRUSTED_SOURCE');
    if (!evidence.artifact_hash || createHash('sha256').update(observed.artifact).digest('hex') !== evidence.artifact_hash) return decide('UNKNOWN', 'ARTIFACT_CORRUPT');
    // V1 executor SourceRef identifies this raw report, not an unrelated collector document.
    if (evidence.source.content_hash !== evidence.artifact_hash) return decide('UNKNOWN', 'SOURCE_HASH_MISMATCH');
    const prior = observed.snapshot;
    if (prior.snapshot_id !== evidence.snapshot_id || prior.project_id !== evidence.project_id || prior.workspace_id !== evidence.workspace_id) return decide('UNKNOWN', 'PROVENANCE_MISMATCH');
    if (target.project_id !== evidence.project_id || target.workspace_id !== evidence.workspace_id) return decide('STALE', 'IDENTITY_CHANGED');
    if ([prior, target].some(s => s.manifest.completeness !== 'COMPLETE' || s.manifest.external_state !== 'CONTROLLED')) return decide('UNKNOWN', 'INPUT_INCOMPLETE');
    if (canonical(prior.manifest) !== canonical(target.manifest)) return decide('STALE', 'INPUT_CHANGED');
    return decide('EXACT', 'DECLARED_INPUTS_MATCH');
  } catch { return decide('UNKNOWN', 'SOURCE_UNAVAILABLE'); }
}
