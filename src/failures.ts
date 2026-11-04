import { canonical, EVIDENCE_POLICY, verifyEvidence, type ExecutionProvenance, type EvidenceDecision } from './evidence.js';
import { ContractError, validateEvidence, validateSnapshot, type Evidence, type Snapshot } from './contracts.js';

export type FailureMatchOutcome = 'EXACT_KNOWN_FAILURE' | 'POSSIBLY_RELATED' | 'CONDITION_CHANGED' | 'UNKNOWN';
export type RootCauseState = 'HYPOTHESIS' | 'ASSERTED' | 'CONFIRMED';

export interface FailedAction {
  action_id: string;
  observable_args: Record<string, JsonValue>;
}

export interface RootCauseHypothesis {
  statement: string;
  epistemic_state: RootCauseState;
}

/** Immutable record of a failed experiment. Root cause remains a hypothesis unless separately revised. */
export interface FailedAttempt {
  schema_version: '1';
  failed_attempt_id: string;
  project_id: string;
  workspace_id: string;
  action: FailedAction;
  condition_fingerprints: Record<string, string>;
  error_signature: string | null;
  failure_evidence: Evidence;
  root_cause: RootCauseHypothesis;
}

export interface FailureCheckRequest {
  project_id: string;
  workspace_id: string;
  action: FailedAction;
  condition_fingerprints: Record<string, string>;
  error_signature: string | null;
  target_snapshot: Snapshot;
}

export interface FailureMatchDecision {
  outcome: FailureMatchOutcome;
  failed_attempt_id: string;
  explanation: string;
  reason_codes: string[];
  evidence?: EvidenceDecision;
}

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

const ID = /^[^\s][\s\S]*$/;
const HASH = /^[a-f0-9]{64}$/;
const isPlainObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
function invalid(message: string): never { throw new ContractError('INVALID_INPUT', message); }
function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  if (Object.keys(value).length !== keys.length || keys.some(key => !(key in value))) invalid(`${label} has unknown or missing fields`);
}
function requireId(value: unknown, label: string): string { if (typeof value !== 'string' || !ID.test(value)) invalid(`${label} must be a non-empty string`); return value; }
function jsonValue(value: unknown, label: string): asserts value is JsonValue {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return;
  if (typeof value === 'number') { if (!Number.isFinite(value)) invalid(`${label} must contain finite JSON numbers`); return; }
  if (Array.isArray(value)) { value.forEach((item, index) => jsonValue(item, `${label}[${index}]`)); return; }
  if (isPlainObject(value)) { Object.entries(value).forEach(([key, item]) => { requireId(key, `${label} key`); jsonValue(item, `${label}.${key}`); }); return; }
  invalid(`${label} must be JSON-compatible`);
}
function validateAction(input: unknown): FailedAction {
  if (!isPlainObject(input)) invalid('action must be an object');
  exactKeys(input, ['action_id', 'observable_args'], 'action');
  const action_id = requireId(input.action_id, 'action.action_id');
  if (!isPlainObject(input.observable_args)) invalid('action.observable_args must be an object');
  Object.entries(input.observable_args).forEach(([key, value]) => { requireId(key, 'action.observable_args key'); jsonValue(value, `action.observable_args.${key}`); });
  return { action_id, observable_args: input.observable_args as Record<string, JsonValue> };
}
function validateConditions(input: unknown): Record<string, string> {
  if (!isPlainObject(input) || Object.keys(input).length === 0) invalid('condition_fingerprints must be a non-empty object');
  for (const [key, value] of Object.entries(input)) {
    requireId(key, 'condition fingerprint name');
    if (typeof value !== 'string' || !HASH.test(value)) invalid('condition fingerprints must be lowercase SHA-256 hashes');
  }
  return input as Record<string, string>;
}
function validateRootCause(input: unknown): RootCauseHypothesis {
  if (!isPlainObject(input)) invalid('root_cause must be an object');
  exactKeys(input, ['statement', 'epistemic_state'], 'root_cause');
  const statement = requireId(input.statement, 'root_cause.statement');
  if (input.epistemic_state !== 'HYPOTHESIS' && input.epistemic_state !== 'ASSERTED' && input.epistemic_state !== 'CONFIRMED') invalid('root_cause.epistemic_state is invalid');
  return { statement, epistemic_state: input.epistemic_state };
}

export function validateFailedAttempt(input: unknown): FailedAttempt {
  if (!isPlainObject(input)) invalid('failed attempt must be an object');
  exactKeys(input, ['schema_version', 'failed_attempt_id', 'project_id', 'workspace_id', 'action', 'condition_fingerprints', 'error_signature', 'failure_evidence', 'root_cause'], 'failed attempt');
  if (input.schema_version !== '1') throw new ContractError('UNSUPPORTED_VERSION', 'Failed attempt schema version is unsupported');
  const attempt: FailedAttempt = {
    schema_version: '1', failed_attempt_id: requireId(input.failed_attempt_id, 'failed_attempt_id'), project_id: requireId(input.project_id, 'project_id'), workspace_id: requireId(input.workspace_id, 'workspace_id'),
    action: validateAction(input.action), condition_fingerprints: validateConditions(input.condition_fingerprints), error_signature: input.error_signature === null ? null : requireId(input.error_signature, 'error_signature'),
    failure_evidence: validateEvidence(input.failure_evidence), root_cause: validateRootCause(input.root_cause),
  };
  if (attempt.failure_evidence.project_id !== attempt.project_id || attempt.failure_evidence.workspace_id !== attempt.workspace_id) invalid('failure evidence identity must match failed attempt');
  return attempt;
}

export function validateFailureCheckRequest(input: unknown): FailureCheckRequest {
  if (!isPlainObject(input)) invalid('failure check request must be an object');
  exactKeys(input, ['project_id', 'workspace_id', 'action', 'condition_fingerprints', 'error_signature', 'target_snapshot'], 'failure check request');
  const request: FailureCheckRequest = {
    project_id: requireId(input.project_id, 'project_id'), workspace_id: requireId(input.workspace_id, 'workspace_id'), action: validateAction(input.action),
    condition_fingerprints: validateConditions(input.condition_fingerprints), error_signature: input.error_signature === null ? null : requireId(input.error_signature, 'error_signature'), target_snapshot: validateSnapshot(input.target_snapshot),
  };
  if (request.target_snapshot.project_id !== request.project_id || request.target_snapshot.workspace_id !== request.workspace_id) invalid('target snapshot identity must match request');
  return request;
}

const same = (left: unknown, right: unknown): boolean => canonical(left) === canonical(right);
function decision(outcome: FailureMatchOutcome, attempt: FailedAttempt, explanation: string, reason_codes: string[], evidence?: EvidenceDecision): FailureMatchDecision {
  return { outcome, failed_attempt_id: attempt.failed_attempt_id, explanation, reason_codes, ...(evidence ? { evidence } : {}) };
}

/**
 * Determines whether one immutable failed attempt blocks a proposed action. This is offline
 * classification only; callers decide whether to pause, retry, or record an audited exception.
 */
export function matchFailedAttempt(attemptInput: unknown, requestInput: unknown, provenance?: ExecutionProvenance, policy = EVIDENCE_POLICY): FailureMatchDecision {
  const attempt = validateFailedAttempt(attemptInput);
  const request = validateFailureCheckRequest(requestInput);
  if (attempt.project_id !== request.project_id || attempt.workspace_id !== request.workspace_id) return decision('UNKNOWN', attempt, 'The failed attempt belongs to a different project or workspace.', ['IDENTITY_MISMATCH']);

  const sameAction = attempt.action.action_id === request.action.action_id && same(attempt.action.observable_args, request.action.observable_args);
  if (!sameAction) {
    const evidence = verifyEvidence(attempt.failure_evidence, request.target_snapshot, policy, provenance);
    if (evidence.applicability === 'UNKNOWN' || evidence.result !== 'FAIL') return decision('UNKNOWN', attempt, 'A related action cannot rely on missing, corrupt, or untrusted historical failure evidence.', ['FAIL_EVIDENCE_UNUSABLE', ...evidence.reason_codes], evidence);
    if (attempt.error_signature !== null && attempt.error_signature === request.error_signature) return decision('POSSIBLY_RELATED', attempt, 'Only the error signature matches; the observable action differs, so this cannot block execution.', ['ERROR_TEXT_ONLY']);
    return decision('POSSIBLY_RELATED', attempt, 'The failure is in the same project and workspace but describes a different observable action.', ['ACTION_DIFFERENT']);
  }
  const evidence = verifyEvidence(attempt.failure_evidence, request.target_snapshot, policy, provenance);
  if (evidence.applicability === 'UNKNOWN' || evidence.result !== 'FAIL') return decision('UNKNOWN', attempt, 'Historical failure evidence is unavailable or untrusted.', ['FAIL_EVIDENCE_UNUSABLE', ...evidence.reason_codes], evidence);
  if (!same(attempt.condition_fingerprints, request.condition_fingerprints)) return decision('CONDITION_CHANGED', attempt, 'The observable action matches, but its condition fingerprints changed; retain the prior record and re-evaluate.', ['CONDITION_FINGERPRINT_CHANGED'], evidence);
  if (evidence.applicability === 'STALE') return decision('CONDITION_CHANGED', attempt, 'The action conditions match, but the verified execution inputs changed; retain the prior record and re-evaluate.', ['EVIDENCE_INPUT_CHANGED', ...evidence.reason_codes], evidence);
  if (evidence.applicability !== 'EXACT' || evidence.result !== 'FAIL') return decision('UNKNOWN', attempt, 'A same-action record exists, but a trusted usable FAIL could not be established for these inputs.', ['FAIL_EVIDENCE_UNUSABLE', ...evidence.reason_codes], evidence);
  return decision('EXACT_KNOWN_FAILURE', attempt, 'The same observable action and condition fingerprints have a trusted, applicable FAIL record.', ['ACTION_AND_CONDITIONS_MATCH', ...evidence.reason_codes], evidence);
}
