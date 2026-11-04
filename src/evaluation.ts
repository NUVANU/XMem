import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export type M9Status = 'PASS' | 'FAIL' | 'INCONCLUSIVE' | 'NOT_READY' | 'NOT_RUN';
export type Arm = 'CONTROL' | 'TREATMENT';
export type Stratum = 'A' | 'B' | 'C' | 'D';
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
const H = /^[a-f0-9]{64}$/;
const strata: Stratum[] = ['A', 'B', 'C', 'D'];
const target = { A: 16, B: 16, C: 16, D: 32 };
const categoriesA = ['STALE_PASS', 'UNKNOWN_PASS', 'DRIFT_PASS', 'TIMEOUT_PASS', 'REPLAY_PASS', 'BYPASS_PASS'];
const bad = (s: string): never => { throw Error(`M9 evaluation input invalid: ${s}`); };
const id = (v: unknown): v is string => typeof v === 'string' && v.trim().length > 0;
const hash = (v: unknown): v is string => typeof v === 'string' && H.test(v);
const bool = (v: unknown): v is boolean => typeof v === 'boolean';
const nonnegative = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v) && v >= 0;
const integer = (v: unknown): v is number => nonnegative(v) && Number.isSafeInteger(v);
const utc = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v) && Number.isFinite(Date.parse(v));

/** Undefined, nonfinite numbers and sparse arrays cannot alias committed JSON. */
export function canonical(v: unknown): string {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number' && Number.isFinite(v)) return JSON.stringify(v);
  if (Array.isArray(v)) {
    if (Object.keys(v).length !== v.length) bad('non-JSON array');
    return `[${v.map(canonical).join(',')}]`;
  }
  if (v && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype)
    return `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(',')}}`;
  return bad('non-JSON value');
}
export const canonicalHash = (v: unknown): string => createHash('sha256').update(canonical(v)).digest('hex');

export interface M9Manifest {
  run_id: string; m9i_accepted: boolean; d3_ready: boolean;
  candidate_pool_hash: string; m9i_version_hash: string; environment_hash: string; harness_hash: string;
  selection_hash: string; selection_record_hash: string; pairing_hash: string; baselines_hash: string;
  exclusions_hash: string; prerequisites_hash: string; analysis_plan_hash: string;
}
export interface M9Prerequisites {
  m9i: { accepted: boolean; version_hash: string; reviewer_id: string; tester_id: string; implementer_id: string; review_hash: string; test_hash: string };
  d3: { ready: boolean; environment_hash: string; resettable: boolean; independent_acceptance: boolean; fixed_models: boolean; usage_available: boolean; evidence_hash: string };
  versions: { m6: string; m7: string; m8: string; harness: string; adapter: string; test_definition: string; preregistration: string };
}
export interface M9Candidate {
  task_id: string; repository_id: string; stratum: Stratum; complexity: string; baseline_snapshot_hash: string;
  acceptance_hash: string; sensitivity: string; eligibility_reason: string; resettable: boolean; independent_acceptance: boolean;
}
export interface M9Baseline { task_id: string; snapshot: Json }
export interface M9Selection { task_id: string; assignment_id: string; stratum: Stratum; baseline_snapshot_hash: string; control_run_id: string; treatment_run_id: string }
export interface M9SelectionRecord {
  algorithm: 'SHA256_RANK_V1'; seed: string; allocator_id: string; frozen_at: string; assigned_at: string; ordered_task_ids: string[];
}
export interface M9Exclusion {
  task_id: string; reason: 'OUTSIDE_STRATUM' | 'NO_LEGAL_RESET' | 'NO_INDEPENDENT_ACCEPTANCE';
  occurred_at: string; responsible_role: string; evidence_hash: string;
}
export interface M9Run {
  task_id: string; run_id: string; arm: Arm; workspace_id: string; session_id: string; cache_id: string;
  baseline_snapshot_hash: string; reset_snapshot: Json; reset_receipt_hash: string; policy_hash: string;
}
export interface M9Pair { task_id: string; assignment_id: string; first_arm: Arm; control: M9Run; treatment: M9Run }
export interface M9ModelSpec { provider: string; model: string; version: string; immutable_version: true }
export interface M9AnalysisPlan {
  bootstrap: { method: 'PAIRED_STRATIFIED_PERCENTILE'; replicates: 10000; seed: number; rng: 'MULBERRY32'; quantile: 'LINEAR_N_MINUS_1' };
  c: { rubric_hash: string; item_ids: string[]; minimum_pairs: 16; relative_reduction: 0.3 };
  d: {
    minimum_pairs: 32; quality_method: 'NEWCOMBE_PAIRED_WILSON_CC_PHI'; quality_margin: -0.02;
    context_reduction: 0.2; cost_reduction: 0.2; control_model: M9ModelSpec; treatment_model: M9ModelSpec;
    adapter_hash: string; prompt_hash: string; tools_hash: string; policy_hash: string;
    temperature: number; top_p: number; model_seed: number | null; max_turns: number; timeout_ms: number;
    retry_limit: number; escalation_policy_hash: string; currency: string; price_hash: string;
  };
}
export interface M9Decision {
  decision_id: string; task_id: string; run_id: string; arm: Arm; result: 'ALLOW' | 'PAUSE' | 'BLOCK' | 'UNKNOWN'; reason_codes: string[]; input_commitment_hash: string;
  input: { task_id: string; run_id: string; arm: Arm; checkpoint: M9Checkpoint['checkpoint']; baseline_snapshot_hash: string; action_fingerprint: string; policy_hash: string };
}
export interface M9Checkpoint {
  task_id: string; run_id: string; arm: Arm; checkpoint: 'before_evidence_reuse' | 'before_known_failure_action';
  decision_id: string; permit_id: string | null; checked_receipt_id: string; action_fingerprint: string;
}
export interface M9Permit { permit_id: string; task_id: string; run_id: string; arm: Arm; decision_id: string; action_fingerprint: string }
export interface M9Receipt {
  receipt_id: string; task_id: string; run_id: string; arm: Arm; permit_id: string; decision_id: string;
  action_fingerprint: string; kind: 'CHECKED' | 'ACTION'; outcome: 'CHECKED' | 'EXECUTED' | 'BLOCKED' | 'PAUSED' | 'UNKNOWN';
}
export interface M9Action { task_id: string; run_id: string; arm: Arm; action_fingerprint: string; decision_id: string; permit_id: string | null; receipt_id: string | null; executed: boolean; exit_code: number | null }
export interface M9ModelCall {
  call_id: string; task_id: string; run_id: string; arm: Arm; provider: string; model: string | null; version: string | null;
  adapter_hash: string | null; prompt_hash: string | null; tools_hash: string | null; response_id: string | null; billing_ref: string | null; occurred_at: string;
  input_tokens: number | null; output_tokens: number | null; cached_tokens: number | null; reasoning_tokens: number | null;
  context: { initial_tokens: number | null; system_tokens: number | null; task_tokens: number | null; tool_tokens: number | null; retrieval_tokens: number | null };
  cost: number | null; currency: string | null; price_hash: string | null; escalated: boolean;
  stage: 'INITIAL' | 'RETRIEVAL' | 'RETRY' | 'ESCALATION'; temperature: number; top_p: number; seed: number | null;
}
export interface M9Cost {
  cost_id: string; task_id: string; run_id: string; arm: Arm; resource: 'EMBEDDING' | 'TOOLS' | 'TEST' | 'LOCAL_COMPUTE' | 'STORAGE' | 'HUMAN';
  amount: number | null; currency: string | null; price_hash: string | null; billing_ref: string | null;
}
export interface M9Outcome {
  task_id: string; run_id: string; stratum: Stratum; arm: Arm; category?: string;
  /** Independent assessment of correct primary A behavior: false is an observed error. */
  accepted: boolean | null; independent_accepted: boolean | null; upgraded_accepted: boolean | null;
  contamination: boolean; assignment_id: string; model_call_ids: string[];
  acceptance_hash: string | null; assessor_id: string | null; assessor_blinded: boolean; independent: boolean;
}
export interface M9RubricEndpoint {
  task_id: string; run_id: string; arm: Arm; rubric_hash: string; acceptance_hash: string;
  assessor_id: string; assessor_blinded: boolean; independent: boolean; unblinded: boolean;
  items: { item_id: string; wrong_next_step: boolean | null; constraint_violation: boolean | null; rework_count: number | null; missing_items: number | null }[];
  handoff_state: 'CURRENT' | 'STALE' | 'INCOMPLETE';
}
export interface LedgerRecord { id: string; occurred_at: string; previous_hash: string | null; payload_hash: string; chain_hash: string; payload: Json }
export interface M9Input {
  manifest: M9Manifest; prerequisites: M9Prerequisites; candidate_pool: M9Candidate[]; baselines: M9Baseline[];
  selection: M9Selection[]; selection_record: M9SelectionRecord; pairing: M9Pair[]; exclusions: M9Exclusion[];
  analysis_plan: M9AnalysisPlan; outcomes: M9Outcome[]; rubric_endpoints: M9RubricEndpoint[];
  decisions: M9Decision[]; checkpoints: M9Checkpoint[]; permits: M9Permit[]; receipts: M9Receipt[];
  actions: M9Action[]; model_calls: M9ModelCall[]; costs: M9Cost[]; ledger: LedgerRecord[];
}
export interface Interval { lower: number; upper: number }
export interface BootstrapEffect { estimate: number | null; interval_95: Interval | null; lower_95_one_sided: number | null }
export interface M9Report {
  interpretation: 'COMPUTED_NOT_ACCEPTED'; status: Record<Stratum, M9Status>;
  counts: Record<Stratum, { denominator: number; numerator: number }>;
  coverage: Record<Stratum, { selected: number; paired_outcomes: number; analyzed: number; incomplete: number; contaminated: number }>;
  intervals: { A: Interval | null; B: Interval | null };
  c: null | { pairs: number; control_errors: number; treatment_errors: number; rubric_items_per_arm: number; absolute_difference: BootstrapEffect; relative_reduction: BootstrapEffect; constraint_violations: Record<Arm, number>; rework: Record<Arm, number>; missing_items: Record<Arm, number>; stale_or_incomplete: number };
  d: null | {
    pairs: number; control_accepted: number; treatment_independent_accepted: number; escalated_tasks: number; upgraded_accepted: number;
    quality: { status: M9Status; difference: number | null; interval_95: Interval | null; lower_95_one_sided: number | null };
    context: { status: M9Status; control_total_tokens: number | null; treatment_total_tokens: number | null; mean_reduction: BootstrapEffect | null; median_reduction: BootstrapEffect | null };
    cost: { status: M9Status; control_total: number | null; treatment_total: number | null; control_per_accepted: number | null; treatment_per_accepted: number | null; reduction: BootstrapEffect | null };
  };
  limitations: string[]; ledger_hash: string; public_task_refs: Record<string, string>;
}

export function ledgerRecord(id: string, occurred_at: string, previous_hash: string | null, payload: Json): LedgerRecord {
  const payload_hash = canonicalHash(payload);
  return { id, occurred_at, previous_hash, payload_hash, chain_hash: canonicalHash({ id, occurred_at, previous_hash, payload_hash }), payload };
}
/** Expected bindings only; actual collector order must preserve checkpoint/action causality. */
export function m9Commitments(x: M9Input): [string, unknown][] {
  return [
    ['manifest', x.manifest], ['prerequisites', x.prerequisites], ['candidate_pool', x.candidate_pool], ['baselines', x.baselines],
    ['exclusions', x.exclusions], ['analysis_plan', x.analysis_plan], ['selection_record', x.selection_record], ['selection', x.selection], ['pairing', x.pairing],
    ...x.outcomes.map(v => ['outcome', v] as [string, unknown]), ...x.rubric_endpoints.map(v => ['rubric', v] as [string, unknown]),
    ...x.decisions.map(v => ['decision', v] as [string, unknown]), ...x.permits.map(v => ['permit', v] as [string, unknown]),
    ...x.checkpoints.map(v => ['checkpoint', v] as [string, unknown]), ...x.receipts.map(v => ['receipt', v] as [string, unknown]),
    ...x.actions.map(v => ['action', v] as [string, unknown]), ...x.model_calls.map(v => ['model_call', v] as [string, unknown]), ...x.costs.map(v => ['cost', v] as [string, unknown]),
  ];
}
function unique<T>(rows: T[], key: (r: T) => string, label: string): void {
  const keys = rows.map(key);
  if (keys.some(k => !id(k)) || new Set(keys).size !== keys.length) bad(`duplicate or invalid ${label}`);
}
const rowKey = (r: { task_id: string; arm: Arm }): string => canonical([r.task_id, r.arm]);
export function m9SelectionSeed(x: Pick<M9Input, 'manifest'>): string {
  const m = x.manifest;
  return createHash('sha256').update(`xmem-m9-20260906${m.candidate_pool_hash}${m.m9i_version_hash}${m.environment_hash}`).digest('hex');
}
export function m9SelectionOrder(pool: M9Candidate[], exclusions: M9Exclusion[], seed: string): string[] {
  const excluded = new Set(exclusions.map(e => e.task_id));
  return strata.flatMap(k => pool.filter(c => c.stratum === k && !excluded.has(c.task_id)).sort((a, b) => {
    const ah = canonicalHash([seed, k, a.task_id]), bh = canonicalHash([seed, k, b.task_id]);
    return ah < bh ? -1 : ah > bh ? 1 : a.task_id < b.task_id ? -1 : 1;
  }).slice(0, target[k]).map(c => c.task_id));
}
export function m9FirstArm(seed: string, stratum: Stratum, index: number): Arm {
  const offset = parseInt(canonicalHash([seed, stratum, 'order']).slice(0, 8), 16) % 2;
  return (index + offset) % 2 ? 'TREATMENT' : 'CONTROL';
}

function validatePlan(p: M9AnalysisPlan): void {
  if (!p || !p.bootstrap || !p.c || !p.d) bad('missing predeclared analysis');
  const b = p.bootstrap, d = p.d;
  if (b.method !== 'PAIRED_STRATIFIED_PERCENTILE' || b.replicates !== 10000 || b.rng !== 'MULBERRY32' || b.quantile !== 'LINEAR_N_MINUS_1' ||
      !integer(b.seed) || b.seed > 0xffffffff || p.c.minimum_pairs !== 16 || p.c.relative_reduction !== 0.3 ||
      !hash(p.c.rubric_hash) || !Array.isArray(p.c.item_ids) || !p.c.item_ids.length || !p.c.item_ids.every(id) ||
      new Set(p.c.item_ids).size !== p.c.item_ids.length || d.minimum_pairs !== 32 || d.quality_margin !== -0.02 ||
      d.quality_method !== 'NEWCOMBE_PAIRED_WILSON_CC_PHI' || d.context_reduction !== 0.2 || d.cost_reduction !== 0.2) bad('predeclared statistics');
  for (const model of [d.control_model, d.treatment_model])
    if (!model || ![model.provider, model.model, model.version].every(id) || model.immutable_version !== true) bad('fixed model specification');
  if (![d.adapter_hash, d.prompt_hash, d.tools_hash, d.policy_hash, d.escalation_policy_hash, d.price_hash].every(hash) ||
      !nonnegative(d.temperature) || !nonnegative(d.top_p) || d.top_p > 1 || (d.model_seed !== null && !integer(d.model_seed)) ||
      !integer(d.max_turns) || !d.max_turns || !integer(d.timeout_ms) || !d.timeout_ms || !integer(d.retry_limit) || !id(d.currency)) bad('frozen model policy');
}

function validateFrozen(x: M9Input): Map<string, number> {
  const m = x.manifest, p = x.prerequisites, sr = x.selection_record;
  validatePlan(x.analysis_plan);
  for (const [field, content] of [
    ['candidate_pool_hash', x.candidate_pool], ['selection_hash', x.selection], ['selection_record_hash', sr],
    ['pairing_hash', x.pairing], ['baselines_hash', x.baselines], ['exclusions_hash', x.exclusions],
    ['prerequisites_hash', p], ['analysis_plan_hash', x.analysis_plan],
  ] as const) if (!hash(m[field]) || m[field] !== canonicalHash(content)) bad(`frozen ${field}`);
  if (!id(m.run_id) || !hash(m.m9i_version_hash) || !hash(m.environment_hash) || !hash(m.harness_hash)) bad('manifest identity');
  if (!p || !p.m9i || !p.d3 || !p.versions ||
      p.m9i.version_hash !== m.m9i_version_hash || p.d3.environment_hash !== m.environment_hash || p.versions.harness !== m.harness_hash ||
      p.versions.adapter !== x.analysis_plan.d.adapter_hash ||
      canonical(Object.keys(p.versions).sort()) !== canonical(['m6', 'm7', 'm8', 'harness', 'adapter', 'test_definition', 'preregistration'].sort()) || !Object.values(p.versions).every(hash) ||
      ![p.m9i.review_hash, p.m9i.test_hash, p.d3.evidence_hash].every(hash) ||
      ![p.m9i.reviewer_id, p.m9i.tester_id, p.m9i.implementer_id].every(id) ||
      new Set([p.m9i.reviewer_id, p.m9i.tester_id, p.m9i.implementer_id]).size !== 3 ||
      ![p.d3.resettable, p.d3.independent_acceptance, p.d3.fixed_models, p.d3.usage_available].every(v => v === true)) bad('typed prerequisites');
  if (!sr || sr.algorithm !== 'SHA256_RANK_V1' || sr.seed !== m9SelectionSeed(x) || !id(sr.allocator_id) ||
      sr.allocator_id === p.m9i.implementer_id || !utc(sr.frozen_at) || !utc(sr.assigned_at) || sr.frozen_at >= sr.assigned_at) bad('selection declaration');
  unique(x.candidate_pool, c => c.task_id, 'candidate'); unique(x.baselines, b => b.task_id, 'baseline');
  unique(x.selection, s => s.task_id, 'selection'); unique(x.selection, s => s.assignment_id, 'assignment');
  unique(x.exclusions, e => e.task_id, 'exclusion'); unique(x.pairing, q => q.task_id, 'pair');
  for (const c of x.candidate_pool) {
    if (![c.task_id, c.repository_id, c.complexity, c.sensitivity, c.eligibility_reason].every(id) || !strata.includes(c.stratum) ||
        !hash(c.baseline_snapshot_hash) || !hash(c.acceptance_hash) || !bool(c.resettable) || !bool(c.independent_acceptance)) bad('candidate content');
    const baseline = x.baselines.find(b => b.task_id === c.task_id);
    if (!baseline || canonicalHash(baseline.snapshot) !== c.baseline_snapshot_hash) bad('baseline content');
  }
  if (x.baselines.length !== x.candidate_pool.length) bad('unrelated baseline');
  for (const e of x.exclusions) {
    const c = x.candidate_pool.find(v => v.task_id === e.task_id);
    if (!c || !['OUTSIDE_STRATUM', 'NO_LEGAL_RESET', 'NO_INDEPENDENT_ACCEPTANCE'].includes(e.reason) ||
        !utc(e.occurred_at) || e.occurred_at >= sr.assigned_at || !id(e.responsible_role) || !hash(e.evidence_hash) ||
        (e.reason === 'NO_LEGAL_RESET' && c.resettable) || (e.reason === 'NO_INDEPENDENT_ACCEPTANCE' && c.independent_acceptance)) bad('illegal or post-assignment exclusion');
  }
  const expected = m9SelectionOrder(x.candidate_pool, x.exclusions, sr.seed);
  if (canonical(expected) !== canonical(sr.ordered_task_ids) || canonical(expected) !== canonical(x.selection.map(s => s.task_id))) bad('seeded selection or substitution');
  if (x.pairing.length !== x.selection.length) bad('missing control/treatment pairing');
  const runs: M9Run[] = [];
  for (const s of x.selection) {
    const c = x.candidate_pool.find(v => v.task_id === s.task_id)!;
    const pair = x.pairing.find(q => q.task_id === s.task_id) ?? bad('missing control/treatment pairing');
    if (c.stratum !== s.stratum || c.baseline_snapshot_hash !== s.baseline_snapshot_hash || !c.resettable || !c.independent_acceptance ||
        !pair || pair.assignment_id !== s.assignment_id || !pair.control || !pair.treatment ||
        pair.first_arm !== m9FirstArm(sr.seed, s.stratum, x.selection.filter(v => v.stratum === s.stratum).indexOf(s))) bad('pair assignment');
    for (const arm of ['CONTROL', 'TREATMENT'] as const) {
      const run = arm === 'CONTROL' ? pair.control : pair.treatment;
      if (run.arm !== arm || run.task_id !== s.task_id || run.run_id !== (arm === 'CONTROL' ? s.control_run_id : s.treatment_run_id) ||
          ![run.run_id, run.workspace_id, run.session_id, run.cache_id].every(id) || !hash(run.reset_receipt_hash) || !hash(run.policy_hash) ||
          run.baseline_snapshot_hash !== s.baseline_snapshot_hash || canonicalHash(run.reset_snapshot) !== s.baseline_snapshot_hash) bad('run baseline substitution');
      runs.push(run);
    }
    if (pair.control.policy_hash !== pair.treatment.policy_hash || (s.stratum === 'D' && pair.control.policy_hash !== x.analysis_plan.d.policy_hash)) bad('paired policy drift');
  }
  for (const k of ['run_id', 'workspace_id', 'session_id', 'cache_id'] as const) unique(runs, r => r[k], `isolated ${k}`);
  if (!x.ledger.length) bad('missing ledger');
  unique(x.ledger, r => r.id, 'ledger ID');
  const expectedBindings = new Set(m9Commitments(x).map(([k, v]) => `${k}:${canonicalHash(v)}`));
  const positions = new Map<string, number>();
  let previous: string | null = null, lastTime = '', observed = false;
  const frozenKinds = new Set(['manifest', 'prerequisites', 'candidate_pool', 'baselines', 'exclusions', 'analysis_plan', 'selection_record', 'selection', 'pairing']);
  x.ledger.forEach((r, index) => {
    if (!utc(r.occurred_at) || r.occurred_at < lastTime || r.previous_hash !== previous || r.payload_hash !== canonicalHash(r.payload) ||
        r.chain_hash !== canonicalHash({ id: r.id, occurred_at: r.occurred_at, previous_hash: r.previous_hash, payload_hash: r.payload_hash })) bad('ledger chain');
    const payload = r.payload as { kind: string; entity_hash: string };
    if (!payload || !id(payload.kind) || !hash(payload.entity_hash)) bad('ledger binding');
    const key = `${payload.kind}:${payload.entity_hash}`;
    if (!expectedBindings.has(key) || positions.has(key)) bad('unrelated or repeated ledger record');
    if (frozenKinds.has(payload.kind)) {
      if (observed || r.occurred_at > sr.assigned_at ||
          (['candidate_pool', 'baselines', 'exclusions', 'analysis_plan', 'prerequisites'].includes(payload.kind) && r.occurred_at > sr.frozen_at)) bad('post-outcome or post-freeze design commitment');
    }
    else { observed = true; if (r.occurred_at < sr.assigned_at) bad('outcome before assignment'); }
    positions.set(key, index); previous = r.chain_hash; lastTime = r.occurred_at;
  });
  if (positions.size !== expectedBindings.size) bad('unbound record');
  const position = (kind: string, value: unknown): number => positions.get(`${kind}:${canonicalHash(value)}`)!;
  if (!(position('candidate_pool', x.candidate_pool) < position('selection_record', sr) &&
        position('analysis_plan', x.analysis_plan) < position('selection', x.selection) &&
        position('selection_record', sr) < position('selection', x.selection) && position('selection', x.selection) < position('pairing', x.pairing))) bad('design commitment order');
  return positions;
}

function validateRows(x: M9Input): void {
  unique(x.outcomes, rowKey, 'outcome'); unique(x.rubric_endpoints, rowKey, 'rubric');
  unique(x.decisions, r => r.decision_id, 'decision'); unique(x.permits, r => r.permit_id, 'permit');
  unique(x.receipts, r => r.receipt_id, 'receipt'); unique(x.model_calls, r => r.call_id, 'call');
  unique(x.model_calls, r => id(r.response_id) ? r.response_id : r.call_id, 'response'); unique(x.costs, r => r.cost_id, 'cost');
  unique(x.actions, r => canonical([r.task_id, r.arm, r.action_fingerprint]), 'action');
  unique(x.checkpoints, r => canonical([r.task_id, r.arm, r.checkpoint]), 'checkpoint');
  for (const r of [...x.outcomes, ...x.rubric_endpoints, ...x.decisions, ...x.checkpoints, ...x.permits, ...x.receipts, ...x.actions, ...x.model_calls, ...x.costs]) {
    const s = x.selection.find(v => v.task_id === r.task_id);
    if (!s || !['CONTROL', 'TREATMENT'].includes(r.arm) || r.run_id !== (r.arm === 'CONTROL' ? s.control_run_id : s.treatment_run_id)) bad('unrelated task/arm/run');
  }
  for (const s of x.selection) {
    const rows = x.outcomes.filter(o => o.task_id === s.task_id);
    if (rows.some(o => o.arm === 'TREATMENT') && !rows.some(o => o.arm === 'CONTROL')) bad('treatment-only outcomes');
    if (rows.some(o => o.stratum !== s.stratum || o.assignment_id !== s.assignment_id)) bad('outcome assignment substitution');
  }
  for (const o of x.outcomes) {
    if (!Array.isArray(o.model_call_ids) || o.model_call_ids.some(v => !id(v)) || new Set(o.model_call_ids).size !== o.model_call_ids.length) bad('call inventory');
    if (x.model_calls.filter(c => rowKey(c) === rowKey(o)).some(c => !o.model_call_ids.includes(c.call_id))) bad('unlisted model call');
  }
}

function trace(o: M9Outcome, x: M9Input, positions: Map<string, number>): M9Action | null {
  const pos = (kind: string, r: unknown): number => positions.get(`${kind}:${canonicalHash(r)}`) ?? -1;
  const same = (r: { task_id: string; run_id: string; arm: Arm }): boolean => rowKey(r) === rowKey(o) && r.run_id === o.run_id;
  const checks = x.checkpoints.filter(same);
  if (checks.length !== 2 || !checks.some(c => c.checkpoint === 'before_evidence_reuse') || !checks.some(c => c.checkpoint === 'before_known_failure_action')) return null;
  const matched: M9Action[] = [];
  for (const c of checks) {
    const d = x.decisions.find(v => v.decision_id === c.decision_id), p = x.permits.find(v => v.permit_id === c.permit_id);
    const checked = x.receipts.find(v => v.receipt_id === c.checked_receipt_id), actions = x.actions.filter(a => same(a) && a.decision_id === c.decision_id);
    const pair = x.pairing.find(v => v.task_id === o.task_id)!, run = o.arm === 'CONTROL' ? pair.control : pair.treatment;
    if (!d || !p || !checked || actions.length !== 1 || !hash(c.action_fingerprint) || !same(d) || !same(p) || !same(checked) ||
        !d.input || canonicalHash(d.input) !== d.input_commitment_hash || !same(d.input) || d.input.checkpoint !== c.checkpoint ||
        d.input.baseline_snapshot_hash !== run.baseline_snapshot_hash || d.input.policy_hash !== run.policy_hash || d.input.action_fingerprint !== c.action_fingerprint ||
        !hash(d.input_commitment_hash) || !['ALLOW', 'PAUSE', 'BLOCK', 'UNKNOWN'].includes(d.result) ||
        p.decision_id !== d.decision_id || p.action_fingerprint !== c.action_fingerprint || checked.kind !== 'CHECKED' || checked.outcome !== 'CHECKED' ||
        checked.decision_id !== d.decision_id || checked.permit_id !== p.permit_id || checked.action_fingerprint !== c.action_fingerprint) return null;
    const a = actions[0], receipt = x.receipts.find(r => r.receipt_id === a.receipt_id);
    if (!receipt || !same(receipt) || receipt.kind !== 'ACTION' || receipt.decision_id !== d.decision_id ||
        a.permit_id !== p.permit_id || receipt.permit_id !== p.permit_id || a.action_fingerprint !== c.action_fingerprint ||
        receipt.action_fingerprint !== c.action_fingerprint || !bool(a.executed) ||
        (a.executed ? receipt.outcome !== 'EXECUTED' || !Number.isInteger(a.exit_code) : a.exit_code !== null || !['BLOCKED', 'PAUSED'].includes(receipt.outcome)) ||
        !(pos('decision', d) < pos('permit', p) && pos('permit', p) < pos('checkpoint', c) &&
          pos('checkpoint', c) < pos('receipt', checked) && pos('receipt', checked) < pos('action', a) && pos('action', a) < pos('receipt', receipt))) return null;
    matched.push(a);
  }
  if (x.actions.filter(same).length !== matched.length || x.permits.filter(same).length !== 2 || x.decisions.filter(same).length !== 2 || x.receipts.filter(same).length !== 4) return null;
  return matched[checks.findIndex(c => c.checkpoint === (o.stratum === 'A' ? 'before_evidence_reuse' : 'before_known_failure_action'))];
}

const mean = (a: number[]): number => a.reduce((s, v) => s + v, 0) / a.length;
const median = (a: number[]): number => { const b = [...a].sort((x, y) => x - y); return (b[Math.floor((b.length - 1) / 2)] + b[Math.floor(b.length / 2)]) / 2; };
const reduction = (control: number, treatment: number): number | null => control > 0 ? (control - treatment) / control : null;
const quantile = (a: number[], p: number): number => { const at = (a.length - 1) * p, lo = Math.floor(at); return a[lo] + (a[Math.ceil(at)] - a[lo]) * (at - lo); };
function rng(seed: number): () => number {
  return () => { let t = seed = (seed + 0x6d2b79f5) >>> 0; t = Math.imul(t ^ t >>> 15, t | 1); t ^= t + Math.imul(t ^ t >>> 7, t | 61); return ((t ^ t >>> 14) >>> 0) / 4294967296; };
}
function bootstrap<T extends { complexity: string }>(rows: T[], plan: M9AnalysisPlan, statistic: (sample: T[]) => number | null): BootstrapEffect {
  const estimate = statistic(rows), values: number[] = [], random = rng(plan.bootstrap.seed);
  const groups = [...new Set(rows.map(r => r.complexity))].sort().map(k => rows.filter(r => r.complexity === k));
  for (let i = 0; i < plan.bootstrap.replicates; i++) {
    const sample = groups.flatMap(g => g.map(() => g[Math.floor(random() * g.length)])), value = statistic(sample);
    if (value === null || !Number.isFinite(value)) return { estimate, interval_95: null, lower_95_one_sided: null };
    values.push(value);
  }
  values.sort((a, b) => a - b);
  return { estimate, interval_95: { lower: quantile(values, 0.025), upper: quantile(values, 0.975) }, lower_95_one_sided: quantile(values, 0.05) };
}
/** Exact binomial tails inverted by bisection; evaluation samples have at most 16 actions. */
export function clopperPearson(errors: number, n: number): Interval | null {
  if (!integer(n) || !integer(errors) || errors > n) bad('binomial counts');
  if (!n) return null;
  const cdf = (k: number, p: number): number => {
    if (p === 0) return 1; if (p === 1) return k >= n ? 1 : 0;
    let term = Math.pow(1 - p, n), sum = term;
    for (let i = 1; i <= k; i++) { term *= (n - i + 1) / i * p / (1 - p); sum += term; }
    return sum;
  };
  const invert = (k: number, probability: number): number => { let lo = 0, hi = 1; for (let j = 0; j < 80; j++) { const mid = (lo + hi) / 2; if (cdf(k, mid) > probability) lo = mid; else hi = mid; } return (lo + hi) / 2; };
  return { lower: errors === 0 ? 0 : invert(errors - 1, 0.975), upper: errors === n ? 1 : invert(errors, 0.025) };
}
/** Newcombe (1998), paired method 10: Wilson scores, continuity correction of positive phi.
 * https://www.eiti.uottawa.ca/~nat/Courses/csi5388/Newcombe.1998.pdf (section 5, method 10).
 */
export function pairedNewcombe(pairs: { control: boolean; treatment: boolean }[], z = 1.959963984540054): Interval {
  const n = pairs.length;
  if (!n || pairs.some(p => !bool(p.control) || !bool(p.treatment)) || !nonnegative(z) || !z) bad('paired statistics');
  const e = pairs.filter(p => p.control && p.treatment).length, f = pairs.filter(p => !p.control && p.treatment).length;
  const g = pairs.filter(p => p.control && !p.treatment).length, h = n - e - f - g, t = (e + f) / n, c = (e + g) / n;
  const wilson = (p: number): Interval => {
    const z2 = z * z, center = (p + z2 / (2 * n)) / (1 + z2 / n), delta = z * Math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / (1 + z2 / n);
    return { lower: Math.max(0, center - delta), upper: Math.min(1, center + delta) };
  };
  const tw = wilson(t), cw = wilson(c), denom = Math.sqrt((e + f) * (g + h) * (e + g) * (f + h));
  const numerator = e * h > f * g ? Math.max(e * h - f * g - n / 2, 0) : e * h - f * g, phi = denom === 0 ? 0 : numerator / denom;
  const dl = t - tw.lower, du = cw.upper - c, ul = tw.upper - t, ud = c - cw.lower;
  return { lower: Math.max(-1, t - c - Math.sqrt(Math.max(0, dl * dl + du * du - 2 * phi * dl * du))), upper: Math.min(1, t - c + Math.sqrt(Math.max(0, ul * ul + ud * ud - 2 * phi * ul * ud))) };
}

function blank(x: M9Input, ready: boolean): M9Report {
  return {
    interpretation: 'COMPUTED_NOT_ACCEPTED', status: { A: ready ? 'INCONCLUSIVE' : 'NOT_READY', B: ready ? 'INCONCLUSIVE' : 'NOT_READY', C: ready ? 'INCONCLUSIVE' : 'NOT_READY', D: ready ? 'INCONCLUSIVE' : 'NOT_READY' },
    counts: { A: { denominator: 0, numerator: 0 }, B: { denominator: 0, numerator: 0 }, C: { denominator: 0, numerator: 0 }, D: { denominator: 0, numerator: 0 } },
    coverage: Object.fromEntries(strata.map(k => [k, { selected: 0, paired_outcomes: 0, analyzed: 0, incomplete: 0, contaminated: 0 }])) as M9Report['coverage'],
    intervals: { A: null, B: null }, c: null, d: null,
    limitations: ready ? [] : ['typed M9I/D3 prerequisites absent or not ready'], ledger_hash: canonicalHash(x.ledger ?? []), public_task_refs: {},
  };
}
const acceptedEvidence = (o: M9Outcome, candidate: M9Candidate, implementer: string): boolean =>
  o.acceptance_hash === candidate.acceptance_hash && id(o.assessor_id) && o.assessor_id !== implementer && o.assessor_blinded === true && o.independent === true;

export function evaluateM9(x: M9Input): M9Report {
  const ready = x.manifest?.m9i_accepted === true && x.manifest?.d3_ready === true && x.prerequisites?.m9i?.accepted === true && x.prerequisites?.d3?.ready === true;
  const r = blank(x, ready);
  if (!ready) return r;
  const positions = validateFrozen(x); validateRows(x);
  r.public_task_refs = Object.fromEntries(x.selection.map(s => [`task-${canonicalHash(s.task_id).slice(0, 12)}`, canonicalHash(s.task_id)]));
  for (const k of strata) {
    const selected = x.selection.filter(s => s.stratum === k), cov = r.coverage[k];
    cov.selected = selected.length;
    cov.paired_outcomes = selected.filter(s => x.outcomes.filter(o => o.task_id === s.task_id).length === 2).length;
    cov.contaminated = selected.filter(s => x.outcomes.some(o => o.task_id === s.task_id && o.contamination !== false)).length;
    if (selected.length < target[k]) r.limitations.push(`${k}: selected ${selected.length}/${target[k]}; frozen sample incomplete`);
    if (cov.paired_outcomes !== selected.length) r.limitations.push(`${k}: ${selected.length - cov.paired_outcomes} selected pairs lack outcomes`);
    if (cov.contaminated) r.limitations.push(`${k}: ${cov.contaminated} contaminated or unknown-contamination pairs retained`);
    const excluded = x.exclusions.filter(e => x.candidate_pool.find(c => c.task_id === e.task_id)?.stratum === k).length;
    if (excluded) r.limitations.push(`${k}: ${excluded} pre-assignment exclusions retained in frozen input`);
  }
  for (const k of ['A', 'B'] as const) {
    const checked: { outcome: M9Outcome; action: M9Action }[] = [];
    for (const o of x.outcomes.filter(o => o.stratum === k && o.arm === 'TREATMENT')) { const action = trace(o, x, positions); if (action) checked.push({ outcome: o, action }); }
    const primary = checked.filter(v => k === 'A' || v.outcome.category === 'EXACT_KNOWN_FAILURE');
    // Missing observations cannot erase an observed primary safety error.
    const errors = primary.filter(v => k === 'A' ? v.outcome.accepted === false : v.action.executed).length;
    r.counts[k] = { denominator: primary.length, numerator: errors }; r.intervals[k] = clopperPearson(errors, primary.length);
    const cov = r.coverage[k]; cov.analyzed = checked.length; cov.incomplete = cov.selected - cov.analyzed;
    const unknown = checked.filter(v => {
      const candidate = x.candidate_pool.find(c => c.task_id === v.outcome.task_id)!, control = x.outcomes.find(o => o.task_id === v.outcome.task_id && o.arm === 'CONTROL');
      return !bool(v.outcome.accepted) || !acceptedEvidence(v.outcome, candidate, x.prerequisites.m9i.implementer_id) ||
        !control || !bool(control.accepted) || !acceptedEvidence(control, candidate, x.prerequisites.m9i.implementer_id);
    }).length;
    const missingCategories = k === 'A' ? categoriesA.filter(c => !checked.some(v => v.outcome.category === c)) : [];
    if (cov.incomplete) r.limitations.push(`${k}: ${cov.incomplete} selected treatment actions lack a complete guard trace`);
    if (unknown) r.limitations.push(`${k}: ${unknown} checked actions lack typed independent primary acceptance`);
    if (primary.length < 12) r.limitations.push(`${k}: only ${primary.length}/12 primary checked actions`);
    if (missingCategories.length) r.limitations.push(`A: missing ${missingCategories.length} required scenario categories`);
    const complete = cov.selected === target[k] && cov.paired_outcomes === cov.selected && !cov.contaminated && !cov.incomplete && !unknown && primary.length >= 12 && !missingCategories.length;
    r.status[k] = errors ? 'FAIL' : complete ? 'PASS' : 'INCONCLUSIVE';
    if (errors) r.limitations.push(`${k}: ${errors} observed primary errors`);
  }
  evaluateC(x, r); evaluateD(x, r);
  return r;
}

function evaluateC(x: M9Input, r: M9Report): void {
  const selected = x.selection.filter(s => s.stratum === 'C'), cov = r.coverage.C;
  type Row = { complexity: string; control: number; treatment: number; ce: M9RubricEndpoint; te: M9RubricEndpoint };
  const rows: Row[] = [];
  for (const s of selected) {
    const candidate = x.candidate_pool.find(c => c.task_id === s.task_id)!;
    const outcomes = x.outcomes.filter(o => o.task_id === s.task_id), endpoints = x.rubric_endpoints.filter(e => e.task_id === s.task_id);
    const valid = endpoints.length === 2 && outcomes.length === 2 && outcomes.every(o => o.contamination === false && acceptedEvidence(o, candidate, x.prerequisites.m9i.implementer_id)) && endpoints.every(e =>
      e.rubric_hash === x.analysis_plan.c.rubric_hash && e.acceptance_hash === candidate.acceptance_hash &&
      id(e.assessor_id) && e.assessor_id !== x.prerequisites.m9i.implementer_id && e.assessor_blinded === true && e.independent === true && e.unblinded === true &&
      ['CURRENT', 'STALE', 'INCOMPLETE'].includes(e.handoff_state) && Array.isArray(e.items) &&
      canonical(e.items.map(i => i.item_id).sort()) === canonical([...x.analysis_plan.c.item_ids].sort()) &&
      e.items.every(i => bool(i.wrong_next_step) && bool(i.constraint_violation) && integer(i.rework_count) && integer(i.missing_items)));
    if (!valid) continue;
    const ce = endpoints.find(e => e.arm === 'CONTROL')!, te = endpoints.find(e => e.arm === 'TREATMENT')!;
    rows.push({ complexity: candidate.complexity, control: ce.items.filter(i => i.wrong_next_step).length, treatment: te.items.filter(i => i.wrong_next_step).length, ce, te });
  }
  cov.analyzed = rows.length; cov.incomplete = cov.selected - rows.length;
  const cErrors = rows.reduce((n, q) => n + q.control, 0), tErrors = rows.reduce((n, q) => n + q.treatment, 0);
  r.counts.C = { denominator: rows.length * x.analysis_plan.c.item_ids.length, numerator: tErrors };
  if (cov.incomplete) r.limitations.push(`C: ${cov.incomplete} pairs lack complete unblinded independent rubric endpoints`);
  if (rows.length !== target.C || cov.contaminated || cov.paired_outcomes !== cov.selected) return;
  const absolute = bootstrap(rows, x.analysis_plan, a => mean(a.map(v => (v.control - v.treatment) / x.analysis_plan.c.item_ids.length)));
  const relative = cErrors === 0 ? { estimate: null, interval_95: null, lower_95_one_sided: null } : bootstrap(rows, x.analysis_plan, a => reduction(mean(a.map(v => v.control)), mean(a.map(v => v.treatment))));
  const totals = (field: 'constraint_violation' | 'rework_count' | 'missing_items'): Record<Arm, number> => ({
    CONTROL: rows.reduce((n, v) => n + v.ce.items.reduce((sum, i) => sum + Number(i[field]), 0), 0),
    TREATMENT: rows.reduce((n, v) => n + v.te.items.reduce((sum, i) => sum + Number(i[field]), 0), 0),
  });
  r.c = { pairs: rows.length, control_errors: cErrors, treatment_errors: tErrors, rubric_items_per_arm: r.counts.C.denominator,
    absolute_difference: absolute, relative_reduction: relative, constraint_violations: totals('constraint_violation'), rework: totals('rework_count'), missing_items: totals('missing_items'),
    stale_or_incomplete: rows.reduce((n, v) => n + Number(v.ce.handoff_state !== 'CURRENT') + Number(v.te.handoff_state !== 'CURRENT'), 0) };
  if (cErrors === 0) { r.status.C = 'FAIL'; r.limitations.push('C: control has zero errors; only absolute difference is defined, relative improvement cannot pass'); }
  else if (relative.lower_95_one_sided === null) r.limitations.push('C: relative bootstrap interval undefined in a zero-control resample');
  else { r.status.C = relative.estimate! >= 0.3 && relative.lower_95_one_sided > 0 ? 'PASS' : 'FAIL'; if (r.status.C === 'FAIL') r.limitations.push('C: complete paired effect does not meet the preregistered threshold'); }
}

function evaluateD(x: M9Input, r: M9Report): void {
  const selected = x.selection.filter(s => s.stratum === 'D'), cov = r.coverage.D, p = x.analysis_plan.d;
  type Row = { complexity: string; control: boolean; treatment: boolean; escalated: boolean; upgraded: boolean; ct: number; tt: number; cc: number | null; tc: number | null };
  const rows: Row[] = [];
  const resources: M9Cost['resource'][] = ['EMBEDDING', 'TOOLS', 'TEST', 'LOCAL_COMPUTE', 'STORAGE', 'HUMAN'];
  const monetary = (v: { cost?: number | null; amount?: number | null; currency: string | null; price_hash: string | null; billing_ref: string | null }): boolean =>
    nonnegative(v.cost === undefined ? v.amount : v.cost) && v.currency === p.currency && v.price_hash === p.price_hash && id(v.billing_ref);
  for (const s of selected) {
    const candidate = x.candidate_pool.find(c => c.task_id === s.task_id)!, outcomes = x.outcomes.filter(o => o.task_id === s.task_id);
    if (outcomes.length !== 2 || outcomes.some(o => o.contamination !== false || !acceptedEvidence(o, candidate, x.prerequisites.m9i.implementer_id) || !bool(o.independent_accepted))) continue;
    const control = outcomes.find(o => o.arm === 'CONTROL')!, treatment = outcomes.find(o => o.arm === 'TREATMENT')!;
    const byArm = [control, treatment].map(o => o.model_call_ids.map(callId => x.model_calls.find(c => c.call_id === callId)));
    if (byArm.some(a => !a.length || a.some(c => !c))) continue;
    const calls = byArm as M9ModelCall[][];
    const validCalls = calls.every((armCalls, armIndex) => armCalls.every((c, index) => {
      const expectedModel = armIndex === 0 || c.escalated ? p.control_model : p.treatment_model;
      const components = c.context && Object.values(c.context);
      return rowKey(c) === rowKey(armIndex ? treatment : control) &&
        bool(c.escalated) && !(armIndex === 0 && c.escalated) && ['INITIAL', 'RETRIEVAL', 'RETRY', 'ESCALATION'].includes(c.stage) &&
        (index === 0 ? c.stage === 'INITIAL' && !c.escalated : c.stage !== 'INITIAL') && (c.stage !== 'ESCALATION' || c.escalated) &&
        !(index > 0 && armCalls[index - 1].escalated && !c.escalated) &&
        c.provider === expectedModel.provider && c.model === expectedModel.model && c.version === expectedModel.version &&
        c.adapter_hash === p.adapter_hash && c.prompt_hash === p.prompt_hash && c.tools_hash === p.tools_hash &&
        c.temperature === p.temperature && c.top_p === p.top_p && c.seed === p.model_seed && utc(c.occurred_at) &&
        c.occurred_at >= x.selection_record.assigned_at && (index === 0 || c.occurred_at >= armCalls[index - 1].occurred_at) && id(c.response_id) &&
        integer(c.input_tokens) && integer(c.output_tokens) && integer(c.cached_tokens) && integer(c.reasoning_tokens) &&
        c.cached_tokens <= c.input_tokens && c.reasoning_tokens <= c.output_tokens &&
        !!components && canonical(Object.keys(c.context).sort()) === canonical(['initial_tokens', 'system_tokens', 'task_tokens', 'tool_tokens', 'retrieval_tokens'].sort()) &&
        components.every(integer) && components.reduce((n: number, v) => n + (v ?? 0), 0) === c.input_tokens;
    }) && armCalls.length <= p.max_turns && armCalls.filter(c => c.stage === 'RETRY').length <= p.retry_limit);
    if (!validCalls) continue;
    const escalated = calls[1].some(c => c.escalated);
    if ((escalated && !bool(treatment.upgraded_accepted)) || (!escalated && treatment.upgraded_accepted !== null) ||
        control.upgraded_accepted !== null || (escalated && treatment.independent_accepted !== false)) continue;
    const costs = [control, treatment].map((o, index) => {
      const extra = x.costs.filter(c => rowKey(c) === rowKey(o));
      if (extra.length !== resources.length || !resources.every(resource => extra.filter(c => c.resource === resource).length === 1) ||
          !extra.every(monetary) || !calls[index].every(monetary)) return null;
      return extra.reduce((sum, c) => sum + c.amount!, 0) + calls[index].reduce((sum, c) => sum + c.cost!, 0);
    });
    rows.push({ complexity: candidate.complexity, control: control.independent_accepted!, treatment: !escalated && treatment.independent_accepted!, escalated,
      upgraded: treatment.upgraded_accepted === true, ct: calls[0].reduce((sum, c) => sum + c.input_tokens!, 0), tt: calls[1].reduce((sum, c) => sum + c.input_tokens!, 0), cc: costs[0], tc: costs[1] });
  }
  cov.analyzed = rows.length; cov.incomplete = cov.selected - rows.length;
  r.counts.D = { denominator: rows.length, numerator: rows.filter(v => v.treatment).length };
  if (cov.incomplete) r.limitations.push(`D: ${cov.incomplete} pairs have incomplete/invalid model, routing, token or independent acceptance records`);
  const d: NonNullable<M9Report['d']> = r.d = { pairs: rows.length, control_accepted: rows.filter(v => v.control).length, treatment_independent_accepted: r.counts.D.numerator,
    escalated_tasks: rows.filter(v => v.escalated).length, upgraded_accepted: rows.filter(v => v.upgraded).length,
    quality: { status: 'INCONCLUSIVE', difference: null, interval_95: null, lower_95_one_sided: null },
    context: { status: 'INCONCLUSIVE', control_total_tokens: null, treatment_total_tokens: null, mean_reduction: null, median_reduction: null },
    cost: { status: 'INCONCLUSIVE', control_total: null, treatment_total: null, control_per_accepted: null, treatment_per_accepted: null, reduction: null } };
  if (rows.length !== target.D || cov.contaminated || cov.paired_outcomes !== cov.selected) { r.limitations.push('D cost: paired quality/context inputs incomplete'); return; }
  const quality95 = pairedNewcombe(rows), lower95 = pairedNewcombe(rows, 1.6448536269514722).lower;
  d.quality = { status: lower95 >= p.quality_margin ? 'PASS' : 'FAIL', difference: (d.treatment_independent_accepted - d.control_accepted) / rows.length, interval_95: quality95, lower_95_one_sided: lower95 };
  const mr = bootstrap(rows, x.analysis_plan, a => reduction(mean(a.map(v => v.ct)), mean(a.map(v => v.tt))));
  const medr = bootstrap(rows, x.analysis_plan, a => reduction(median(a.map(v => v.ct)), median(a.map(v => v.tt))));
  d.context = { status: mr.interval_95 === null || medr.interval_95 === null ? 'INCONCLUSIVE' : mr.estimate! >= p.context_reduction && medr.estimate! >= p.context_reduction ? 'PASS' : 'FAIL',
    control_total_tokens: rows.reduce((n, v) => n + v.ct, 0), treatment_total_tokens: rows.reduce((n, v) => n + v.tt, 0), mean_reduction: mr, median_reduction: medr };
  r.status.D = d.context.status === 'INCONCLUSIVE' ? 'INCONCLUSIVE' : d.quality.status === 'PASS' && d.context.status === 'PASS' ? 'PASS' : 'FAIL';
  if (d.quality.status === 'FAIL') r.limitations.push('D: complete quality interval does not meet the noninferiority threshold');
  if (d.context.status !== 'PASS') r.limitations.push(`D: context reduction ${d.context.status === 'FAIL' ? 'does not meet the threshold' : 'interval is undefined'}`);
  if (d.escalated_tasks) r.limitations.push(`D: ${d.escalated_tasks} escalated tasks remain independent-completion failures; upgraded results are separate`);
  if (rows.some(v => v.cc === null || v.tc === null)) { r.limitations.push('D cost: incomplete monetary provenance or UNKNOWN resource costs; quality/context remain separately evaluated'); return; }
  d.cost.control_total = rows.reduce((n, v) => n + v.cc!, 0); d.cost.treatment_total = rows.reduce((n, v) => n + v.tc!, 0);
  d.cost.control_per_accepted = d.control_accepted ? d.cost.control_total / d.control_accepted : null;
  d.cost.treatment_per_accepted = d.treatment_independent_accepted ? d.cost.treatment_total / d.treatment_independent_accepted : null;
  d.cost.reduction = bootstrap(rows, x.analysis_plan, a => {
    const ca = a.filter(v => v.control).length, ta = a.filter(v => v.treatment).length;
    return ca && ta ? reduction(a.reduce((n, v) => n + v.cc!, 0) / ca, a.reduce((n, v) => n + v.tc!, 0) / ta) : null;
  });
  if (d.cost.reduction.interval_95 === null) r.limitations.push('D cost: cost per accepted task or bootstrap interval undefined');
  else if (r.status.D === 'INCONCLUSIVE') r.limitations.push('D cost: quality/context conclusion incomplete');
  else { d.cost.status = r.status.D === 'PASS' && d.cost.reduction.estimate! >= p.cost_reduction ? 'PASS' : 'FAIL'; if (d.cost.status === 'FAIL') r.limitations.push('D cost: complete data do not satisfy the conditional cost rule'); }
}

export function writeM9Report(f: string, r: M9Report): void {
  if (!path.isAbsolute(f) || fs.existsSync(f)) bad('report path');
  fs.writeFileSync(f, canonical(r) + '\n', { flag: 'wx' });
}
/** Callback utility only; caller trace labels are not guard evidence or evaluator acceptance. */
export async function executeControlledTask<T>(t: { decision_id: string; permit_id: string; receipt_id: string; action_fingerprint: string; executed: true }, run: () => T | Promise<T>) {
  if (!hash(t.action_fingerprint) || ![t.decision_id, t.permit_id, t.receipt_id].every(id) || t.executed !== true) bad('trace');
  return { executed: true as const, value: await run(), trace: t };
}
