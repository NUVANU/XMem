import { createHash } from 'node:crypto';
import { type Evidence, type Event, type MemoryRecord, type SourceRef, validateEvidence, validateEvent, validateMemoryRecord } from './contracts.js';

export type ExtractionOutcome = 'SUCCESS' | 'DISABLED' | 'TIMEOUT' | 'ERROR' | 'BUDGET_EXHAUSTED';
export interface SourceSlice { locator: string; bytes: Uint8Array; }
export interface ExtractionOutput { kind: MemoryRecord['kind']; content: string; epistemic_state: MemoryRecord['epistemic_state']; information_role: MemoryRecord['information_role']; uncertainty: number; }
export interface ExtractionCandidate { schema_version: '1'; candidate_id: string; request_id: string; project_id: string; workspace_id: string; event_id: string; evidence_id: string | null; source: SourceRef; source_slice: { locator: string; content_hash: string }; extractor_version: string; extractor_config: Record<string, JsonValue>; output: ExtractionOutput; }
/** Immutable request material persisted for every terminal attempt, including no-provider paths. */
export interface ExtractionRequestCommitment { source: SourceRef; source_slice: { locator: string; content_hash: string }; extractor_version: string; extractor_config: Record<string, JsonValue>; provider_id: string | null; }
export interface ExtractionAttempt { schema_version: '1'; attempt_id: string; request_id: string; candidate_id: string | null; project_id: string; workspace_id: string; event_id: string; evidence_id: string | null; request: ExtractionRequestCommitment; outcome: ExtractionOutcome; reason: string; }
export interface ExtractionProviderInput { event: Event; evidence: Evidence | null; source_slice: SourceSlice; extractor_version: string; extractor_config: Record<string, JsonValue>; }
/**
 * This narrow adapter receives retained data only. It deliberately has no command runner,
 * filesystem writer, network client, or storage writer; adapters must not execute commands or
 * make network calls. The core records only the returned candidate or a terminal outcome.
 */
export interface ExtractionProvider { provider_id?: string; extract(input: ExtractionProviderInput): Promise<unknown>; }
export interface ExtractionRequest { request_id: string; event: Event; evidence: Evidence | null; source_slice: SourceSlice; extractor_version: string; extractor_config: Record<string, JsonValue>; }
export interface ExtractionRunOptions { provider?: ExtractionProvider; timeout_ms?: number; budget_available?: boolean; }
export interface ExtractionRunResult { candidate: ExtractionCandidate | null; attempt: ExtractionAttempt; replayed: boolean; }
export interface ExtractionStorage {
  getStoredEvent(projectId: string, sourceId: string, eventId: string): Event | undefined;
  getStoredEvidence(evidenceId: string): Evidence | undefined;
  persistExtractionOutcome(candidate: ExtractionCandidate | null, attempt: ExtractionAttempt): { candidate: ExtractionCandidate | null; attempt: ExtractionAttempt; replayed: boolean };
}

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
const hash = (value: Uint8Array | string) => createHash('sha256').update(value).digest('hex');
const canonicalize = (value: unknown): unknown => Array.isArray(value) ? value.map(canonicalize) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value as Record<string, unknown>).sort().map(key => [key, canonicalize((value as Record<string, unknown>)[key])])) : value;
const canonical = (value: unknown) => JSON.stringify(canonicalize(value));
const id = (value: unknown, label: string): string => { if (typeof value !== 'string' || value.trim() === '') throw new ExtractionError('INVALID_INPUT', `${label} is required`); return value; };
const exact = (value: unknown, keys: readonly string[], label: string): Record<string, unknown> => { if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some(key => !(key in value))) throw new ExtractionError('INVALID_INPUT', `${label} has unknown or missing fields`); return value as Record<string, unknown>; };
function json(value: unknown, label: string): asserts value is JsonValue { if (value === null || typeof value === 'boolean' || typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value))) return; if (Array.isArray(value)) { value.forEach((item, index) => json(item, `${label}[${index}]`)); return; } if (value && typeof value === 'object') { Object.entries(value).forEach(([key, item]) => { id(key, `${label} key`); json(item, `${label}.${key}`); }); return; } throw new ExtractionError('INVALID_INPUT', `${label} must be JSON-compatible`); }
const clone = <T>(value: T): T => structuredClone(value);

export class ExtractionError extends Error { constructor(public readonly code: 'INVALID_INPUT' | 'IDENTITY_CONFLICT' | 'SOURCE_MISSING', message: string) { super(message); this.name = 'ExtractionError'; } }

function output(input: unknown): ExtractionOutput {
  const x = exact(input, ['kind','content','epistemic_state','information_role','uncertainty'], 'Extraction output');
  if (!['Observation','DecisionRef','ConstraintRef','FailedAttempt','RootCauseHypothesis'].includes(String(x.kind)) || !['OBSERVED','ASSERTED','HYPOTHESIS','CONFIRMED'].includes(String(x.epistemic_state)) || !['FACT','NORMATIVE_REF','EXPERIENCE','SUGGESTION'].includes(String(x.information_role)) || typeof x.content !== 'string' || x.content.trim() === '' || typeof x.uncertainty !== 'number' || !Number.isFinite(x.uncertainty) || x.uncertainty < 0 || x.uncertainty > 1) throw new ExtractionError('INVALID_INPUT', 'Extraction output is invalid');
  if ((x.kind === 'DecisionRef' || x.kind === 'ConstraintRef') && x.information_role !== 'NORMATIVE_REF') throw new ExtractionError('INVALID_INPUT', 'Normative extraction candidates need a normative role');
  return clone(x as unknown as ExtractionOutput);
}
export function validateExtractionProviderResult(input: unknown): { output: ExtractionOutput } { const x = exact(input, ['output'], 'Extraction provider result'); return { output: output(x.output) }; }
export function validateExtractionCandidate(input: unknown): ExtractionCandidate {
  const x = exact(input, ['schema_version','candidate_id','request_id','project_id','workspace_id','event_id','evidence_id','source','source_slice','extractor_version','extractor_config','output'], 'Extraction candidate');
  if (x.schema_version !== '1' || x.evidence_id !== null && (typeof x.evidence_id !== 'string' || x.evidence_id.trim() === '')) throw new ExtractionError('INVALID_INPUT', 'Extraction candidate schema is invalid');
  const source = clone(x.source as SourceRef); try { validateEvent({schema_version:'1',event_id:'validation',project_id:id(x.project_id,'project_id'),workspace_id:id(x.workspace_id,'workspace_id'),run_id:'validation',source,sequence:0,occurred_at:'2026-01-01T00:00:00.000Z',completeness:'COMPLETE',kind:'observation',content:'validation',evidence_id:null}); } catch { throw new ExtractionError('INVALID_INPUT', 'Extraction candidate source is invalid'); }
  const slice = exact(x.source_slice, ['locator','content_hash'], 'Source slice'); if (slice.locator !== source.locator || typeof slice.content_hash !== 'string' || !/^[a-f0-9]{64}$/.test(slice.content_hash)) throw new ExtractionError('INVALID_INPUT', 'Source slice must retain locator and content hash');
  const config = x.extractor_config; if (!config || typeof config !== 'object' || Array.isArray(config)) throw new ExtractionError('INVALID_INPUT', 'Extractor config must be an object'); json(config, 'extractor_config');
  return { schema_version:'1', candidate_id:id(x.candidate_id,'candidate_id'), request_id:id(x.request_id,'request_id'), project_id:id(x.project_id,'project_id'), workspace_id:id(x.workspace_id,'workspace_id'), event_id:id(x.event_id,'event_id'), evidence_id:x.evidence_id as string|null, source, source_slice:{locator:slice.locator as string,content_hash:slice.content_hash as string}, extractor_version:id(x.extractor_version,'extractor_version'), extractor_config:clone(config as Record<string,JsonValue>), output:output(x.output) };
}
export function validateExtractionAttempt(input: unknown): ExtractionAttempt {
  const x = exact(input, ['schema_version','attempt_id','request_id','candidate_id','project_id','workspace_id','event_id','evidence_id','request','outcome','reason'], 'Extraction attempt');
  if (x.schema_version !== '1' || x.candidate_id !== null && (typeof x.candidate_id !== 'string' || x.candidate_id.trim() === '') || x.evidence_id !== null && (typeof x.evidence_id !== 'string' || x.evidence_id.trim() === '') || !['SUCCESS','DISABLED','TIMEOUT','ERROR','BUDGET_EXHAUSTED'].includes(String(x.outcome)) || typeof x.reason !== 'string' || x.reason.trim() === '') throw new ExtractionError('INVALID_INPUT', 'Extraction attempt is invalid');
  if ((x.outcome === 'SUCCESS') !== (x.candidate_id !== null)) throw new ExtractionError('INVALID_INPUT', 'Only successful extraction attempts bind a candidate');
  const request=exact(x.request,['source','source_slice','extractor_version','extractor_config','provider_id'],'Extraction request commitment'); const source=clone(request.source as SourceRef); try { validateEvent({schema_version:'1',event_id:'validation',project_id:id(x.project_id,'project_id'),workspace_id:id(x.workspace_id,'workspace_id'),run_id:'validation',source,sequence:0,occurred_at:'2026-01-01T00:00:00.000Z',completeness:'COMPLETE',kind:'observation',content:'validation',evidence_id:null}); } catch { throw new ExtractionError('INVALID_INPUT','Extraction attempt source is invalid'); }
  const slice=exact(request.source_slice,['locator','content_hash'],'Extraction request source slice'); if(slice.locator!==source.locator||typeof slice.content_hash!=='string'||!/^[a-f0-9]{64}$/.test(slice.content_hash)||slice.content_hash!==source.content_hash)throw new ExtractionError('INVALID_INPUT','Extraction request source slice must bind its source'); if(!request.extractor_config||typeof request.extractor_config!=='object'||Array.isArray(request.extractor_config))throw new ExtractionError('INVALID_INPUT','Extraction request config is invalid');json(request.extractor_config,'request.extractor_config');if(request.provider_id!==null&&(typeof request.provider_id!=='string'||request.provider_id.trim()===''))throw new ExtractionError('INVALID_INPUT','Extraction provider identity is invalid');
  return {schema_version:'1',attempt_id:id(x.attempt_id,'attempt_id'),request_id:id(x.request_id,'request_id'),candidate_id:x.candidate_id as string|null,project_id:id(x.project_id,'project_id'),workspace_id:id(x.workspace_id,'workspace_id'),event_id:id(x.event_id,'event_id'),evidence_id:x.evidence_id as string|null,request:{source,source_slice:{locator:slice.locator as string,content_hash:slice.content_hash as string},extractor_version:id(request.extractor_version,'extractor_version'),extractor_config:clone(request.extractor_config as Record<string,JsonValue>),provider_id:request.provider_id as string|null},outcome:x.outcome as ExtractionOutcome,reason:x.reason};
}

function validateRequest(input: ExtractionRequest): ExtractionRequest {
  const x = exact(input, ['request_id','event','evidence','source_slice','extractor_version','extractor_config'], 'Extraction request');
  const event = validateEvent(clone(x.event)); const evidence = x.evidence === null ? null : validateEvidence(clone(x.evidence));
  if ((event.evidence_id === null) !== (evidence === null) || evidence && (evidence.evidence_id !== event.evidence_id || evidence.project_id !== event.project_id || evidence.workspace_id !== event.workspace_id || evidence.run_id !== event.run_id)) throw new ExtractionError('INVALID_INPUT', 'Extraction evidence must bind its event');
  const source_slice = exact(x.source_slice, ['locator','bytes'], 'Source slice'); if (source_slice.locator !== event.source.locator || !(source_slice.bytes instanceof Uint8Array) || hash(source_slice.bytes) !== event.source.content_hash) throw new ExtractionError('INVALID_INPUT', 'Source slice must bind the event source hash and locator');
  if (!x.extractor_config || typeof x.extractor_config !== 'object' || Array.isArray(x.extractor_config)) throw new ExtractionError('INVALID_INPUT', 'Extractor config must be an object'); json(x.extractor_config, 'extractor_config');
  return {request_id:id(x.request_id,'request_id'),event,evidence,source_slice:{locator:source_slice.locator as string,bytes:clone(source_slice.bytes as Uint8Array)},extractor_version:id(x.extractor_version,'extractor_version'),extractor_config:clone(x.extractor_config as Record<string,JsonValue>)};
}
function attempt(request: ExtractionRequest, outcome: ExtractionOutcome, reason: string, candidateId: string | null, providerId: string | null): ExtractionAttempt { const commitment:ExtractionRequestCommitment={source:clone(request.event.source),source_slice:{locator:request.source_slice.locator,content_hash:hash(request.source_slice.bytes)},extractor_version:request.extractor_version,extractor_config:clone(request.extractor_config),provider_id:providerId};return {schema_version:'1',attempt_id:`extract-attempt-${hash(canonical({request_id:request.request_id,outcome,reason,candidate_id:candidateId,event_id:request.event.event_id,request:commitment}))}`,request_id:request.request_id,candidate_id:candidateId,project_id:request.event.project_id,workspace_id:request.event.workspace_id,event_id:request.event.event_id,evidence_id:request.event.evidence_id,request:commitment,outcome,reason}; }

/** Runs the optional adapter outside storage transactions; every terminal result is immutable. */
export async function runExtraction(storage: ExtractionStorage, input: ExtractionRequest, options: ExtractionRunOptions = {}): Promise<ExtractionRunResult> {
  const request = validateRequest(input); const storedEvent = storage.getStoredEvent(request.event.project_id, request.event.source.source_id, request.event.event_id);
  if (!storedEvent || canonical(storedEvent) !== canonical(request.event)) throw new ExtractionError('SOURCE_MISSING', 'Extraction event must already be stored authoritatively');
  if (request.evidence) { const storedEvidence = storage.getStoredEvidence(request.evidence.evidence_id); if (!storedEvidence || canonical(storedEvidence) !== canonical(request.evidence)) throw new ExtractionError('SOURCE_MISSING', 'Extraction evidence must already be stored authoritatively'); }
  const providerId=options.provider?.provider_id===undefined?null:id(options.provider.provider_id,'provider_id');
  const terminal = (outcome: ExtractionOutcome, reason: string, candidate: ExtractionCandidate | null): ExtractionRunResult => storage.persistExtractionOutcome(candidate, attempt(request,outcome,reason,candidate?.candidate_id ?? null,providerId));
  if (!options.provider) return terminal('DISABLED','NO_PROVIDER',null);
  if (options.budget_available === false) return terminal('BUDGET_EXHAUSTED','BUDGET_EXHAUSTED',null);
  const timeout = options.timeout_ms ?? 30_000; if (!Number.isInteger(timeout) || timeout <= 0) throw new ExtractionError('INVALID_INPUT', 'timeout_ms must be a positive integer');
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      Promise.resolve(options.provider.extract({event:clone(request.event),evidence:clone(request.evidence),source_slice:clone(request.source_slice),extractor_version:request.extractor_version,extractor_config:clone(request.extractor_config)})),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('TIMEOUT')), timeout); }),
    ]);
    const parsed = validateExtractionProviderResult(result); const candidate: ExtractionCandidate = {schema_version:'1',candidate_id:`candidate-${hash(canonical({request_id:request.request_id,event_id:request.event.event_id,source_slice_hash:hash(request.source_slice.bytes),extractor_version:request.extractor_version,extractor_config:request.extractor_config,output:parsed.output}))}`,request_id:request.request_id,project_id:request.event.project_id,workspace_id:request.event.workspace_id,event_id:request.event.event_id,evidence_id:request.event.evidence_id,source:clone(request.event.source),source_slice:{locator:request.source_slice.locator,content_hash:hash(request.source_slice.bytes)},extractor_version:request.extractor_version,extractor_config:clone(request.extractor_config),output:parsed.output};
    return terminal('SUCCESS','CANDIDATE_RECORDED',candidate);
  } catch (error) { return terminal(error instanceof Error && error.message === 'TIMEOUT' ? 'TIMEOUT' : 'ERROR', error instanceof Error && error.message === 'TIMEOUT' ? 'TIMEOUT' : 'PROVIDER_RESULT_REJECTED_OR_ERROR', null); }
  finally { if (timer) clearTimeout(timer); }
}
