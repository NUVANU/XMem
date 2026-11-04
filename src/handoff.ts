import { createHash } from 'node:crypto';
import { type ContextCoverage } from './context.js';
import { type Snapshot } from './contracts.js';
import { SqliteMemoryStorage, StorageError, type HandoffPackage, type HandoffReceipt, type HandoffValidation } from './storage.js';
import { createDependencyReadBoundary,type DependencyReadOptions,type DependencyReadSession } from './dependency-read-boundary.js';
export interface HandoffDependencyOptions {projectRoot:string;options?:DependencyReadOptions;session?:DependencyReadSession;}

/** Packages never restore enrollment. A live caller must supply its real handle again. */
function handoffBoundary(storage:SqliteMemoryStorage,manifestHash:string,options?:HandoffDependencyOptions) {
  const manifest=storage.getContextManifest(manifestHash);if(!manifest)throw new StorageError('SOURCE_MISSING','Handoff context manifest is missing');
  const boundary=options?createDependencyReadBoundary(options.projectRoot,storage,manifest.request,options.options,options.session):null;
  boundary?.chargeView();const view=storage.readContextView(manifest.request);boundary?.chargeViewBytes(view.entries);
  if(view.snapshot_hash!==manifest.view_snapshot_hash)throw new StorageError('SOURCE_MISSING','Handoff context is stale');
  const before=boundary?boundary.check(view.entries):storage.readEngineeringDependencyBoundary(manifest.request,view.entries);
  return()=>{
    boundary?.chargeView();const after=storage.readContextView(manifest.request);boundary?.chargeViewBytes(after.entries);
    if(after.snapshot_hash!==view.snapshot_hash)throw new StorageError('INPUT_INCOMPLETE','Handoff context changed');
    if(boundary)boundary.verify(after.entries,before);
    else if(storage.readEngineeringDependencyBoundary(manifest.request,after.entries)!==before)throw new StorageError('INPUT_INCOMPLETE','Handoff dependency changed');
  };
}

const hash = (value: unknown) => createHash('sha256').update(canonicalJson(value)).digest('hex');
const canonicalize = (value: unknown): unknown => Array.isArray(value) ? value.map(canonicalize) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value as Record<string, unknown>).sort().map(key => [key, canonicalize((value as Record<string, unknown>)[key])])) : value;
export const canonicalJson = (value: unknown): string => JSON.stringify(canonicalize(value));
const id = (value: unknown, label: string): string => { if (typeof value !== 'string' || value.trim() === '') throw new StorageError('INVALID_INPUT', `${label} is required`); return value; };
const uniqueStrings = (value: unknown, label: string): string[] => { if (!Array.isArray(value) || !value.every(item => typeof item === 'string' && item.trim() !== '') || new Set(value).size !== value.length) throw new StorageError('INVALID_INPUT', `${label} must be unique non-empty strings`); return [...value].sort(); };

export interface HandoffPrepareRequest {
  project_id: string;
  workspace_id: string;
  task_ref: string;
  task_version: string;
  target_snapshot: Snapshot;
  revision_ids: string[];
  evidence_ids: string[];
  failed_attempt_ids: string[];
  context_manifest_hash: string;
  completed: string[];
  pending: string[];
  blocked: string[];
  next_steps: string[];
}

export interface HandoffAcknowledgement {
  recipient_id: string;
  action: 'ACCEPTED' | 'REJECTED';
  reason_codes: string[];
}

function validateRequest(input: HandoffPrepareRequest): HandoffPrepareRequest {
  const x = input as unknown as Record<string, unknown>;
  const keys = ['project_id','workspace_id','task_ref','task_version','target_snapshot','revision_ids','evidence_ids','failed_attempt_ids','context_manifest_hash','completed','pending','blocked','next_steps'];
  if (!x || typeof x !== 'object' || Array.isArray(x) || Object.keys(x).length !== keys.length || keys.some(key => !(key in x))) throw new StorageError('INVALID_INPUT', 'Handoff request has unknown or missing fields');
  const target = x.target_snapshot as Snapshot;
  if (!target || typeof target !== 'object' || target.project_id !== x.project_id || target.workspace_id !== x.workspace_id) throw new StorageError('PROJECT_MISMATCH', 'Target snapshot must bind the handoff project and workspace');
  return { project_id:id(x.project_id,'project_id'), workspace_id:id(x.workspace_id,'workspace_id'), task_ref:id(x.task_ref,'task_ref'), task_version:id(x.task_version,'task_version'), target_snapshot:structuredClone(target), revision_ids:uniqueStrings(x.revision_ids,'revision_ids'), evidence_ids:uniqueStrings(x.evidence_ids,'evidence_ids'), failed_attempt_ids:uniqueStrings(x.failed_attempt_ids,'failed_attempt_ids'), context_manifest_hash:id(x.context_manifest_hash,'context_manifest_hash'), completed:uniqueStrings(x.completed,'completed'), pending:uniqueStrings(x.pending,'pending'), blocked:uniqueStrings(x.blocked,'blocked'), next_steps:uniqueStrings(x.next_steps,'next_steps') };
}

/**
 * Build and persist a derived, immutable package. The package id is derived from its canonical
 * material; no timestamp, actor, or mutable session data contributes to its identity.
 */
export function prepareHandoff(storage: SqliteMemoryStorage, input: HandoffPrepareRequest,options?:HandoffDependencyOptions): HandoffPackage {
  const request = validateRequest(input);
  const finish=handoffBoundary(storage,request.context_manifest_hash,options);
  const material = storage.buildHandoffMaterial(request);
  const body = { kind:'HandoffPackage' as const, protocol_version:'handoff-v1' as const, ...material };
  const content_hash = hash(body);
  const package_id = `handoff-${content_hash}`;
  const saved=storage.persistHandoffPackage({ ...body, package_id, content_hash });finish();return saved;
}

/** Rechecks the retained source, snapshot, revision, evidence, failure and context material. */
export function validateHandoff(storage: SqliteMemoryStorage, packageId: string,options?:HandoffDependencyOptions): HandoffValidation {
  const result=storage.validateHandoff(packageId);
  if(result.status==='VALID'){const pack=storage.getHandoffPackage(packageId);if(!pack)throw new StorageError('SOURCE_MISSING','Handoff missing');handoffBoundary(storage,pack.context_manifest_hash,options)();}
  return result;
}

/**
 * Save the receiver's choice only after a fresh validation. This does not schedule or execute
 * anything; a receiver must call validateHandoff again before it acts after recovery.
 */
export function acknowledgeHandoff(storage: SqliteMemoryStorage, packageId: string, acknowledgement: HandoffAcknowledgement,options?:HandoffDependencyOptions): HandoffReceipt {
  if (!acknowledgement || (acknowledgement.action !== 'ACCEPTED' && acknowledgement.action !== 'REJECTED')) throw new StorageError('INVALID_INPUT', 'Handoff acknowledgement action is invalid');
  const pack=storage.getHandoffPackage(packageId),finish=pack?handoffBoundary(storage,pack.context_manifest_hash,options):null;
  const receipt=storage.acknowledgeHandoff(packageId, id(acknowledgement.recipient_id,'recipient_id'), acknowledgement.action, uniqueStrings(acknowledgement.reason_codes,'reason_codes'));
  finish?.();return receipt;
}

/** Session recovery intentionally performs no action: it returns only a fresh material verdict. */
export function recoverHandoffSession(storage: SqliteMemoryStorage, packageId: string,options?:HandoffDependencyOptions): HandoffValidation { return validateHandoff(storage, packageId,options); }

export type { ContextCoverage };
