import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { validateSnapshot, type Evidence, type Snapshot } from './contracts.js';
import { canonical, contentHash, EVIDENCE_POLICY, verifyEvidence } from './evidence.js';
import { type FailedAction, type JsonValue } from './failures.js';
import { StorageExecutionProvenance } from './provenance.js';
import { type GuardAuditKind, type GuardAuditRecord, SqliteMemoryStorage } from './storage.js';

export type GuardCheckpoint = 'before_evidence_reuse' | 'before_known_failure_action';
export type GuardDecisionResult = 'ALLOW' | 'PAUSE' | 'BLOCK' | 'UNKNOWN' | 'EXECUTED_AUDIT_FAILURE';

export interface ControlledWriteMarkerAction {
  action_id: 'controlled-write-marker';
  marker_id: string;
  value: string;
  observable_args: Record<string, JsonValue>;
}
export interface GuardCheckRequest {
  request_id: string;
  project_id: string;
  workspace_id: string;
  task_id: string;
  run_id: string;
  target_snapshot: Snapshot;
  condition_fingerprints: Record<string, string>;
  policy_version: string;
  action: ControlledWriteMarkerAction;
  reference_id: string;
}
export interface GuardPermit {
  permit_id: string;
  decision_id: string;
  run_id: string;
  project_id: string;
  workspace_id: string;
  target_snapshot_hash: string;
  condition_fingerprints_hash: string;
  action_fingerprint: string;
}
export interface GuardDecision {
  decision_id: string;
  result: GuardDecisionResult;
  reason_codes: string[];
  input_commitment_hash: string;
  invalidation: string[];
  permit?: GuardPermit;
}
export interface GuardRunManifest { run_id:string; project_id:string; workspace_id:string; task_id:string; target_snapshot:Snapshot; target_snapshot_hash:string; }
export interface ReferenceGuardOptions { audit_root: string; now?: () => string; ids?: () => string; }

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const hash = (value: unknown) => sha256(canonical(value));
const ID = /^\S(?:[\s\S]*\S)?$/;
const HASH = /^[a-f0-9]{64}$/;
const fileFor: Record<GuardAuditKind,string> = { run_manifest:'run-manifest.json', decision:'xmem-decisions.jsonl', permit:'guard-checkpoints.jsonl', reservation:'guard-checkpoints.jsonl', checkpoint:'guard-checkpoints.jsonl', execution:'execution-events.jsonl', receipt:'guard-checkpoints.jsonl', deviation:'deviations.jsonl' };

/** A resettable, process-local test action. It cannot execute commands or write project files. */
export class ControlledWriteMarker {
  private current: string | null = null;
  constructor(readonly marker_id: string) { if (!ID.test(marker_id)) throw new Error('Marker identity is required'); }
  read(): string | null { return this.current; }
  reset(): void { this.current = null; }
  apply(action: ControlledWriteMarkerAction): void { if (action.marker_id !== this.marker_id || action.action_id !== 'controlled-write-marker') throw new Error('Marker action does not match this controlled marker'); this.current = action.value; }
}

/**
 * Minimal M9I reference adapter. Its only executable effect is assigning a supplied value to a
 * ControlledWriteMarker after an immutable, single-use permit has been persisted.
 */
export class ReferenceGuard {
  private readonly now: () => string;
  private readonly ids: () => string;
  private readonly auditRoot: string;
  private readonly manifests = new Map<string,GuardRunManifest>();
  private auditFailed = false;
  constructor(private readonly storage: SqliteMemoryStorage, options: ReferenceGuardOptions) {
    if (!options || !path.isAbsolute(options.audit_root) || !fs.existsSync(options.audit_root) || !fs.statSync(options.audit_root).isDirectory()) throw new Error('A pre-existing absolute audit root is required');
    this.auditRoot = fs.realpathSync.native(options.audit_root); this.now = options.now ?? (() => new Date().toISOString()); this.ids = options.ids ?? randomUUID;
  }
  private actionSummary(action: ControlledWriteMarkerAction) { return { action_id:action.action_id, marker_id:action.marker_id, value_hash:sha256(action.value), observable_args_hash:hash(action.observable_args) }; }
  private actionFingerprint(action: ControlledWriteMarkerAction): string { return hash(this.actionSummary(action)); }
  private binding(request: GuardCheckRequest, details: ReturnType<ReferenceGuard['validate']>) { return {request_id:request.request_id,task_id:request.task_id,run_id:request.run_id,project_id:request.project_id,workspace_id:request.workspace_id,target_snapshot_hash:contentHash(details.snapshot),condition_fingerprints_hash:details.condition_fingerprints_hash,action_fingerprint:details.action_fingerprint,policy_version:request.policy_version,reference_id:request.reference_id,input_commitment_hash:details.input_commitment_hash}; }
  private validate(request: GuardCheckRequest): { snapshot:Snapshot; action_fingerprint:string; condition_fingerprints_hash:string; input_commitment_hash:string } {
    if (!request || ![request.request_id,request.project_id,request.workspace_id,request.task_id,request.run_id,request.policy_version,request.reference_id].every(value => typeof value === 'string' && ID.test(value))) throw new Error('Guard request identity is incomplete');
    const snapshot=validateSnapshot(structuredClone(request.target_snapshot));
    if (snapshot.project_id !== request.project_id || snapshot.workspace_id !== request.workspace_id) throw new Error('Target snapshot identity does not match guard request');
    if (!request.action || request.action.action_id !== 'controlled-write-marker' || !ID.test(request.action.marker_id) || typeof request.action.value !== 'string' || !request.action.observable_args || typeof request.action.observable_args !== 'object' || Array.isArray(request.action.observable_args)) throw new Error('Only a structured controlled write-marker action is permitted');
    if (!request.condition_fingerprints || typeof request.condition_fingerprints !== 'object' || Array.isArray(request.condition_fingerprints) || Object.keys(request.condition_fingerprints).length===0 || Object.entries(request.condition_fingerprints).some(([key,value]) => !ID.test(key) || !HASH.test(value))) throw new Error('Condition fingerprints must be non-empty SHA-256 values');
    if (request.policy_version !== EVIDENCE_POLICY) throw new Error('Unsupported guard policy');
    const action_fingerprint=this.actionFingerprint(request.action), condition_fingerprints_hash=hash(request.condition_fingerprints);
    return { snapshot, action_fingerprint, condition_fingerprints_hash, input_commitment_hash:hash({ request_id:request.request_id, project_id:request.project_id, workspace_id:request.workspace_id, task_id:request.task_id, run_id:request.run_id, target_snapshot_hash:contentHash(snapshot), condition_fingerprints_hash, policy_version:request.policy_version, action_fingerprint, reference_id:request.reference_id }) };
  }
  private runDirectory(runId: string): string { return path.join(this.auditRoot, sha256(runId)); }
  private nextRecord(request: Pick<GuardCheckRequest,'run_id'|'project_id'|'workspace_id'>, kind: GuardAuditKind, fields: Omit<GuardAuditRecord,'record_id'|'run_id'|'project_id'|'workspace_id'|'occurred_at'|'kind'|'previous_hash'|'payload_hash'|'chain_hash'> & {record_id?:string}): GuardAuditRecord {
    const prior=this.storage.readGuardAuditRecords(request.run_id); const previous_hash=prior.length ? prior.at(-1)!.chain_hash : null, payload_hash=hash(fields.payload);
    const body={record_id:fields.record_id??this.ids(),run_id:request.run_id,project_id:request.project_id,workspace_id:request.workspace_id,occurred_at:this.now(),kind,decision_id:fields.decision_id,permit_id:fields.permit_id,action_fingerprint:fields.action_fingerprint,previous_hash,payload_hash};
    return { ...body, chain_hash:hash(body), payload:structuredClone(fields.payload) };
  }
  private mirror(record: GuardAuditRecord): void {
    const directory=this.runDirectory(record.run_id), root=this.auditRoot.toLowerCase(), inside=(candidate:string)=>{const relative=path.relative(this.auditRoot,candidate);if(relative===''||relative==='..'||relative.startsWith(`..${path.sep}`)||path.isAbsolute(relative))throw new Error('Audit path escapes root');}; inside(directory); if (!fs.existsSync(directory)) fs.mkdirSync(directory,{recursive:true,mode:0o700}); const directoryStat=fs.lstatSync(directory), directoryReal=fs.realpathSync.native(directory).toLowerCase(); if(directoryStat.isSymbolicLink()||!directoryStat.isDirectory()||!directoryReal.startsWith(`${root}${path.sep.toLowerCase()}`))throw new Error('Audit directory is unsafe');
    const file=path.join(directory,fileFor[record.kind]), bytes=Buffer.from(`${canonical(record)}\n`); inside(file); if(fs.existsSync(file)){const leaf=fs.lstatSync(file),real=fs.realpathSync.native(file).toLowerCase();if(leaf.isSymbolicLink()||!leaf.isFile()||leaf.nlink!==1||!real.startsWith(`${root}${path.sep.toLowerCase()}`))throw new Error('Audit file is unsafe');}
    if (record.kind==='run_manifest') fs.writeFileSync(file,bytes,{flag:'wx',mode:0o600}); else fs.appendFileSync(file,bytes,{encoding:'utf8',mode:0o600});
  }
  private verifyMirror(runId: string, records: GuardAuditRecord[]): boolean {
    try { const directory=this.runDirectory(runId), root=this.auditRoot.toLowerCase(), contained=(candidate:string)=>{const real=fs.realpathSync.native(candidate).toLowerCase();return real.startsWith(`${root}${path.sep.toLowerCase()}`);}; const stat=fs.lstatSync(directory); if(stat.isSymbolicLink()||!stat.isDirectory()||!contained(directory)) return false; for(const file of new Set(records.map(record=>fileFor[record.kind]))){const target=path.join(directory,file), leaf=fs.lstatSync(target);if(leaf.isSymbolicLink()||!leaf.isFile()||leaf.nlink!==1||!contained(target))return false;const expected=records.filter(record=>fileFor[record.kind]===file).map(record=>canonical(record));const actual=fs.readFileSync(target,'utf8').trimEnd().split('\n');if(canonical(actual)!==canonical(expected))return false;}return true; } catch { return false; }
  }
  private persist(record: GuardAuditRecord, consume = false): boolean {
    if (this.auditFailed) return false;
    try { if (consume) this.storage.consumeGuardPermit(record); else this.storage.appendGuardAuditRecord(record); this.mirror(record); return true; }
    catch { this.auditFailed = true; return false; }
  }
  private reserve(record: GuardAuditRecord): boolean { if(this.auditFailed)return false;try{this.storage.reserveGuardPermit(record);this.mirror(record);return true;}catch{this.auditFailed=true;return false;} }
  startRun(manifest: GuardRunManifest): void {
    if (!manifest || Object.keys(manifest).sort().join(',')!=='project_id,run_id,target_snapshot,target_snapshot_hash,task_id,workspace_id' || ![manifest.run_id,manifest.project_id,manifest.workspace_id,manifest.task_id].every(value=>typeof value==='string'&&ID.test(value)) || !HASH.test(manifest.target_snapshot_hash) || this.manifests.has(manifest.run_id)) throw new Error('Invalid or duplicate guard run manifest');
    const snapshot=validateSnapshot(structuredClone(manifest.target_snapshot)); if(snapshot.project_id!==manifest.project_id||snapshot.workspace_id!==manifest.workspace_id||contentHash(snapshot)!==manifest.target_snapshot_hash)throw new Error('Run manifest snapshot binding is invalid'); this.storage.recordSnapshot(snapshot);
    const record=this.nextRecord(manifest,'run_manifest',{decision_id:null,permit_id:null,action_fingerprint:null,payload:{task_id:manifest.task_id,target_snapshot_id:snapshot.snapshot_id,target_snapshot_hash:contentHash(snapshot)}});
    if (!this.persist(record)) throw new Error('Guard audit could not record the run manifest'); this.manifests.set(manifest.run_id,structuredClone(manifest));
  }
  private pause(request: GuardCheckRequest, details: ReturnType<ReferenceGuard['validate']>, checkpoint: GuardCheckpoint, code: string): GuardDecision {
    const decision_id=this.ids(), decision:GuardDecision={decision_id,result:'PAUSE',reason_codes:[code],input_commitment_hash:details.input_commitment_hash,invalidation:['AUDIT_OR_INPUT_FAILURE']};
    this.persist(this.nextRecord(request,'decision',{record_id:decision_id,decision_id,permit_id:null,action_fingerprint:details.action_fingerprint,payload:{checkpoint,result:decision.result,reason_codes:decision.reason_codes,input_commitment_hash:decision.input_commitment_hash,invalidation:decision.invalidation,binding:this.binding(request,details),reference_kind:null,reference_id:null,reference_hash:null}}));
    return decision;
  }
  private decide(request: GuardCheckRequest, checkpoint: GuardCheckpoint, result: GuardDecisionResult, reason_codes: string[], details: ReturnType<ReferenceGuard['validate']>, reference_kind:'EVIDENCE'|'FAILED_ATTEMPT', reference_hash:string): GuardDecision {
    if (this.auditFailed || !this.manifests.has(request.run_id) || this.manifests.get(request.run_id)!.target_snapshot_hash!==contentHash(details.snapshot)) return this.pause(request,details,checkpoint,'AUDIT_OR_MANIFEST_UNAVAILABLE');
    const decision_id=this.ids(), decision:GuardDecision={decision_id,result,reason_codes:[...new Set(reason_codes)].sort(),input_commitment_hash:details.input_commitment_hash,invalidation:['SNAPSHOT_DRIFT','ACTION_DRIFT','CONDITION_DRIFT','PERMIT_REPLAY','AUDIT_FAILURE']};
    const binding=this.binding(request,details);
    if (!this.persist(this.nextRecord(request,'decision',{record_id:decision_id,decision_id,permit_id:null,action_fingerprint:details.action_fingerprint,payload:{checkpoint,result,reason_codes:decision.reason_codes,invalidation:decision.invalidation,binding,reference_kind,reference_id:request.reference_id,reference_hash}}))) return { ...decision,result:'PAUSE',reason_codes:['AUDIT_FAILURE'] };
    if (result!=='ALLOW') return decision;
    const permit:GuardPermit={permit_id:this.ids(),decision_id,run_id:request.run_id,project_id:request.project_id,workspace_id:request.workspace_id,target_snapshot_hash:contentHash(details.snapshot),condition_fingerprints_hash:details.condition_fingerprints_hash,action_fingerprint:details.action_fingerprint};
    const action=this.actionSummary(request.action);
    if (!this.persist(this.nextRecord(request,'permit',{record_id:permit.permit_id,decision_id,permit_id:permit.permit_id,action_fingerprint:permit.action_fingerprint,payload:{permit,binding,action}}))) return {...decision,result:'PAUSE',reason_codes:['AUDIT_FAILURE']};
    return {...decision,permit};
  }
  checkEvidenceReuse(request: GuardCheckRequest, evidence: Evidence): GuardDecision {
    let details:ReturnType<ReferenceGuard['validate']>; try { details=this.validate(request); } catch { return {decision_id:this.ids(),result:'PAUSE',reason_codes:['INVALID_REQUEST'],input_commitment_hash:'',invalidation:['INPUT_INVALID']}; }
    try { if(evidence.evidence_id!==request.reference_id)return this.pause(request,details,'before_evidence_reuse','REFERENCE_MISMATCH'); const decision=verifyEvidence(evidence,details.snapshot,request.policy_version,new StorageExecutionProvenance(this.storage)); return this.decide(request,'before_evidence_reuse',decision.reusable_pass?'ALLOW':'PAUSE',decision.reason_codes,details,'EVIDENCE',hash(evidence)); }
    catch { return this.pause(request,details,'before_evidence_reuse','CORE_DECISION_UNAVAILABLE'); }
  }
  checkKnownFailure(request: GuardCheckRequest): GuardDecision {
    let details:ReturnType<ReferenceGuard['validate']>; try { details=this.validate(request); } catch { return {decision_id:this.ids(),result:'PAUSE',reason_codes:['INVALID_REQUEST'],input_commitment_hash:'',invalidation:['INPUT_INVALID']}; }
    try { const outcome=this.storage.decideFailedAttempt({project_id:request.project_id,workspace_id:request.workspace_id,action:{action_id:request.action.action_id,observable_args:request.action.observable_args} as FailedAction,condition_fingerprints:request.condition_fingerprints,error_signature:null,target_snapshot:details.snapshot}); const valid=['EXACT_KNOWN_FAILURE','CONDITION_CHANGED','POSSIBLY_RELATED','UNKNOWN']; if(!outcome||!valid.includes(outcome.outcome)||!Array.isArray(outcome.decisions)||outcome.decisions.length===0||outcome.decisions.some(item=>!item||!valid.includes(item.outcome)||!Array.isArray(item.reason_codes)))return this.pause(request,details,'before_known_failure_action','CORE_RESPONSE_INVALID'); const match=outcome.decisions.find(item=>item.failed_attempt_id===request.reference_id); if(!match)return this.pause(request,details,'before_known_failure_action','CORE_RESPONSE_INVALID'); const attempt=this.storage.queryFailedAttempts({project_id:request.project_id,workspace_id:request.workspace_id,action:{action_id:request.action.action_id,observable_args:request.action.observable_args},condition_fingerprints:request.condition_fingerprints,error_signature:null,target_snapshot:details.snapshot}).find(item=>item.failed_attempt_id===request.reference_id); if(!attempt)return this.pause(request,details,'before_known_failure_action','REFERENCE_MISMATCH'); const codes=outcome.decisions.flatMap(item=>item.reason_codes); if(outcome.decisions.some(item=>item.outcome==='EXACT_KNOWN_FAILURE')) return this.decide(request,'before_known_failure_action','BLOCK',['EXACT_KNOWN_FAILURE',...codes],details,'FAILED_ATTEMPT',hash(attempt)); if(outcome.outcome==='CONDITION_CHANGED'&&match.outcome==='CONDITION_CHANGED'&&outcome.decisions.every(item=>item.outcome==='CONDITION_CHANGED'))return this.decide(request,'before_known_failure_action','ALLOW',[outcome.outcome,...codes],details,'FAILED_ATTEMPT',hash(attempt)); return this.decide(request,'before_known_failure_action','PAUSE',['FAILURE_CLASSIFICATION_UNKNOWN',...codes],details,'FAILED_ATTEMPT',hash(attempt)); }
    catch { return this.pause(request,details,'before_known_failure_action','CORE_DECISION_UNAVAILABLE'); }
  }
  execute(request: GuardCheckRequest, permit: GuardPermit, marker: ControlledWriteMarker, currentSnapshot: Snapshot, currentConditions: Record<string,string>): GuardDecisionResult {
    let details:ReturnType<ReferenceGuard['validate']>; try { details=this.validate(request); } catch { return 'PAUSE'; }
    let actionStarted=false, actionApplied=false;
    try {
      const manifest=this.manifests.get(request.run_id); if (!manifest || this.auditFailed || marker.marker_id!==request.action.marker_id || contentHash(validateSnapshot(currentSnapshot))!==permit.target_snapshot_hash || contentHash(details.snapshot)!==permit.target_snapshot_hash || hash(currentConditions)!==permit.condition_fingerprints_hash || details.condition_fingerprints_hash!==permit.condition_fingerprints_hash || details.action_fingerprint!==permit.action_fingerprint || permit.run_id!==request.run_id || permit.project_id!==request.project_id || permit.workspace_id!==request.workspace_id) return this.recordDrift(request,details,permit);
      const records=this.storage.readGuardAuditRecords(request.run_id), stored=records.find(record=>record.kind==='permit'&&record.record_id===permit.permit_id);
      const decision=records.find(record=>record.kind==='decision'&&record.record_id===permit.decision_id), binding=this.binding(request,details), action=this.actionSummary(request.action); if (!this.verifyMirror(request.run_id,records) || !stored || !decision || stored.decision_id!==permit.decision_id || stored.action_fingerprint!==permit.action_fingerprint || canonical(stored.payload)!==canonical({permit,binding,action}) || (decision.payload as Record<string,unknown>).result!=='ALLOW' || canonical((decision.payload as Record<string,unknown>).binding)!==canonical(binding)) return this.recordDrift(request,details,permit);
      const reservation=this.nextRecord(request,'reservation',{decision_id:permit.decision_id,permit_id:permit.permit_id,action_fingerprint:permit.action_fingerprint,payload:{state:'RESERVED',target_snapshot_hash:permit.target_snapshot_hash,condition_fingerprints_hash:permit.condition_fingerprints_hash}});
      if (!this.reserve(reservation)) return 'PAUSE';
      const execution=this.nextRecord(request,'execution',{decision_id:permit.decision_id,permit_id:permit.permit_id,action_fingerprint:permit.action_fingerprint,payload:{state:'STARTED',action_id:request.action.action_id,marker_id:request.action.marker_id,value_hash:sha256(request.action.value)}});
      if (!this.persist(execution)) return 'PAUSE';
      // Once apply is entered, an exception cannot establish that no side effect occurred.
      actionStarted=true;
      try { marker.apply(request.action); actionApplied=true; } catch { this.persist(this.nextRecord(request,'execution',{decision_id:permit.decision_id,permit_id:permit.permit_id,action_fingerprint:permit.action_fingerprint,payload:{state:'UNKNOWN',reason:'ACTION_OUTCOME_UNKNOWN',action_id:request.action.action_id,marker_id:request.action.marker_id,value_hash:sha256(request.action.value)}})); return 'UNKNOWN'; }
      const completed=this.nextRecord(request,'execution',{decision_id:permit.decision_id,permit_id:permit.permit_id,action_fingerprint:permit.action_fingerprint,payload:{state:'SUCCEEDED',action_id:request.action.action_id,marker_id:request.action.marker_id,value_hash:sha256(request.action.value)} });
      if (!this.persist(completed)) return 'EXECUTED_AUDIT_FAILURE';
      const receipt=this.nextRecord(request,'receipt',{decision_id:permit.decision_id,permit_id:permit.permit_id,action_fingerprint:permit.action_fingerprint,payload:{outcome:'EXECUTED',action_id:request.action.action_id,marker_id:request.action.marker_id,value_hash:sha256(request.action.value)}});
      if (!this.persist(receipt,true)) return 'EXECUTED_AUDIT_FAILURE';
      return 'ALLOW';
    } catch { this.auditFailed=true; return actionApplied?'EXECUTED_AUDIT_FAILURE':actionStarted?'UNKNOWN':'PAUSE'; }
  }
  private recordDrift(request: GuardCheckRequest, details: ReturnType<ReferenceGuard['validate']>, permit: GuardPermit): GuardDecisionResult {
    const manifest=this.manifests.get(permit.run_id); if (!manifest) return 'PAUSE';
    const stored=this.storage.readGuardAuditRecords(permit.run_id).find(record=>record.kind==='permit'&&record.record_id===permit.permit_id);
    if (!stored) return 'PAUSE';
    this.persist(this.nextRecord(manifest,'checkpoint',{decision_id:stored.decision_id,permit_id:stored.permit_id,action_fingerprint:stored.action_fingerprint,payload:{checkpoint:'consumed',outcome:'PAUSED',reason:'POST_CHECK_DRIFT',binding:stored.payload.binding,attempted_binding:this.binding(request,details),attempted_permit_hash:hash(permit)}})); return 'PAUSE';
  }
}
