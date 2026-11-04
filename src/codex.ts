import type { PhysicalReadSession } from './physical-readonly.js';
import fs from 'node:fs';
import { initProject, doctorProject, readProjectConfig, serializeError } from './index.js';
import { SqliteMemoryStorage, StorageError } from './storage.js';
import { PathsError, withPathValidationScope } from './paths.js';
import { configureStorageLocation, withStorageLocationLock, readStorageLocationAtProjectRoot, resolveMemoryStorageRoot, type StorageLocationConfigureInput } from './storage-location.js';
import { StorageExecutionProvenance } from './provenance.js';
import { verifyEvidence, EVIDENCE_POLICY } from './evidence.js';
import { compileContext, type ContextRequest, type ContextPack } from './context.js';
import { acknowledgeHandoff, prepareHandoff, recoverHandoffSession, validateHandoff, type HandoffAcknowledgement, type HandoffPrepareRequest } from './handoff.js';
import type { Evidence, Snapshot } from './contracts.js';
import { RETENTION_POLICY_VERSION, createCleanupPlan } from './lifecycle.js';
import { createDependencyReadBoundary,type DependencyReadOptions } from './dependency-read-boundary.js';

export type CodexResult = { ok: true; value: unknown } | { ok: false; error: { code: string; message: string }; diagnostics?: unknown };

function failure(error: unknown): CodexResult {
  const serialized = serializeError(error);
  if (!serialized.ok && serialized.error.code !== 'IO_ERROR') return serialized;
  const value = error as { code?: unknown; message?: unknown };
  return { ok: false, error: { code: typeof value?.code === 'string' ? value.code : 'INTERNAL_ERROR', message: typeof value?.message === 'string' ? value.message : 'XMem operation failed' } };
}

/** Opens only the initialized project's own .xmem directory and always closes it. */
export function withProject<T>(projectRoot: string, operation: (storage: SqliteMemoryStorage) => T, options: {readOnly?:boolean;expectedStorageLocationHash?:string;physicalRead?:PhysicalReadSession} = {}): CodexResult {
  return withPathValidationScope(() => {
    let storage: SqliteMemoryStorage | undefined;
    try {
      // Configuration/path checks only; doctor must not be a mutating store initializer.
      options.physicalRead?.check();
      const config = readProjectConfig(projectRoot);
      if(options.expectedStorageLocationHash!==undefined){
        if(options.readOnly||!/^[a-f0-9]{64}$/.test(options.expectedStorageLocationHash))throw new PathsError('INVALID_INPUT','Expected location requires an explicit writer hash');
        // Guarded capture only: compare before opening any store, and keep the
        // same owner location lock through operation/close. Do not nest open's lock.
        return withStorageLocationLock(config.root,()=>{
          const location=readStorageLocationAtProjectRoot(config.root,config.project_id);
          if(!location.configured||location.location_hash!==options.expectedStorageLocationHash)throw new PathsError('IDENTITY_CONFLICT','Capture storage location changed before write');
          storage=new SqliteMemoryStorage({root:location.storage_root});
          try{return{ok:true,value:operation(storage)};}
          finally{const closing=storage;storage=undefined;closing.close();}
        });
      }
      const open=()=>{
        const root=resolveMemoryStorageRoot(config.root,config.project_id);
        if(!fs.existsSync(root))throw new Error('Project storage is missing');
        return new SqliteMemoryStorage({root,readOnly:options.readOnly,physicalRead:options.physicalRead});
      };
      // Serialize only a writer's first/open phase with owner location changes.
      // Once SQLite exists, the existing no-implicit-migration gate blocks moves.
      storage=options.readOnly?open():withStorageLocationLock(config.root,open);
      return { ok: true, value: operation(storage) };
    } catch (error) { return failure(error); }
    finally { storage?.close(); }
  });
}

export function codexInit(projectRoot: string): CodexResult { try { return { ok: true, value: initProject(projectRoot) }; } catch (error) { return failure(error); } }
export function codexDoctor(projectRoot: string): CodexResult {
  try {
    const report = doctorProject(projectRoot);
    return report.ok ? {ok:true,value:report} : {ok:false,error:{code:'STORAGE_'+report.storage.status,message:'Storage health check did not pass; inspect diagnostics before use'},diagnostics:report};
  } catch (error) { return failure(error); }
}

export function codexStorageStatus(projectRoot:string):CodexResult {
  try {
    const report=doctorProject(projectRoot),config=report.config;
    if(report.storage.status==='NOT_CREATED')return{ok:true,value:{storage_health:report.storage,storage_location:report.storage_location,lifecycle:null,cleanup_available:false,reason_codes:['NO_DATABASE_YET']}};
    if(report.storage.status!=='OK')return{ok:false,error:{code:'STORAGE_'+report.storage.status,message:'Storage health check did not pass; cleanup/lifecycle status is unavailable'},diagnostics:report};
    return withProject(projectRoot,storage=>({storage_health:report.storage,storage_location:report.storage_location,lifecycle:storage.getStorageLifecycleStatus(config.project_id),cleanup_available:true,reason_codes:['LIFECYCLE_STATUS_AVAILABLE']}));
  } catch(error){return failure(error);}
}
export function codexCleanupPreview(projectRoot:string):CodexResult {
  try {
    const report=doctorProject(projectRoot),config=report.config;
    if(report.storage.status==='NOT_CREATED')return{ok:true,value:createCleanupPlan(config.project_id,[])};
    if(report.storage.status!=='OK')return{ok:false,error:{code:'STORAGE_'+report.storage.status,message:'Storage health check did not pass; cleanup preview is unavailable'},diagnostics:report};
    return withProject(projectRoot,storage=>storage.previewCleanup(config.project_id));
  } catch(error){return failure(error);}
}
export function codexCleanupApply(projectRoot:string,input:{confirm:true;plan_hash:string}):CodexResult {
  try {
    if(!input||input.confirm!==true||typeof input.plan_hash!=='string')throw new StorageError('INVALID_INPUT','Cleanup apply requires explicit confirmation and an exact preview plan hash');
    const report=doctorProject(projectRoot),config=report.config;
    if(report.storage.status==='NOT_CREATED'){
      const empty=createCleanupPlan(config.project_id,[]);if(empty.plan_hash!==input.plan_hash)throw new StorageError('IDENTITY_CONFLICT','Cleanup plan changed; request a new preview before applying');
      return{ok:true,value:{kind:'xmem-cleanup-result',policy_version:RETENTION_POLICY_VERSION,project_id:config.project_id,applied_plan_hash:input.plan_hash,deleted:{CONTEXT_MANIFEST:0,ARTIFACT_ROW:0,ARTIFACT_FILE:0},estimated_bytes_targeted:0,physical_artifact_bytes_removed:0,remaining_prunable_candidates:0,artifact_file_cleanup_incomplete:false,reason_codes:['NO_DATABASE_YET']}};
    }
    if(report.storage.status!=='OK')return{ok:false,error:{code:'STORAGE_'+report.storage.status,message:'Storage health check did not pass; cleanup apply is unavailable'},diagnostics:report};
    return withProject(projectRoot,storage=>storage.applyCleanup(config.project_id,input.plan_hash));
  } catch(error){return failure(error);}
}
export function codexStorageCompact(projectRoot:string,input:{confirm:true}):CodexResult {
  try {
    if(!input||input.confirm!==true)throw new StorageError('INVALID_INPUT','Storage compaction requires explicit confirmation');
    const report=doctorProject(projectRoot),config=report.config;if(report.storage.status==='NOT_CREATED')throw new StorageError('SOURCE_MISSING','Storage database does not exist');
    if(report.storage.status!=='OK')return{ok:false,error:{code:'STORAGE_'+report.storage.status,message:'Storage health check did not pass; compaction is unavailable'},diagnostics:report};
    return withProject(projectRoot,storage=>storage.compactStorage(config.project_id));
  } catch(error){return failure(error);}
}

export function codexStorageLocationStatus(projectRoot: string): CodexResult {
  try { const config=readProjectConfig(projectRoot); return {ok:true,value:readStorageLocationAtProjectRoot(config.root,config.project_id)}; } catch (error) { return failure(error); }
}
export function codexConfigureStorageLocation(projectRoot:string,input:StorageLocationConfigureInput):CodexResult {
  try { const config=readProjectConfig(projectRoot); return {ok:true,value:configureStorageLocation(projectRoot,config.project_id,input)}; } catch(error){ return failure(error); }
}

export function codexTrustedEvidence(projectRoot: string, evidenceId: string): CodexResult {
  return withProject(projectRoot, storage => {
    const observed = new StorageExecutionProvenance(storage).resolve(evidenceId);
    return observed ? {
      trusted: true,
      evidence: {
        evidence_id: observed.evidence.evidence_id,
        project_id: observed.evidence.project_id,
        workspace_id: observed.evidence.workspace_id,
        run_id: observed.evidence.run_id,
        snapshot_id: observed.evidence.snapshot_id,
        result: observed.evidence.result,
        exit_code: observed.evidence.exit_code,
        recorded_at: observed.evidence.recorded_at,
        source: { source_id: observed.evidence.source.source_id, kind: observed.evidence.source.kind },
      },
    } : { trusted: false, evidence_id: evidenceId, reason_codes: ['SOURCE_MISSING_OR_UNTRUSTED'] };
  });
}
export function codexVerifyEvidence(projectRoot: string, evidence: Evidence, targetSnapshot: Snapshot): CodexResult {
  return withProject(projectRoot, storage => verifyEvidence(evidence, targetSnapshot, EVIDENCE_POLICY, new StorageExecutionProvenance(storage)));
}

export interface CodexContextCompile { request: ContextRequest; source_bytes: Array<{ source_id: string; bytes_base64: string }>; }
export function codexCompileContext(projectRoot: string, input: CodexContextCompile,options?:DependencyReadOptions): CodexResult {
  return withProject(projectRoot, storage => {
    if (input.request.project_id !== readProjectConfig(projectRoot).project_id) throw new StorageError('PROJECT_MISMATCH','Request does not belong to this initialized project');
    if (!Array.isArray(input.source_bytes) || input.source_bytes.length>256 || new Set(input.source_bytes.map(x=>x.source_id)).size!==input.source_bytes.length || input.source_bytes.some(x=>typeof x.bytes_base64!=='string'||x.bytes_base64.length>2*1024*1024)) throw new StorageError('INVALID_INPUT','Invalid or oversized source byte input');
    const sources = new Map(input.source_bytes.map(item => [item.source_id, Buffer.from(item.bytes_base64, 'base64')]));
    const boundary=createDependencyReadBoundary(projectRoot,storage,input.request,options);
    const request=boundary.context?.allowedSourceIds===undefined?input.request:{...input.request,allowed_source_ids:[...boundary.context.allowedSourceIds]};
    boundary.chargeView();const view=storage.readContextView(request);boundary.chargeViewBytes(view.entries);const before=boundary.check(view.entries);
    // Caller bytes retain their old declaration semantics; only the independent
    // live boundary may establish dependency source observations.
    const pack = compileContext(request, view, { read: source => {
      const declared=sources.get(source.source_id);if(!options)return declared;
      const actual=boundary.read(source);return actual&&declared&&actual.equals(declared)?declared:undefined;
    } });
    if(options&&pack.coverage.some(item=>item.reason==='source_unavailable'||item.reason==='source_changed'))throw new PathsError('INPUT_INCOMPLETE','Declared source bytes do not match live sources');
    boundary.assertUsable();
    const manifest=storage.persistContextManifest(pack);
    boundary.chargeView();const after=storage.readContextView(request);boundary.chargeViewBytes(after.entries);if(after.snapshot_hash!==view.snapshot_hash)throw new StorageError('INPUT_INCOMPLETE','Context changed');boundary.verify(after.entries,before);
    return {...manifest,diagnostics:describeContext(pack,'CALLER_SUPPLIED_BYTES')};
  });
}
export function codexReadManifest(projectRoot: string, contentHash: string, request?: ContextRequest): CodexResult {
  return withProject(projectRoot, storage => {const manifest=storage.getContextManifest(contentHash,request);return manifest?{...manifest,applicability:'NOT_EVALUATED',live_dependency_verification:false}:null;});
}
export function codexPrepareHandoff(projectRoot: string, input: HandoffPrepareRequest,options?:DependencyReadOptions): CodexResult { return withProject(projectRoot, storage => prepareHandoff(storage, input,{projectRoot,options})); }
export function codexValidateHandoff(projectRoot: string, packageId: string,options?:DependencyReadOptions): CodexResult { return withProject(projectRoot, storage => validateHandoff(storage, packageId,{projectRoot,options})); }
export function codexAcknowledgeHandoff(projectRoot: string, packageId: string, acknowledgement: HandoffAcknowledgement,options?:DependencyReadOptions): CodexResult { return withProject(projectRoot, storage => acknowledgeHandoff(storage, packageId, acknowledgement,{projectRoot,options})); }
export function codexRecoverHandoff(projectRoot: string, packageId: string,options?:DependencyReadOptions): CodexResult { return withProject(projectRoot, storage => recoverHandoffSession(storage, packageId,{projectRoot,options})); }

/** Transient result diagnostics, deliberately not part of the persisted pack hash. */
export function describeContext(pack: ContextPack, freshnessMode: 'CALLER_SUPPLIED_BYTES'|'LIVE_LOCAL_SOURCE_READ') {
  const reasons: string[]=[];
  if (pack.coverage.length===0) reasons.push('NO_MATCHING_ACTIVE_BINDINGS');
  for (const item of pack.coverage) if(item.state!=='included_inline' && !reasons.includes(item.reason)) reasons.push(item.reason);
  if (pack.traversal_incomplete) reasons.push('TRAVERSAL_INCOMPLETE');
  const status=pack.payload_bytes===0?'EMPTY':reasons.length?'PARTIAL':'READY';
  return {status,reason_codes:reasons.length?reasons:['CONTEXT_COMPILED'],freshness_mode:freshnessMode,execution_verified:false,meaning:'READY describes selected context, not product readiness or trusted execution'};
}
