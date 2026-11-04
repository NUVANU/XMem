/** Supported local-file adapter. It captures declarations, never execution PASS evidence. */
import { readProjectConfig } from './index.js';
import { withProject, type CodexResult, describeContext } from './codex.js';
import { StorageError, type HandoffValidationStatus } from './storage.js';
import { compileContext, canonicalContextJson, type ContextRequest, type ContextBinding } from './context.js';
import { type MemoryRecord } from './contracts.js';
import { hashBytes, localSourceRef, readLocalSource, validateLocalMemoryInput, validateLocalSnapshotInput, type LocalMemoryInput, type LocalSnapshotInput } from './local-source.js';
import { captureLocalSnapshotWithStorage, compileLocalContextWithStorage, currentFileSnapshot, readCurrentSourceReference } from './local-runtime.js';
import { createDependencyReadBoundary,type DependencyReadOptions } from './dependency-read-boundary.js';
export { registerEngineeringDependencies as registerMemoryDependencies,revokeEngineeringDependencies as revokeMemoryDependencies } from './engineering-memory.js';
export type { EngineeringDependencyHandle,EngineeringDependencyOptions } from './engineering-dependencies.js';

export type { LocalMemoryInput, LocalSnapshotInput } from './local-source.js';
export function captureLocalMemory(projectRoot: string, input: LocalMemoryInput): CodexResult {
  return withProject(projectRoot, storage => {
    const x = validateLocalMemoryInput(input), config = readProjectConfig(projectRoot);
    const material = readLocalSource(projectRoot, x.source_path);
    if (!material.text.includes(x.excerpt)) throw new StorageError('INVALID_INPUT', 'Excerpt must appear verbatim in the current source; no invented memory text');
    const source = localSourceRef(config.project_id, material.relative, material.bytes);
    const record_id = 'local-memory-' + hashBytes(canonicalContextJson([config.project_id,x.workspace_id,x.task_ref,x.task_version,x.memory_key]));
    const epistemic_state = x.kind === 'RootCauseHypothesis' ? 'HYPOTHESIS' as const : 'ASSERTED' as const;
    const information_role = x.kind === 'ConstraintRef' || x.kind === 'DecisionRef' ? 'NORMATIVE_REF' as const : x.kind === 'FailedAttempt' ? 'EXPERIENCE' as const : 'SUGGESTION' as const;
    // IDs commit the selected source, text, predecessor, task, and access policy.
    const revision_id = 'local-revision-' + hashBytes(canonicalContextJson({record_id,source,excerpt:x.excerpt,kind:x.kind,roles:x.roles,mandatory:x.mandatory,previous_revision_id:x.previous_revision_id}));
    const record: MemoryRecord = {schema_version:'1',record_id,revision_id,project_id:config.project_id,kind:x.kind,source,epistemic_state,lifecycle:'ACTIVE',information_role,content:x.excerpt,previous_revision_id:x.previous_revision_id};
    const binding: ContextBinding = {revision_id,project_id:config.project_id,workspace_id:x.workspace_id,task_ref:x.task_ref,task_version:x.task_version,roles:x.roles,allowed_source_ids:[source.source_id],mandatory:x.mandatory,priority:0,conflicts:[]};
    if (hashBytes(readLocalSource(projectRoot, material.relative).bytes) !== source.content_hash) throw new StorageError('SOURCE_MISSING', 'Source changed before intake; nothing was recorded');
    const receipt = storage.recordMemoryCapture(record, binding);
    return {...receipt,project_id:config.project_id,workspace_id:x.workspace_id,task_ref:x.task_ref,task_version:x.task_version,epistemic_state,information_role,execution_verified:false,owner_confirmation_verified:false,record_type:x.kind==='FailedAttempt'?'FAILURE_EXPERIENCE_NOT_TRUSTED_FAILURE_REGISTRY':'FILE_ASSERTION'};
  });
}

export function captureLocalSnapshot(projectRoot: string, input: LocalSnapshotInput): CodexResult {
  return withProject(projectRoot, storage => captureLocalSnapshotWithStorage(projectRoot,storage,input));
}
/** Live reads of permitted local source references; no caller-supplied old bytes. */
export function compileLocalContext(projectRoot: string, request: ContextRequest,options?:DependencyReadOptions): CodexResult {
  return withProject(projectRoot, storage => compileLocalContextWithStorage(projectRoot,storage,request,true,options).context);
}
export interface LocalHandoffRecoveryInput { package_id:string; snapshot_files:string[]; }
/** Fresh local-source and declared-file checks; VALID does not authorize task execution. */
export function recoverLocalHandoff(projectRoot: string, input: LocalHandoffRecoveryInput,options?:DependencyReadOptions): CodexResult {
  return withProject(projectRoot, storage => {
    if (!input || Object.keys(input).sort().join(',')!=='package_id,snapshot_files' || typeof input.package_id!=='string' || !input.package_id.trim()) throw new StorageError('INVALID_INPUT','Invalid local recovery input');
    const config=readProjectConfig(projectRoot), pack=storage.getHandoffPackage(input.package_id);
    const baseline=storage.validateHandoff(input.package_id);
    const result=(status:HandoffValidationStatus, reason:string, context:unknown=null)=>({validation:{...baseline,status,reason_codes:[reason]},scope:'STORED_MATERIAL_AND_EXPLICIT_LOCAL_FILES',execution_verified:false,context});
    if (!pack) return result('INCOMPLETE','PACKAGE_MISSING');
    if (pack.project_id!==config.project_id) throw new StorageError('PROJECT_MISMATCH','Handoff belongs to another project');
    const snapshotInput=validateLocalSnapshotInput({workspace_id:pack.workspace_id,files:input.snapshot_files});
    if (baseline.status!=='VALID') return {...result(baseline.status,baseline.reason_codes[0]??'MATERIAL_UNAVAILABLE'),validation:baseline};
    const target=storage.getSnapshot(pack.target_snapshot_id,pack.project_id,pack.workspace_id);
    if (!target) return result('INCOMPLETE','TARGET_SNAPSHOT_MISSING');
    // This adapter only knows its own explicit-file snapshot recipe. It does not
    // reclassify opaque imported/executor snapshots as freshly observed.
    if (target.manifest.command!=='xmem:declared-file-observation') return result('UNKNOWN','UNSUPPORTED_SNAPSHOT_RECIPE');
    try {
      const now=currentFileSnapshot(projectRoot,config.project_id,snapshotInput);
      if (canonicalContextJson(now.manifest)!==canonicalContextJson(target.manifest)) return result('STALE','DECLARED_FILES_OR_RUNTIME_CHANGED');
      const manifest=storage.getContextManifest(pack.context_manifest_hash);
      if (!manifest) return result('INCOMPLETE','CONTEXT_MANIFEST_MISSING');
      const boundary=createDependencyReadBoundary(projectRoot,storage,manifest.request,options);
      boundary.chargeView();const view=storage.readContextView(manifest.request);boundary.chargeViewBytes(view.entries);const before=boundary.check(view.entries);
      for (const source of pack.source_refs) {
        const bytes=boundary.read(source);
        if (!bytes) return result('UNKNOWN','UNSUPPORTED_LIVE_SOURCE');
        if (hashBytes(bytes)!==source.content_hash) return result('STALE','LOCAL_SOURCE_CHANGED');
      }
      const rebuilt=compileContext(manifest.request,view,{read:boundary.read});
      boundary.assertUsable();
      if (rebuilt.content_hash!==manifest.content_hash) {
        const oldSet=new Set(manifest.revisions),newSet=new Set(rebuilt.revisions),equivalentUpgrade=manifest.policy_version==='context-policy-v1'&&rebuilt.policy_version==='context-policy-v2'&&oldSet.size===newSet.size&&[...oldSet].every(id=>newSet.has(id))&&manifest.source_snapshot_hash===rebuilt.source_snapshot_hash&&manifest.view_snapshot_hash===rebuilt.view_snapshot_hash;
        if(!equivalentUpgrade)return result('STALE','CONTEXT_RECOMPILE_CHANGED');
      }
      // Final snapshot pass detects changes while source/context checks ran.
      if (canonicalContextJson(currentFileSnapshot(projectRoot,config.project_id,snapshotInput).manifest)!==canonicalContextJson(target.manifest)) return result('STALE','DECLARED_FILES_CHANGED_DURING_RECOVERY');
      boundary.chargeView();const after=storage.readContextView(manifest.request);boundary.chargeViewBytes(after.entries);if(after.snapshot_hash!==view.snapshot_hash)return result('INCOMPLETE','LOCAL_MATERIAL_UNAVAILABLE');boundary.verify(after.entries,before);
      return result('VALID','DECLARED_LOCAL_MATERIAL_CURRENT_NOT_EXECUTION_PROOF',{...rebuilt,diagnostics:describeContext(rebuilt,'LIVE_LOCAL_SOURCE_READ')});
    } catch (error) {
      const code=(error as {code?:string}).code;
      if (['SOURCE_MISSING','UNSAFE_SOURCE','UNSAFE_PATH','LINK_PATH','SOURCE_DRIFT','INPUT_INCOMPLETE'].includes(code??'')) return result('INCOMPLETE','LOCAL_MATERIAL_UNAVAILABLE');
      return result('UNKNOWN','LOCAL_VALIDATION_FAILED');
    }
  });
}
