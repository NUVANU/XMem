/** Internal local-context hot path. Not exposed by the xmem/local package entry. */
import { readProjectConfig } from './index.js';
import { describeContext } from './codex.js';
import { StorageError, type SqliteMemoryStorage, type ContextManifest } from './storage.js';
import { compileContext, summarizeContextResolution, type ContextRequest, type ContextPack } from './context.js';
import { validateSnapshot, type Snapshot, type SourceRef } from './contracts.js';
import { hashBytes, readLocalSource, readSourceReference, validateLocalSnapshotInput, type LocalSnapshotInput } from './local-source.js';
import { contentHash } from './evidence.js';
import { createDependencyReadBoundary,type DependencyReadOptions,type DependencyReadSession } from './dependency-read-boundary.js';

export function readCurrentSourceReference(root:string, storage:SqliteMemoryStorage, projectId:string, source:SourceRef):Buffer|undefined {
  return readSourceReference(root,projectId,source) ?? storage.readHostCandidateSource(projectId,source);
}

export function currentFileSnapshot(root: string, projectId: string, input: LocalSnapshotInput): Snapshot {
  const x=validateLocalSnapshotInput(input);
  // Two bounded reads per approved file preserve the R3.1.2 drift check. The
  // expensive Windows drive-class verification is cached in paths.ts rather than
  // weakening this source-integrity pass.
  const initial=x.files.map(file=>{const material=readLocalSource(root,file);return{file,digest:hashBytes(material.bytes)};});
  const empty=contentHash([]),missing=['dependency_closure_not_proven','environment_not_controlled','test_inputs_not_collected','external_state'];
  const manifest:Snapshot['manifest']={completeness:'INCOMPLETE',missing,files_hash:contentHash(initial.map(item=>[item.file,item.digest])),test_definition_hash:empty,config_hash:empty,dependencies_hash:empty,fixtures_hash:empty,command:'xmem:declared-file-observation',args:[],toolchain_hash:contentHash({node:process.version,platform:process.platform,arch:process.arch}),environment_hash:contentHash({mode:'local-observation'}),external_state:'UNKNOWN'};
  const snapshot=validateSnapshot({schema_version:'1',snapshot_id:contentHash({project_id:projectId,workspace_id:x.workspace_id,manifest}),project_id:projectId,workspace_id:x.workspace_id,captured_at:new Date().toISOString(),manifest});
  for(const {file,digest} of initial)if(hashBytes(readLocalSource(root,file).bytes)!==digest)throw new StorageError('SOURCE_MISSING','Source changed during snapshot collection');
  return snapshot;
}

export function captureLocalSnapshotWithStorage(projectRoot:string,storage:SqliteMemoryStorage,input:LocalSnapshotInput) {
  const config=readProjectConfig(projectRoot),observed=currentFileSnapshot(projectRoot,config.project_id,input);
  const snapshot=storage.recordSnapshot(observed);
  return {snapshot,observed_at:observed.captured_at,stored:true,scope:'EXPLICIT_FILES_ONLY',execution_verified:false};
}

function requireLocalScope(root: string, storage: SqliteMemoryStorage, request: ContextRequest): void {
  const config = readProjectConfig(root);
  if (request.project_id !== config.project_id) throw new StorageError('PROJECT_MISMATCH','Request does not belong to this initialized project');
  if (!storage.getSnapshot(request.target_snapshot_id,request.project_id,request.workspace_id)) throw new StorageError('SOURCE_MISSING','Capture and store the target snapshot before compilation');
}

export interface LocalContextTelemetry {
  freshness_ms:number;
  context_compile_ms:number;
  candidate_records:number;
  selected_records:number;
  deduplicated_records:number;
  authority_suppressed_records:number;
  unresolved_conflicts:number;
  source_bytes_considered:number;
  context_bytes_emitted:number;
  estimated_context_tokens:number;
  token_estimate_method:'UTF8_BYTES_DIV_4_APPROXIMATION';
  cache_hit:boolean;
  changed_files:number|null;
  changed_files_known:boolean;
}
export interface LocalContextCompileWithStorageResult { context:ContextManifest & {diagnostics:ReturnType<typeof describeContext>}; telemetry:LocalContextTelemetry; dependencySession?:DependencyReadSession; verify:()=>void; }

function validateReusableLocalManifest(projectRoot:string,storage:SqliteMemoryStorage,request:ContextRequest,manifest:ContextManifest,view:ReturnType<SqliteMemoryStorage['readContextView']>,read:(source:SourceRef)=>Buffer|undefined):{ok:boolean;source_bytes:number;freshness_ms:number} {
  const started=performance.now();
  if(manifest.view_snapshot_hash!==view.snapshot_hash)return{ok:false,source_bytes:0,freshness_ms:performance.now()-started};
  const records=new Map(view.entries.map(entry=>[entry.record.revision_id,entry.record]));
  const sources:SourceRef[]=[];
  for(const revisionId of manifest.revisions){const record=records.get(revisionId);if(!record)return{ok:false,source_bytes:0,freshness_ms:performance.now()-started};sources.push(record.source);}
  const unique=new Map<string,number>();
  // Two live passes preserve the compiler's source-drift safety property while
  // avoiding full graph selection/serialization on unchanged sessions.
  for(let pass=0;pass<2;pass++)for(const source of sources){let bytes:Buffer|undefined;try{bytes=read(source);}catch{return{ok:false,source_bytes:[...unique.values()].reduce((a,b)=>a+b,0),freshness_ms:performance.now()-started};}if(!bytes||hashBytes(bytes)!==source.content_hash)return{ok:false,source_bytes:[...unique.values()].reduce((a,b)=>a+b,0),freshness_ms:performance.now()-started};if(pass===0)unique.set(source.source_id,bytes.byteLength);}
  return{ok:true,source_bytes:[...unique.values()].reduce((a,b)=>a+b,0),freshness_ms:performance.now()-started};
}

/** R3.1.2 single-storage fast path with exact request/view/source validation. */
export function compileLocalContextWithStorage(projectRoot:string,storage:SqliteMemoryStorage,request:ContextRequest,allowReuse=true,options?:DependencyReadOptions,session?:DependencyReadSession):LocalContextCompileWithStorageResult {
  requireLocalScope(projectRoot,storage,request);
  const boundary=createDependencyReadBoundary(projectRoot,storage,request,options,session);
  if(boundary.context?.allowedSourceIds!==undefined)request={...request,allowed_source_ids:[...boundary.context.allowedSourceIds]};
  boundary.chargeView();
  const viewStarted=performance.now(),view=storage.readContextView(request),viewMs=performance.now()-viewStarted;
  boundary.chargeViewBytes(view.entries);const dependencyHash=boundary.check(view.entries);
  const finish=()=>{boundary.chargeView();const after=storage.readContextView(request);boundary.chargeViewBytes(after.entries);if(after.snapshot_hash!==view.snapshot_hash)throw new StorageError('INPUT_INCOMPLETE','Context changed during dependency verification');boundary.verify(after.entries,dependencyHash);};
  const latestScope=storage.getLatestContextManifestForScope(request.project_id,request.workspace_id,request.task_ref,request.task_version);
  if(allowReuse){
    const reusable=storage.getLatestReusableContextManifest(request);
    if(reusable){
      const checked=validateReusableLocalManifest(projectRoot,storage,request,reusable,view,boundary.read);
      if(checked.ok){finish();const diagnostics=describeContext(reusable as ContextPack,'LIVE_LOCAL_SOURCE_READ'),resolution=summarizeContextResolution(view,reusable as ContextPack);return{context:{...reusable,diagnostics},dependencySession:boundary.session,verify:finish,telemetry:{freshness_ms:Math.round((viewMs+checked.freshness_ms)*1000)/1000,context_compile_ms:0,candidate_records:resolution.candidate_records,selected_records:resolution.selected_records,deduplicated_records:resolution.deduplicated_records,authority_suppressed_records:resolution.authority_suppressed_records,unresolved_conflicts:resolution.unresolved_conflicts,source_bytes_considered:options?boundary.sourceBytes():checked.source_bytes,context_bytes_emitted:reusable.payload_bytes,estimated_context_tokens:Math.ceil(reusable.payload_bytes/4),token_estimate_method:'UTF8_BYTES_DIV_4_APPROXIMATION',cache_hit:true,changed_files:0,changed_files_known:true}};}
    }
  }
  let sourceReadMs=0;const uniqueBytes=new Map<string,number>();
  const resolver={read:(source:SourceRef)=>{const started=performance.now();try{const bytes=boundary.read(source);if(bytes&&!uniqueBytes.has(source.source_id))uniqueBytes.set(source.source_id,bytes.byteLength);return bytes;}finally{sourceReadMs+=performance.now()-started;}}};
  const compileStarted=performance.now(),pack=compileContext(request,view,resolver);boundary.assertUsable();const manifest=storage.persistContextManifest(pack);finish();const compileMs=performance.now()-compileStarted,resolution=summarizeContextResolution(view,pack);
  const sameSnapshot=latestScope?.request.target_snapshot_id===request.target_snapshot_id;
  return{context:{...manifest,diagnostics:describeContext(pack,'LIVE_LOCAL_SOURCE_READ')},dependencySession:boundary.session,verify:finish,telemetry:{freshness_ms:Math.round((viewMs+sourceReadMs)*1000)/1000,context_compile_ms:Math.round(compileMs*1000)/1000,candidate_records:resolution.candidate_records,selected_records:resolution.selected_records,deduplicated_records:resolution.deduplicated_records,authority_suppressed_records:resolution.authority_suppressed_records,unresolved_conflicts:resolution.unresolved_conflicts,source_bytes_considered:options?boundary.sourceBytes():[...uniqueBytes.values()].reduce((a,b)=>a+b,0),context_bytes_emitted:pack.payload_bytes,estimated_context_tokens:Math.ceil(pack.payload_bytes/4),token_estimate_method:'UTF8_BYTES_DIV_4_APPROXIMATION',cache_hit:false,changed_files:sameSnapshot?0:null,changed_files_known:!!sameSnapshot}};
}
