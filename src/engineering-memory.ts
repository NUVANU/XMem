import { runPhysicalRead, type PhysicalReadOptions, type PhysicalReadSession } from './physical-readonly.js';
/** V2.1 explicit, exact-task engineering recall. No automatic capture or execution. */
import fs from 'node:fs';
import { z } from 'zod';
import { readProjectConfig, resolveProjectRoot, resolveProjectPath } from './index.js';
import { PathsError, withPathValidationScope } from './paths.js';
import { withProject, type CodexResult } from './codex.js';
import { captureStandaloneMemory, readStandalonePolicy, type ExpectedCaptureScope } from './standalone.js';
import { readStorageLocationAtProjectRoot } from './storage-location.js';
import { canonicalContextJson, compileContext, contextAuthority, type ContextEntry } from './context.js';
import { hashBytes, normalizeLocalSourcePath } from './local-source.js';
import { readCurrentSourceReference } from './local-runtime.js';
import { engineeringRetrievalPathCache } from './local-retrieval-path-cache.js';
import { DATABASE_SCHEMA_VERSION } from './storage-version.js';
import { issueEngineeringDependencyHandle,precheckDependencyReadOptions,resolveDependencyReadEnrollment,resolveExpansionDependencies,assertEnrollmentActive,EngineeringDependencyLedger,type EnrollmentContext,type EngineeringDependencyOptions } from './engineering-dependencies.js';
export { revokeEngineeringDependencies } from './engineering-dependencies.js';
export type { EngineeringDependencyHandle, EngineeringDependencyOptions, DependencyBudgetNarrowing } from './engineering-dependencies.js';
import type { SqliteMemoryStorage } from './storage.js';
export { retractEngineeringMemory, reconcileEngineeringRetraction, ENGINEERING_RETRACTION_CONTRACT, ENGINEERING_RETRACTION_INTENT_SCHEMA, ENGINEERING_RETRACTION_INPUT_SCHEMA } from './engineering-retraction.js';
export type { EngineeringRetractionIntent, EngineeringRetractionInput } from './engineering-retraction.js';

const text=z.string().min(1).max(512).refine(s=>s.trim().length>0&&!s.includes('\0'));
const prose=z.string().min(1).max(4096).refine(s=>s.trim().length>0&&!s.includes('\0'));
const unique=(schema:z.ZodType<string>,max:number)=>z.array(schema).max(max).refine(a=>new Set(a).size===a.length);
const list=unique(prose,16);
const digest=z.string().regex(/^[a-f0-9]{64}$/);
const scope={task_ref:text,task_version:text,role:text.optional()};
const fileKey=(s:string)=>{const normalized=normalizeLocalSourcePath(s);return process.platform==='win32'?normalized.toLowerCase():normalized;};
const files=unique(text.transform(fileKey),16);
export const ENGINEERING_RECORD_SCHEMA=z.object({
  format:z.literal('xmem-engineering/1'),
  information_type:z.enum(['CONSTRAINT','DECISION','INTERFACE','FAILURE','UNKNOWN','NOTE']),
  title:z.string().min(1).max(160).refine(s=>s.trim().length>0&&!s.includes('\0')),
  associations:z.object({files,modules:unique(text,16),topics:unique(text,16)}).strict(),
  conditions:list,constraints:list,unknowns:list,details:prose,
  experience:z.object({problem:prose,attempts:z.array(z.object({action:prose,result:prose}).strict()).min(1).max(16),
    analysis:z.object({status:z.enum(['UNKNOWN','HYPOTHESIS','SUPPORTED_BY_REFERENCES']),reason:prose}).strict(),
    avoid_when:list,retry_when:list,next_steps:list}).strict().nullable(),
  sources:z.array(z.object({source_id:text,locator:text,sha256:z.union([digest,z.literal('UNKNOWN')])}).strict()).min(1).max(16)
}).strict().superRefine((r,c)=>{
  if((r.information_type==='FAILURE')!==(r.experience!==null))c.addIssue({code:'custom',message:'Failure experience required only for failure records'});
  if(!r.associations.files.length&&!r.associations.modules.length&&!r.associations.topics.length)c.addIssue({code:'custom',message:'At least one explicit association required'});
  if(r.experience?.analysis.status==='UNKNOWN'&&r.experience.analysis.reason!=='UNKNOWN')c.addIssue({code:'custom',message:'Unknown cause must remain UNKNOWN'});
  if(r.experience?.analysis.status==='SUPPORTED_BY_REFERENCES'&&!r.sources.some(s=>s.sha256!=='UNKNOWN'&&s.locator!=='UNKNOWN'))c.addIssue({code:'custom',message:'Claimed reference support needs a reference'});
});
export type EngineeringRecord=z.infer<typeof ENGINEERING_RECORD_SCHEMA>;
export const ENGINEERING_CAPTURE_EXPECTED_SCOPE_SCHEMA=z.object({project_id:text,workspace_id:text,policy_hash:digest,storage_location_hash:digest}).strict();
export type EngineeringCaptureExpectedScope=ExpectedCaptureScope;
const captureSchema=z.object({task_ref:text,task_version:text,memory_key:text,previous_revision_id:text.nullable(),roles:unique(text,8).refine(a=>a.length>0).optional(),expected_scope:ENGINEERING_CAPTURE_EXPECTED_SCOPE_SCHEMA,record:ENGINEERING_RECORD_SCHEMA}).strict();
export type EngineeringCaptureInput=z.input<typeof captureSchema>;
export const ENGINEERING_QUERY_SCHEMA=z.object({...scope,files:files.default([]),modules:unique(text,16).default([]),topics:unique(text,16).default([]),
  query:z.string().max(256).refine(s=>!s.includes('\0')).default(''),allowed_source_ids:unique(text,512).optional(),
  mode:z.enum(['preview','context']).default('preview'),limit:z.number().int().min(1).max(32).default(16),payload_budget_bytes:z.number().int().nonnegative().max(262144)}).strict();
export type EngineeringQuery=z.input<typeof ENGINEERING_QUERY_SCHEMA>;
const refSchema=z.object({project_id:text,workspace_id:text,task_ref:text,task_version:text,role:text,revision_id:text,source_id:text,
  source_content_hash:digest,record_content_hash:digest,binding_hash:digest,policy_hash:digest}).strict();
export type EngineeringExpansionRef=z.infer<typeof refSchema>;
const expandSchema=z.object({reference:refSchema,view:z.enum(['current','historical']).default('current'),payload_budget_bytes:z.number().int().nonnegative().max(262144)}).strict();
const fail=(code:string):CodexResult=>({ok:false,error:{code,message:'Engineering memory operation unavailable within the requested scope'}});
function caught(e:unknown):CodexResult {return fail(e instanceof z.ZodError?'INVALID_INPUT':typeof (e as any)?.code==='string'?(e as any).code:'INTERNAL_ERROR');}
function safeResult(r:CodexResult):CodexResult{return r.ok?r:fail(r.error.code);}
function environment(projectRoot:string,role?:string,budget?:number){
  const config=readProjectConfig(projectRoot),root=config.root,current=readStandalonePolicy(root);
  if(!current?.policy.enabled)throw new PathsError('NOT_CONFIGURED','Enabled policy required');
  if(!readStorageLocationAtProjectRoot(root,config.project_id).configured)throw new PathsError('STORAGE_LOCATION_UNCONFIRMED','Confirmed storage required');
  const selected=role??current.policy.default_role;
  if(!current.policy.allowed_roles.includes(selected))throw new PathsError('UNTRUSTED_SOURCE','Role unavailable');
  if(budget!==undefined&&budget>current.policy.payload_budget_bytes)throw new PathsError('INVALID_INPUT','Budget may only narrow');
  return{root,config,...current,role:selected};
}
function dependencyContext(env:ReturnType<typeof environment>,storage:SqliteMemoryStorage,task:{task_ref:string;task_version:string},allowedSourceIds?:readonly string[]):EnrollmentContext {
  const location=readStorageLocationAtProjectRoot(env.root,env.config.project_id);
  if(!location.configured||!location.location_hash)throw new PathsError('STORAGE_LOCATION_UNCONFIRMED','Confirmed storage required');
  return{scope:{projectRoot:env.root,projectId:env.config.project_id,workspaceId:env.policy.workspace_id,taskId:task.task_ref,taskVersion:task.task_version,role:env.role},storageRoot:storage.root,policyHash:env.policy_hash,locationHash:location.location_hash,allowedSourceIds};
}
const enrollmentSchema=z.object({...scope,expected_scope:ENGINEERING_CAPTURE_EXPECTED_SCOPE_SCHEMA,relation_ids:unique(text,32),allowed_source_ids:unique(text,512).optional()}).strict();
/** Explicit local SDK enrollment, separate from ordinary query JSON and ACLs.
 * The returned opaque handle has no meaning after serialization/restart. */
export function registerEngineeringDependencies(projectRoot:string,input:unknown,physical?:PhysicalReadOptions):CodexResult {
  if(physical!==undefined)return runPhysicalRead(projectRoot,input,physical,session=>registerEngineeringDependenciesInternal(projectRoot,input,session));
  return registerEngineeringDependenciesInternal(projectRoot,input);
}
function registerEngineeringDependenciesInternal(projectRoot:string,input:unknown,physicalRead?:PhysicalReadSession):CodexResult {
  return withPathValidationScope(()=>{try{
    const x=enrollmentSchema.parse(input),env=environment(projectRoot,x.role);
    return safeResult(withProject(env.root,storage=>{
      const context=dependencyContext(env,storage,x,x.allowed_source_ids),expected=x.expected_scope;
      if(expected.project_id!==context.scope.projectId||expected.workspace_id!==context.scope.workspaceId||expected.policy_hash!==context.policyHash||expected.storage_location_hash!==context.locationHash)throw new PathsError('IDENTITY_CONFLICT','Enrollment expected scope changed');
      const registered=storage.readEngineeringEnrollment(context,x.relation_ids);
      if(readStandalonePolicy(env.root)?.policy_hash!==env.policy_hash||readStorageLocationAtProjectRoot(env.root,env.config.project_id).location_hash!==context.locationHash)throw new PathsError('IDENTITY_CONFLICT','Policy or storage changed during enrollment');
      return{handle:issueEngineeringDependencyHandle(context,registered.relations,registered.nodePins),registered_edges:registered.relations.length,authority:'LOCAL_SDK_EXPLICIT_ENROLLMENT',actor_identity_verified:false,read_permission_granted:false};
    },{readOnly:true,physicalRead}));
  }catch(e){return caught(e);}});
}
export const registerMemoryDependencies=registerEngineeringDependencies;

/** Structured content uses existing capture transaction, source, receipt and CAS. */
export function captureEngineeringMemory(projectRoot:string,input:unknown):CodexResult {
  return withPathValidationScope(()=>{try{
    const x=captureSchema.parse(input),root=resolveProjectRoot(projectRoot);
    for(const file of x.record.associations.files)resolveProjectPath(root,file);
    const content=canonicalContextJson(x.record);
    if(Buffer.byteLength(content,'utf8')>16384)return fail('INVALID_INPUT');
    const category=x.record.information_type==='FAILURE'?'FAILED_APPROACH':x.record.information_type==='CONSTRAINT'?'CONSTRAINT':x.record.information_type==='DECISION'?'DECISION':x.record.information_type==='UNKNOWN'?'ROOT_CAUSE_HYPOTHESIS':'IMPORTANT_DISCOVERY';
    return safeResult(captureStandaloneMemory(root,{task_ref:x.task_ref,task_version:x.task_version,memory_key:x.memory_key,previous_revision_id:x.previous_revision_id,roles:x.roles,category,declared_actor:'agent',content},x.expected_scope));
  }catch(e){return caught(e);}});
}

function structured(content:string):EngineeringRecord|null {
  let value:unknown;try{value=JSON.parse(content);}catch{return null;}
  if((value as any)?.format!=='xmem-engineering/1')return null;
  // A malformed structured record must never be rendered as a shortened success.
  return ENGINEERING_RECORD_SCHEMA.parse(value);
}
function typeOf(entry:ContextEntry,r:EngineeringRecord|null):string {
  return r?.information_type??(entry.record.kind==='ConstraintRef'?'CONSTRAINT':entry.record.kind==='DecisionRef'?'DECISION':entry.record.kind==='FailedAttempt'?'FAILURE':entry.record.kind==='RootCauseHypothesis'?'UNKNOWN':'NOTE');
}
/** Deterministic round-robin across explicit information classes; no semantic merge. */
function complementary<T extends {entry:ContextEntry;type:string;score:number}>(items:T[]):T[]{
  const order=['CONSTRAINT','DECISION','INTERFACE','FAILURE','UNKNOWN','NOTE'];
  const required=items.filter(i=>i.entry.binding!.mandatory).sort((a,b)=>b.score-a.score||a.entry.record.revision_id.localeCompare(b.entry.record.revision_id,'en'));
  const groups=order.map(type=>items.filter(i=>!i.entry.binding!.mandatory&&i.type===type).sort((a,b)=>b.score-a.score||contextAuthority(b.entry.record).authority_score-contextAuthority(a.entry.record).authority_score||a.entry.record.revision_id.localeCompare(b.entry.record.revision_id,'en')));
  const result=[...required];for(let index=0;groups.some(g=>index<g.length);index++)for(const group of groups)if(group[index])result.push(group[index]);return result;
}

/** Read-only metadata preview or complete selected bodies, always one exact task. */
export function queryEngineeringMemory(projectRoot:string,input:unknown,options?:EngineeringDependencyOptions):CodexResult;
export function queryEngineeringMemory(projectRoot:string,input:unknown,physical:PhysicalReadOptions,dependencies?:EngineeringDependencyOptions):CodexResult;
export function queryEngineeringMemory(projectRoot:string,input:unknown,options?:PhysicalReadOptions|EngineeringDependencyOptions,dependencies?:EngineeringDependencyOptions):CodexResult {
  try{
    if(options!==undefined&&(!options||typeof options!=='object'||Array.isArray(options)))throw new PathsError('INPUT_INCOMPLETE','Invalid read options');
    const physical=options!==undefined&&Object.hasOwn(options,'storage_read_profile');
    if(dependencies!==undefined&&!physical)throw new PathsError('INPUT_INCOMPLETE','Combined reads require physical third options');
    if(physical)return runPhysicalRead(projectRoot,input,options as PhysicalReadOptions,session=>queryEngineeringMemoryInternal(projectRoot,input,session,dependencies));
    return queryEngineeringMemoryInternal(projectRoot,input,undefined,options as EngineeringDependencyOptions|undefined);
  }catch(error){return caught(error);}
}
function queryEngineeringMemoryInternal(projectRoot:string,input:unknown,physicalRead?:PhysicalReadSession,options?:EngineeringDependencyOptions):CodexResult {
  return withPathValidationScope(()=>{try{
    const started=performance.now();
    const x=ENGINEERING_QUERY_SCHEMA.parse(input),env=environment(projectRoot,x.role,x.payload_budget_bytes);
    const requestedFiles=x.files.map(file=>({path:file,status:fs.existsSync(resolveProjectPath(env.root,file))?'PRESENT':'MISSING_OR_RENAMED'}));
    const terms=x.query.toLowerCase().split(/\s+/u).filter(Boolean);
    const request={project_id:env.config.project_id,workspace_id:env.policy.workspace_id,task_ref:x.task_ref,task_version:x.task_version,role:env.role,allowed_source_ids:x.allowed_source_ids,selectors:{files:x.files,modules:x.modules,topics:x.topics,terms}};
    if(options!==undefined)precheckDependencyReadOptions(options);
    return safeResult(withProject(env.root,storage=>{
      const baseScope=dependencyContext(env,storage,x,x.allowed_source_ids),resolved=options!==undefined?resolveDependencyReadEnrollment(options,baseScope):null;
      const dependencyScope=resolved?.context??baseScope,enrollment=resolved?.state??null;
      if(enrollment)request.allowed_source_ids=dependencyScope.allowedSourceIds===undefined?undefined:[...dependencyScope.allowedSourceIds];
      const ledger=enrollment?new EngineeringDependencyLedger(options?.dependency_budget,env.policy.max_depth):null,epoch=enrollment?.epoch;
      const physicalReader=(source:ContextEntry['record']['source'])=>{
        if(enrollment){assertEnrollmentActive(enrollment,epoch!);if(readStandalonePolicy(env.root)?.policy_hash!==env.policy_hash||readStorageLocationAtProjectRoot(env.root,env.config.project_id).location_hash!==dependencyScope.locationHash)throw new PathsError('INPUT_INCOMPLETE','Current dependency scope changed');storage.assertEngineeringDependencySourceAllowed(dependencyScope,source,ledger!);}
        return readCurrentSourceReference(env.root,storage,env.config.project_id,source);
      };
      // Cache only the fixed selector's compiled steps, keyed by the actual current environment.
      const lease=engineeringRetrievalPathCache.acquire({project_root:env.root,storage_root:storage.root,project_id:request.project_id,workspace_id:request.workspace_id,task_ref:request.task_ref,task_version:request.task_version,role:env.role,
        allowed_source_ids:request.allowed_source_ids===undefined?{kind:'UNSPECIFIED'}:{kind:'EXACT',ids:request.allowed_source_ids},policy_hash:env.policy_hash,
        sdk_contract:'xmem-engineering/2',selector_version:'engineering-selector-v1',storage_schema:DATABASE_SCHEMA_VERSION,compiler_version:'context-v2',context_policy:'context-policy-v5',
        mode:x.mode,limit:x.limit,payload_budget_bytes:x.payload_budget_bytes,policy_max_nodes:env.policy.max_nodes,policy_max_depth:env.policy.max_depth,policy_payload_budget_bytes:env.policy.payload_budget_bytes,
        dependency_mode:enrollment?'POSITIVE_LOCAL_ENROLLMENT':'NEGATIVE_ONLY',dependency_enrollment:enrollment?.enrollmentId??null,dependency_budget:ledger?{sql:ledger.sqlLimits,evaluator:ledger.evaluationLimits,source_bytes:ledger.sourceLimit}:null,
        candidate_limit:512,candidate_bytes:8*1024*1024,source_processing_bytes:16*1024*1024,compiler_max_nodes:512,compiler_max_depth:0,compiler_payload_bytes:16*1024*1024,dependency_edges:256,dependency_metadata_bytes:262144},request.selectors);
      try{
      ledger?.spendSql('queries',1);
      const scan=storage.readEngineeringContextView(request,lease.plan),reasons=new Set<string>();
      if(ledger)ledger.spendSql('metadataBytes',Buffer.byteLength(canonicalContextJson(scan.view.entries),'utf8'));
      const dependencyBoundary=enrollment?storage.observeEngineeringDependencyGraph(dependencyScope,scan.view.entries.map(e=>e.record.revision_id),enrollment,ledger!,physicalReader):storage.readEngineeringDependencyBoundary(request,scan.view.entries);
      if(scan.incomplete)reasons.add('CANDIDATE_SCAN_LIMIT');
      const candidates=scan.view.entries.flatMap(entry=>{
        const record=structured(entry.record.content),hits:string[]=[];
        if(record){
          if(x.files.some(f=>record.associations.files.includes(f)))hits.push('FILE_EXACT');
          if(x.modules.some(m=>record.associations.modules.includes(m)))hits.push('MODULE_EXACT');
          if(x.topics.some(t=>record.associations.topics.includes(t)))hits.push('TOPIC_EXACT');
        }
        if(terms.length&&terms.every(t=>entry.record.content.toLowerCase().includes(t)))hits.push('KEYWORDS');
        if(entry.binding!.mandatory)hits.unshift('REQUIRED_TASK_CONTEXT');
        if(!hits.length)return[];
        return[{entry,record,hits,type:typeOf(entry,record),score:hits.includes('FILE_EXACT')?4:hits.includes('MODULE_EXACT')?3:hits.includes('TOPIC_EXACT')?2:1}];
      });
      // Compiler performs existing conflict/source checks and exact-body dedup.
      // This internal processing envelope never changes the public Owner budget.
      let sourceBytes=0;
      const resolver={read:(source:ContextEntry['record']['source'])=>{const bytes=ledger?ledger.read(source,physicalReader):physicalReader(source);sourceBytes+=bytes?.byteLength??0;if(sourceBytes>16*1024*1024)throw new PathsError('INPUT_INCOMPLETE','Source processing ceiling');return bytes;}};
      const pack=compileContext({...request,allowed_source_ids:[...new Set(candidates.map(c=>c.entry.record.source.source_id))],target_snapshot_id:'engineering-read-only',max_nodes:512,max_depth:0,payload_budget_bytes:16*1024*1024},{entries:candidates.map(c=>c.entry),edges:[]},resolver);
      if(sourceBytes>16*1024*1024)throw new PathsError('INPUT_INCOMPLETE','Source processing ceiling');
      const included=new Set(pack.revisions),required=new Set(candidates.filter(c=>c.entry.binding!.mandatory).map(c=>c.entry.record.revision_id));
      for(const c of pack.coverage)if(required.has(c.revision_id)&&c.reason.startsWith('duplicate_context:'))required.add(c.reason.slice('duplicate_context:'.length));
      const available=candidates.filter(c=>included.has(c.entry.record.revision_id)).map(c=>({...c,entry:{...c.entry,binding:{...c.entry.binding!,mandatory:required.has(c.entry.record.revision_id)}}}));
      if(available.filter(c=>c.entry.binding.mandatory).length>Math.min(64,env.policy.max_nodes)||available.filter(c=>c.entry.binding.mandatory).length>x.limit)throw new PathsError('BUDGET_UNSATISFIABLE','Required entries exceed node/result bound');
      const ordered=complementary(available),lines:string[]=[],omitted:Array<{reference:EngineeringExpansionRef;reason:string}>=[];
      let used=0,selected=0;
      const ref=(entry:ContextEntry):EngineeringExpansionRef=>({project_id:env.config.project_id,workspace_id:env.policy.workspace_id,task_ref:x.task_ref,task_version:x.task_version,role:env.role,revision_id:entry.record.revision_id,source_id:entry.record.source.source_id,source_content_hash:entry.record.source.content_hash,record_content_hash:hashBytes(entry.record.content),binding_hash:hashBytes(canonicalContextJson(candidates.find(c=>c.entry.record.revision_id===entry.record.revision_id)!.entry.binding)),policy_hash:env.policy_hash});
      for(const c of ordered){
        const reference=ref(c.entry),r=c.record;
        const view={revision_id:c.entry.record.revision_id,source_id:c.entry.record.source.source_id,source_content_hash:c.entry.record.source.content_hash,record_content_hash:reference.record_content_hash,information_type:c.type,
          match_reasons:c.hits,persisted:'SAVED',epistemic_state:c.entry.record.epistemic_state,applicability:'NOT_EVALUATED',mandatory:c.entry.binding.mandatory,execution_verified:false,actor_identity_verified:false,
          preview_only:x.mode==='preview'&&!c.entry.binding.mandatory&&r!==null,reference,
          ...(x.mode==='context'||c.entry.binding.mandatory||!r?{content:c.entry.record.content}:{title:r.title,conditions:r.conditions,constraints:r.constraints,unknowns:r.unknowns,analysis_status:r.experience?.analysis.status??'NOT_EVALUATED',avoid_when:r.experience?.avoid_when??[],retry_when:r.experience?.retry_when??[],sources:r.sources})};
        const line=canonicalContextJson(view),bytes=Buffer.byteLength(line,'utf8')+(lines.length?1:0);
        const reason=selected>=Math.min(x.limit,env.policy.max_nodes,64)?'RESULT_OR_NODE_LIMIT':used+bytes>x.payload_budget_bytes?'PAYLOAD_BUDGET':null;
        if(reason){if(c.entry.binding.mandatory)throw new PathsError('BUDGET_UNSATISFIABLE','Indivisible required context does not fit');reasons.add(reason);omitted.push({reference,reason});continue;}
        lines.push(line);used+=bytes;selected++;
      }
      for(const c of pack.coverage)if(c.reason==='unresolved_conflict'||c.reason==='lower_authority_conflict')reasons.add('CONFLICT_WITHHELD');else if(['source_unavailable','source_changed'].includes(c.reason))reasons.add('SOURCE_REQUIRES_VERIFICATION');
      // Optional expansion references consume the same payload budget as previews.
      for(const item of omitted.slice(0,32)){const line=canonicalContextJson({available_by_reference:true,...item}),size=Buffer.byteLength(line,'utf8')+(lines.length?1:0);if(used+size<=x.payload_budget_bytes){lines.push(line);used+=size;}}
      ledger?.spendSql('queries',1);
      const afterScan=storage.readEngineeringContextView(request,lease.plan);
      if(ledger)ledger.spendSql('metadataBytes',Buffer.byteLength(canonicalContextJson(afterScan.view.entries),'utf8'));
      if(afterScan.view.snapshot_hash!==scan.view.snapshot_hash||afterScan.incomplete!==scan.incomplete)throw new PathsError('IDENTITY_CONFLICT','Source revisions, bindings or matching-candidate boundary changed during query');
      const finalBoundary=enrollment?storage.observeEngineeringDependencyGraph(dependencyScope,afterScan.view.entries.map(e=>e.record.revision_id),enrollment,ledger!,physicalReader):storage.readEngineeringDependencyBoundary(request,afterScan.view.entries);
      if(finalBoundary!==dependencyBoundary)throw new PathsError('IDENTITY_CONFLICT','Dependency or lifecycle boundary changed during query');
      if(enrollment)assertEnrollmentActive(enrollment,epoch!);
      if(readStandalonePolicy(env.root)?.policy_hash!==env.policy_hash)throw new PathsError('IDENTITY_CONFLICT','Policy changed during query');
      if(readStorageLocationAtProjectRoot(env.root,env.config.project_id).location_hash!==dependencyScope.locationHash)throw new PathsError('IDENTITY_CONFLICT','Storage changed during query');
      if(reasons.has('SOURCE_REQUIRES_VERIFICATION')||scan.incomplete)engineeringRetrievalPathCache.invalidate(lease);
      else engineeringRetrievalPathCache.finish(lease,hashBytes(canonicalContextJson({view:scan.view.snapshot_hash,dependencies:dependencyBoundary,sources:pack.source_snapshot_hash,policy:env.policy_hash})));
      const payload=lines.join('\n');
      return{contract:'xmem-engineering/2',read_only:true,mode:x.mode,status:reasons.size?'INCOMPLETE':payload?'READY':'EMPTY',payload,payload_bytes:used,payload_sha256:hashBytes(payload),budget_basis:'UTF8_PUBLIC_JSONL_ITEMS_AND_EXPANSION_REFERENCES',payload_budget_bytes:x.payload_budget_bytes,
        requested_files:requestedFiles,coverage:{incomplete:reasons.size>0,reasons:[...reasons].sort(),semantic_completeness_guaranteed:false,expand:'USE_RETURNED_REFERENCE_OR_REPEAT_NARROWER_QUERY'},
        telemetry:{xmem_latency_ms:Math.round((performance.now()-started)*1000)/1000,candidate_body_bytes:scan.view.entries.reduce((s,e)=>s+Buffer.byteLength(e.record.content,'utf8'),0),source_bytes_read:ledger?.sourceBytes??sourceBytes,hidden_host_tokens:'UNKNOWN'}};
      }catch(error){engineeringRetrievalPathCache.invalidate(lease);throw error;}
    },{readOnly:true,physicalRead}));
  }catch(e){return caught(e);}});
}

/** Exact revision expansion. A preview is a reference, never authorization. */
export function expandEngineeringMemory(projectRoot:string,input:unknown,options?:EngineeringDependencyOptions):CodexResult {
  return withPathValidationScope(()=>{try{
    const started=performance.now();
    const x=expandSchema.parse(input),r=x.reference,env=environment(projectRoot,r.role,x.payload_budget_bytes);
    if(env.config.project_id!==r.project_id||env.policy.workspace_id!==r.workspace_id)return fail('PROJECT_MISMATCH');
    if(env.policy_hash!==r.policy_hash)return fail('PREVIEW_CHANGED');
    return safeResult(withProject(env.root,storage=>{
      // Expansion has no public source-allowance field. The exact local handle's
      // allowance is retained; it cannot be widened by the preview reference.
      const dependencyScope=dependencyContext(env,storage,{task_ref:r.task_ref,task_version:r.task_version});
      // Resolve with the handle's exact allowance through the dedicated helper.
      const enrollment=resolveExpansionDependencies(options,dependencyScope);
      const ledger=enrollment?new EngineeringDependencyLedger(options?.dependency_budget,env.policy.max_depth):null,epoch=enrollment?.epoch;
      if(enrollment?.context.allowedSourceIds!==undefined&&!enrollment.context.allowedSourceIds.includes(r.source_id))throw new PathsError('INPUT_INCOMPLETE','Expansion source unavailable within enrollment scope');
      const physicalReader=(source:ContextEntry['record']['source'])=>{
        if(enrollment){assertEnrollmentActive(enrollment,epoch!);if(readStandalonePolicy(env.root)?.policy_hash!==env.policy_hash||readStorageLocationAtProjectRoot(env.root,env.config.project_id).location_hash!==dependencyScope.locationHash)throw new PathsError('INPUT_INCOMPLETE','Current dependency scope changed');storage.assertEngineeringDependencySourceAllowed(enrollment.context,source,ledger!);}
        return readCurrentSourceReference(env.root,storage,r.project_id,source);
      };
      const request={project_id:r.project_id,workspace_id:r.workspace_id,task_ref:r.task_ref,task_version:r.task_version,role:r.role,record_id:null,revision_id:r.revision_id};
      ledger?.spendSql('queries',1);
      const current=storage.readEngineeringContextView({...request,allowed_source_ids:[r.source_id],include_history:true}).view.entries[0];
      if(ledger&&current)ledger.spendSql('metadataBytes',Buffer.byteLength(canonicalContextJson(current),'utf8'));
      const found=current?.record.source.kind==='file'?null:storage.readHostMemoryCapture(request,ledger?bytes=>ledger.sourceRead(bytes):undefined);
      const fallback=found?null:current;
      const entry=found?{record:found.record,binding:found.binding}:fallback;
      const base={contract:'xmem-engineering/2',read_only:true,payload:null,payload_bytes:0,applicability:'NOT_EVALUATED'};
      if(!entry||entry.record.source.source_id!==r.source_id)return{...base,status:'NOT_FOUND_WITHIN_SCOPE'};
      if(hashBytes(canonicalContextJson(entry.binding))!==r.binding_hash||entry.record.source.content_hash!==r.source_content_hash||hashBytes(entry.record.content)!==r.record_content_hash)return{...base,status:'PREVIEW_CHANGED'};
      const historical=found?!found.is_current||found.current_lifecycle!=='ACTIVE':entry.record.lifecycle!=='ACTIVE';
      if(historical&&x.view==='current')return{...base,status:'PREVIEW_CHANGED'};
      if(historical&&!found)return{...base,status:'HISTORICAL_FILE_EXPANSION_UNAVAILABLE'};
      const dependencyRequest={...request,allowed_source_ids:enrollment?.context.allowedSourceIds===undefined?undefined:[...enrollment.context.allowedSourceIds],allow_history:true};
      const dependencyBoundary=enrollment?storage.observeEngineeringDependencyGraph(enrollment.context,[r.revision_id],enrollment,ledger!,physicalReader):storage.readEngineeringDependencyBoundary(dependencyRequest,[entry]);
      if(entry.binding!.conflicts.length)return{...base,status:'CONFLICT_WITHHELD'};
      const bytes=ledger?ledger.read(entry.record.source,physicalReader):physicalReader(entry.record.source);
      if(!bytes||hashBytes(bytes)!==r.source_content_hash)return{...base,status:'SOURCE_REQUIRES_VERIFICATION'};
      const view={revision_id:r.revision_id,source_id:r.source_id,source_content_hash:r.source_content_hash,record_content_hash:r.record_content_hash,binding_hash:r.binding_hash,scope:{project_id:r.project_id,workspace_id:r.workspace_id,task_ref:r.task_ref,task_version:r.task_version,role:r.role},historical,
        lifecycle:found?.current_lifecycle??entry.record.lifecycle,epistemic_state:entry.record.epistemic_state,applicability:'NOT_EVALUATED',execution_verified:false,actor_identity_verified:false,
        content:entry.record.content,...(found?{durable_receipt:found.durable_receipt}:{source_kind:entry.record.source.kind})};
      const payload=canonicalContextJson(view),size=Buffer.byteLength(payload,'utf8');
      const again=found?storage.readHostMemoryCapture(request,ledger?bytes=>ledger.sourceRead(bytes):undefined):null;
      let same:boolean|undefined;
      if(found)same=!!again&&again.is_current===found.is_current&&again.current_lifecycle===found.current_lifecycle&&again.current_revision_id===found.current_revision_id&&canonicalContextJson(again.binding)===canonicalContextJson(found.binding);
      else {ledger?.spendSql('queries',1);const finalView=storage.readEngineeringContextView({...request,allowed_source_ids:[r.source_id]}).view;
        if(ledger)ledger.spendSql('metadataBytes',Buffer.byteLength(canonicalContextJson(finalView.entries),'utf8'));
        same=finalView.entries.some(e=>canonicalContextJson(e)===canonicalContextJson(entry));}
      const sourceAgain=ledger?ledger.read(entry.record.source,physicalReader):physicalReader(entry.record.source);
      if(!same||!sourceAgain||hashBytes(sourceAgain)!==r.source_content_hash||readStandalonePolicy(env.root)?.policy_hash!==env.policy_hash)return{...base,status:'PREVIEW_CHANGED'};
      const finalBoundary=enrollment?storage.observeEngineeringDependencyGraph(enrollment.context,[r.revision_id],enrollment,ledger!,physicalReader):storage.readEngineeringDependencyBoundary(dependencyRequest,[entry]);
      if(finalBoundary!==dependencyBoundary)return{...base,status:'PREVIEW_CHANGED'};
      if(enrollment)assertEnrollmentActive(enrollment,epoch!);
      if(readStandalonePolicy(env.root)?.policy_hash!==env.policy_hash||readStorageLocationAtProjectRoot(env.root,env.config.project_id).location_hash!==dependencyScope.locationHash)return{...base,status:'PREVIEW_CHANGED'};
      if(size>x.payload_budget_bytes)return{...base,status:'BUDGET_UNSATISFIABLE',required_payload_bytes:size};
      return{...base,status:'COMPLETE',persisted:'SAVED',payload,payload_bytes:size,payload_sha256:hashBytes(payload),historical,telemetry:{xmem_latency_ms:Math.round((performance.now()-started)*1000)/1000,source_bytes_read:ledger?.sourceBytes??bytes.byteLength+sourceAgain.byteLength,hidden_host_tokens:'UNKNOWN'}};
    },{readOnly:true}));
  }catch(e){return caught(e);}});
}
