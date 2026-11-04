import { runPhysicalRead, type PhysicalReadOptions, type PhysicalReadSession } from './physical-readonly.js';
/** Explicit owner grants for same-project historical candidates. Never a scheduler. */
import fs from 'node:fs';
import { z } from 'zod';
import { readProjectConfig, resolveProjectPath, resolveProjectRoot } from './index.js';
import { PathsError, withPathValidationScope } from './paths.js';
import { withConfigurationLock, writeConfigurationAtomically } from './config-write.js';
import { withProject, type CodexResult } from './codex.js';
import { canonicalContextJson, compileContext, type ContextEntry } from './context.js';
import { readStandalonePolicy } from './standalone.js';
import { hashBytes, readLocalSource, normalizeLocalSourcePath } from './local-source.js';
import { readStorageLocationAtProjectRoot } from './storage-location.js';
import { createDependencyReadBoundary,createDependencyReadSession,dependencyReadLedger,liveDependencyContext,type DependencyReadSession } from './dependency-read-boundary.js';
import { issueEngineeringDependencyHandle,dependencyHandleScope,type EngineeringDependencyHandle,type DependencyBudgetNarrowing,type DependencyRevisionAuthorization } from './engineering-dependencies.js';

const text=z.string().min(1).max(512).refine(x=>x.trim().length>0&&!x.includes('\0'));
const unique=(max:number)=>z.array(text).max(max).refine(x=>new Set(x).size===x.length);
const scope=z.object({task_ref:text,task_version:text}).strict();
const basis=z.object({path:text,sha256:z.string().regex(/^[a-f0-9]{64}$/)}).strict();
const review=z.object({decision:z.enum(['APPLICABLE','CONFLICT','REQUIRES_VERIFICATION']),basis:z.array(basis).min(1).max(8)}).strict();
const revision=z.object({revision_id:text,source_id:text,tags:unique(8),review:review.optional()}).strict();
const grant=z.object({grant_id:text,source_scope:scope,target_scope:scope,roles:unique(8).refine(x=>x.length>0),purpose:z.literal('TASK_RECALL'),expires_at:z.string().datetime().nullable(),revisions:z.array(revision).min(1).max(16)}).strict();
const policySchema=z.object({schema_version:z.literal(1),project_id:text,workspace_id:text,grants:z.array(grant).max(32)}).strict();
const configureSchema=z.object({consent:z.literal(true),expected_policy_hash:z.string().regex(/^[a-f0-9]{64}$/).nullable(),policy:policySchema}).strict();
const querySchema=z.object({project_id:text,workspace_id:text,target_scope:scope,role:text,purpose:z.literal('TASK_RECALL'),allowed_source_ids:unique(512),query:z.string().max(256),tags:unique(8),limit:z.number().int().min(1).max(32),payload_budget_bytes:z.number().int().nonnegative().max(262144)}).strict();
export type MemorySharingPolicy=z.infer<typeof policySchema>;
export type SharedMemoryQuery=z.infer<typeof querySchema>;
export type MemoryApplicability='NOT_EVALUATED'|'CURRENT_CONFIRMED'|'REQUIRES_VERIFICATION'|'STALE_OR_SUPERSEDED'|'CONFLICT';
export interface SharedDependencyOptions {dependencies:readonly EngineeringDependencyHandle[];dependency_budget?:DependencyBudgetNarrowing;}
const sharedEnrollmentSchema=z.object({task_ref:text,task_version:text,role:text,expected_scope:z.object({project_id:text,workspace_id:text,policy_hash:z.string().regex(/^[a-f0-9]{64}$/),storage_location_hash:z.string().regex(/^[a-f0-9]{64}$/)}).strict(),
  relation_ids:unique(32),allowed_source_ids:unique(512).optional(),target_scope:scope,expected_sharing_policy_hash:z.string().regex(/^[a-f0-9]{64}$/)}).strict();
const SHARING_FILE='.xmem/sharing-v1.json';
const hash=(value:unknown)=>hashBytes(canonicalContextJson(value));
const fail=(code:string,message:string):CodexResult=>({ok:false,error:{code,message}});
function caught(error:unknown):CodexResult {
  if(error instanceof z.ZodError)return fail('INVALID_INPUT','Invalid sharing contract; no query was performed');
  const code=(error as {code?:unknown})?.code;
  // Do not put denied paths, revision IDs, or raw exception text into this public view.
  return fail(typeof code==='string'?code:'INTERNAL_ERROR','Sharing operation could not be completed within the approved scope');
}
function environment(root:string) {
  const config=readProjectConfig(root),standalone=readStandalonePolicy(root);
  if(!standalone||!standalone.policy.enabled)throw new PathsError('NOT_CONFIGURED','Standalone policy unavailable');
  if(!readStorageLocationAtProjectRoot(root,config.project_id).configured)throw new PathsError('STORAGE_LOCATION_UNCONFIRMED','Storage location unconfirmed');
  return {config,...standalone};
}
function readPolicy(root:string) {
  const filename=resolveProjectPath(root,SHARING_FILE);
  if(!fs.existsSync(filename))return null;
  if(fs.statSync(filename).size>1024*1024)throw new PathsError('INVALID_CONFIG','Sharing policy exceeds size bound');
  const policy=policySchema.parse(JSON.parse(fs.readFileSync(filename,'utf8')));
  return{policy,policy_hash:hash(policy)};
}

/** Exact grant gate runs before nodeMetadata may load a full revision, including enrollment. */
function dependencyAuthorization(root:string,projectId:string,workspaceId:string,sourceScope:z.infer<typeof scope>,targetScope:z.infer<typeof scope>,role:string,policyHash:string):DependencyRevisionAuthorization {
  const config=readProjectConfig(root),standalone=readStandalonePolicy(root),location=readStorageLocationAtProjectRoot(root,projectId);
  if(config.project_id!==projectId||!standalone?.policy.enabled||standalone.policy.workspace_id!==workspaceId||!standalone.policy.allowed_roles.includes(role)||!location.configured||!location.location_hash)throw new PathsError('INPUT_INCOMPLETE','Sharing dependency authorization unavailable');
  const standaloneHash=standalone.policy_hash,locationHash=location.location_hash;
  const select=()=>{
    const now=readPolicy(root),nowStandalone=readStandalonePolicy(root),nowLocation=readStorageLocationAtProjectRoot(root,projectId),nowConfig=readProjectConfig(root);
    if(!now||now.policy_hash!==policyHash||now.policy.project_id!==projectId||now.policy.workspace_id!==workspaceId)throw new PathsError('INPUT_INCOMPLETE','Sharing dependency authorization unavailable');
    if(nowConfig.project_id!==projectId||nowConfig.root!==config.root||nowStandalone?.policy_hash!==standaloneHash||nowLocation.location_hash!==locationHash)throw new PathsError('INPUT_INCOMPLETE','Sharing dependency authorization unavailable');
    return now.policy.grants.filter(g=>g.source_scope.task_ref===sourceScope.task_ref&&g.source_scope.task_version===sourceScope.task_version&&g.target_scope.task_ref===targetScope.task_ref&&g.target_scope.task_version===targetScope.task_version&&g.roles.includes(role)&&(g.expires_at===null||Date.parse(g.expires_at)>Date.now())).flatMap(g=>g.revisions);
  };
  const allowedRevisionIds=[...new Set(select().map(r=>r.revision_id))].sort();
  return{identity:hash({policyHash,projectId,workspaceId,sourceScope,targetScope,role}),targetScope:{...targetScope},allowedRevisionIds,
    assertLive:(id,source)=>{
      const grants=select();
      if(id!==undefined&&(!allowedRevisionIds.includes(id)||!grants.some(r=>r.revision_id===id&&(!source||r.source_id===source.source_id)))||id===undefined&&source&&!grants.some(r=>r.source_id===source.source_id))throw new PathsError('INPUT_INCOMPLETE','Sharing dependency authorization unavailable');
    }};
}

/** Explicit process-local enrollment. Sharing grants still grant only their exact revisions. */
export function registerSharedMemoryDependencies(projectRoot:string,input:unknown,physical?:PhysicalReadOptions):CodexResult {
  if(physical!==undefined)return runPhysicalRead(projectRoot,input,physical,session=>registerSharedMemoryDependenciesInternal(projectRoot,input,session));
  return registerSharedMemoryDependenciesInternal(projectRoot,input);
}
function registerSharedMemoryDependenciesInternal(projectRoot:string,input:unknown,physicalRead?:PhysicalReadSession):CodexResult {
  return withPathValidationScope(()=>{try{
    const root=resolveProjectRoot(projectRoot),x=sharedEnrollmentSchema.parse(input),current=environment(root);
    return withProject(root,storage=>{
      const authorization=dependencyAuthorization(root,x.expected_scope.project_id,x.expected_scope.workspace_id,{task_ref:x.task_ref,task_version:x.task_version},x.target_scope,x.role,x.expected_sharing_policy_hash);
      const live=liveDependencyContext(root,storage,{project_id:x.expected_scope.project_id,workspace_id:x.expected_scope.workspace_id,task_ref:x.task_ref,task_version:x.task_version,role:x.role,allowed_source_ids:x.allowed_source_ids},authorization);
      if(live.context.policyHash!==x.expected_scope.policy_hash||live.context.locationHash!==x.expected_scope.storage_location_hash||current.policy_hash!==live.context.policyHash)throw new PathsError('IDENTITY_CONFLICT','Registration expected scope changed');
      live.assertLive();const registered=storage.readEngineeringEnrollment(live.context,x.relation_ids);live.assertLive();
      return{handle:issueEngineeringDependencyHandle(live.context,registered.relations,registered.nodePins),registered_edges:registered.relations.length,authority:'LOCAL_SDK_EXPLICIT_ENROLLMENT',actor_identity_verified:false,read_permission_granted:false,sharing_policy_hash:x.expected_sharing_policy_hash,target_scope:x.target_scope};
    },{readOnly:true,physicalRead});
  }catch(error){return caught(error);}});
}

/** Owner setup only. Not registered in ordinary MCP. Old exact-task policy is untouched. */
export function configureMemorySharing(projectRoot:string,input:unknown):CodexResult {
  return withPathValidationScope(()=>{
    try{
      const root=resolveProjectRoot(projectRoot),x=configureSchema.parse(input),current=environment(root);
      if(Buffer.byteLength(JSON.stringify(x.policy,null,2)+'\n','utf8')>1024*1024)throw new PathsError('INVALID_INPUT','Sharing policy exceeds read limit');
      if(x.policy.project_id!==current.config.project_id||x.policy.workspace_id!==current.policy.workspace_id)throw new PathsError('PROJECT_MISMATCH','Sharing project/workspace mismatch');
      if(new Set(x.policy.grants.map(g=>g.grant_id)).size!==x.policy.grants.length)throw new PathsError('INVALID_INPUT','Duplicate grant identity');
      for(const g of x.policy.grants){
        if(g.roles.some(role=>!current.policy.allowed_roles.includes(role)))throw new PathsError('UNTRUSTED_SOURCE','Sharing roles cannot expand standalone policy');
        if(new Set(g.revisions.map(r=>r.revision_id)).size!==g.revisions.length)throw new PathsError('INVALID_INPUT','Duplicate revision identity');
        for(const r of g.revisions)for(const file of r.review?.basis??[]){
          if(normalizeLocalSourcePath(file.path)!==file.path||!current.policy.snapshot_files.includes(file.path))throw new PathsError('UNTRUSTED_SOURCE','Review basis must use already approved files');
        }
      }
      const filename=resolveProjectPath(root,SHARING_FILE);
      return withConfigurationLock(filename,()=>{
        const before=readPolicy(root),nextHash=hash(x.policy);
        if(before&&before.policy_hash!==x.expected_policy_hash&&before.policy_hash!==nextHash||!before&&x.expected_policy_hash!==null)throw new PathsError('IDENTITY_CONFLICT','Sharing policy changed');
        if(!before||before.policy_hash!==nextHash)writeConfigurationAtomically(filename,x.policy);
        return{ok:true,value:{policy_hash:nextHash,replayed:before?.policy_hash===nextHash,grant_count:x.policy.grants.length,scope:'OWNER_SETUP_ONLY',authenticated_owner:false}};
      });
    }catch(error){return caught(error);}
  });
}

function applicability(root:string,policyFiles:string[],reviewValue:z.infer<typeof review>|undefined,cache=new Map<string,boolean>()):{state:MemoryApplicability;basis_match:boolean|null} {
  if(!reviewValue)return{state:'NOT_EVALUATED',basis_match:null};
  for(const file of reviewValue.basis){
    if(!policyFiles.includes(file.path))return{state:'REQUIRES_VERIFICATION',basis_match:false};
    try{const key=file.path+'\0'+file.sha256;if(!cache.has(key))cache.set(key,hashBytes(readLocalSource(root,file.path).bytes)===file.sha256);if(!cache.get(key))return{state:'REQUIRES_VERIFICATION',basis_match:false};}
    catch{return{state:'REQUIRES_VERIFICATION',basis_match:false};}
  }
  return{state:reviewValue.decision==='APPLICABLE'?'CURRENT_CONFIRMED':reviewValue.decision,basis_match:true};
}

/** Read-only, exact source→target grants. Compiler is reused; no target bindings are saved. */
export function querySharedMemory(projectRoot:string,input:unknown,options?:SharedDependencyOptions):CodexResult;
export function querySharedMemory(projectRoot:string,input:unknown,physical:PhysicalReadOptions,dependencies?:SharedDependencyOptions):CodexResult;
export function querySharedMemory(projectRoot:string,input:unknown,options?:PhysicalReadOptions|SharedDependencyOptions,dependencies?:SharedDependencyOptions):CodexResult {
  try{
    if(options!==undefined&&(!options||typeof options!=='object'||Array.isArray(options)))throw new PathsError('INPUT_INCOMPLETE','Invalid read options');
    const physical=options!==undefined&&Object.hasOwn(options,'storage_read_profile');
    if(dependencies!==undefined&&!physical)throw new PathsError('INPUT_INCOMPLETE','Combined reads require physical third options');
    if(physical)return runPhysicalRead(projectRoot,input,options as PhysicalReadOptions,session=>querySharedMemoryInternal(projectRoot,input,session,dependencies));
    return querySharedMemoryInternal(projectRoot,input,undefined,options as SharedDependencyOptions|undefined);
  }catch(error){return caught(error);}
}
function querySharedMemoryInternal(projectRoot:string,input:unknown,physicalRead?:PhysicalReadSession,options?:SharedDependencyOptions):CodexResult {
  return withPathValidationScope(()=>{
    try{
      const root=resolveProjectRoot(projectRoot),x=querySchema.parse(input),current=environment(root);
      if(options!==undefined&&(!options||Object.getPrototypeOf(options)!==Object.prototype||!Object.hasOwn(options,'dependencies')||Object.values(Object.getOwnPropertyDescriptors(options)).some(d=>!('value'in d)||!d.enumerable)||!Array.isArray(options.dependencies)||options.dependencies.length>8||new Set(options.dependencies).size!==options.dependencies.length||Reflect.ownKeys(options).some(k=>!['dependencies','dependency_budget'].includes(String(k)))))throw new PathsError('INPUT_INCOMPLETE','Invalid dependency options');
      if(options)for(const handle of options.dependencies)dependencyHandleScope(handle);
      if(x.project_id!==current.config.project_id||x.workspace_id!==current.policy.workspace_id)throw new PathsError('PROJECT_MISMATCH','Query project/workspace mismatch');
      if(!current.policy.allowed_roles.includes(x.role))throw new PathsError('UNTRUSTED_SOURCE','Role unavailable');
      if(x.payload_budget_bytes>current.policy.payload_budget_bytes)throw new PathsError('INVALID_INPUT','Budget exceeds approved policy');
      const before=readPolicy(root);
      const base={kind:'AuthorizedRelatedMemoryCandidates',contract_version:'xmem-shared-memory/1',read_only:true,scope:{project_id:x.project_id,workspace_id:x.workspace_id,...x.target_scope,role:x.role},
        payload_budget_bytes:x.payload_budget_bytes,budget_unit:'utf8-bytes',budget_basis:'PUBLIC_PAYLOAD_INCLUDING_ORIGIN_AND_APPLICABILITY',mandatory:false,execution_verified:false,actor_identity_verified:false,owner_confirmation_verified:false};
      const empty=()=>({...base,status:'EMPTY',reason:'NO_AUTHORIZED_MATCHES',payload:'',payload_bytes:0,payload_sha256:hashBytes(''),coverage:{incomplete:false,reasons:[] as string[]}});
      if(!before)return{ok:true,value:empty()};
      if(before.policy.project_id!==x.project_id||before.policy.workspace_id!==x.workspace_id)throw new PathsError('PROJECT_MISMATCH','Sharing policy identity changed');
      const authorized=before.policy.grants.filter(g=>g.target_scope.task_ref===x.target_scope.task_ref&&g.target_scope.task_version===x.target_scope.task_version&&g.roles.includes(x.role)&&g.purpose===x.purpose&&(g.expires_at===null||Date.parse(g.expires_at)>Date.now()))
        .flatMap(g=>g.revisions.filter(r=>x.allowed_source_ids.includes(r.source_id)&&x.tags.every(tag=>r.tags.includes(tag))).map(r=>({grant:g,revision:r})))
        .sort((a,b)=>a.grant.grant_id.localeCompare(b.grant.grant_id,'en')||a.revision.revision_id.localeCompare(b.revision.revision_id,'en'));
      if(!authorized.length)return{ok:true,value:empty()};
      const maxNodes=Math.min(64,current.policy.max_nodes),terms=x.query.toLocaleLowerCase('en').split(/\s+/u).filter(Boolean);
      const result=withProject(root,storage=>{
        const session:DependencyReadSession|undefined=options?createDependencyReadSession(options.dependency_budget,current.policy.max_depth):undefined;
        const ledger=session?dependencyReadLedger(session):undefined;
        const key=(s:z.infer<typeof scope>)=>canonicalContextJson(s);
        const groups=new Map<string,{sourceScope:z.infer<typeof scope>;ids:string[];boundary:ReturnType<typeof createDependencyReadBoundary>;before:string;entries:ContextEntry[]}>();
        if(options){
          if(authorized.length>Math.min(8,maxNodes))throw new PathsError('INPUT_INCOMPLETE','Dependency root limit');
          for(const item of authorized){const k=key(item.grant.source_scope);if(!groups.has(k)){
            const matching=options.dependencies.filter(h=>{const s=dependencyHandleScope(h);return s.projectId===x.project_id&&s.workspaceId===x.workspace_id&&s.taskId===item.grant.source_scope.task_ref&&s.taskVersion===item.grant.source_scope.task_version&&s.role===x.role;});
            if(matching.length!==1)throw new PathsError('INPUT_INCOMPLETE','Exact sharing enrollment unavailable');
            const auth=dependencyAuthorization(root,x.project_id,x.workspace_id,item.grant.source_scope,x.target_scope,x.role,before.policy_hash);
            const boundary=createDependencyReadBoundary(root,storage,{project_id:x.project_id,workspace_id:x.workspace_id,...item.grant.source_scope,role:x.role,allowed_source_ids:x.allowed_source_ids},{dependencies:matching[0],dependency_budget:options.dependency_budget},session,auth);
            groups.set(k,{sourceScope:item.grant.source_scope,ids:[],boundary,before:'',entries:[]});
          }groups.get(k)!.ids.push(item.revision.revision_id);}
          for(const group of groups.values())group.before=group.boundary.checkRoots(group.ids);
        }
        const requests=authorized.map(item=>({project_id:x.project_id,workspace_id:x.workspace_id,...item.grant.source_scope,role:x.role,record_id:null,revision_id:item.revision.revision_id,source_id:item.revision.source_id}));
        const batch=options?{indices:requests.map((_,i)=>i),permitted_count:requests.length,captures:requests.map((request,i)=>{
          groups.get(key(authorized[i].grant.source_scope))!.boundary.assertRevision(request.revision_id!);ledger!.spendSql('queries',1);
          return storage.readHostMemoryCapture(request,bytes=>ledger!.sourceRead(bytes));
        })}:storage.readAuthorizedHostCaptureBatch(requests,maxNodes,request=>dependencyAuthorization(root,x.project_id,x.workspace_id,{task_ref:request.task_ref,task_version:request.task_version},x.target_scope,x.role,before.policy_hash).assertLive(request.revision_id!));
        const bounded=batch.indices.map(i=>authorized[i]),found=batch.captures;
        if(!bounded.length)return empty();
        if(new Set(bounded.map(item=>item.revision.revision_id)).size!==bounded.length)throw new PathsError('IDENTITY_CONFLICT','Ambiguous sharing grants');
        for(let i=0;i<bounded.length;i++)if(found[i]){
          const item=bounded[i],k=key(item.grant.source_scope);if(!groups.has(k))groups.set(k,{sourceScope:item.grant.source_scope,ids:[],before:'',entries:[],boundary:createDependencyReadBoundary(root,storage,{project_id:x.project_id,workspace_id:x.workspace_id,...item.grant.source_scope,role:x.role,allowed_source_ids:x.allowed_source_ids},undefined,undefined,dependencyAuthorization(root,x.project_id,x.workspace_id,item.grant.source_scope,x.target_scope,x.role,before.policy_hash))});
          groups.get(k)!.entries.push({record:found[i]!.record,binding:found[i]!.binding});
        }
        if(!options)for(const group of groups.values())group.before=group.boundary.check(group.entries,true);
        const hits:Array<{entry:ContextEntry;view:Record<string,unknown>;rank:number}>=[],notices:Array<Record<string,unknown>>=[],basisCache=new Map<string,boolean>(),firstBasis=new Map<string,boolean|null>();
        for(let i=0;i<bounded.length;i++){
          const item=bounded[i],saved=found[i];
          if(!saved||saved.record.source.source_id!==item.revision.source_id)continue;
          if(terms.length&&!terms.every(term=>(saved.record.content+' '+item.revision.tags.join(' ')).toLocaleLowerCase('en').includes(term)))continue;
          const assessed=applicability(root,current.policy.snapshot_files,item.revision.review,basisCache);
          firstBasis.set(item.revision.revision_id,assessed.basis_match);
          const state:MemoryApplicability=!saved.is_current||saved.current_lifecycle!=='ACTIVE'?'STALE_OR_SUPERSEDED':assessed.state;
          const origin={task_ref:item.grant.source_scope.task_ref,task_version:item.grant.source_scope.task_version};
          const metadata={revision_id:saved.record.revision_id,source_id:item.revision.source_id,source_content_hash:saved.record.source.content_hash,origin,
            applicability:state,basis_match:assessed.basis_match,applicability_authority:item.revision.review?'OWNER_DECLARED_REVIEW_WITH_APPROVED_FILE_HASHES':'NOT_EVALUATED',
            epistemic_state:saved.record.epistemic_state,mandatory:false,execution_verified:false,owner_confirmation_verified:false};
          if(state==='STALE_OR_SUPERSEDED'||state==='CONFLICT'){notices.push({...metadata,content_withheld:true});continue;}
          const rank=terms.length+x.tags.length;
          hits.push({entry:{record:saved.record,binding:{...saved.binding,task_ref:x.target_scope.task_ref,task_version:x.target_scope.task_version,roles:[x.role],allowed_source_ids:[item.revision.source_id],mandatory:false,priority:rank,conflicts:[]}},
            view:{...metadata,content:saved.record.content},rank});
        }
        // Dedup/authority/budget selection uses the existing compiler on a transient
        // explicitly granted target view. Origin metadata remains in public output.
        const entries=hits.map(h=>h.entry),viewHash=hash(entries.map(e=>e.binding));
        let pack:ReturnType<typeof compileContext>;
        try {
          pack=compileContext({project_id:x.project_id,workspace_id:x.workspace_id,...x.target_scope,role:x.role,target_snapshot_id:'read-only-sharing-'+viewHash,
          allowed_source_ids:[...new Set(entries.map(e=>e.record.source.source_id))],payload_budget_bytes:x.payload_budget_bytes,max_depth:current.policy.max_depth,max_nodes:maxNodes},
          {entries,edges:[],snapshot_hash:viewHash},{read:source=>{const hit=hits.find(h=>h.entry.record.source.source_id===source.source_id);if(!hit)return undefined;const origin=hit.view.origin as z.infer<typeof scope>;return groups.get(key(origin))!.boundary.read(source);}});
        } catch(error) {
          ledger?.assertAvailable();
          throw error;
        }
        ledger?.assertAvailable();
        const selected=new Set(pack.revisions),ordered=hits.filter(h=>selected.has(h.entry.record.revision_id)).sort((a,b)=>b.rank-a.rank||a.entry.record.revision_id.localeCompare(b.entry.record.revision_id,'en'));
        const reasons=new Set<string>();if(batch.permitted_count>maxNodes)reasons.add('NODE_BUDGET');
        if(pack.coverage.some(c=>c.reason==='payload_budget'))reasons.add('PAYLOAD_BUDGET');
        const lines:string[]=[];let used=0,count=0;
        for(const value of [...ordered.map(h=>h.view),...notices]){
          if(count>=x.limit){reasons.add('RESULT_LIMIT');break;}
          const line=canonicalContextJson(value),bytes=Buffer.byteLength(line,'utf8')+(lines.length?1:0);
          if(used+bytes>x.payload_budget_bytes){reasons.add('PAYLOAD_BUDGET');continue;}
          lines.push(line);used+=bytes;count++;
        }
        const payload=lines.join('\n');
        // Policy revocation and standalone ACL changes cannot be ignored mid-query.
        // Recheck review files after selection before returning applicability.
        const afterBasisCache=new Map<string,boolean>();
        for(const item of bounded)if(item.revision.review&&firstBasis.has(item.revision.revision_id)){const a=applicability(root,current.policy.snapshot_files,item.revision.review,afterBasisCache);if(a.basis_match!==firstBasis.get(item.revision.revision_id))throw new PathsError('SOURCE_MISSING','Review material changed during query');}
        const after=readPolicy(root),afterStandalone=readStandalonePolicy(root);
        if(after?.policy_hash!==before.policy_hash||afterStandalone?.policy_hash!==current.policy_hash)throw new PathsError('IDENTITY_CONFLICT','Authorization changed during query');
        if(bounded.some(item=>item.grant.expires_at!==null&&Date.parse(item.grant.expires_at)<=Date.now()))throw new PathsError('IDENTITY_CONFLICT','Sharing grant expired during query');
        for(let i=0;i<bounded.length;i++)if(found[i]){
          const group=groups.get(key(bounded[i].grant.source_scope))!;group.boundary.assertRevision(bounded[i].revision.revision_id,found[i]!.record.source);ledger?.spendSql('queries',1);
          const again=storage.readHostMemoryCapture(requests[batch.indices[i]],ledger?bytes=>ledger.sourceRead(bytes):undefined);
          if(canonicalContextJson(again)!==canonicalContextJson(found[i]))throw new PathsError('INPUT_INCOMPLETE','Sharing material changed');
        }
        for(const group of groups.values())if(options){if(group.boundary.checkRoots(group.ids)!==group.before)throw new PathsError('INPUT_INCOMPLETE','Sharing dependency changed');}else if(group.boundary.check(group.entries,true)!==group.before)throw new PathsError('INPUT_INCOMPLETE','Sharing dependency changed');
        if(!payload&&!reasons.size)return empty();
        return{...base,status:reasons.size?'INCOMPLETE':payload?'READY':'EMPTY',payload,payload_bytes:used,payload_sha256:hashBytes(payload),
          authorization_hash:hash(bounded),compiler:{version:pack.compiler_version,policy_version:pack.policy_version,view:'TRANSIENT_AUTHORIZED_VIEW_NOT_PERSISTED'},
          ...(ledger?{telemetry:{source_bytes_read:ledger.sourceBytes,measurement_scope:'LOGICAL_DEPENDENCY_AND_CAPTURE_SOURCE_RETURNS_NOT_PHYSICAL_IO'}}:{}),
          coverage:{incomplete:reasons.size>0,reasons:[...reasons].sort()}};
      },{readOnly:true,physicalRead});
      return result;
    }catch(error){return caught(error);}
  });
}
