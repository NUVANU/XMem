/** Thin structured MCP adapter. SDK/Core remains the only memory implementation. */
import { randomUUID } from 'node:crypto';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { readProjectConfig, resolveProjectRoot } from './index.js';
import { PathsError, withPathValidationScope } from './paths.js';
import { readStandalonePolicy } from './standalone.js';
import { readStorageLocationAtProjectRoot } from './storage-location.js';
import { canonicalContextJson } from './context.js';
import { hashBytes } from './local-source.js';
import { captureEngineeringMemory, queryEngineeringMemory, expandEngineeringMemory, ENGINEERING_RECORD_SCHEMA } from './engineering-memory.js';
import { retractEngineeringMemory, reconcileEngineeringRetraction } from './engineering-retraction.js';
import { ENGINEERING_MCP_CONTRACT, ENGINEERING_MCP_DEFAULT_BUDGET, ENGINEERING_MCP_SCHEMAS as schemas, ENGINEERING_MCP_OUTPUT_SCHEMA } from './engineering-mcp-contract.js';
import { createDependencyMcpRegistry,type DependencyMcpRegistry } from './dependency-mcp-registry.js';

type Binding = { id:string; session:string; transport:string; root:string; project:string; workspace:string; task:string; version:string;
  role:string; policy:string; location:string; budget:number; sources:string[]|undefined; fingerprint:string };
type Extra = { sessionId?:string };
const error = (code:string, commit?:string, reconciliation='Revalidate the original binding and reconcile the original task/memory_key with xmem_session_read; do not create a new key or retry blindly.') => ({ok:false as const,error:{code,message:'Engineering MCP operation unavailable within the verified session scope.',
  ...(commit ? {commit_state:commit,reconciliation}: {})}});
const throwCode = (code:string):never => { throw new PathsError(code,'Engineering MCP scope check failed'); };
const codeOf = (e:unknown) => e instanceof PathsError ? e.code : 'INTERNAL_ERROR';
function observed(rootInput:string) {
  const root=resolveProjectRoot(rootInput), config=readProjectConfig(root), policy=readStandalonePolicy(root);
  if(!policy?.policy.enabled)throwCode('NOT_CONFIGURED');
  const location=readStorageLocationAtProjectRoot(root,config.project_id);
  if(!location.configured||!location.location_hash)throwCode('STORAGE_LOCATION_UNCONFIRMED');
  return{root,config,policy:policy!,location};
}
function describe(b:Binding) {
  return{binding_id:b.id,session_ref:b.session,project_root:b.root,project_id:b.project,workspace_id:b.workspace,
    task_ref:b.task,task_version:b.version,role:b.role,policy_hash:b.policy,storage_location_hash:b.location,
    payload_budget_bytes:b.budget,allowed_source_ids:b.sources??null,verified:true as const,identity_authenticated:false as const,ephemeral:true as const};
}
function success(operation:string,b:Binding,status:string,data:Record<string,unknown>) {
  return{ok:true as const,value:{contract:ENGINEERING_MCP_CONTRACT,operation,status,binding:describe(b),data}};
}
function output(value:ReturnType<typeof error>|ReturnType<typeof success>) {
  ENGINEERING_MCP_OUTPUT_SCHEMA.parse(value);
  return{isError:!value.ok,structuredContent:value,content:[{type:'text' as const,text:JSON.stringify(value)}]};
}

/** Per-server/transport handle registry; no ambient "last project/task" and no disk state. */
export function registerEngineeringMcpTools(server:McpServer,dependencies:DependencyMcpRegistry=createDependencyMcpRegistry(server)):void {
  const namespace=randomUUID(), bindings=new Map<string,Binding>(), sessions=new Map<string,string>();
  const transport=(extra:Extra)=>extra.sessionId??namespace;
  const sessionKey=(session:string,extra:Extra)=>canonicalContextJson([transport(extra),session]);
  const verify=(b:Binding)=>{
    const now=observed(b.root);
    if(now.root!==b.root||now.config.project_id!==b.project||now.policy.policy.workspace_id!==b.workspace||
      now.policy.policy_hash!==b.policy||now.location.location_hash!==b.location||!now.policy.policy.allowed_roles.includes(b.role))throwCode('BINDING_CHANGED');
  };
  const get=(x:{session_ref:string;binding_id:string},extra:Extra)=>{
    const b=bindings.get(x.binding_id);
    if(!b||b.session!==x.session_ref||b.transport!==transport(extra)||sessions.get(sessionKey(x.session_ref,extra))!==b.id)throwCode('BINDING_NOT_FOUND');
    verify(b!);return b!;
  };
  const effectiveBudget=(b:Binding,requested?:number)=>{
    const result=requested??b.budget;
    if(result>b.budget)throwCode('INVALID_INPUT');
    return result;
  };
  const effectiveSources=(b:Binding,requested?:string[])=>{
    if(b.sources&&requested?.some(s=>!b.sources!.includes(s)))throwCode('SOURCE_FILTER_WIDENING');
    return requested??b.sources;
  };
  dependencies.setRegistrationGuard((x,extra)=>{
    if(!x.binding_id)return throwCode('BINDING_NOT_FOUND');
    const b=get({session_ref:x.session_ref,binding_id:x.binding_id},extra),input=x.input;
    const role=input.role??observed(b.root).policy.policy.default_role;
    if(readProjectConfig(x.project_root).root!==b.root||input.task_ref!==b.task||input.task_version!==b.version||role!==b.role||
      input.expected_scope.project_id!==b.project||input.expected_scope.workspace_id!==b.workspace||input.expected_scope.policy_hash!==b.policy||input.expected_scope.storage_location_hash!==b.location)throwCode('REFERENCE_OUTSIDE_BINDING');
    if(b.sources&&(input.allowed_source_ids===undefined||input.allowed_source_ids.some((s:string)=>!b.sources!.includes(s))))throwCode('SOURCE_FILTER_WIDENING');
  });
  const run=(work:()=>ReturnType<typeof error>|ReturnType<typeof success>)=>{
    try{return output(withPathValidationScope(work));}catch(e){return output(error(codeOf(e)));}
  };
  const readOnly={readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false};
  server.registerTool('xmem_engineering_bind',{
    description:'Bind this caller session to one explicitly selected project/task/version/role after project discovery. Check expected project/workspace IDs. No history search, grants or database writes. Every new chat must bind and verify independently. Handles and caller session labels are NOT authenticated identities. Rebind uses previous_binding_id CAS and invalidates the old handle.',
    inputSchema:schemas.xmem_engineering_bind,outputSchema:ENGINEERING_MCP_OUTPUT_SCHEMA,
    annotations:{...readOnly,readOnlyHint:false}
  },(x,extra)=>run(()=>{
    const env=observed(x.project_root);
    if(env.config.project_id!==x.expected_project_id||env.policy.policy.workspace_id!==x.expected_workspace_id)throwCode('PROJECT_MISMATCH');
    const role=x.role??env.policy.policy.default_role;
    if(!env.policy.policy.allowed_roles.includes(role))throwCode('UNTRUSTED_SOURCE');
    const budget=x.payload_budget_bytes??Math.min(ENGINEERING_MCP_DEFAULT_BUDGET,env.policy.policy.payload_budget_bytes);
    if(budget>env.policy.policy.payload_budget_bytes)throwCode('INVALID_INPUT');
    const key=sessionKey(x.session_ref,extra), previousId=sessions.get(key), previous=previousId?bindings.get(previousId):undefined;
    if(x.previous_binding_id!==null&&x.previous_binding_id!==previous?.id)throwCode('BINDING_NOT_FOUND');
    const data={session:x.session_ref,transport:transport(extra),root:env.root,project:env.config.project_id,workspace:env.policy.policy.workspace_id,
      task:x.task_ref,version:x.task_version,role,policy:env.policy.policy_hash,location:env.location.location_hash!,budget,
      sources:x.allowed_source_ids?[...x.allowed_source_ids].sort():undefined};
    const fingerprint=hashBytes(canonicalContextJson({...data,sources:data.sources??null}));
    if(previous?.fingerprint===fingerprint){verify(previous);return success('bind',previous,'BOUND',{replayed:true});}
    if(previous&&x.previous_binding_id!==previous.id)throwCode('BINDING_CONFLICT');
    if(!previous&&bindings.size>=128)throwCode('BINDING_CAPACITY');
    const next:Binding={...data,id:randomUUID(),fingerprint};
    verify(next);
    dependencies.invalidateSession(x.session_ref,extra);
    if(previous)bindings.delete(previous.id);
    bindings.set(next.id,next);sessions.set(key,next.id);
    return success('bind',next,'BOUND',{replayed:false});
  }));
  server.registerTool('xmem_engineering_binding_status',{
    description:'Independently revalidate this explicit session handle against current project, policy, role and confirmed storage location. No implicit last binding; no body reads or writes. Failure requires explicit rebind. Returned caller session label is not native host identity proof.',
    inputSchema:schemas.xmem_engineering_binding_status,outputSchema:ENGINEERING_MCP_OUTPUT_SCHEMA,annotations:readOnly
  },(x,extra)=>run(()=>success('binding_status',get(x,extra),'VERIFIED',{})));

  server.registerTool('xmem_engineering_query',{
    description:'Before editing a related file/module, query current authorized experience in this exact bound task. Returns structured preview items with conditions, UNKNOWN, sources and exact expansion references; no JSONL parsing required. Selector groups are OR, keywords are literal AND. EMPTY is normal; INCOMPLETE never promises semantic coverage. Defaults only narrow Owner/binding budgets. Never searches other historical tasks.',
    inputSchema:schemas.xmem_engineering_query,outputSchema:ENGINEERING_MCP_OUTPUT_SCHEMA,annotations:readOnly
  },(x,extra)=>run(()=>{
    const b=get(x,extra), budget=effectiveBudget(b,x.payload_budget_bytes);
    // JSONL separators become array commas; reserve the two array brackets.
    const sdkBudget=Math.max(0,budget-2);
    const result=queryEngineeringMemory(b.root,{task_ref:b.task,task_version:b.version,role:b.role,files:x.files,modules:x.modules,topics:x.topics,
      query:x.query,mode:'preview',limit:x.limit,payload_budget_bytes:sdkBudget,allowed_source_ids:effectiveSources(b,x.allowed_source_ids)},dependencies.options(b.root,x.dependency_token,x.dependency_token?x.session_ref:undefined,extra));
    if(!result.ok)return error(result.error.code);
    verify(b);
    const value=result.value as Record<string,any>, items=value.payload?String(value.payload).split('\n').map(line=>JSON.parse(line)):[];
    const body=budget>=2?canonicalContextJson(items):null;
    if(body&&Buffer.byteLength(body,'utf8')>budget)throwCode('MCP_PROJECTION_INVALID');
    return success('query',b,value.status,{items:body===null?null:items,requested_files:value.requested_files,coverage:value.coverage,
      payload_bytes:body===null?0:Buffer.byteLength(body,'utf8'),payload_sha256:body===null?null:hashBytes(body),payload_budget_bytes:budget,
      payload_representation:'CANONICAL_JSON_ITEMS_ARRAY_OR_NULL',budget_basis:'PUBLIC_ITEMS_ARRAY_UTF8_ENVELOPE_EXCLUDED',
      sdk_payload_bytes:value.payload_bytes,sdk_payload_sha256:value.payload_sha256,sdk_payload_budget_bytes:sdkBudget,telemetry:value.telemetry});
  }));

  server.registerTool('xmem_engineering_expand',{
    description:'Expand exactly one returned revision reference under this same verified session/task/role/source filter. Returns the complete logical entry and structured engineering record, never a cropped body. Changed preview, revoked scope, conflict or insufficient budget is a tool error; query again or reconcile as appropriate. Historical reads must be explicit and remain historical; no guessed replacement IDs.',
    inputSchema:schemas.xmem_engineering_expand,outputSchema:ENGINEERING_MCP_OUTPUT_SCHEMA,annotations:readOnly
  },(x,extra)=>run(()=>{
    const b=get(x,extra),r=x.reference,budget=effectiveBudget(b,x.payload_budget_bytes);
    if(r.project_id!==b.project||r.workspace_id!==b.workspace||r.task_ref!==b.task||r.task_version!==b.version||r.role!==b.role||
      (b.sources&&!b.sources.includes(r.source_id)))throwCode('REFERENCE_OUTSIDE_BINDING');
    const result=expandEngineeringMemory(b.root,{reference:r,view:x.view,payload_budget_bytes:budget},dependencies.options(b.root,x.dependency_token,x.dependency_token?x.session_ref:undefined,extra));
    if(!result.ok)return error(result.error.code);
    verify(b);
    const value=result.value as Record<string,any>;
    if(value.status!=='COMPLETE')return error(value.status);
    const entry=JSON.parse(value.payload);
    // Preserve arbitrary legacy prose; decode only this known structured record slot.
    let parsed:unknown;try{parsed=JSON.parse(entry.content);}catch{parsed=null;}
    if(parsed&&typeof parsed==='object'&&(parsed as any).format==='xmem-engineering/1'){
      const record=ENGINEERING_RECORD_SCHEMA.parse(parsed);
      // Older authorized captures can contain pretty-printed JSON. Keep its exact
      // source content when canonicalizing would change the referenced body hash.
      if(hashBytes(canonicalContextJson(record))===entry.record_content_hash){delete entry.content;entry.record=record;}
    }
    const body=canonicalContextJson(entry),size=Buffer.byteLength(body,'utf8');
    if(size>budget)throwCode('BUDGET_UNSATISFIABLE');
    return success('expand',b,'COMPLETE',{entry,payload_bytes:size,payload_sha256:hashBytes(body),payload_budget_bytes:budget,
      payload_representation:'CANONICAL_JSON_ENTRY',budget_basis:'PUBLIC_ENTRY_UTF8_ENVELOPE_EXCLUDED',
      sdk_payload_bytes:value.payload_bytes,sdk_payload_sha256:value.payload_sha256,historical:value.historical,telemetry:value.telemetry});
  }));

  server.registerTool('xmem_engineering_capture',{
    description:'WRITE one explicitly authorized engineering experience in this bound task. Record rule: information_type FAILURE requires the complete experience object; for NOTE, CONSTRAINT, DECISION, INTERFACE or UNKNOWN, experience must be exactly null. Reuses Core durable receipt/CAS and never executes advice. Exact replay uses the same key and predecessor; lost/unknown replies require read-only reconciliation, not a new key. Audience is only the bound role, non-mandatory Agent assertion. Source-filtered bindings are read-only; bind explicitly without a read filter to save. Use one save path per event, not this tool plus legacy capture.',
    inputSchema:schemas.xmem_engineering_capture,outputSchema:ENGINEERING_MCP_OUTPUT_SCHEMA,
    annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}
  },(x,extra)=>run(()=>{
    const b=get(x,extra);if(b.sources!==undefined)throwCode('READ_FILTERED_BINDING');
    const result=captureEngineeringMemory(b.root,{task_ref:b.task,task_version:b.version,memory_key:x.memory_key,
      previous_revision_id:x.previous_revision_id,roles:[b.role],record:x.record,
      expected_scope:{project_id:b.project,workspace_id:b.workspace,policy_hash:b.policy,storage_location_hash:b.location}});
    // Core errors do not expose the failing transaction stage. Even an integrity
    // or input-looking code can originate in post-commit source revalidation.
    // Only our pre-SDK checks can establish a rejection before this write call.
    if(!result.ok)return error(result.error.code,'UNKNOWN_RECONCILE_SAME_IDENTITY');
    try{verify(b);}catch{return error('SAVE_RECONCILIATION_REQUIRED','SAVED_RECEIPT_WITHHELD_BINDING_CHANGED');}
    return success('capture',b,'SAVED',{receipt:result.value});
  }));

  server.registerTool('xmem_engineering_retract',{
    description:'Explicit developer-only host CONSTRAINT/DECISION withdrawal or strictly read-only RECONCILE; action is mandatory. Preserve the full immutable intent, operation UUID, exact key/reference and approved public basis hashes. RETRACT atomically checks the current revision/lifecycle and reads public basis bytes twice; source-filtered bindings cannot write. Lost/unknown replies require a fresh binding and RECONCILE with the original intent. Returns the complete SDK canonical receipt payload/hash unchanged, never a truncated or reconstructed success. No Owner authentication, broadcast, hidden memory, cross-task authority or automatic restoration.',
    inputSchema:schemas.xmem_engineering_retract,outputSchema:ENGINEERING_MCP_OUTPUT_SCHEMA,
    annotations:{readOnlyHint:false,destructiveHint:true,idempotentHint:true,openWorldHint:false}
  },(x,extra)=>run(()=>{
    const b=get(x,extra),s=x.intent.scope,budget=effectiveBudget(b,x.payload_budget_bytes);
    if(b.role!=='developer')throwCode('UNTRUSTED_SOURCE');
    if(s.project_id!==b.project||s.workspace_id!==b.workspace||s.task_ref!==b.task||s.task_version!==b.version||s.role!==b.role)throwCode('REFERENCE_OUTSIDE_BINDING');
    if(x.action==='RETRACT'&&b.sources!==undefined)throwCode('READ_FILTERED_BINDING');
    const reconcile='Rebind independently and use xmem_engineering_retract action RECONCILE with the complete original intent; preserve operation_id/key/revision/guards. UNKNOWN does not authorize rewriting.';
    const fn=x.action==='RETRACT'?retractEngineeringMemory:reconcileEngineeringRetraction;
    const result=fn(b.root,{expected_scope:{project_id:b.project,workspace_id:b.workspace,task_ref:b.task,task_version:b.version,role:b.role},intent:x.intent,
      payload_budget_bytes:budget,...(b.sources===undefined?{}:{allowed_source_ids:b.sources})});
    if(!result.ok)return error(result.error.code,(result.diagnostics as any)?.commit_state??(x.action==='RETRACT'?'UNKNOWN_RECONCILE_SAME_IDENTITY':'COMMIT_UNKNOWN'),reconcile);
    try{verify(b);}catch{return error('RECONCILIATION_REQUIRED',x.action==='RETRACT'?'SAVED_RECEIPT_WITHHELD_BINDING_CHANGED':'COMMIT_UNKNOWN',reconcile);}
    const value=result.value as Record<string,unknown>;
    return success('retract',b,String(value.status),value);
  }));
}
