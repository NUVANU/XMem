/** Explicit host-rule withdrawal. Historical commitments are not present authority. */
import { z } from 'zod';
import { readProjectConfig, resolveProjectRoot, resolveProjectPath } from './index.js';
import { PathsError, withPathValidationScope } from './paths.js';
import { withProject, type CodexResult } from './codex.js';
import { withConfigurationLock } from './config-write.js';
import { readStandalonePolicy, STANDALONE_POLICY_FILE } from './standalone.js';
import { readStorageLocationAtProjectRoot } from './storage-location.js';
import { canonicalContextJson } from './context.js';
import { hashBytes, normalizeLocalSourcePath, readLocalSource, rejectObviousSecret } from './local-source.js';
import { ENGINEERING_RECORD_SCHEMA } from './engineering-memory.js';
import type { SqliteMemoryStorage, LifecycleEvent } from './storage.js';

export const ENGINEERING_RETRACTION_CONTRACT='xmem-engineering-retraction/1' as const;
const text=z.string().min(1).max(512).refine(s=>s.trim().length>0&&!s.includes('\0'));
const digest=z.string().regex(/^[a-f0-9]{64}$/);
const scope=z.object({project_id:text,workspace_id:text,task_ref:text,task_version:text,role:text}).strict();
export const ENGINEERING_RETRACTION_INTENT_SCHEMA=z.object({
  format:z.literal('xmem-engineering-retraction-intent/1'),operation_id:z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/),
  scope,memory_key:text,target:z.object({...scope.shape,revision_id:text,source_id:text,source_content_hash:digest,record_content_hash:digest,binding_hash:digest,policy_hash:digest}).strict(),
  guard_at_intent:z.object({policy_hash:digest,storage_location_hash:digest}).strict(),
  reason:z.string().min(1).refine(s=>s.trim().length>0&&!s.includes('\0')&&Buffer.byteLength(s,'utf8')<=1024),
  basis:z.array(z.object({path:text,sha256:digest}).strict()).min(1).max(8)
}).strict().superRefine((x,c)=>{
  if(canonicalContextJson(x.scope)!==canonicalContextJson(Object.fromEntries(Object.keys(scope.shape).map(k=>[k,(x.target as any)[k]])))||x.target.policy_hash!==x.guard_at_intent.policy_hash)c.addIssue({code:'custom',message:'Target and intent scopes or guards differ'});
  if(new Set(x.basis.map(b=>b.path)).size!==x.basis.length)c.addIssue({code:'custom',message:'Duplicate basis'});
  if(Buffer.byteLength(canonicalContextJson(x),'utf8')>16384)c.addIssue({code:'custom',message:'Intent exceeds UTF8 bound'});
});
export type EngineeringRetractionIntent=z.infer<typeof ENGINEERING_RETRACTION_INTENT_SCHEMA>;
export const ENGINEERING_RETRACTION_INPUT_SCHEMA=z.object({expected_scope:scope,intent:ENGINEERING_RETRACTION_INTENT_SCHEMA,
  payload_budget_bytes:z.number().int().nonnegative().max(262144).optional(),
  allowed_source_ids:z.array(text).max(512).refine(a=>new Set(a).size===a.length).optional()}).strict();
export type EngineeringRetractionInput=z.input<typeof ENGINEERING_RETRACTION_INPUT_SCHEMA>;
export type HostCapture=NonNullable<ReturnType<SqliteMemoryStorage['readHostMemoryCapture']>>;
export function retractionIdentity(intent:EngineeringRetractionIntent){return{format:ENGINEERING_RETRACTION_CONTRACT,...intent.scope,operation_id:intent.operation_id};}
export function retractionEventId(intent:EngineeringRetractionIntent){return'host-retract-'+hashBytes(canonicalContextJson(retractionIdentity(intent)));}
export function retractionRecordId(intent:EngineeringRetractionIntent){const s=intent.scope;return'host-memory-'+hashBytes(canonicalContextJson([s.project_id,s.workspace_id,s.task_ref,s.task_version,intent.memory_key]));}
export function captureReceiptCommitment(found:HostCapture){return{...found.durable_receipt,record_id:found.record.record_id,revision_id:found.record.revision_id,
  source_id:found.record.source.source_id,source_content_hash:found.record.source.content_hash,record_content_hash:hashBytes(found.record.content),binding_hash:hashBytes(canonicalContextJson(found.binding))};}
/** Also enforced by the narrow storage method, independently of SDK callbacks. */
export function retractionInformationType(found:HostCapture):'CONSTRAINT'|'DECISION' {
  let record;try{record=ENGINEERING_RECORD_SCHEMA.parse(JSON.parse(found.record.content));}catch{throw new PathsError('UNTRUSTED_SOURCE','Structured host rule required');}
  if(!['CONSTRAINT','DECISION'].includes(record.information_type)||found.record.kind!==(record.information_type==='CONSTRAINT'?'ConstraintRef':'DecisionRef'))throw new PathsError('UNTRUSTED_SOURCE','Structured host rule required');
  return record.information_type as 'CONSTRAINT'|'DECISION';
}
/** Canonical intent is retained in full; normalized basis ordering is returned in receipt. */
export function parseRetractionIntent(input:unknown):EngineeringRetractionIntent {
  const intent=ENGINEERING_RETRACTION_INTENT_SCHEMA.parse(input);
  for(const b of intent.basis)if(normalizeLocalSourcePath(b.path)!==b.path)throw new PathsError('INVALID_INPUT','Canonical public basis path required');
  intent.basis.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
  rejectObviousSecret(canonicalContextJson(intent));return intent;
}
function failure(code:string):CodexResult{return{ok:false,error:{code,message:'Engineering retraction unavailable within the requested scope'}};}

function operate(projectRoot:string,input:unknown,action:'RETRACT'|'RECONCILE'):CodexResult {
  return withPathValidationScope(()=>{try{
    const x=ENGINEERING_RETRACTION_INPUT_SCHEMA.parse(input),intent=parseRetractionIntent(x.intent),root=resolveProjectRoot(projectRoot);
    if(canonicalContextJson(x.expected_scope)!==canonicalContextJson(intent.scope))throw new PathsError('PROJECT_MISMATCH','Explicit scope required');
    if(intent.scope.role!=='developer')throw new PathsError('UNTRUSTED_SOURCE','Developer scope required');
    if(action==='RETRACT'&&x.allowed_source_ids!==undefined)throw new PathsError('READ_FILTERED_BINDING','Read-filtered binding cannot write');
    const environment=()=>{
      const config=readProjectConfig(root),p=readStandalonePolicy(root),location=readStorageLocationAtProjectRoot(root,config.project_id);
      if(!p?.policy.enabled)throw new PathsError('NOT_CONFIGURED','Enabled policy required');
      if(!location.configured||!location.location_hash)throw new PathsError('STORAGE_LOCATION_UNCONFIRMED','Confirmed location required');
      if(config.project_id!==intent.scope.project_id||p.policy.workspace_id!==intent.scope.workspace_id)throw new PathsError('PROJECT_MISMATCH','Scope differs');
      if(!p.policy.allowed_roles.includes('developer'))throw new PathsError('UNTRUSTED_SOURCE','Role unavailable');
      const budget=x.payload_budget_bytes??p.policy.payload_budget_bytes;
      if(budget>p.policy.payload_budget_bytes)throw new PathsError('INVALID_INPUT','Budget may only narrow');
      return{config,...p,location,budget};
    };
    const work=()=>{
      const env=environment();
      const unchanged=()=>{const now=environment();if(now.policy_hash!==env.policy_hash||now.location.location_hash!==env.location.location_hash)throw new PathsError('BINDING_CHANGED','Current read authority changed');};
      const validateCurrent=(found:HostCapture)=>{
        if(!env.policy.capture_categories.includes(retractionInformationType(found)))throw new PathsError('UNTRUSTED_SOURCE','Authorized structured host rule required');
        unchanged();
      };
      const validateWrite=()=>{
        unchanged();
        if(env.policy_hash!==intent.guard_at_intent.policy_hash||env.location.location_hash!==intent.guard_at_intent.storage_location_hash)throw new PathsError('PREVIEW_CHANGED','Write guard changed');
        for(const b of intent.basis){
          if(!env.policy.snapshot_files.includes(b.path))throw new PathsError('UNTRUSTED_SOURCE','Basis is not approved public source');
          const source=readLocalSource(root,b.path);rejectObviousSecret(source.text);
          if(hashBytes(source.bytes)!==b.sha256)throw new PathsError('SOURCE_DRIFT','Basis bytes changed');
        }
      };
      const receipt=(event:LifecycleEvent,found:HostCapture,replayed:boolean)=>{
        const material={contract:'xmem-engineering/2',capability:ENGINEERING_RETRACTION_CONTRACT,operation_identity:retractionIdentity(intent),request_hash:hashBytes(canonicalContextJson(intent)),
          event,event_sha256:hashBytes(canonicalContextJson(event)),capture_receipt_commitment:captureReceiptCommitment(found),persisted:'SAVED',commit_state:'COMMITTED',
          observed:{current_revision_id:found.is_current?found.current_revision_id:null,current_revision_withheld:!found.is_current,current_lifecycle:found.current_lifecycle,is_current_revision:found.is_current,active_for_recall:found.is_current&&found.current_lifecycle==='ACTIVE'},
          applicability:'NOT_EVALUATED',owner_confirmation_verified:false,actor_identity_verified:false,execution_verified:false};
        const payload=canonicalContextJson(material),size=Buffer.byteLength(payload,'utf8');
        if(size>env.budget)throw new PathsError('BUDGET_UNSATISFIABLE','Complete receipt does not fit');
        return{contract:'xmem-engineering/2',capability:ENGINEERING_RETRACTION_CONTRACT,status:action==='RECONCILE'?'COMMITTED_RECONCILED':replayed?'COMMITTED_REPLAYED':'COMMITTED',
          persisted:'SAVED',commit_state:'COMMITTED',read_only:action==='RECONCILE'||replayed,replayed,payload,payload_bytes:size,payload_sha256:hashBytes(payload),
          payload_budget_bytes:env.budget,budget_basis:'COMPLETE_CANONICAL_RECEIPT_PAYLOAD_UTF8_TRANSPORT_EXCLUDED'};
      };
      const result=withProject(root,storage=>action==='RECONCILE'
        ?storage.readHostMemoryRetraction(intent,{allowed_source_ids:x.allowed_source_ids,validateCurrent,receipt})
        :storage.retractHostMemoryCapture(intent,{validateCurrent,validateWrite,receipt}),
        action==='RECONCILE'?{readOnly:true}:{expectedStorageLocationHash:env.location.location_hash!});
      if(!result.ok)return{...failure(result.error.code),...(action==='RETRACT'?{diagnostics:{commit_state:'UNKNOWN_RECONCILE_SAME_IDENTITY'}}:{diagnostics:{commit_state:'COMMIT_UNKNOWN'}})} as CodexResult;
      try{unchanged();}catch{return{...failure('RECONCILIATION_REQUIRED'),diagnostics:{commit_state:action==='RETRACT'?'SAVED_RECEIPT_WITHHELD':'COMMIT_UNKNOWN'}} as CodexResult;}
      return result;
    };
    // A read-only reconciliation never creates a configuration lock or opens a writer.
    return action==='RETRACT'?withConfigurationLock(resolveProjectPath(root,STANDALONE_POLICY_FILE),work):work();
  }catch(e){return{...failure(e instanceof z.ZodError?'INVALID_INPUT':typeof(e as any)?.code==='string'?(e as any).code:'INCOMPLETE_OR_INCONSISTENT'),
    diagnostics:{commit_state:action==='RETRACT'?'UNKNOWN_RECONCILE_SAME_IDENTITY':'COMMIT_UNKNOWN'}} as CodexResult;}});
}
export function retractEngineeringMemory(projectRoot:string,input:unknown):CodexResult{return operate(projectRoot,input,'RETRACT');}
export function reconcileEngineeringRetraction(projectRoot:string,input:unknown):CodexResult{return operate(projectRoot,input,'RECONCILE');}
