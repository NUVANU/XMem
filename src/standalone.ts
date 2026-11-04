import { runPhysicalRead, type PhysicalReadOptions, type PhysicalReadSession } from './physical-readonly.js';
/** R3 standalone semi-automatic host adapter.
 *
 * The core stays host-agnostic: no background daemon or invented lifecycle hooks.
 * A host opts in once, then uses session_start/capture/checkpoint from project
 * instructions. Host narrative is always unverified ASSERTED/HYPOTHESIS material.
 */
import fs from 'node:fs';
import { withConfigurationLock, writeConfigurationAtomically } from './config-write.js';
import path from 'node:path';
import { readProjectConfig, resolveProjectPath, resolveProjectRoot } from './index.js';
import { PathsError, withPathValidationScope } from './paths.js';
import { withProject, type CodexResult } from './codex.js';
import { StorageError, type HandoffPackage, type SqliteMemoryStorage } from './storage.js';
import type { MemoryRecord } from './contracts.js';
import { canonicalContextJson, type ContextBinding, type ContextRequest } from './context.js';
import { captureLocalSnapshotWithStorage, compileLocalContextWithStorage, type LocalContextTelemetry } from './local-runtime.js';
import { dependencyReadLedger,type DependencyReadOptions,type DependencyReadSession } from './dependency-read-boundary.js';
export { registerEngineeringDependencies as registerMemoryDependencies,revokeEngineeringDependencies as revokeMemoryDependencies } from './engineering-memory.js';
export type { EngineeringDependencyHandle,EngineeringDependencyOptions } from './engineering-dependencies.js';
import { prepareHandoff } from './handoff.js';
import { hashBytes, rejectObviousSecret, validateLocalSnapshotInput } from './local-source.js';
import { hostCandidateSourceRef, type HostDeclaredActor } from './host-source.js';
import { readStorageLocationAtProjectRoot, storageLocationNotice } from './storage-location.js';
import { runtimeInfo } from './runtime-info.js';
import { TOPIC_CAPTURE_SCHEMA, prepareTopicOperation, topicDeadline, type TopicCaptureInput } from './topic-continuity.js';

export const STANDALONE_POLICY_FILE = '.xmem/standalone-v1.json';
export type StandaloneCaptureCategory = 'DECISION'|'CONSTRAINT'|'REQUIREMENT_CHANGE'|'FAILED_APPROACH'|'ROOT_CAUSE_HYPOTHESIS'|'IMPORTANT_DISCOVERY'|'HANDOFF_STATE';
const ALL_CATEGORIES: readonly StandaloneCaptureCategory[] = ['DECISION','CONSTRAINT','REQUIREMENT_CHANGE','FAILED_APPROACH','ROOT_CAUSE_HYPOTHESIS','IMPORTANT_DISCOVERY','HANDOFF_STATE'];

export interface StandalonePolicy {
  schema_version: 1;
  mode: 'SEMI_AUTO';
  enabled: boolean;
  workspace_id: string;
  default_role: string;
  allowed_roles: string[];
  snapshot_files: string[];
  payload_budget_bytes: number;
  max_depth: number;
  max_nodes: number;
  capture_categories: StandaloneCaptureCategory[];
  visible_receipts: boolean;
}
export interface StandaloneEnableInput { consent: true; expected_policy_hash: string|null; policy: StandalonePolicy; }
export interface StandaloneSessionInput { task_ref:string; task_version:string; role?:string; payload_budget_bytes?:number; allowed_source_ids?:string[]; }
export interface StandaloneCaptureInput { task_ref:string; task_version:string; memory_key:string; category:StandaloneCaptureCategory; declared_actor:HostDeclaredActor; content:string; previous_revision_id:string|null; roles?:string[]; }
/** Caller-observed scope, not a grant. Engineering SDK callers must provide it. */
export interface ExpectedCaptureScope { project_id:string; workspace_id:string; policy_hash:string; storage_location_hash:string; }
export interface StandaloneCheckpointInput extends StandaloneSessionInput { completed:string[]; pending:string[]; blocked:string[]; next_steps:string[]; }

function fail(code:string,message:string):CodexResult{return{ok:false,error:{code,message}};}
function caught(error:unknown):CodexResult { const x=error as {code?:unknown;message?:unknown}; return fail(typeof x?.code==='string'?x.code:'INTERNAL_ERROR',typeof x?.message==='string'?x.message:'XMem standalone operation failed'); }
function nonEmpty(value:unknown,max=512):value is string{return typeof value==='string'&&value.trim().length>0&&value.length<=max&&!value.includes('\0');}
function exactObject(input:unknown,keys:string[],label:string):Record<string,unknown>{if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).sort().join(',')!==[...keys].sort().join(','))throw new PathsError('INVALID_INPUT',`${label} has unknown or missing fields`);return input as Record<string,unknown>;}
function stringList(value:unknown,label:string,maxItems=64):string[]{if(!Array.isArray(value)||value.length>maxItems||!value.every(x=>nonEmpty(x,2048))||new Set(value).size!==value.length)throw new PathsError('INVALID_INPUT',`${label} must be unique bounded strings`);return [...value].sort() as string[];}
function policyHash(policy:StandalonePolicy):string{return hashBytes(canonicalContextJson(policy));}
function policyPath(root:string):string{return resolveProjectPath(root,STANDALONE_POLICY_FILE);}

export function validateStandalonePolicy(input:unknown):StandalonePolicy {
  const x=exactObject(input,['schema_version','mode','enabled','workspace_id','default_role','allowed_roles','snapshot_files','payload_budget_bytes','max_depth','max_nodes','capture_categories','visible_receipts'],'Standalone policy');
  if(x.schema_version!==1||x.mode!=='SEMI_AUTO'||typeof x.enabled!=='boolean'||!nonEmpty(x.workspace_id)||!nonEmpty(x.default_role)||typeof x.visible_receipts!=='boolean')throw new PathsError('INVALID_INPUT','Invalid standalone policy identity');
  const allowed_roles=stringList(x.allowed_roles,'allowed_roles',8); if(!allowed_roles.includes(String(x.default_role)))throw new PathsError('INVALID_INPUT','default_role must be in allowed_roles');
  const snapshot=validateLocalSnapshotInput({workspace_id:x.workspace_id,files:x.snapshot_files});
  if(!Number.isSafeInteger(x.payload_budget_bytes)||Number(x.payload_budget_bytes)<1024||Number(x.payload_budget_bytes)>256*1024||!Number.isSafeInteger(x.max_depth)||Number(x.max_depth)<0||Number(x.max_depth)>16||!Number.isSafeInteger(x.max_nodes)||Number(x.max_nodes)<1||Number(x.max_nodes)>512)throw new PathsError('INVALID_INPUT','Invalid standalone context budget');
  if(!Array.isArray(x.capture_categories)||x.capture_categories.length<1||x.capture_categories.some(v=>!ALL_CATEGORIES.includes(v as StandaloneCaptureCategory))||new Set(x.capture_categories).size!==x.capture_categories.length)throw new PathsError('INVALID_INPUT','Invalid standalone capture categories');
  return {schema_version:1,mode:'SEMI_AUTO',enabled:x.enabled as boolean,workspace_id:x.workspace_id as string,default_role:x.default_role as string,allowed_roles,snapshot_files:snapshot.files,payload_budget_bytes:Number(x.payload_budget_bytes),max_depth:Number(x.max_depth),max_nodes:Number(x.max_nodes),capture_categories:[...(x.capture_categories as StandaloneCaptureCategory[])].sort(),visible_receipts:x.visible_receipts as boolean};
}

export function readStandalonePolicy(projectRoot:string):{policy:StandalonePolicy;policy_hash:string}|null {
  const root=readProjectConfig(projectRoot).root; const filename=policyPath(root); if(!fs.existsSync(filename))return null;
  let raw:unknown; try{raw=JSON.parse(fs.readFileSync(filename,'utf8'));}catch{throw new PathsError('INVALID_CONFIG','Standalone policy is invalid JSON');}
  const policy=validateStandalonePolicy(raw); return{policy,policy_hash:policyHash(policy)};
}
function writePolicy(root:string,policy:StandalonePolicy):void { const filename=policyPath(root); writeConfigurationAtomically(filename,policy); }

export function configureStandalone(projectRoot:string,input:StandaloneEnableInput):CodexResult {
  return withPathValidationScope(() => {
  try{
    const root=resolveProjectRoot(projectRoot); readProjectConfig(root);
    return withConfigurationLock(policyPath(root),()=>{
    const x=exactObject(input,['consent','expected_policy_hash','policy'],'Standalone configure input'); if(x.consent!==true)throw new PathsError('INVALID_INPUT','Explicit project consent is required');
    if(!(x.expected_policy_hash===null||(typeof x.expected_policy_hash==='string'&&/^[a-f0-9]{64}$/.test(x.expected_policy_hash))))throw new PathsError('INVALID_INPUT','expected_policy_hash must be null or a SHA-256 hash');
    const policy=validateStandalonePolicy(x.policy), current=readStandalonePolicy(root);
    if(current&&x.expected_policy_hash!==null&&x.expected_policy_hash!==current.policy_hash)throw new PathsError('IDENTITY_CONFLICT','Standalone policy changed since it was read');
    if(current&&current.policy_hash!==policyHash(policy)){
      if(x.expected_policy_hash===null){if(current.policy_hash!==policyHash(policy))throw new PathsError('IDENTITY_CONFLICT','Standalone policy already exists; provide its current policy hash to update');}
      else if(x.expected_policy_hash!==current.policy_hash)throw new PathsError('IDENTITY_CONFLICT','Standalone policy changed since it was read');
    } else if(!current&&x.expected_policy_hash!==null) throw new PathsError('IDENTITY_CONFLICT','No standalone policy exists for the supplied expected hash');
    if(!current||current.policy_hash!==policyHash(policy))writePolicy(root,policy); const config=readProjectConfig(root); return{ok:true,value:{project_root:root,mode:'SEMI_AUTO',enabled:policy.enabled,policy,policy_hash:policyHash(policy),replayed:!!current&&current.policy_hash===policyHash(policy),automatic_hooks:false,host_mode:'PROJECT_INSTRUCTION_SEMI_AUTO',context_control:partialContextControl(),storage_location:storageLocationNotice(root,config.project_id),instruction:standaloneProjectInstruction()}};
    });
  }catch(error){return caught(error);}
  });
}
export function standaloneStatus(projectRoot:string,profile:'sdk'|'full'|'companion'|'engineering'='sdk'):CodexResult {
  return withPathValidationScope(() => {
    try {
      const root=resolveProjectRoot(projectRoot),config=readProjectConfig(root),current=readStandalonePolicy(root);
      return{ok:true,value:{project_root:root,project_id:config.project_id,configured:!!current,...current,runtime:runtimeInfo(profile),automatic_hooks:false,host_mode:'PROJECT_INSTRUCTION_SEMI_AUTO',context_control:partialContextControl(),storage_location:storageLocationNotice(root,config.project_id),instruction:standaloneProjectInstruction()}};
    } catch(error) { return caught(error); }
  });
}

export function discoverStandaloneProject(startPath?:string):CodexResult {
  try{
    // An isolated host may constrain discovery without changing project policy.
    // Check lexical containment before inspecting an unapproved start directory,
    // then recheck the canonical path before any project configuration read.
    const limit=process.env.XMEM_DISCOVERY_ROOT;
    const boundary=limit?resolveProjectRoot(limit):null;
    const inside=(candidate:string)=>{if(!boundary)return true;const relative=path.relative(boundary,candidate);return relative!== '..'&&!relative.startsWith('..'+path.sep)&&!path.isAbsolute(relative);};
    if(!inside(path.resolve(startPath??process.cwd())))return fail('INVALID_ROOT','Discovery start is outside the configured discovery root');
    let current=resolveProjectRoot(startPath??process.cwd());
    if(!inside(current))return fail('INVALID_ROOT','Discovery start redirects outside the configured discovery root');
    // resolveProjectRoot requires a directory. A host should pass its workspace folder,
    // not an arbitrary file. Walk upward but never cross the filesystem root.
    while(true){const config=path.join(current,'.xmem','config.json');if(fs.existsSync(config)){const parsed=readProjectConfig(current);const policy=readStandalonePolicy(current);return{ok:true,value:{project_root:current,project_id:parsed.project_id,standalone_configured:!!policy,enabled:policy?.policy.enabled??false,policy_hash:policy?.policy_hash??null,context_control:partialContextControl(),storage_location:storageLocationNotice(current,parsed.project_id)}};}const parent=path.dirname(current);if(parent===current||!inside(parent))break;current=parent;}
    return fail('NOT_INITIALIZED','No initialized XMem project was found from the supplied workspace path');
  }catch(error){return caught(error);}
}

function requireEnabled(root:string):{policy:StandalonePolicy;policy_hash:string} { const current=readStandalonePolicy(root);if(!current)throw new PathsError('NOT_CONFIGURED','Standalone semi-auto policy is not configured');if(!current.policy.enabled)throw new PathsError('INPUT_INCOMPLETE','Standalone semi-auto policy is paused');const config=readProjectConfig(root),location=readStorageLocationAtProjectRoot(root,config.project_id);if(!location.configured)throw new PathsError('STORAGE_LOCATION_UNCONFIRMED',`XMem memory defaults to ${location.default_storage_root}. Ask the user whether to keep this location or choose an existing empty local directory before semi-auto capture/session/checkpoint.`);return current; }
function validateSession(input:unknown):StandaloneSessionInput { const given=input as StandaloneSessionInput;const x=exactObject({...given,role:given?.role,payload_budget_bytes:given?.payload_budget_bytes,allowed_source_ids:given?.allowed_source_ids},['task_ref','task_version','role','payload_budget_bytes','allowed_source_ids'],'Session input');if(!nonEmpty(x.task_ref)||!nonEmpty(x.task_version)||!(x.role===undefined||nonEmpty(x.role))||!(x.payload_budget_bytes===undefined||Number.isSafeInteger(x.payload_budget_bytes)&&Number(x.payload_budget_bytes)>=0))throw new PathsError('INVALID_INPUT','Invalid session scope or budget');const sources=x.allowed_source_ids===undefined?undefined:stringList(x.allowed_source_ids,'allowed_source_ids',512);return{task_ref:x.task_ref,task_version:x.task_version,role:x.role as string|undefined,payload_budget_bytes:x.payload_budget_bytes as number|undefined,allowed_source_ids:sources}; }
function effectiveBudget(policy:StandalonePolicy,requested?:number):number { if(requested===undefined)return policy.payload_budget_bytes;if(!Number.isSafeInteger(requested)||requested<0||requested>policy.payload_budget_bytes)throw new PathsError('INVALID_INPUT','Per-call budget may only narrow the approved policy');return requested; }
function allowedRole(policy:StandalonePolicy,role?:string):string { const selected=role??policy.default_role;if(!policy.allowed_roles.includes(selected))throw new PathsError('UNTRUSTED_SOURCE','Requested role is outside the approved standalone policy');return selected; }
function compileStandalone(root:string,storage:SqliteMemoryStorage,policy:StandalonePolicy,task:StandaloneSessionInput,options?:DependencyReadOptions):{snapshot:import('./contracts.js').Snapshot;manifest:Record<string,unknown>;diagnostics:unknown;source_ids:string[];revision_ids:string[];role:string;telemetry:LocalContextTelemetry&{snapshot_ms:number};dependencySession?:DependencyReadSession;verify:()=>void} {
  const config=readProjectConfig(root),role=allowedRole(policy,task.role);
  const snapshotStarted=performance.now(),snapshotResult=captureLocalSnapshotWithStorage(root,storage,{workspace_id:policy.workspace_id,files:policy.snapshot_files}),snapshot_ms=Math.round((performance.now()-snapshotStarted)*1000)/1000;
  const scope=storage.listActiveContextSourceIds({project_id:config.project_id,workspace_id:policy.workspace_id,task_ref:task.task_ref,task_version:task.task_version,role});
  const request:ContextRequest={project_id:config.project_id,workspace_id:policy.workspace_id,task_ref:task.task_ref,task_version:task.task_version,role,target_snapshot_id:snapshotResult.snapshot.snapshot_id,allowed_source_ids:task.allowed_source_ids===undefined?scope.source_ids:scope.source_ids.filter(id=>task.allowed_source_ids!.includes(id)),payload_budget_bytes:effectiveBudget(policy,task.payload_budget_bytes),max_depth:policy.max_depth,max_nodes:policy.max_nodes};
  const compiled=compileLocalContextWithStorage(root,storage,request,true,options),context=compiled.context as unknown as Record<string,unknown>;
  return{snapshot:snapshotResult.snapshot,manifest:context,diagnostics:context.diagnostics,source_ids:request.allowed_source_ids,revision_ids:scope.revision_ids,role,dependencySession:compiled.dependencySession,verify:compiled.verify,telemetry:{snapshot_ms,...compiled.telemetry}};
}

function partialContextControl(){return{mode:'PARTIAL_CONTEXT_CONTROL' as const,host_memory_visible:'UNKNOWN' as const,conversation_history_replaceable:'UNKNOWN' as const,hidden_host_context_tokens:'UNKNOWN' as const,total_prompt_tokens:'UNKNOWN' as const,replacement_enforced:false,meaning:'Standalone/Companion mode can deduplicate XMem candidates, but cannot claim removal of hidden Host context.'};}
function usageTelemetry(){return{actual_usage_available:false,llm_input_tokens:null,llm_output_tokens:null,total_task_tokens:null,cost_per_verified_task:null};}

type StandaloneHandoffValidation = {status:'VALID'|'STALE'|'INCOMPLETE'|'UNKNOWN';reason_codes:string[]};

/**
 * Validate optional R3 continuity against the fresh material already compiled for
 * this session. This intentionally avoids calling recoverLocalHandoff(), which
 * would capture the same snapshot and rebuild the same context a second time.
 *
 * Safety is not weakened: getLatestHandoffPackage() verifies the immutable package;
 * captureLocalSnapshot()/compileLocalContext() have already verified the current
 * approved files, active revisions, live source hashes and persisted context
 * manifest. R3 checkpoints never carry trusted evidence or failure-registry refs;
 * packages that do are conservatively withheld from automatic continuity.
 */
function validateStandaloneContinuity(storage:SqliteMemoryStorage,latest:HandoffPackage,compiled:{snapshot:import('./contracts.js').Snapshot;manifest:Record<string,unknown>}):StandaloneHandoffValidation {
  if(latest.evidence_refs.length>0||latest.failed_attempt_refs.length>0)return{status:'UNKNOWN',reason_codes:['NON_R3_REFERENCES_REQUIRE_EXPLICIT_RECOVERY']};
  if(latest.target_snapshot_id!==compiled.snapshot.snapshot_id)return{status:'STALE',reason_codes:['DECLARED_FILES_OR_RUNTIME_CHANGED']};
  if(hashBytes(canonicalContextJson(compiled.snapshot))!==latest.target_snapshot_hash)return{status:'UNKNOWN',reason_codes:['TARGET_SNAPSHOT_INTEGRITY_MISMATCH']};
  const contentHash=compiled.manifest.content_hash, revisions=compiled.manifest.revisions;
  if(!nonEmpty(contentHash)||!Array.isArray(revisions)||!revisions.every(v=>nonEmpty(v)))return{status:'UNKNOWN',reason_codes:['CURRENT_CONTEXT_MANIFEST_INVALID']};
  if(latest.context_manifest_hash!==contentHash){
    // One-time R3.1.1 -> R3.1.2 policy upgrade is continuity-safe only when the
    // authoritative included revision set and source/view commitments are unchanged.
    const previous=storage.getContextManifest(latest.context_manifest_hash),policy=compiled.manifest.policy_version,sourceHash=compiled.manifest.source_snapshot_hash,viewHash=compiled.manifest.view_snapshot_hash;
    const previousSet=new Set(previous?.revisions??[]),currentSet=new Set(revisions as string[]);
    const equivalentUpgrade=previous?.policy_version==='context-policy-v1'&&policy==='context-policy-v2'&&previousSet.size===currentSet.size&&[...previousSet].every(id=>currentSet.has(id))&&previous.source_snapshot_hash===sourceHash&&previous.view_snapshot_hash===viewHash;
    if(!equivalentUpgrade){
      if(previous&&previous.view_snapshot_hash===viewHash&&previous.request.payload_budget_bytes!==(compiled.manifest.request as ContextRequest).payload_budget_bytes)return{status:'INCOMPLETE',reason_codes:['REQUEST_CONTEXT_BUDGET_CHANGED']};
      return{status:'STALE',reason_codes:['CONTEXT_RECOMPILE_CHANGED']};
    }
  }
  const current=new Set(revisions as string[]);
  if(latest.revision_refs.some(ref=>!current.has(ref.revision_id)))return{status:'STALE',reason_codes:['CURRENT_REVISION_SET_CHANGED']};
  return{status:'VALID',reason_codes:['FRESH_SESSION_MATERIAL_MATCH']};
}

export function startStandaloneSession(projectRoot:string,input:StandaloneSessionInput,options?:DependencyReadOptions):CodexResult {
  return withPathValidationScope(() => {
    const operationStarted=performance.now();
    try{
      const root=resolveProjectRoot(projectRoot),current=requireEnabled(root),task=validateSession({...input,role:input.role,payload_budget_bytes:input.payload_budget_bytes,allowed_source_ids:input.allowed_source_ids}),config=readProjectConfig(root),budget=effectiveBudget(current.policy,task.payload_budget_bytes);
      const result=withProject(root,storage=>{
        const compiled=compileStandalone(root,storage,current.policy,task,options),latest=storage.getLatestHandoffPackage(config.project_id,current.policy.workspace_id,task.task_ref,task.task_version,compiled.role)??null;
        let handoff:unknown=null;
        let continuityBytes=0,interpretationBytes=0;
        if(latest){
          let validation=validateStandaloneContinuity(storage,latest,compiled);
          const continuity={completed:latest.completed,pending:latest.pending,blocked:latest.blocked,next_steps:latest.next_steps};
          try{for(const text of [...latest.completed,...latest.pending,...latest.blocked,...latest.next_steps])rejectObviousSecret(text);}catch{validation={status:'UNKNOWN',reason_codes:['SENSITIVE_CONTINUITY_WITHHELD']};}
          // Material freshness never attests that a historical business pending item
          // is still pending. This projection is not persisted into the old package.
          const interpretationFor=(state:StandaloneHandoffValidation['status'])=>({
            kind:'HISTORICAL_CHECKPOINT_SNAPSHOT',applicability:'NOT_EVALUATED',material_validation_only:true,
            scope:{project_id:config.project_id,workspace_id:current.policy.workspace_id,task_ref:task.task_ref,task_version:task.task_version,role:compiled.role},
            basis:{package_id:latest.package_id,context_manifest_hash:latest.context_manifest_hash},
            next_host_action:state==='VALID'?'VERIFY_CURRENT_FACTS_BEFORE_ACTING_ON_HISTORICAL_PENDING':'REVIEW_WITHHELD_MATERIAL_BEFORE_RESUME'
          });
          const bytes=(value:unknown)=>Buffer.byteLength(canonicalContextJson(value),'utf8');
          if(validation.status==='VALID'&&Number(compiled.manifest.payload_bytes)+bytes(continuity)+bytes(interpretationFor('VALID'))>budget)
            validation={status:'INCOMPLETE',reason_codes:['CONTINUITY_BUDGET_UNSATISFIABLE']};
          const interpretation=interpretationFor(validation.status);
          continuityBytes=validation.status==='VALID'?bytes(continuity):0;
          interpretationBytes=bytes(interpretation);
          if(Number(compiled.manifest.payload_bytes)+continuityBytes+interpretationBytes>budget)
            throw new StorageError('BUDGET_UNSATISFIABLE','Historical checkpoint interpretation cannot fit within the approved session budget; no resume context was returned');
          handoff={package_id:latest.package_id,validation,continuity:validation.status==='VALID'?continuity:null,interpretation};
        }
        compiled.verify();if(compiled.dependencySession)compiled.telemetry.source_bytes_considered=dependencyReadLedger(compiled.dependencySession).sourceBytes;
        return{project_root:root,project_id:config.project_id,policy_hash:current.policy_hash,mode:'SEMI_AUTO',automatic_hooks:false,context_control:partialContextControl(),budget:{approved_limit_bytes:current.policy.payload_budget_bytes,effective_limit_bytes:budget,unit:'utf8-bytes',basis:handoff===null?'INTERNAL_PRE_REDACTION_CONTEXT_PLUS_CONTINUITY':'INTERNAL_PRE_REDACTION_CONTEXT_PLUS_RETURNED_CONTINUITY_PLUS_INTERPRETATION',measured_bytes:{context:Number(compiled.manifest.payload_bytes),continuity:continuityBytes,interpretation:interpretationBytes,total:Number(compiled.manifest.payload_bytes)+continuityBytes+interpretationBytes}},session:{workspace_id:current.policy.workspace_id,task_ref:task.task_ref,task_version:task.task_version,role:compiled.role},snapshot:{snapshot_id:compiled.snapshot.snapshot_id,scope:'APPROVED_FILES_ONLY'},context:compiled.manifest,handoff,telemetry:{operation:'session_start',xmem_latency_ms:0,...compiled.telemetry,...usageTelemetry()},receipt:{visible:current.policy.visible_receipts,message:'XMem session context compiled from currently approved sources; host automation is instruction-driven, not a lifecycle hook.'}};
      });
      if(!result.ok)return result;
      const value=result.value as Record<string,unknown>,telemetry=value.telemetry as Record<string,unknown>;telemetry.xmem_latency_ms=Math.round((performance.now()-operationStarted)*1000)/1000;
      return{ok:true,value};
    }catch(error){return caught(error);}
  });
}

function captureMapping(category:StandaloneCaptureCategory):{kind:MemoryRecord['kind'];epistemic_state:MemoryRecord['epistemic_state'];information_role:MemoryRecord['information_role'];confirmation_recommended:boolean} {
  switch(category){
    case'DECISION':return{kind:'DecisionRef',epistemic_state:'ASSERTED',information_role:'NORMATIVE_REF',confirmation_recommended:true};
    case'CONSTRAINT':return{kind:'ConstraintRef',epistemic_state:'ASSERTED',information_role:'NORMATIVE_REF',confirmation_recommended:true};
    case'REQUIREMENT_CHANGE':return{kind:'DecisionRef',epistemic_state:'ASSERTED',information_role:'NORMATIVE_REF',confirmation_recommended:true};
    case'FAILED_APPROACH':return{kind:'FailedAttempt',epistemic_state:'ASSERTED',information_role:'EXPERIENCE',confirmation_recommended:false};
    case'ROOT_CAUSE_HYPOTHESIS':return{kind:'RootCauseHypothesis',epistemic_state:'HYPOTHESIS',information_role:'SUGGESTION',confirmation_recommended:false};
    case'IMPORTANT_DISCOVERY':return{kind:'Observation',epistemic_state:'ASSERTED',information_role:'SUGGESTION',confirmation_recommended:false};
    case'HANDOFF_STATE':return{kind:'Observation',epistemic_state:'ASSERTED',information_role:'SUGGESTION',confirmation_recommended:false};
  }
}
function validateCapture(input:unknown):StandaloneCaptureInput { const given=input as StandaloneCaptureInput;const x=exactObject({...given,roles:given?.roles},['task_ref','task_version','memory_key','category','declared_actor','content','previous_revision_id','roles'],'Session capture');if(!nonEmpty(x.task_ref)||!nonEmpty(x.task_version)||!nonEmpty(x.memory_key)||!ALL_CATEGORIES.includes(x.category as StandaloneCaptureCategory)||!['user','agent'].includes(String(x.declared_actor))||typeof x.content!=='string'||!x.content.trim()||x.content.includes('\0')||Buffer.byteLength(x.content,'utf8')>16*1024||!(x.previous_revision_id===null||nonEmpty(x.previous_revision_id)))throw new PathsError('INVALID_INPUT','Invalid semi-auto capture');if(x.roles!==undefined){const roles=stringList(x.roles,'roles',8);if(!roles.length)throw new PathsError('INVALID_INPUT','Capture roles cannot be empty');x.roles=roles;}return x as unknown as StandaloneCaptureInput; }

export function captureStandaloneMemory(projectRoot:string,input:StandaloneCaptureInput,expectedScope?:ExpectedCaptureScope):CodexResult {
  return withPathValidationScope(() => {
    const operationStarted=performance.now();
    try{
      const root=resolveProjectRoot(projectRoot),x=validateCapture(input);
      let expected:ExpectedCaptureScope|undefined;
      if(expectedScope!==undefined){
        const e=exactObject(expectedScope,['project_id','workspace_id','policy_hash','storage_location_hash'],'Expected capture scope');
        if(!nonEmpty(e.project_id)||!nonEmpty(e.workspace_id)||![e.policy_hash,e.storage_location_hash].every(v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)))throw new PathsError('INVALID_INPUT','Invalid expected capture scope');
        expected={project_id:e.project_id,workspace_id:e.workspace_id,policy_hash:e.policy_hash as string,storage_location_hash:e.storage_location_hash as string};
      }
      // Same lock as configureStandalone. Order: policy -> location -> SQLite.
      // No configuration writer can change workspace/roles after this read and
      // before the guarded operation closes its store and releases both locks.
      return withConfigurationLock(policyPath(root),()=>{
      const current=requireEnabled(root),config=readProjectConfig(root);
      if(expected&&(config.project_id!==expected.project_id||current.policy.workspace_id!==expected.workspace_id||current.policy_hash!==expected.policy_hash))throw new PathsError('IDENTITY_CONFLICT','Capture scope changed before write');
      const location=readStorageLocationAtProjectRoot(root,config.project_id);
      if(!location.configured||!location.location_hash)throw new PathsError('STORAGE_LOCATION_UNCONFIRMED','Capture requires confirmed storage');
      if(!current.policy.capture_categories.includes(x.category))throw new PathsError('UNTRUSTED_SOURCE','Capture category is outside the approved standalone policy');
      const roles=x.roles??current.policy.allowed_roles;if(roles.some(role=>!current.policy.allowed_roles.includes(role)))throw new PathsError('UNTRUSTED_SOURCE','Capture roles may only narrow the approved policy');
      const source=hostCandidateSourceRef(config.project_id,x.declared_actor,x.content),mapping=captureMapping(x.category);
      const record_id='host-memory-'+hashBytes(canonicalContextJson([config.project_id,current.policy.workspace_id,x.task_ref,x.task_version,x.memory_key]));
      const revision_id='host-revision-'+hashBytes(canonicalContextJson({record_id,source,content:x.content,category:x.category,roles,previous_revision_id:x.previous_revision_id}));
      const record:MemoryRecord={schema_version:'1',record_id,revision_id,project_id:config.project_id,kind:mapping.kind,source,epistemic_state:mapping.epistemic_state,lifecycle:'ACTIVE',information_role:mapping.information_role,content:x.content,previous_revision_id:x.previous_revision_id};
      const binding:ContextBinding={revision_id,project_id:config.project_id,workspace_id:current.policy.workspace_id,task_ref:x.task_ref,task_version:x.task_version,roles,allowed_source_ids:[source.source_id],mandatory:false,priority:0,conflicts:[]};
      // R3.1.2: one storage open covers both the atomic write and retained-source
      // revalidation. R3.1.1 reopened SQLite for the second read.
      const result=withProject(root,storage=>{const receipt=storage.recordHostMemoryCapture(record,binding);const fresh=storage.readHostCandidateSource(config.project_id,source);if(!fresh||hashBytes(fresh)!==source.content_hash)throw new StorageError('SOURCE_MISSING','Host candidate source could not be revalidated');return{...receipt,project_id:config.project_id,workspace_id:current.policy.workspace_id,task_ref:x.task_ref,task_version:x.task_version,category:x.category,epistemic_state:mapping.epistemic_state,information_role:mapping.information_role,mandatory:false,execution_verified:false,owner_confirmation_verified:false,actor_identity_verified:false,confirmation_recommended:mapping.confirmation_recommended,record_type:x.category==='FAILED_APPROACH'?'FAILURE_EXPERIENCE_NOT_TRUSTED_FAILURE_REGISTRY':'HOST_ASSERTION',telemetry:{operation:'session_capture',xmem_latency_ms:0,capture_bytes:Buffer.byteLength(x.content,'utf8'),...usageTelemetry()},receipt:{visible:current.policy.visible_receipts,message:'Captured a bounded host candidate. It is not trusted execution evidence or authenticated owner approval.'}};},{expectedStorageLocationHash:expected?.storage_location_hash??location.location_hash});
      if(!result.ok)return result;const value=result.value as Record<string,unknown>,telemetry=value.telemetry as Record<string,unknown>;telemetry.xmem_latency_ms=Math.round((performance.now()-operationStarted)*1000)/1000;return{ok:true,value};
      });
    }catch(error){return caught(error);}
  });
}

/** Explicit opt-in content envelope. Existing plain capture and its CAS are unchanged. */
export function captureStandaloneTopic(projectRoot:string,input:TopicCaptureInput):CodexResult {
  try{
    const x=TOPIC_CAPTURE_SCHEMA.parse(input),clock=topicDeadline(x.deadline_unix_ms);
    return withPathValidationScope(()=>{
      const env=prepareTopicOperation(projectRoot,undefined,x.payload_budget_bytes,16384,clock);
      const content=canonicalContextJson({format:'xmem-topic-capture/1',memory_key:x.memory_key,topic:x.topic,category:x.category,declared_actor:x.declared_actor,content:x.content});
      if(Buffer.byteLength(content,'utf8')>env.payloadBudget)throw new PathsError('BUDGET_UNSATISFIABLE','The entire Topic envelope must fit the approved capture budget');
      clock.check();
      const result=captureStandaloneMemory(env.root,{task_ref:x.task_ref,task_version:x.task_version,memory_key:x.memory_key,category:x.category,declared_actor:x.declared_actor,content,previous_revision_id:x.previous_revision_id,roles:x.roles},{project_id:env.config.project_id,workspace_id:env.policy.workspace_id,policy_hash:env.options.expected.policy_hash,storage_location_hash:env.options.expected.location_hash});
      clock.check();return result;
    },clock.remaining);
  }catch(error){return caught(error);}
}

export interface StandaloneReadInput { task_ref:string; task_version:string; role?:string; memory_key:string|null; revision_id:string|null; payload_budget_bytes:number; }

/** Explicit, indivisible logical readback. No context/snapshot is written or inferred. */
export function readStandaloneMemory(projectRoot:string,input:StandaloneReadInput,options?:PhysicalReadOptions):CodexResult {
  if(options!==undefined)return runPhysicalRead(projectRoot,input,options,session=>readStandaloneMemoryInternal(projectRoot,input,session));
  return readStandaloneMemoryInternal(projectRoot,input);
}
function readStandaloneMemoryInternal(projectRoot:string,input:StandaloneReadInput,physicalRead?:PhysicalReadSession):CodexResult {
  return withPathValidationScope(()=>{
    try {
      const root=resolveProjectRoot(projectRoot),current=requireEnabled(root);
      const x=exactObject({...input,role:input.role},['task_ref','task_version','role','memory_key','revision_id','payload_budget_bytes'],'Session read');
      const task=validateSession({task_ref:x.task_ref,task_version:x.task_version,role:x.role}),role=allowedRole(current.policy,task.role);
      if(!(x.memory_key===null||nonEmpty(x.memory_key))||(x.memory_key===null&&x.revision_id===null)||!(x.revision_id===null||nonEmpty(x.revision_id))||!Number.isSafeInteger(x.payload_budget_bytes)||Number(x.payload_budget_bytes)<0||Number(x.payload_budget_bytes)>current.policy.payload_budget_bytes)throw new PathsError('INVALID_INPUT','Read budget must stay within the approved policy and identities must be bounded');
      const config=readProjectConfig(root),recordId=x.memory_key===null?null:'host-memory-'+hashBytes(canonicalContextJson([config.project_id,current.policy.workspace_id,task.task_ref,task.task_version,x.memory_key]));
      return withProject(root,storage=>{
        const found=storage.readHostMemoryCapture({project_id:config.project_id,workspace_id:current.policy.workspace_id,...task,role,record_id:recordId,revision_id:x.revision_id as string|null});
        const base={contract:'CORE_HOST_CAPTURE_READBACK_V1',policy_hash:current.policy_hash,execution_verified:false,owner_confirmation_verified:false,actor_identity_verified:false,applicability:'NOT_EVALUATED',budget_unit:'utf8-bytes',payload_budget_bytes:Number(x.payload_budget_bytes)};
        if(!found)return {...base,status:'NOT_FOUND_WITHIN_SCOPE',persisted:'UNKNOWN',payload:null,payload_bytes:0,meaning:'No matching permitted capture was found; this does not prove an earlier request never committed.'};
        const {record,binding}=found;
        const view={schema_version:1,scope:{project_id:config.project_id,workspace_id:current.policy.workspace_id,task_ref:task.task_ref,task_version:task.task_version,role},
          record:{record_id:record.record_id,revision_id:record.revision_id,previous_revision_id:record.previous_revision_id,kind:record.kind,epistemic_state:record.epistemic_state,information_role:record.information_role,lifecycle_at_save:record.lifecycle,content:record.content},
          source:{source_id:record.source.source_id,kind:record.source.kind},source_content_hash:record.source.content_hash,
          binding:{roles:binding.roles,mandatory:binding.mandatory,allowed_source_ids:binding.allowed_source_ids},
          current:found.is_current?{revision_id:found.current_revision_id,lifecycle:found.current_lifecycle,is_current:true}:{revision_id:null,lifecycle:'UNKNOWN',is_current:false},durable_receipt:found.durable_receipt};
        const payload=canonicalContextJson(view),required=Buffer.byteLength(payload,'utf8'),contentHash=hashBytes(payload);
        if(required>Number(x.payload_budget_bytes))return {...base,status:'BUDGET_UNSATISFIABLE',persisted:'SAVED',required_payload_bytes:required,payload:null,payload_bytes:0,content_hash:contentHash,meaning:'This logical capture is indivisible; no partial body was returned and the approved budget was not raised.'};
        return {...base,status:'COMPLETE',persisted:'SAVED',required_payload_bytes:required,payload,payload_bytes:required,content_hash:contentHash};
      },{readOnly:true,physicalRead});
    } catch(error){return caught(error);}
  });
}

function validateCheckpoint(input:unknown):StandaloneCheckpointInput { const x=exactObject(input,['task_ref','task_version','role','completed','pending','blocked','next_steps','payload_budget_bytes','allowed_source_ids'],'Session checkpoint');const task=validateSession({task_ref:x.task_ref,task_version:x.task_version,role:x.role,payload_budget_bytes:x.payload_budget_bytes,allowed_source_ids:x.allowed_source_ids});return{...task,completed:stringList(x.completed,'completed',64),pending:stringList(x.pending,'pending',64),blocked:stringList(x.blocked,'blocked',64),next_steps:stringList(x.next_steps,'next_steps',64)}; }
export function checkpointStandaloneSession(projectRoot:string,input:StandaloneCheckpointInput,options?:DependencyReadOptions):CodexResult {
  return withPathValidationScope(() => {
    const operationStarted=performance.now();
    try{
      const root=resolveProjectRoot(projectRoot),current=requireEnabled(root),x=validateCheckpoint({...input,role:input.role,payload_budget_bytes:input.payload_budget_bytes,allowed_source_ids:input.allowed_source_ids}),config=readProjectConfig(root),budget=effectiveBudget(current.policy,x.payload_budget_bytes);
      for(const value of [...x.completed,...x.pending,...x.blocked,...x.next_steps])rejectObviousSecret(value);
      const continuityBytes=Buffer.byteLength(canonicalContextJson({completed:x.completed,pending:x.pending,blocked:x.blocked,next_steps:x.next_steps}),'utf8');
      if(continuityBytes>budget)throw new StorageError('BUDGET_UNSATISFIABLE','Checkpoint continuity exceeds the effective payload budget');
      const result=withProject(root,storage=>{
        const compiled=compileStandalone(root,storage,current.policy,x,options),manifest=compiled.manifest as {content_hash?:unknown;revisions?:unknown};
        if(!nonEmpty(manifest.content_hash)||!Array.isArray(manifest.revisions)||!manifest.revisions.every(v=>nonEmpty(v)))throw new StorageError('IDENTITY_CONFLICT','Compiled context manifest is incomplete');
        if(Number(compiled.manifest.payload_bytes)+continuityBytes>budget)throw new StorageError('BUDGET_UNSATISFIABLE','Context plus checkpoint continuity exceeds the effective payload budget');
        const revision_ids=[...(manifest.revisions as string[])];
        const handoff=prepareHandoff(storage,{project_id:config.project_id,workspace_id:current.policy.workspace_id,task_ref:x.task_ref,task_version:x.task_version,target_snapshot:compiled.snapshot,revision_ids,evidence_ids:[],failed_attempt_ids:[],context_manifest_hash:manifest.content_hash as string,completed:x.completed,pending:x.pending,blocked:x.blocked,next_steps:x.next_steps},{projectRoot:root,options,session:compiled.dependencySession});
        if(compiled.dependencySession)compiled.telemetry.source_bytes_considered=dependencyReadLedger(compiled.dependencySession).sourceBytes;
        const selected=storage.getLatestHandoffPackage(config.project_id,current.policy.workspace_id,x.task_ref,x.task_version,compiled.role);
        const selectedForResume=selected?.package_id===handoff.package_id;
        compiled.verify();if(compiled.dependencySession)compiled.telemetry.source_bytes_considered=dependencyReadLedger(compiled.dependencySession).sourceBytes;
        return{project_root:root,project_id:config.project_id,policy_hash:current.policy_hash,package_id:handoff.package_id,selected_for_resume:selectedForResume,resume_package_id:selected?.package_id??null,checkpoint_semantics:'IMMUTABLE_CONTENT_REPLAY_DOES_NOT_REORDER',content_hash:handoff.content_hash,target_snapshot_id:handoff.target_snapshot_id,context_manifest_hash:handoff.context_manifest_hash,revision_count:handoff.revision_refs.length,evidence_count:0,failed_attempt_registry_count:0,continuity:{completed:handoff.completed,pending:handoff.pending,blocked:handoff.blocked,next_steps:handoff.next_steps},context_control:partialContextControl(),telemetry:{operation:'session_checkpoint',xmem_latency_ms:0,...compiled.telemetry,...usageTelemetry()},execution_verified:false,owner_confirmation_verified:false,receipt:{visible:current.policy.visible_receipts,message:selectedForResume?'Checkpoint persisted and selected for this role. A later session must revalidate live sources before using it.':'Historical checkpoint replayed; a newer distinct checkpoint remains selected for this role. No resume pointer was rewound.'}};
      });
      if(!result.ok)return result;
      const value=result.value as Record<string,unknown>,telemetry=value.telemetry as Record<string,unknown>;telemetry.xmem_latency_ms=Math.round((performance.now()-operationStarted)*1000)/1000;
      return{ok:true,value};
    }catch(error){return caught(error);}
  });
}

export function standaloneProjectInstruction():string { return [
  '# XMem R3 standalone semi-auto',
  'This project has user-approved XMem semi-auto continuity. Before the first session_start/capture/checkpoint, inspect storage_location from configure/status. If prompt_required=true, tell the user the exact default memory storage path in the user\'s language and ask whether to keep it. If the user wants another location, ask for an existing empty absolute local-drive directory and hand off to the owner setup CLI (xmem storage-location-configure) or the explicitly authorized full setup surface. The ordinary Companion cannot configure policy or storage. Never choose or migrate a storage path without owner approval.',
  'After storage location is explicitly confirmed, at the first substantive turn of a new project session, call xmem_session_start for the active task before asking the user to repeat known project context.',
  'At the first substantive request and when the user changes to a topic that may have prior decisions or constraints, use xmem_project_discover with its explicit topic branch if the original task scope is unknown. Use only literal terms from the current request. Preview at most two bounded pages, then use xmem_session_read mode=expand/view=current for at most two exact returned references. Check current/source/receipt/conflicts and byte budgets before adoption. Explain EMPTY, incomplete, ambiguous or unavailable material honestly; clarify once when several candidates remain. These reads grant no permission and never rebind, copy or inherit another task into a target ContextPack.',
  'An explicit high-value follow-up decision may use session_capture mode=topic with the verified original memory_key/scope and exact current predecessor. Topic envelopes preserve caller content and key; legacy plain keys remain UNKNOWN_READ_ONLY and must not be guessed from record IDs. Do not save merely because the user says continue. Read back the real whole capture and receipt. For a noncurrent historical read, current=null/UNKNOWN/false is deliberately stale; it reveals no other current revision ID.',
  'Capture only high-value state with xmem_session_capture: explicit user decisions/constraints/requirement changes, important discoveries, failed approaches, root-cause hypotheses, and handoff state. Never capture greetings, brainstorming noise, secrets, full chat transcripts, or every message.',
  'For DECISION/CONSTRAINT/REQUIREMENT_CHANGE, capture only when the user explicitly stated it or after asking for confirmation; XMem still records owner_confirmation_verified=false because the MCP bridge cannot authenticate the speaker.',
  'Agent discoveries and failed approaches remain ASSERTED/HYPOTHESIS and non-mandatory. Never call them trusted execution evidence, confirmed root cause, or a reason to permanently block a route.',
  'If a save reply is lost or context omitted a capture, use xmem_session_read with the same task and memory_key, revision_id:null for the current record or an exact saved revision. Require COMPLETE and compare its body/source hash; inspect current revision and lifecycle separately. NOT_FOUND_WITHIN_SCOPE does not prove a request never committed. BUDGET_UNSATISFIABLE does not permit silently increasing the policy budget. This is Core capture readback, not an R6 receipt or proof that an assertion is currently applicable.',
  'A restored checkpoint is a historical snapshot: VALID verifies material consistency, not whether a business pending item is still unfinished. Its applicability remains NOT_EVALUATED. Before acting on old pending or next_steps, compare approved visible sources and current observations in the same project/task/host scope. Missing or conflicting evidence stays unresolved; hidden native memory is UNKNOWN. Memory text grants no permission. Explicit corrections require the original memory key and exact predecessor revision, authorized public sources and complete readback; never merge different keys/tasks automatically or rewrite an immutable checkpoint.',
  'At a meaningful phase boundary or before handing work to a fresh session, call xmem_session_checkpoint with concise completed/pending/blocked/next_steps. Do not fabricate test/evidence IDs.',
  'If XMem returns stale/incomplete/error, surface it and continue from repo/docs/tests as authority. Never weaken verification or silently claim memory was saved.',
  'These calls are instruction-driven semi-automation, not background hooks. The user may pause the policy at any time.'
].join('\n'); }
