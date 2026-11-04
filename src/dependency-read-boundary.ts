/** Per-call dependency checks shared by live SDK entry points. No reusable read permit. */
import { readProjectConfig } from './index.js';
import { readStandalonePolicy } from './standalone.js';
import { readStorageLocationAtProjectRoot } from './storage-location.js';
import { PathsError } from './paths.js';
import { canonicalContextJson,type ContextRequest,type ContextEntry } from './context.js';
import type { SourceRef } from './contracts.js';
import type { SqliteMemoryStorage } from './storage.js';
import { readCurrentSourceReference } from './local-runtime.js';
import { assertEnrollmentActive,EngineeringDependencyLedger,resolveDependencyReadEnrollment,
  type EnrollmentContext,type EngineeringDependencyOptions,type DependencyRevisionAuthorization,type DependencyBudgetNarrowing } from './engineering-dependencies.js';

export type DependencyReadOptions=EngineeringDependencyOptions;
type Request=Pick<ContextRequest,'project_id'|'workspace_id'|'task_ref'|'task_version'|'role'> & {allowed_source_ids?:readonly string[]};
declare const sessionBrand:unique symbol;
export interface DependencyReadSession {readonly [sessionBrand]:true;}
const sessions=new WeakMap<object,{ledger:EngineeringDependencyLedger;roots:Set<string>}>();
export function createDependencyReadSession(budget:DependencyBudgetNarrowing|undefined,depth:number):DependencyReadSession {
  const session=Object.freeze({}) as DependencyReadSession;sessions.set(session,{ledger:new EngineeringDependencyLedger(budget,depth),roots:new Set()});return session;
}
function stop():never {throw new PathsError('INPUT_INCOMPLETE','Dependency verification unavailable within the requested scope');}
function sessionState(session:DependencyReadSession){const state=session&&typeof session==='object'?sessions.get(session):undefined;if(!state)stop();return state;}
/** Internal accounting access; a JSON-shaped session is never admitted. */
export function dependencyReadLedger(session:DependencyReadSession):EngineeringDependencyLedger {return sessionState(session).ledger;}

export function liveDependencyContext(rootInput:string,storage:SqliteMemoryStorage,request:Request,authorization?:DependencyRevisionAuthorization):{context:EnrollmentContext;depth:number;assertLive:()=>void} {
  const config=readProjectConfig(rootInput),policy=readStandalonePolicy(config.root),location=readStorageLocationAtProjectRoot(config.root,config.project_id);
  if(!policy?.policy.enabled||!location.configured||!location.location_hash||request.project_id!==config.project_id||request.workspace_id!==policy.policy.workspace_id||!policy.policy.allowed_roles.includes(request.role))stop();
  const context:EnrollmentContext={scope:{projectRoot:config.root,projectId:request.project_id,workspaceId:request.workspace_id,taskId:request.task_ref,taskVersion:request.task_version,role:request.role},
    storageRoot:storage.root,policyHash:policy.policy_hash,locationHash:location.location_hash,allowedSourceIds:request.allowed_source_ids,authorization};
  const assertLive=()=>{
    const nowConfig=readProjectConfig(config.root),now=readStandalonePolicy(config.root),where=readStorageLocationAtProjectRoot(config.root,config.project_id);
    if(nowConfig.root!==config.root||nowConfig.project_id!==config.project_id||now?.policy_hash!==context.policyHash||where.location_hash!==context.locationHash||!now.policy.enabled||!now.policy.allowed_roles.includes(request.role))stop();
    authorization?.assertLive();
  };
  return{context,depth:policy.policy.max_depth,assertLive};
}

export function createDependencyReadBoundary(root:string,storage:SqliteMemoryStorage,request:Request,options?:DependencyReadOptions,
  session?:DependencyReadSession,authorization?:DependencyRevisionAuthorization) {
  const live=options?liveDependencyContext(root,storage,request,authorization):null;
  const resolved=options?resolveDependencyReadEnrollment(options,live!.context):null;
  const context=resolved?.context,state=resolved?.state,epoch=state?.epoch;
  const activeSession=options?(session??createDependencyReadSession(options.dependency_budget,live!.depth)):session;
  const accounting=activeSession?sessionState(activeSession):undefined,ledger=accounting?.ledger;
  let sourceBytes=0;
  const assertLive=()=>{if(state){assertEnrollmentActive(state,epoch!);live!.assertLive();}authorization?.assertLive();};
  const physical=(source:SourceRef)=>{
    assertLive();
    if(context)storage.assertEngineeringDependencySourceAllowed(context,source,ledger!);
    const bytes=readCurrentSourceReference(root,storage,request.project_id,source);sourceBytes+=bytes?.byteLength??0;return bytes;
  };
  const read=(source:SourceRef)=>ledger?ledger.read(source,physical):physical(source);
  const checkRoots=(roots:readonly string[]):string=>{
    assertLive();if(!state||!context||!accounting)stop();
    for(const id of roots)accounting.roots.add(canonicalContextJson([request.project_id,request.workspace_id,request.task_ref,request.task_version,id]));
    if(accounting.roots.size>8)stop();
    return storage.observeEngineeringDependencyGraph(context,roots,state,ledger!,physical);
  };
  const check=(entries:readonly ContextEntry[],allowHistory=false):string=>{
    assertLive();
    if(accounting){for(const entry of entries)accounting.roots.add(canonicalContextJson([request.project_id,request.workspace_id,request.task_ref,request.task_version,entry.record.revision_id]));if(accounting.roots.size>8)stop();}
    if(authorization)for(const entry of entries){if(!authorization.allowedRevisionIds.includes(entry.record.revision_id))stop();authorization.assertLive(entry.record.revision_id,entry.record.source);}
    return state?checkRoots(entries.map(e=>e.record.revision_id)):
      storage.readEngineeringDependencyBoundary({...request,allowed_source_ids:request.allowed_source_ids?[...request.allowed_source_ids]:undefined,allow_history:allowHistory},entries);
  };
  return{read,check,checkRoots,assertLive,assertUsable:()=>{ledger?.spendSql('queries',0);assertLive();},assertRevision:(id:string,source?:SourceRef)=>{assertLive();if(authorization){if(!authorization.allowedRevisionIds.includes(id))stop();authorization.assertLive(id,source);}},context,session:activeSession,
    verify:(entries:readonly ContextEntry[],before:string)=>{if(check(entries)!==before)stop();assertLive();},
    sourceBytes:()=>ledger?.sourceBytes??sourceBytes,
    chargeView:()=>{ledger?.spendSql('queries',1);},
    chargeViewBytes:(entries:readonly ContextEntry[])=>{ledger?.spendSql('metadataBytes',Buffer.byteLength(canonicalContextJson(entries),'utf8'));}};
}
