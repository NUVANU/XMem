/** Local SDK enrollment only. This module does not authenticate a Host/Owner and
 * never grants source access. An opaque handle cannot enter via MCP JSON. */
import { randomUUID } from 'node:crypto';
import { canonicalContextJson } from './context.js';
import type { Relation, SourceRef } from './contracts.js';
import { PathsError } from './paths.js';
import type { Scope, Budget } from './dependency-snapshot.js';
import type { SqlBudget } from './dependency-sqlite-snapshot.js';

declare const handleBrand: unique symbol;
export interface EngineeringDependencyHandle { readonly [handleBrand]: true; }
export interface EnrollmentContext {
  scope: Scope; storageRoot: string; policyHash: string; locationHash: string;
  allowedSourceIds: readonly string[] | undefined;
  authorization?: DependencyRevisionAuthorization;
}
/** Internal live constraint. Data pins are comparable; the function is never JSON authority. */
export interface DependencyRevisionAuthorization {
  identity: string; targetScope: {task_ref:string;task_version:string};
  allowedRevisionIds: readonly string[];
  assertLive: (revisionId?:string,source?:SourceRef)=>void;
}
export interface EnrollmentState {
  context: EnrollmentContext; relations: ReadonlyMap<string, Relation>;
  nodePins:ReadonlyMap<string,string>;
  enrollmentId: string; active: boolean; epoch: number;
}
export interface DependencyBudgetNarrowing {
  sourceBytes?: number; sqlQueries?: number; sqlNodes?: number;
  edges?: number; depth?: number; work?: number;
}
export interface EngineeringDependencyOptions {
  dependencies: EngineeringDependencyHandle;
  dependency_budget?: DependencyBudgetNarrowing;
}
const handles = new WeakMap<object, EnrollmentState>();
const unavailable = () => new PathsError('INPUT_INCOMPLETE','Dependency verification unavailable within the requested scope');
const contextData = (c: EnrollmentContext) => ({scope:c.scope,storageRoot:c.storageRoot,policyHash:c.policyHash,locationHash:c.locationHash,
  allowedSourceIds:c.allowedSourceIds===undefined?null:[...c.allowedSourceIds].sort(),
  authorization:c.authorization?{identity:c.authorization.identity,targetScope:c.authorization.targetScope,allowedRevisionIds:[...c.authorization.allowedRevisionIds].sort()}:null});
const contextKey = (c: EnrollmentContext) => canonicalContextJson(contextData(c));
function assertOptions(options:unknown):asserts options is EngineeringDependencyOptions {
  if(!options||typeof options!=='object'||Object.getPrototypeOf(options)!==Object.prototype
    ||!Object.hasOwn(options,'dependencies')||Reflect.ownKeys(options).some(k=>typeof k!=='string'||!['dependencies','dependency_budget'].includes(k))
    ||Object.values(Object.getOwnPropertyDescriptors(options)).some(d=>!('value'in d)||!d.enumerable))throw unavailable();
}
/** Internal issuance after the SDK has checked expected scope and stored rows. */
export function issueEngineeringDependencyHandle(context:EnrollmentContext, relations:readonly Relation[],nodePins:ReadonlyMap<string,string>):EngineeringDependencyHandle {
  if(relations.length>32||new Set(relations.map(r=>r.relation_id)).size!==relations.length)throw unavailable();
  const handle=Object.freeze({}) as EngineeringDependencyHandle;
  const {authorization,...serializable}=context;
  const copied:EnrollmentContext={...structuredClone(serializable),...(authorization?{authorization:{...authorization,targetScope:{...authorization.targetScope},allowedRevisionIds:[...authorization.allowedRevisionIds]}}:{})};
  handles.set(handle,{context:copied,relations:new Map(relations.map(r=>[r.relation_id,structuredClone(r)])),nodePins:new Map(nodePins),enrollmentId:'LOCAL_SDK_ENROLLMENT:'+randomUUID(),active:true,epoch:1});
  return handle;
}
/** Explicit local revocation; it grants no authority to another handle. */
export function revokeEngineeringDependencies(handle:EngineeringDependencyHandle):boolean {
  const state=handle&&typeof handle==='object'?handles.get(handle):undefined;
  if(!state||!state.active)return false;state.active=false;state.epoch++;return true;
}
export function resolveEngineeringDependencies(options:unknown,context:EnrollmentContext):EnrollmentState|null {
  if(options===undefined)return null;
  assertOptions(options);
  const h=(options as EngineeringDependencyOptions).dependencies;
  const state=h&&typeof h==='object'?handles.get(h):undefined;
  if(!state?.active||contextKey(state.context)!==contextKey(context))throw unavailable();
  return state;
}
/** Expansion preserves the enrollment's explicit allowance, because its public
 * reference does not carry an allowance and cannot authorize a broader one. */
export function resolveExpansionDependencies(options:unknown,context:EnrollmentContext):EnrollmentState|null {
  if(options===undefined)return null;
  assertOptions(options);
  const h=options&&typeof options==='object'?(options as EngineeringDependencyOptions).dependencies:null;
  const state=h&&typeof h==='object'?handles.get(h):undefined;
  if(!state)throw unavailable();
  return resolveEngineeringDependencies(options,{...context,allowedSourceIds:state.context.allowedSourceIds});
}
export function assertEnrollmentActive(state:EnrollmentState,epoch:number):void {if(!state.active||state.epoch!==epoch)throw unavailable();}

/** Internal per-read narrowing. Undefined never widens an explicit enrollment allowance. */
export function resolveDependencyReadEnrollment(options:EngineeringDependencyOptions,context:EnrollmentContext):{context:EnrollmentContext;state:EnrollmentState} {
  assertOptions(options);
  const handle=options.dependencies,state=handle&&typeof handle==='object'?handles.get(handle):undefined;
  if(!state?.active)throw unavailable();
  const requested=context.allowedSourceIds,registered=state.context.allowedSourceIds;
  const allowedSourceIds=registered===undefined?requested:requested===undefined?[...registered]:requested.filter(id=>registered.includes(id));
  const compare=(c:EnrollmentContext)=>canonicalContextJson({...contextData(c),allowedSourceIds:null});
  if(compare(context)!==compare(state.context))throw unavailable();
  return{context:{...context,allowedSourceIds},state};
}
/** Scope inspection only for routing real SDK handles; not a permission permit. */
export function dependencyHandleScope(handle:EngineeringDependencyHandle):Scope {
  const state=handle&&typeof handle==='object'?handles.get(handle):undefined;if(!state?.active)throw unavailable();return{...state.context.scope};
}

/** Internal rejection only; backend context and authorization checks remain mandatory. */
export function precheckDependencyReadOptions(options:unknown):void {
  assertOptions(options);
  dependencyHandleScope(options.dependencies);
}

const TOTAL_SQL:SqlBudget={roots:8,nodes:128,edgeRows:256,metadataBytes:1048576,queries:1024};
const TOTAL_EVAL:Budget={nodes:64,edges:512,depth:16,sourceBytes:2097152,work:4096};
type SqlConsumption={nodes:number;edgeRows:number;metadataBytes:number;queries:number};
/** Shared across discovery, both adapters, compiler and final checks. Values are
 * logical returned/processed bytes, not a physical IO or pre-allocation limit. */
export class EngineeringDependencyLedger {
  readonly sql={nodes:0,edgeRows:0,metadataBytes:0,queries:0};
  readonly evaluation={nodes:0,edges:0,depth:0,sourceBytes:0,work:0};
  sourceBytes=0;
  readonly sqlLimits:SqlBudget={...TOTAL_SQL};
  readonly evaluationLimits:{-readonly[K in keyof Budget]:Budget[K]}={...TOTAL_EVAL};
  sourceLimit=2097152;
  private phaseStart:SqlConsumption|null=null;
  private exhausted=false;
  private budgetFailure():never {this.exhausted=true;throw unavailable();}
  private assertUsable():void {if(this.exhausted)throw unavailable();}
  assertAvailable():void {this.assertUsable();}
  constructor(narrow:DependencyBudgetNarrowing|undefined,depth:number){
    this.evaluationLimits.depth=Math.min(16,depth);
    if(narrow!==undefined){
      if(!narrow||typeof narrow!=='object'||Array.isArray(narrow)||Object.keys(narrow).some(k=>!['sourceBytes','sqlQueries','sqlNodes','edges','depth','work'].includes(k)))throw unavailable();
      for(const [key,value]of Object.entries(narrow)){
        const cap=key==='sourceBytes'?2097152:key==='sqlQueries'?1024:key==='sqlNodes'?128:key==='edges'?512:key==='depth'?this.evaluationLimits.depth:4096;
        if(!Number.isSafeInteger(value)||value<0||value>cap)throw unavailable();
        if(key==='sourceBytes'){this.sourceLimit=value;this.evaluationLimits.sourceBytes=value;}
        else if(key==='sqlQueries')this.sqlLimits.queries=value;else if(key==='sqlNodes')this.sqlLimits.nodes=value;
        else this.evaluationLimits[key as 'edges'|'depth'|'work']=value;
      }
    }
  }
  spendSql(key:keyof SqlConsumption,count:number):void {
    this.assertUsable();
    const phaseCaps={nodes:32,edgeRows:64,metadataBytes:262144,queries:256};
    if(!Number.isSafeInteger(count)||count<0||count>this.sqlLimits[key]-this.sql[key]
      ||this.phaseStart&&count>phaseCaps[key]-(this.sql[key]-this.phaseStart[key]))this.budgetFailure();this.sql[key]+=count;
  }
  beginSqlPhase():void {this.assertUsable();if(this.phaseStart)this.budgetFailure();this.phaseStart={...this.sql};}
  endSqlPhase():void {this.phaseStart=null;}
  consumeSql(count:SqlConsumption):void {for(const key of Object.keys(this.sql)as Array<keyof SqlConsumption>)this.spendSql(key,count[key]);}
  consumeEvaluation(count:Budget):void {
    this.assertUsable();
    for(const key of ['nodes','edges','sourceBytes','work']as const){if(count[key]>this.evaluationLimits[key]-this.evaluation[key])this.budgetFailure();this.evaluation[key]+=count[key];}
    this.evaluation.depth=Math.max(this.evaluation.depth,count.depth);if(this.evaluation.depth>this.evaluationLimits.depth)this.budgetFailure();
  }
  sourceRead(bytes:Uint8Array|undefined):void {
    this.assertUsable();const n=bytes?.byteLength??0;this.sourceBytes+=n;if(n>65536||this.sourceBytes>this.sourceLimit)this.budgetFailure();
  }
  read(source:SourceRef,reader:(source:SourceRef)=>Buffer|undefined):Buffer|undefined {this.assertUsable();const bytes=reader(source);this.sourceRead(bytes);return bytes;}
}
