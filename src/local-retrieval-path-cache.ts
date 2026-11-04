/** Process-local compiled retrieval steps only. Never contains bodies, candidates or authority. */
import { canonicalContextJson } from './context.js';

export interface EngineeringSelectors { files:string[]; modules:string[]; topics:string[]; terms:string[]; }
export interface EngineeringSelectorPlan { readonly selectors_key:string; }
const compiled=new WeakMap<EngineeringSelectorPlan,(content:unknown)=>number>();
const keyOf=(selectors?:EngineeringSelectors)=>canonicalContextJson(selectors??null);
const pathKey=(value:string)=>process.platform==='win32'?value.replaceAll('\\','/').toLowerCase():value.replaceAll('\\','/');

/** The only plan factory. Predicates and their Sets are private and cannot be supplied by callers. */
export function compileEngineeringSelector(selectors?:EngineeringSelectors):EngineeringSelectorPlan {
  const key=keyOf(selectors),plan=Object.freeze({selectors_key:key});
  if(!selectors){compiled.set(plan,(_content:unknown)=>1);return plan;}
  const files=new Set(selectors.files),modules=new Set(selectors.modules),topics=new Set(selectors.topics),terms=[...selectors.terms];
  compiled.set(plan,(content:unknown)=>{
    if(typeof content!=='string')return 0;
    if(terms.length){const lower=content.toLowerCase();if(terms.every(term=>lower.includes(term)))return 1;}
    try{
      const r=JSON.parse(content);if(r?.format!=='xmem-engineering/1')return 0;const a=r.associations;
      return Number(Array.isArray(a?.files)&&a.files.some((v:unknown)=>typeof v==='string'&&files.has(pathKey(v)))
        ||Array.isArray(a?.modules)&&a.modules.some((v:unknown)=>typeof v==='string'&&modules.has(v))
        ||Array.isArray(a?.topics)&&a.topics.some((v:unknown)=>typeof v==='string'&&topics.has(v)));
    }catch{return 0;}
  });
  return plan;
}

/** A forged or mismatched opaque plan is replaced by normal compilation, never called. */
export function engineeringSelectorPredicate(selectors?:EngineeringSelectors,plan?:EngineeringSelectorPlan):(content:unknown)=>number {
  const actual=plan&&compiled.has(plan)&&plan.selectors_key===keyOf(selectors)?plan:compileEngineeringSelector(selectors);
  return compiled.get(actual)!;
}

type Entry={plan:EngineeringSelectorPlan;bytes:number;expires:number;witness:string|null};
export interface RetrievalPathLease { readonly plan:EngineeringSelectorPlan; readonly status:'HIT'|'MISS'|'BYPASS'; }
type LeaseState={key:string;entry:Entry};
const leases=new WeakMap<RetrievalPathLease,LeaseState>();
export class LocalRetrievalPathCache {
  private readonly entries=new Map<string,Entry>();
  private bytes=0;
  private enabled=true;
  private available=true;
  private readonly counts={hits:0,misses:0,bypasses:0,evictions:0,expired:0,invalidations:0};
  readonly maxEntries:number;readonly maxBytes:number;readonly ttlMs:number;
  constructor(options:{maxEntries?:number;maxBytes?:number;ttlMs?:number}={}){
    this.maxEntries=options.maxEntries??32;this.maxBytes=options.maxBytes??65536;this.ttlMs=options.ttlMs??30000;
    if(!Number.isInteger(this.maxEntries)||this.maxEntries<1||this.maxEntries>64||!Number.isInteger(this.maxBytes)||this.maxBytes<1||this.maxBytes>262144||!Number.isInteger(this.ttlMs)||this.ttlMs<1||this.ttlMs>30000)throw new RangeError('Local cache bounds exceeded');
  }
  /** Keys are exact canonical descriptors, not hash-only identities. Undefined sources must be encoded explicitly. */
  acquire(scope:Record<string,unknown>,selectors:EngineeringSelectors,now=performance.now()):RetrievalPathLease {
    const key=canonicalContextJson({scope,selectors}),bytes=Buffer.byteLength(key,'utf8');
    if(!this.enabled||!this.available||!Number.isFinite(now)||bytes>this.maxBytes){this.counts.bypasses++;return Object.freeze({plan:compileEngineeringSelector(selectors),status:'BYPASS'});}
    this.expire(now);
    let entry=this.entries.get(key),status:'HIT'|'MISS';
    if(entry){status='HIT';this.counts.hits++;this.entries.delete(key);this.entries.set(key,entry);}
    else{
      status='MISS';this.counts.misses++;entry={plan:compileEngineeringSelector(selectors),bytes,expires:now+this.ttlMs,witness:null};
      while(this.entries.size>=this.maxEntries||this.bytes+bytes>this.maxBytes)this.drop(this.entries.keys().next().value!,'evictions');
      this.entries.set(key,entry);this.bytes+=bytes;
    }
    const lease=Object.freeze({plan:entry.plan,status});leases.set(lease,{key,entry});return lease;
  }
  /** Live validation is done by the normal reader. Changed evidence evicts this step without a retry. */
  finish(lease:RetrievalPathLease,witness:string):void {
    const state=leases.get(lease);if(!state||this.entries.get(state.key)!==state.entry)return;
    if(state.entry.witness!==null&&state.entry.witness!==witness){this.drop(state.key,'invalidations');return;}
    state.entry.witness=witness;
  }
  invalidate(lease:RetrievalPathLease):void {const state=leases.get(lease);if(state&&this.entries.get(state.key)===state.entry)this.drop(state.key,'invalidations');}
  clear():void {this.entries.clear();this.bytes=0;}
  setEnabled(value:boolean):void {this.enabled=value===true;this.clear();}
  setAvailable(value:boolean):void {this.available=value===true;this.clear();}
  stats(){return Object.freeze({...this.counts,entries:this.entries.size,accounted_key_bytes:this.bytes,enabled:this.enabled,available:this.available});}
  private expire(now:number):void {for(const [key,entry]of this.entries)if(now>=entry.expires)this.drop(key,'expired');}
  private drop(key:string,reason:'evictions'|'expired'|'invalidations'):void {const entry=this.entries.get(key);if(entry){this.entries.delete(key);this.bytes-=entry.bytes;this.counts[reason]++;}}
}

/** Internal SDK control, deliberately absent from MCP schemas and persistent configuration. */
export const engineeringRetrievalPathCache=new LocalRetrievalPathCache();
