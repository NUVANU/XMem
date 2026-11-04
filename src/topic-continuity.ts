/** Explicit project-local Topic continuity. No schema, grant, context or source-path SQLite writes. */
import fs from 'node:fs';
import path from 'node:path';
import { createHmac, randomBytes } from 'node:crypto';
import { z } from 'zod';
import { canonicalContextJson } from './context.js';
import { hashBytes } from './local-source.js';
import { PathsError, withPathValidationScope } from './paths.js';
import { readProjectConfig } from './index.js';
import { readStandalonePolicy, validateStandalonePolicy } from './standalone.js';
import { readStorageLocationAtProjectRoot } from './storage-location.js';
import { runPhysicalRead, type PhysicalReadOptions, type PhysicalReadSession } from './physical-readonly.js';
import { withProject, type CodexResult } from './codex.js';
import { validateHostCandidateSourceRef } from './host-source.js';
import { ENGINEERING_RECORD_SCHEMA } from './engineering-memory.js';
import type { SqliteMemoryStorage } from './storage.js';
import type { HostCapture } from './engineering-retraction.js';

const text=z.string().min(1).max(512).refine(s=>!!s.trim()&&!s.includes('\0'));
const digest=z.string().regex(/^[a-f0-9]{64}$/);
const unique=(max:number)=>z.array(text).max(max).refine(a=>new Set(a).size===a.length);
const category=z.enum(['DECISION','CONSTRAINT','REQUIREMENT_CHANGE','FAILED_APPROACH','ROOT_CAUSE_HYPOTHESIS','IMPORTANT_DISCOVERY','HANDOFF_STATE']);
const content=z.string().min(1).refine(s=>!!s.trim()&&!s.includes('\0')&&Buffer.byteLength(s,'utf8')<=16384);
const deadline={deadline_unix_ms:z.number().int().safe().optional()};
export const TOPIC_METADATA_SCHEMA=z.object({title:z.string().min(1).max(160).refine(s=>!!s.trim()&&!s.includes('\0')),topics:unique(8),aliases:unique(8)}).strict();
export const TOPIC_ENVELOPE_SCHEMA=z.object({format:z.literal('xmem-topic-capture/1'),memory_key:text,topic:TOPIC_METADATA_SCHEMA,category,declared_actor:z.enum(['user','agent']),content}).strict();
export const TOPIC_CAPTURE_SCHEMA=z.object({mode:z.literal('topic'),task_ref:text,task_version:text,memory_key:text,category,declared_actor:z.enum(['user','agent']),content,previous_revision_id:text.nullable(),roles:unique(8).refine(a=>a.length>0).optional(),topic:TOPIC_METADATA_SCHEMA,payload_budget_bytes:z.number().int().nonnegative().max(16384).optional(),...deadline}).strict();
export const TOPIC_DISCOVERY_SCHEMA=z.object({query:z.string().max(256).refine(s=>!s.includes('\0')).default(''),topics:unique(8).default([]),role:text.optional(),allowed_source_ids:unique(512).optional(),limit:z.number().int().min(1).max(4).default(4),scan_limit:z.number().int().min(1).max(32).default(32),cursor:z.string().min(1).max(2048).nullable().default(null),payload_budget_bytes:z.number().int().nonnegative().max(8192).optional(),...deadline}).strict().refine(x=>!!x.query.trim()||x.topics.length>0);
const entrySchema=z.object({project_id:text,workspace_id:text,task_ref:text,task_version:text,role:text,revision_id:text,source_id:text,source_content_hash:digest,record_content_hash:digest,binding_hash:digest,policy_hash:digest}).strict();
const captureKey=z.object({memory_key:text,key_verified:z.literal(true),format:z.literal('xmem-topic-capture/1')}).strict();
const allowance=unique(512).refine(a=>a.every((s,i)=>i===0||a[i-1]<s)).nullable();
export const TOPIC_REFERENCE_SCHEMA=z.object({entry:entrySchema,storage_location_hash:digest,source_allowance:allowance,discovery_fingerprint:digest,capture_key:captureKey.nullable()}).strict();
export const TOPIC_EXPANSION_SCHEMA=z.object({mode:z.literal('expand'),reference:TOPIC_REFERENCE_SCHEMA,view:z.literal('current'),payload_budget_bytes:z.number().int().nonnegative().max(16384),...deadline}).strict();
export type TopicCaptureInput=z.input<typeof TOPIC_CAPTURE_SCHEMA>;
export type TopicReference=z.infer<typeof TOPIC_REFERENCE_SCHEMA>;
const CONTRACT='xmem-topic-continuity/1';
const fail=(code:string):CodexResult=>({ok:false,error:{code,message:'Topic operation unavailable within the approved scope'}});
function caught(e:unknown):CodexResult{return fail(e instanceof z.ZodError?'INVALID_INPUT':typeof (e as any)?.code==='string'?(e as any).code:'INPUT_INCOMPLETE');}
const problem=(code:string):never=>{throw new PathsError(code,'Topic operation unavailable');};

/** One monotonic cutoff starts before bootstrap paths, and is inherited by original path scopes. */
export function topicDeadline(requested?:number){
  const wall=Date.now(),mono=performance.now(),absolute=requested??wall+10000;
  if(!Number.isSafeInteger(absolute)||absolute-wall<1||absolute-wall>10000)problem('PATH_DEADLINE_EXPIRED');
  const stop=mono+(absolute-wall);
  const remaining=()=>{const n=Math.floor(Math.min(absolute-Date.now(),stop-performance.now()));if(n<1)problem('PATH_DEADLINE_EXPIRED');return n;};
  return{absolute,remaining,check:()=>{remaining();}};
}
/** These bounded raw static commitments precede the first original path/DriveInfo guard.
 * They are declarations frozen from approved on-disk configuration, then independently
 * checked by PHYSICAL_CLOSED_V1. They never authorize a root from a returned Topic ref. */
export function prepareTopicOperation(projectPath:string|undefined,role:string|undefined,budget:number|undefined,maximum:number,clock:ReturnType<typeof topicDeadline>,discover=false){
  let staticBytes=0;
  const safePath=(file:string)=>{
    clock.check();if(!path.isAbsolute(file)||!/^\w:[\\/]/.test(file))problem('INVALID_ROOT');
    let at=path.parse(file).root;
    for(const component of path.relative(at,file).split(path.sep).filter(Boolean)){
      if(component==='.'||component==='..'||/[<>:"|?*\x00-\x1f]/.test(component)||/[. ]$/.test(component))problem('UNSAFE_PATH');
      at=path.join(at,component);
      let stat:fs.Stats;try{stat=fs.lstatSync(at);}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')break;throw e;}
      if(stat.isSymbolicLink()||path.resolve(fs.realpathSync.native(at)).toLowerCase()!==path.resolve(at).toLowerCase())problem('LINK_PATH');
    }
    clock.check();
  };
  const read=(file:string,required=false)=>{
    safePath(file);let before:fs.Stats;
    try{before=fs.lstatSync(file);}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT'&&!required)return null;throw e;}
    if(!before.isFile()||before.nlink!==1||before.size>2*1024*1024-staticBytes)problem('STATIC_INPUT_TOO_LARGE');
    const bytes=fs.readFileSync(file),after=fs.lstatSync(file);staticBytes+=bytes.length;
    if(staticBytes>2*1024*1024||before.dev!==after.dev||before.ino!==after.ino||before.size!==bytes.length||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)problem('PREVIEW_CHANGED');
    clock.check();return bytes;
  };
  let root=path.resolve(projectPath??process.cwd());
  const boundary=discover&&process.env.XMEM_DISCOVERY_ROOT?path.resolve(process.env.XMEM_DISCOVERY_ROOT):null;
  const inside=(p:string)=>{if(!boundary)return true;const r=path.relative(boundary,p);return r!=='..'&&!r.startsWith('..'+path.sep)&&!path.isAbsolute(r);};
  if(!inside(root))problem('INVALID_ROOT');safePath(root);
  if(!fs.statSync(root).isDirectory())problem('INVALID_ROOT');
  if(discover){while(!read(path.join(root,'.xmem/config.json'))){const parent=path.dirname(root);if(parent===root||!inside(parent))problem('NOT_INITIALIZED');root=parent;}}
  const configBytes=read(path.join(root,'.xmem/config.json'),true)!,policyBytes=read(path.join(root,'.xmem/standalone-v1.json'),true)!,locationBytes=read(path.join(root,'.xmem/storage-location-v1.json'),true)!;
  const config=JSON.parse(configBytes.toString('utf8'));
  if(Object.keys(config).sort().join(',')!=='project_id,root,schema_version'||config.schema_version!==1||typeof config.project_id!=='string'||!/^[0-9a-f-]{36}$/.test(config.project_id)||config.root!==root)problem('INVALID_CONFIG');
  const policy=validateStandalonePolicy(JSON.parse(policyBytes.toString('utf8'))),selected=role??policy.default_role;
  if(!policy.enabled||!policy.allowed_roles.includes(selected))problem('UNTRUSTED_SOURCE');
  const location=JSON.parse(locationBytes.toString('utf8'));
  if(Object.keys(location).sort().join(',')!=='mode,project_id,schema_version,storage_root'||location.schema_version!==1||location.project_id!==config.project_id||!['PROJECT_LOCAL','CUSTOM_LOCAL'].includes(location.mode)||typeof location.storage_root!=='string'||!path.isAbsolute(location.storage_root))problem('INVALID_CONFIG');
  const storageRoot=path.resolve(location.storage_root);
  if(location.mode==='PROJECT_LOCAL'&&storageRoot!==path.join(root,'.xmem')||location.mode==='CUSTOM_LOCAL'&&storageRoot===path.join(root,'.xmem'))problem('INVALID_CONFIG');
  // Freeze location identity before any custom-root filesystem access.
  const locationHash=hashBytes(JSON.stringify({schema_version:1,project_id:config.project_id,mode:location.mode,storage_root:storageRoot}));
  const sharingBytes=read(path.join(root,'.xmem/sharing-v1.json')),identityBytes=read(path.join(storageRoot,'xmem-storage-identity-v1.json'),location.mode==='CUSTOM_LOCAL');
  if(location.mode==='PROJECT_LOCAL'&&identityBytes!==null)problem('INVALID_CONFIG');
  if(identityBytes){const identity=JSON.parse(identityBytes.toString('utf8'));if(Object.keys(identity).sort().join(',')!=='project_id,schema_version'||identity.schema_version!==1||identity.project_id!==config.project_id)problem('PROJECT_MISMATCH');}
  const totalBudget=Math.min(16384,policy.payload_budget_bytes),payloadBudget=budget??Math.min(maximum,policy.payload_budget_bytes);
  if(!Number.isSafeInteger(payloadBudget)||payloadBudget<0||payloadBudget>maximum||payloadBudget>policy.payload_budget_bytes)problem('INVALID_INPUT');
  const commit=(bytes:Buffer|null)=>bytes?{presence:'PRESENT' as const,sha256:hashBytes(bytes)}:{presence:'ABSENT' as const,sha256:null};
  const options:PhysicalReadOptions={storage_read_profile:'PHYSICAL_CLOSED_V1',expected:{project_id:config.project_id,workspace_id:policy.workspace_id,role:selected,mode:location.mode,canonical_storage_root:storageRoot,location_hash:locationHash,policy_hash:hashBytes(canonicalContextJson(policy)),static_files:{PROJECT_CONFIG:commit(configBytes),STANDALONE_POLICY:commit(policyBytes),STORAGE_LOCATION:commit(locationBytes),SHARING_POLICY:commit(sharingBytes),CUSTOM_IDENTITY:commit(identityBytes)}},payload_budget_bytes:totalBudget,deadline_unix_ms:clock.absolute};
  clock.check();return{root,config,policy,role:selected,options,payloadBudget,totalBudget};
}
type Environment=ReturnType<typeof prepareTopicOperation>;
function authority(env:Environment,clock:ReturnType<typeof topicDeadline>){
  clock.check();const config=readProjectConfig(env.root),policy=readStandalonePolicy(env.root),location=readStorageLocationAtProjectRoot(env.root,env.config.project_id);
  if(config.project_id!==env.config.project_id||policy?.policy_hash!==env.options.expected.policy_hash||policy.policy.workspace_id!==env.policy.workspace_id||!policy.policy.allowed_roles.includes(env.role)||location.location_hash!==env.options.expected.location_hash)problem('PREVIEW_CHANGED');clock.check();
}
class ReadLedger {
  bytes=0;bodyBytes=0;
  constructor(private clock:ReturnType<typeof topicDeadline>){}
  source=(bytes:Buffer|undefined)=>{this.clock.check();if(!bytes)problem('SOURCE_REQUIRES_VERIFICATION');this.spend(bytes!.length);};
  spend(n:number){this.clock.check();this.bytes+=n;if(this.bytes>8*1024*1024)problem('INPUT_INCOMPLETE');}
  body(s:string){const n=Buffer.byteLength(s,'utf8');this.bodyBytes+=n;if(n>16384||this.bodyBytes>524288)problem('INPUT_INCOMPLETE');}
}
const mapping=(c:string)=>c==='CONSTRAINT'?['ConstraintRef','ASSERTED','NORMATIVE_REF']:c==='DECISION'||c==='REQUIREMENT_CHANGE'?['DecisionRef','ASSERTED','NORMATIVE_REF']:c==='FAILED_APPROACH'?['FailedAttempt','ASSERTED','EXPERIENCE']:c==='ROOT_CAUSE_HYPOTHESIS'?['RootCauseHypothesis','HYPOTHESIS','SUGGESTION']:['Observation','ASSERTED','SUGGESTION'];
function material(found:HostCapture){
  const {record,binding}=found;let parsed:any;
  try{parsed=JSON.parse(record.content);}catch{/* Exact legacy plain content remains readable. */}
  if(parsed?.format==='xmem-topic-capture/1'){
    const envelope=TOPIC_ENVELOPE_SCHEMA.parse(parsed),source=validateHostCandidateSourceRef(record.project_id,record.source),m=mapping(envelope.category);
    const recordId='host-memory-'+hashBytes(canonicalContextJson([record.project_id,binding.workspace_id,binding.task_ref,binding.task_version,envelope.memory_key]));
    if(canonicalContextJson(envelope)!==record.content||recordId!==record.record_id||source?.actor!==envelope.declared_actor||m[0]!==record.kind||m[1]!==record.epistemic_state||m[2]!==record.information_role)problem('IDENTITY_CONFLICT');
    return{title:envelope.topic.title,topics:envelope.topic.topics,aliases:envelope.topic.aliases,content:envelope.content,format:envelope.format,key:{memory_key:envelope.memory_key,key_verified:true as const,format:'xmem-topic-capture/1' as const},external_references:'NOT_EVALUATED'};
  }
  if(parsed?.format==='xmem-engineering/1'){
    const r=ENGINEERING_RECORD_SCHEMA.parse(parsed);return{title:r.title,topics:r.associations.topics,aliases:[] as string[],content:record.content,format:r.format,key:null,external_references:'UNKNOWN'};
  }
  return{title:null,topics:[] as string[],aliases:[] as string[],content:record.content,format:'LEGACY_PLAIN',key:null,external_references:'UNKNOWN'};
}
function proof(storage:SqliteMemoryStorage,pointer:{task_ref:string;task_version:string;revision_id:string;source_id:string},env:Environment,ledger:ReadLedger){
  const request={project_id:env.config.project_id,workspace_id:env.policy.workspace_id,task_ref:pointer.task_ref,task_version:pointer.task_version,role:env.role,record_id:null,revision_id:pointer.revision_id};
  const found=storage.readHostMemoryCapture(request,ledger.source);
  if(!found||!found.is_current||found.current_lifecycle!=='ACTIVE'||found.record.source.source_id!==pointer.source_id)problem('PREVIEW_CHANGED');
  if(found!.binding.conflicts.length)problem('CONFLICT_WITHHELD');
  const boundary=storage.readEngineeringDependencyBoundary(request,[{record:found!.record,binding:found!.binding}]);
  ledger.spend(Buffer.byteLength(canonicalContextJson(found),'utf8'));return{found:found!,boundary,commit:hashBytes(canonicalContextJson(found))};
}
function reference(p:ReturnType<typeof proof>,env:Environment,allow:string[]|null,fingerprint:string,m:ReturnType<typeof material>):TopicReference{
  const {record,binding}=p.found;return{entry:{project_id:env.config.project_id,workspace_id:env.policy.workspace_id,task_ref:binding.task_ref,task_version:binding.task_version,role:env.role,revision_id:record.revision_id,source_id:record.source.source_id,source_content_hash:record.source.content_hash,record_content_hash:hashBytes(record.content),binding_hash:hashBytes(canonicalContextJson(binding)),policy_hash:env.options.expected.policy_hash},storage_location_hash:env.options.expected.location_hash,source_allowance:allow,discovery_fingerprint:fingerprint,capture_key:m.key};
}
function output(env:Environment,mode:'discover'|'expand',status:string,payload:unknown|null):CodexResult{
  const body=payload===null?null:canonicalContextJson(payload),size=body===null?0:Buffer.byteLength(body,'utf8');
  const base={contract:CONTRACT,mode,read_only:true,status,applicability:'NOT_EVALUATED',execution_verified:false,owner_confirmation_verified:false,actor_identity_verified:false,budget_unit:'utf8-bytes',payload_budget_bytes:env.payloadBudget,public_total_budget_bytes:env.totalBudget,payload:body,payload_bytes:size,payload_sha256:body===null?null:hashBytes(body)};
  if(size>env.payloadBudget||Buffer.byteLength(JSON.stringify({ok:true,value:base}),'utf8')>env.totalBudget){base.status='BUDGET_UNSATISFIABLE';base.payload=null;base.payload_bytes=0;base.payload_sha256=null;}
  if(Buffer.byteLength(JSON.stringify({ok:true,value:base}),'utf8')>env.totalBudget)return fail('BUDGET_UNSATISFIABLE');return{ok:true,value:base};
}
function value(result:CodexResult):unknown{if(!result.ok)problem(result.error.code);return result.ok?result.value:undefined;}
const normalize=(s:string)=>s.normalize('NFKC').toLowerCase();
const cursorSecret=randomBytes(32);
// Bounded replay bookkeeping contains only signed cursor strings, never ACL/body conclusions.
const consumedCursors=new Set<string>();
function cursorEncode(value:unknown):string{const encoded=Buffer.from(canonicalContextJson(value),'utf8').toString('base64url');return encoded+'.'+createHmac('sha256',cursorSecret).update(encoded).digest('hex');}
function cursorDecode(cursor:string){const [encoded,mac,...rest]=cursor.split('.');if(rest.length||!encoded||createHmac('sha256',cursorSecret).update(encoded).digest('hex')!==mac)problem('INVALID_INPUT');return JSON.parse(Buffer.from(encoded,'base64url').toString('utf8'));}

export function discoverStandaloneTopics(startPath:string|undefined,input:unknown):CodexResult{
  try{
    const x=TOPIC_DISCOVERY_SCHEMA.parse(input),clock=topicDeadline(x.deadline_unix_ms);
    return withPathValidationScope(()=>{
      const env=prepareTopicOperation(startPath,x.role,x.payload_budget_bytes,8192,clock,true),allow=x.allowed_source_ids?[...x.allowed_source_ids].sort():null;
      const terms=normalize(x.query).split(/\s+/u).filter(Boolean);if(terms.length>8||terms.some(s=>s.length>64))return fail('INVALID_INPUT');
      const fingerprint=hashBytes(canonicalContextJson({contract:CONTRACT,root:env.root,project_id:env.config.project_id,workspace_id:env.policy.workspace_id,role:env.role,policy:env.options.expected.policy_hash,location:env.options.expected.location_hash,allow,query:normalize(x.query),topics:x.topics.map(normalize).sort(),scan_limit:x.scan_limit,limit:x.limit,payload_budget_bytes:env.payloadBudget}));
      // Reject invalid cursors before physical capture; acceptance and consumption remain below.
      if(x.cursor){clock.check();const c=cursorDecode(x.cursor);if(!c||typeof c!=='object'||Array.isArray(c)||Object.keys(c).sort().join(',')!=='after,fingerprint,image,nonce,offset'||c.fingerprint!==fingerprint||typeof c.image!=='string'||!/^[a-f0-9]{64}$/.test(c.image)||typeof c.nonce!=='string'||!/^[a-f0-9]{24}$/.test(c.nonce)||typeof c.after!=='string'||!Number.isSafeInteger(c.offset)||c.offset<0||c.offset>32)problem('PREVIEW_CHANGED');if(consumedCursors.has(x.cursor))problem('PREVIEW_CHANGED');}
      return runPhysicalRead(env.root,{role:env.role},env.options,physical=>withProject(env.root,storage=>{
        authority(env,clock);const ledger=new ReadLedger(clock),image=physical.sourceImage!.sha256;
        let after='',offset=0;
        if(x.cursor){const c=cursorDecode(x.cursor);if(Object.keys(c).sort().join(',')!=='after,fingerprint,image,nonce,offset'||c.fingerprint!==fingerprint||c.image!==image||typeof c.nonce!=='string'||!/^[a-f0-9]{24}$/.test(c.nonce)||typeof c.after!=='string'||!Number.isSafeInteger(c.offset)||c.offset<0||c.offset>32)problem('PREVIEW_CHANGED');if(consumedCursors.has(x.cursor))problem('PREVIEW_CHANGED');if(consumedCursors.size>=64)problem('INPUT_INCOMPLETE');consumedCursors.add(x.cursor);after=c.after;offset=c.offset;}
        const request={project_id:env.config.project_id,workspace_id:env.policy.workspace_id,role:env.role,allowed_source_ids:allow??undefined,after_revision_id:after,limit:x.scan_limit};
        const page=storage.readTopicCurrentCandidates(request);ledger.spend(Buffer.byteLength(canonicalContextJson(page),'utf8'));
        const verified:Array<{pointer:typeof page.items[number];p:ReturnType<typeof proof>;m:ReturnType<typeof material>}>=[],matches:Array<{score:number;item:any;id:string}>=[];let unsupported=false;
        for(const pointer of page.items){clock.check();if(pointer.source_kind!=='user'&&pointer.source_kind!=='agent'){unsupported=true;continue;}
          const p=proof(storage,pointer,env,ledger);ledger.body(p.found.record.content);const m=material(p.found);verified.push({pointer,p,m});
          const title=normalize(m.title??''),labels=[...m.topics,...m.aliases].map(normalize),body=normalize(m.content);
          const explicit=x.topics.some(t=>labels.includes(normalize(t))||title===normalize(t)),exact=!!x.query.trim()&&(title===normalize(x.query)||labels.includes(normalize(x.query)));
          const literal=terms.length>0&&terms.every(t=>title.includes(t)||labels.some(s=>s.includes(t))||body.includes(t));if(!explicit&&!exact&&!literal)continue;
          matches.push({score:exact?3:explicit?2:1,id:pointer.revision_id,item:{scope:{project_id:env.config.project_id,workspace_id:env.policy.workspace_id,task_ref:pointer.task_ref,task_version:pointer.task_version,role:env.role},title:m.title,topics:m.topics,aliases:m.aliases,preview:m.content.slice(0,160),preview_only:true,key_state:m.key?'VERIFIED':'UNKNOWN_READ_ONLY',reference:reference(p,env,allow,fingerprint,m),epistemic_state:p.found.record.epistemic_state,source_kind:p.found.record.source.kind,integrity:'RETAINED_HOST_DECLARATION_ONLY',external_references:m.external_references,applicability:'NOT_EVALUATED'}});
        }
        matches.sort((a,b)=>b.score-a.score||a.id.localeCompare(b.id,'en'));if(offset>matches.length)problem('PREVIEW_CHANGED');
        const selected=matches.slice(offset,offset+x.limit);let chosen=selected.map(m=>m.item),continuation:string|null=null;
        const makePayload=()=>{const remains=offset+chosen.length<matches.length;if(remains||page.more){continuation=cursorEncode({after:remains?after:page.items.at(-1)?.revision_id??after,offset:remains?offset+chosen.length:0,fingerprint,image,nonce:randomBytes(12).toString('hex')});}else continuation=null;return{items:chosen,cursor:continuation,coverage:{scanned_authorized:page.items.length,incomplete:unsupported||!!continuation,unsupported_sources:unsupported,payload_limited:chosen.length<selected.length},match_state:matches.length>1?'AMBIGUOUS':matches.length===1?'MATCH':'NO_AUTHORIZED_MATCHES'};};
        let payload=makePayload();while(chosen.length){const trial=output(env,'discover','READY',payload);if(trial.ok&&(trial.value as any).status!=='BUDGET_UNSATISFIABLE')break;chosen.pop();payload=makePayload();}
        for(const item of verified){const again=proof(storage,item.pointer,env,ledger);if(again.commit!==item.p.commit||again.boundary!==item.p.boundary)problem('PREVIEW_CHANGED');}
        if(canonicalContextJson(storage.readTopicCurrentCandidates(request))!==canonicalContextJson(page))problem('PREVIEW_CHANGED');authority(env,clock);physical.check();
        if(selected.length&&!chosen.length)return value(output(env,'discover','BUDGET_UNSATISFIABLE',null));
        const status=payload.coverage.incomplete?'INCOMPLETE':matches.length>1?'AMBIGUOUS':matches.length?'READY':'EMPTY';return value(output(env,'discover',status,payload));
      },{readOnly:true,physicalRead:physical}));
    },clock.remaining);
  }catch(e){return caught(e);}
}

export function expandStandaloneTopic(projectRoot:string,input:unknown):CodexResult{
  try{const x=TOPIC_EXPANSION_SCHEMA.parse(input),r=x.reference,clock=topicDeadline(x.deadline_unix_ms);
    return withPathValidationScope(()=>{
      const env=prepareTopicOperation(projectRoot,r.entry.role,x.payload_budget_bytes,16384,clock);
      if(env.config.project_id!==r.entry.project_id||env.policy.workspace_id!==r.entry.workspace_id||env.options.expected.policy_hash!==r.entry.policy_hash||env.options.expected.location_hash!==r.storage_location_hash||r.source_allowance!==null&&!r.source_allowance.includes(r.entry.source_id))return fail('PREVIEW_CHANGED');
      return runPhysicalRead(env.root,{role:env.role},env.options,physical=>withProject(env.root,storage=>{
        authority(env,clock);const ledger=new ReadLedger(clock),pointer={task_ref:r.entry.task_ref,task_version:r.entry.task_version,revision_id:r.entry.revision_id,source_id:r.entry.source_id};
        const p=proof(storage,pointer,env,ledger);ledger.body(p.found.record.content);const m=material(p.found),actual=reference(p,env,r.source_allowance,r.discovery_fingerprint,m);
        if(canonicalContextJson(actual)!==canonicalContextJson(r))return value(output(env,'expand','PREVIEW_CHANGED',null));
        const payload={scope:{project_id:env.config.project_id,workspace_id:env.policy.workspace_id,task_ref:pointer.task_ref,task_version:pointer.task_version,role:env.role},reference:actual,content:p.found.record.content,caller_content:m.content,caller_content_sha256:hashBytes(m.content),format:m.format,key_state:m.key?'VERIFIED':'UNKNOWN_READ_ONLY',capture_key:m.key,current:{revision_id:p.found.record.revision_id,lifecycle:'ACTIVE',is_current:true},durable_receipt:p.found.durable_receipt,integrity:'RETAINED_HOST_DECLARATION_ONLY',external_references:m.external_references,epistemic_state:p.found.record.epistemic_state,actor_identity_verified:false,owner_confirmation_verified:false,applicability:'NOT_EVALUATED'};
        const again=proof(storage,pointer,env,ledger);if(again.commit!==p.commit||again.boundary!==p.boundary)problem('PREVIEW_CHANGED');authority(env,clock);physical.check();return value(output(env,'expand','COMPLETE',payload));
      },{readOnly:true,physicalRead:physical}));
    },clock.remaining);
  }catch(e){return caught(e);}
}
