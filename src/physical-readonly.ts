/** Explicit closed-file image strategy. No module-load IO and no path SQLite fallback. */
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import Database from 'better-sqlite3';
import { readProjectConfig } from './index.js';
import { readStandalonePolicy } from './standalone.js';
import { readStorageLocationAtProjectRoot, enterPhysicalLocationScope } from './storage-location.js';
import { resolveProjectRoot, resolveProjectPath, withPathValidationScope, powerShellHost } from './paths.js';
import { inspectOpenDatabase, notCreatedStorageHealth, type StorageHealth } from './diagnostics.js';
import type { CodexResult } from './codex.js';

export const PHYSICAL_READ_PROFILE = 'PHYSICAL_CLOSED_V1' as const;
export const PHYSICAL_READ_CONTRACT = 'xmem-physical-readonly-preflight/1' as const;
const MAX_IMAGE = 8 * 1024 * 1024, MAX_STATIC = 2 * 1024 * 1024, MAX_PAYLOAD = 16384;
const slots = ['PROJECT_CONFIG','STANDALONE_POLICY','STORAGE_LOCATION','SHARING_POLICY','CUSTOM_IDENTITY'] as const;
type Slot = typeof slots[number];
type StaticCommitment = {presence:'PRESENT'|'ABSENT';sha256:string|null};
export interface PhysicalReadOptions {
  storage_read_profile: typeof PHYSICAL_READ_PROFILE;
  expected: {project_id:string;workspace_id:string;role:string;mode:'PROJECT_LOCAL'|'CUSTOM_LOCAL';canonical_storage_root:string;location_hash:string;policy_hash:string;static_files:Record<Slot,StaticCommitment>};
  payload_budget_bytes:number;
  deadline_unix_ms:number;
}
type Status = 'BUSY'|'DENIED'|'CORRUPT'|'MIGRATION_REQUIRED'|'UNSUPPORTED_VERSION'|'UNKNOWN'|'UNSUPPORTED';
export class PhysicalReadError extends Error {
  readonly code:string;
  constructor(readonly status:Status, readonly reason:string) {
    super(reason); this.name='PhysicalReadError';
    this.code=status==='BUSY'?'PHYSICAL_READ_BUSY':status==='DENIED'?'PHYSICAL_READ_DENIED':status==='UNSUPPORTED'?'PHYSICAL_READ_UNSUPPORTED':'PHYSICAL_READ_UNKNOWN';
  }
}
const deny=(reason:string):never=>{throw new PhysicalReadError('DENIED',reason);};
const sha=(bytes:Uint8Array|string)=>createHash('sha256').update(bytes).digest('hex');
function exact(value:unknown,keys:readonly string[]):Record<string,unknown> {
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.getPrototypeOf(value)!==Object.prototype||Reflect.ownKeys(value).some(k=>typeof k!=='string')||Reflect.ownKeys(value).sort().join(',')!==[...keys].sort().join(','))deny('INVALID_OPTIONS');
  if(Object.values(Object.getOwnPropertyDescriptors(value)).some(d=>!('value' in d)||!d.enumerable))deny('INVALID_OPTIONS');
  return value as Record<string,unknown>;
}
const boundedText=(x:unknown,max=512):x is string=>typeof x==='string'&&x.length>0&&x.length<=max&&x.trim().length>0&&!x.includes('\0');
const digest=(x:unknown):x is string=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
function parseOptions(value:unknown):PhysicalReadOptions {
  const x=exact(value,['storage_read_profile','expected','payload_budget_bytes','deadline_unix_ms']);
  if(x.storage_read_profile!==PHYSICAL_READ_PROFILE)throw new PhysicalReadError('UNSUPPORTED','PROFILE_UNSUPPORTED');
  const e=exact(x.expected,['project_id','workspace_id','role','mode','canonical_storage_root','location_hash','policy_hash','static_files']);
  if(!boundedText(e.project_id)||!boundedText(e.workspace_id)||!boundedText(e.role)||!['PROJECT_LOCAL','CUSTOM_LOCAL'].includes(String(e.mode))||!boundedText(e.canonical_storage_root,4096)||!digest(e.location_hash)||!digest(e.policy_hash))deny('INVALID_EXPECTED');
  const s=exact(e.static_files,slots);
  for(const name of slots){const c=exact(s[name],['presence','sha256']);if(c.presence!=='PRESENT'&&c.presence!=='ABSENT'||c.presence==='PRESENT'&&!digest(c.sha256)||c.presence==='ABSENT'&&c.sha256!==null)deny('INVALID_STATIC_COMMITMENT');}
  if(!Number.isSafeInteger(x.payload_budget_bytes)||Number(x.payload_budget_bytes)<0||Number(x.payload_budget_bytes)>MAX_PAYLOAD)deny('PAYLOAD_BUDGET_EXCEEDED');
  if(!Number.isSafeInteger(x.deadline_unix_ms))deny('INVALID_DEADLINE');
  return JSON.parse(JSON.stringify(value)) as PhysicalReadOptions;
}
function exists(file:string):boolean {try{fs.lstatSync(file);return true;}catch(e){if((e as NodeJS.ErrnoException).code==='ENOENT')return false;throw e;}}
function safeLeaf(file:string):fs.Stats|null {
  if(!exists(file))return null;
  const s=fs.lstatSync(file);
  if(s.isSymbolicLink()||!s.isFile()||s.nlink!==1||path.resolve(fs.realpathSync.native(file)).toLowerCase()!==path.resolve(file).toLowerCase())deny('LINKED_OR_NONREGULAR_LEAF');
  return s;
}
function fingerprint(s:fs.Stats|null):string|null {return s?JSON.stringify([s.dev,s.ino,s.size,s.mtimeMs,s.ctimeMs,s.birthtimeMs,s.nlink]):null;}
function mapped(error:unknown):PhysicalReadError {
  if(error instanceof PhysicalReadError)return error;
  const code=(error as {code?:string})?.code;
  if(['MODE_MISMATCH','STORAGE_ROOT_MISMATCH','LOCATION_HASH_MISMATCH','LINKED_OR_NONREGULAR_LEAF','STATIC_INPUT_TOO_LARGE','STATIC_HASH_MISMATCH','STATIC_PRESENCE_MISMATCH','STATIC_REQUIRED'].includes(code??''))return new PhysicalReadError('DENIED',code!);
  if(['LINK_PATH','PATH_OUTSIDE_PROJECT','OUTSIDE_PROJECT','UNSAFE_PATH','INVALID_ROOT','NETWORK_PATH','UNTRUSTED_SOURCE','PROJECT_MISMATCH','INVALID_CONFIG'].includes(code??''))return new PhysicalReadError('DENIED','PATH_OR_BINDING_DENIED');
  if(code==='SQLITE_CORRUPT'||code==='SQLITE_NOTADB')return new PhysicalReadError('CORRUPT','SQLITE_CORRUPT');
  return new PhysicalReadError('UNKNOWN','PHYSICAL_OPERATION_UNKNOWN');
}

/** One entry budget, established before the session's first path guard. */
class PhysicalBudget {
  readonly options:PhysicalReadOptions;
  readonly stopAt:number;
  constructor(value:unknown) {
    const entryWall=Date.now(),entryMono=performance.now();
    this.options=parseOptions(value);
    const remaining=this.options.deadline_unix_ms-entryWall;
    if(remaining<1||remaining>10000)throw new PhysicalReadError('UNKNOWN','DEADLINE_EXPIRED_OR_OUT_OF_RANGE');
    this.stopAt=entryMono+remaining;
  }
  check():void {if(performance.now()>=this.stopAt||Date.now()>=this.options.deadline_unix_ms)throw new PhysicalReadError('UNKNOWN','DEADLINE_EXPIRED');}
  remaining():number {this.check();const value=Math.floor(Math.min(10000,this.stopAt-performance.now(),this.options.deadline_unix_ms-Date.now()));if(value<1)throw new PhysicalReadError('UNKNOWN','DEADLINE_EXPIRED');return value;}
}

/** Internal operation token; source paths are never passed to Database. */
export class PhysicalReadSession {
  readonly options:PhysicalReadOptions;
  readonly stopAt:number;
  readonly root:string;
  storageRoot='';
  private initialFingerprint:string|null=null;
  private image:Buffer|null=null;
  private imageHash:string|null=null;
  private readonly connections=new Set<Database.Database>();
  private ended=false;
  constructor(projectRoot:string,private readonly budget:PhysicalBudget,private readonly actualRole?:unknown) {
    this.options=budget.options;
    this.stopAt=budget.stopAt;
    if(process.platform!=='win32')throw new PhysicalReadError('UNSUPPORTED','WINDOWS_REQUIRED');
    this.root=projectRoot;
    this.guard();
    this.check();
    this.initialFingerprint=fingerprint(this.databaseStat());
    if(this.initialFingerprint!==null){this.image=this.capture();this.imageHash=sha(this.image);}
    this.check();
  }
  check():void {this.budget.check();}
  remaining():number {return this.budget.remaining();}
  get missing():boolean{return this.image===null;}
  get sourceImage(){return this.image===null?null:{sha256:this.imageHash!,byte_length:this.image.length};}
  get binding(){const e=this.options.expected;return{project_id:e.project_id,workspace_id:e.workspace_id,role:e.role,mode:e.mode,location_hash:e.location_hash,policy_hash:e.policy_hash};}
  private databaseStat():fs.Stats|null {
    const s=safeLeaf(path.join(this.storageRoot,'xmem.sqlite'));
    if(s&&s.size>MAX_IMAGE)deny('INPUT_TOO_LARGE');
    return s;
  }
  private guard():void {
    this.check();
    // No cross-operation caching: these are the original canonical/drive/policy guards.
    const canonical=resolveProjectRoot(this.root),xmem=resolveProjectPath(canonical,'.xmem');
    const staticAtProject=['config.json','standalone-v1.json','storage-location-v1.json','sharing-v1.json'].map(name=>resolveProjectPath(canonical,'.xmem/'+name));
    // Bound all policy bytes before any existing JSON reader is called.
    let earlyBytes=0;
    for(const file of staticAtProject){const stat=safeLeaf(file);earlyBytes+=stat?.size??0;if(earlyBytes>MAX_STATIC)deny('STATIC_INPUT_TOO_LARGE');}
    this.knownPending(xmem,staticAtProject);
    const config=readProjectConfig(this.root),current=readStandalonePolicy(canonical);
    if(!current?.policy.enabled)throw new PhysicalReadError('DENIED','POLICY_UNAVAILABLE');
    const e=this.options.expected;
    if(config.project_id!==e.project_id)deny('PROJECT_MISMATCH');
    if(current.policy.workspace_id!==e.workspace_id)deny('WORKSPACE_MISMATCH');
    const location=readStorageLocationAtProjectRoot(canonical,config.project_id,{mode:e.mode,canonical_storage_root:e.canonical_storage_root,location_hash:e.location_hash,identity_commit:e.static_files.CUSTOM_IDENTITY,identity_byte_limit:MAX_STATIC-earlyBytes});
    if(!location.configured)deny('LOCATION_UNCONFIRMED');
    this.storageRoot=resolveProjectRoot(location.storage_root);
    if(config.project_id!==e.project_id)deny('PROJECT_MISMATCH');
    if(current.policy.workspace_id!==e.workspace_id)deny('WORKSPACE_MISMATCH');
    if(location.mode!==e.mode)deny('MODE_MISMATCH');
    if(this.storageRoot!==e.canonical_storage_root)deny('STORAGE_ROOT_MISMATCH');
    if(location.location_hash!==e.location_hash)deny('LOCATION_HASH_MISMATCH');
    if(current.policy_hash!==e.policy_hash)deny('POLICY_HASH_MISMATCH');
    if(!current.policy.allowed_roles.includes(e.role))deny('ROLE_DENIED');
    const selected=this.actualRole===undefined?current.policy.default_role:this.actualRole;
    if(selected!==e.role)deny('ROLE_MISMATCH');
    if(this.options.payload_budget_bytes>current.policy.payload_budget_bytes)deny('PAYLOAD_BUDGET_EXCEEDED');
    const identity=path.join(this.storageRoot,'xmem-storage-identity-v1.json');
    const files=[...staticAtProject,identity];
    this.knownPending(this.storageRoot,[identity]);
    let staticBytes=0;
    for(let i=0;i<slots.length;i++){
      const slot=slots[i],commit=e.static_files[slot],file=files[i];
      // PROJECT_LOCAL has no custom identity slot, even if an unexpected leaf exists.
      if(slot==='CUSTOM_IDENTITY'&&location.mode==='PROJECT_LOCAL'){
        if(commit.presence!=='ABSENT'||exists(file))deny('CUSTOM_IDENTITY_MISMATCH');continue;
      }
      if((i<3||slot==='CUSTOM_IDENTITY'&&location.mode==='CUSTOM_LOCAL')&&commit.presence!=='PRESENT')deny('STATIC_REQUIRED');
      const stat=safeLeaf(file);
      if(!stat){if(commit.presence!=='ABSENT')deny('STATIC_PRESENCE_MISMATCH');continue;}
      staticBytes+=stat.size;if(staticBytes>MAX_STATIC)deny('STATIC_INPUT_TOO_LARGE');
      const bytes=fs.readFileSync(file);staticBytes+=Math.max(0,bytes.length-stat.size);if(staticBytes>MAX_STATIC)deny('STATIC_INPUT_TOO_LARGE');
      if(commit.presence!=='PRESENT'||sha(bytes)!==commit.sha256)deny('STATIC_HASH_MISMATCH');
      if(fingerprint(stat)!==fingerprint(safeLeaf(file)))throw new PhysicalReadError('BUSY','STATIC_CHANGED');
    }
    for(const suffix of ['-wal','-shm','-journal'])if(exists(path.join(this.storageRoot,'xmem.sqlite'+suffix)))throw new PhysicalReadError('BUSY','SIDECAR_PRESENT');
    this.databaseStat();
    this.check();
  }
  private knownPending(directory:string,files:string[]):void {
    const names=fs.readdirSync(directory);if(names.length>4096)deny('KNOWN_MEMBER_SCAN_TOO_LARGE');
    for(const file of files){const base=path.basename(file);if(names.includes(base+'.lock')||names.some(n=>n.startsWith('.'+base+'.')&&n.endsWith('.tmp')))throw new PhysicalReadError('BUSY','CONFIG_PENDING');}
    if(names.includes('xmem.sqlite.lock')||names.some(n=>n.startsWith('.xmem.sqlite.')&&n.endsWith('.tmp')))throw new PhysicalReadError('BUSY','DATABASE_PENDING');
  }
  private capture():Buffer {
    this.check();
    const file=path.join(this.storageRoot,'xmem.sqlite'),before=this.databaseStat();
    if(!before)throw new PhysicalReadError('BUSY','DATABASE_CHANGED');
    const encoded=Buffer.from(file,'utf8').toString('base64');
    // Fixed script. Only a validated path encoded as data varies; Open never creates.
    const script=`$ErrorActionPreference='Stop';$f=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'));$s=$null;try{`+
      `$p=[IO.Path]::GetDirectoryName($f);while($p){if(([IO.File]::GetAttributes($p)-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'J01_DENIED'};$q=[IO.Path]::GetDirectoryName($p);if($q-eq$p){break};$p=$q};`+
      `foreach($x in @('-wal','-shm','-journal')){if([IO.File]::Exists($f+$x)-or[IO.Directory]::Exists($f+$x)){throw 'J01_BUSY'}};`+
      `if(([IO.File]::GetAttributes($f)-band([IO.FileAttributes]::ReparsePoint-bor[IO.FileAttributes]::Directory))-ne 0){throw 'J01_DENIED'};`+
      `$s=[IO.File]::Open($f,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);if($s.Length-gt${MAX_IMAGE}){throw 'J01_SIZE'};$b=New-Object byte[] ([int]$s.Length);$n=0;while($n-lt$b.Length){$r=$s.Read($b,$n,$b.Length-$n);if($r-le 0){throw 'J01_UNKNOWN'};$n+=$r};`+
      `foreach($x in @('-wal','-shm','-journal')){if([IO.File]::Exists($f+$x)-or[IO.Directory]::Exists($f+$x)){throw 'J01_BUSY'}};`+
      `$s.Dispose();$s=$null;[Console]::Out.Write([Convert]::ToBase64String($b))`+
      `}catch{if($null-ne$s){try{$s.Dispose();$s=$null}catch{[Console]::Error.Write('J01_UNKNOWN');exit 4}};if($_.Exception.Message-eq'J01_SIZE'){[Console]::Error.Write('J01_SIZE');exit 3};if($_.Exception.Message-eq'J01_DENIED'-or$_.Exception-is[UnauthorizedAccessException]){[Console]::Error.Write('J01_DENIED');exit 3};if($_.Exception.Message-eq'J01_BUSY'-or$_.Exception-is[IO.IOException]){[Console]::Error.Write('J01_BUSY');exit 2};[Console]::Error.Write('J01_UNKNOWN');exit 4}finally{if($null-ne$s){$s.Dispose()}}`;
    let output:string;
    try{output=execFileSync(powerShellHost(),['-MTA','-NoProfile','-NonInteractive','-Command',script],{encoding:'utf8',windowsHide:true,timeout:this.remaining(),maxBuffer:Math.ceil(MAX_IMAGE/3)*4+8192});}
    catch(e){const err=e as {stderr?:Buffer|string;signal?:string};const marker=String(err.stderr??'');if(marker==='J01_BUSY')throw new PhysicalReadError('BUSY','EXCLUSIVE_CAPTURE_BUSY');if(marker==='J01_SIZE')deny('INPUT_TOO_LARGE');if(marker==='J01_DENIED')deny('CAPTURE_PATH_DENIED');throw new PhysicalReadError('UNKNOWN',err.signal?'CAPTURE_TIMEOUT_CLOSURE_UNKNOWN':'CAPTURE_FAILED');}
    this.check();
    if(!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(output))throw new PhysicalReadError('UNKNOWN','CAPTURE_OUTPUT_INVALID');
    const bytes=Buffer.from(output,'base64');
    if(bytes.length>MAX_IMAGE||bytes.length!==before.size||fingerprint(before)!==fingerprint(this.databaseStat()))throw new PhysicalReadError('BUSY','DATABASE_CHANGED');
    return bytes;
  }
  openDatabase(storageRoot:string):Database.Database {
    this.check();if(this.ended||storageRoot!==this.storageRoot)deny('IMAGE_ROOT_MISMATCH');
    if(!this.image)throw new PhysicalReadError('DENIED','DATABASE_NOT_CREATED');
    if(this.image.length<100||this.image.subarray(0,16).toString('binary')!=='SQLite format 3\0')throw new PhysicalReadError('CORRUPT','DATABASE_HEADER_INVALID');
    const bytes=Buffer.from(this.image);
    if(bytes[18]===2&&bytes[19]===2){bytes[18]=1;bytes[19]=1;}
    else if(bytes[18]!==1||bytes[19]!==1)throw new PhysicalReadError('CORRUPT','DATABASE_HEADER_INVALID');
    let db:Database.Database|undefined;
    try{this.check();db=new Database(bytes,{readonly:true,timeout:0});this.connections.add(db);db.pragma('query_only = ON');db.pragma('temp_store = MEMORY');this.check();return db;}
    catch(e){if(db){try{db.close();this.connections.delete(db);}catch{throw new PhysicalReadError('UNKNOWN','IMAGE_CLOSE_FAILED');}}throw mapped(e);}
  }
  /** Caller may close first; this also closes every construction/early-return path. */
  closeConnections():void {let failed=false;for(const db of this.connections){try{if(db.open)db.close();}catch{failed=true;}}this.connections.clear();if(failed)throw new PhysicalReadError('UNKNOWN','IMAGE_CLOSE_FAILED');}
  finish():void {
    this.closeConnections();this.check();
    if(fingerprint(this.databaseStat())!==this.initialFingerprint)throw new PhysicalReadError('BUSY','DATABASE_CHANGED');
    if(this.image){const second=this.capture();if(second.length!==this.image.length||sha(second)!==this.imageHash)throw new PhysicalReadError('BUSY','DATABASE_CHANGED');}
    // Static authority is re-read after the final helper, before payload release.
    this.guard();
    if(fingerprint(this.databaseStat())!==this.initialFingerprint)throw new PhysicalReadError('BUSY','DATABASE_CHANGED');
    this.check();this.ended=true;
  }
}

export function runPhysicalRead(projectRoot:string,input:unknown,options:PhysicalReadOptions,operation:(session:PhysicalReadSession)=>CodexResult):CodexResult {
  let budget:PhysicalBudget|undefined;
  return withPathValidationScope(()=>{
    let session:PhysicalReadSession|undefined;
    let locationScope:ReturnType<typeof enterPhysicalLocationScope>|undefined;
    try{
      budget=new PhysicalBudget(options);
      const e=budget.options.expected;
      locationScope=enterPhysicalLocationScope(projectRoot,e.project_id,{mode:e.mode,canonical_storage_root:e.canonical_storage_root,location_hash:e.location_hash,identity_commit:e.static_files.CUSTOM_IDENTITY,identity_byte_limit:MAX_STATIC});
      session=new PhysicalReadSession(projectRoot,budget,(input as {role?:unknown}|null)?.role);
      if(session.missing)deny('DATABASE_NOT_CREATED');
      const result=operation(session);
      session.closeConnections();
      session.check();
      if(!result.ok)return result;
      const value=result.value as {payload?:unknown;payload_bytes?:unknown};
      if(typeof value?.payload==='string'&&Buffer.byteLength(value.payload,'utf8')>session.options.payload_budget_bytes)deny('RESULT_PAYLOAD_BUDGET_EXCEEDED');
      if(Buffer.byteLength(JSON.stringify(result),'utf8')>MAX_PAYLOAD)deny('RESULT_ENVELOPE_TOO_LARGE');
      session.finish();session.check();return result;
    }catch(e){let error=mapped(e);try{session?.closeConnections();}catch(closeError){error=mapped(closeError);}return{ok:false,error:{code:error.code,message:error.reason}};}
    finally{try{if(session)try{session.closeConnections();}catch{/* Failure is already UNKNOWN in explicit close/finish before any success. */}}finally{locationScope?.close();}}
  },()=>budget?.remaining()??10000);
}
export function physicalDoctor(projectRoot:string,options:PhysicalReadOptions) {
  let budget:PhysicalBudget|undefined;
  return withPathValidationScope(()=>{
    let session:PhysicalReadSession|undefined;
    let locationScope:ReturnType<typeof enterPhysicalLocationScope>|undefined;
    const base={contract:PHYSICAL_READ_CONTRACT,profile:PHYSICAL_READ_PROFILE};
    try{
      budget=new PhysicalBudget(options);
      const e=budget.options.expected;
      locationScope=enterPhysicalLocationScope(projectRoot,e.project_id,{mode:e.mode,canonical_storage_root:e.canonical_storage_root,location_hash:e.location_hash,identity_commit:e.static_files.CUSTOM_IDENTITY,identity_byte_limit:MAX_STATIC});
      session=new PhysicalReadSession(projectRoot,budget);
      let storage:StorageHealth;
      if(session.missing)storage=notCreatedStorageHealth();
      else{const db=session.openDatabase(session.storageRoot);try{storage=inspectOpenDatabase(db,session.options.expected.project_id);}finally{session.closeConnections();}}
      session.finish();
      const status=storage.status==='OK'?'CHECKED_CLOSED_IMAGE':storage.status==='UNAVAILABLE'?'UNKNOWN':storage.status;
      const result={ok:status==='CHECKED_CLOSED_IMAGE'||status==='NOT_CREATED',...base,status,binding:session.binding,source_image:session.sourceImage,storage,reason_codes:storage.reason_codes};
      if(Buffer.byteLength(JSON.stringify(result),'utf8')>Math.min(MAX_PAYLOAD,session.options.payload_budget_bytes))deny('RESULT_PAYLOAD_BUDGET_EXCEEDED');
      session.check();return result;
    }catch(e){let error=mapped(e);try{session?.closeConnections();}catch(closeError){error=mapped(closeError);}return{ok:false,...base,status:error.status,binding:session?.binding??null,source_image:null,storage:null,reason_codes:[error.reason]};}
    finally{try{if(session)try{session.closeConnections();}catch{/* Explicit close is before success. */}}finally{locationScope?.close();}}
  },()=>budget?.remaining()??10000);
}
