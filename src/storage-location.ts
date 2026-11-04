/** Project-level memory storage location selection.
 *
 * Project identity/configuration remains in <project>/.xmem. The actual XMem
 * database/artifacts may stay there (PROJECT_LOCAL) or be placed in an
 * owner-selected existing local directory (CUSTOM_LOCAL).
 *
 * This module never migrates existing memory. Changing an effective storage
 * root after persisted memory exists is rejected with STORAGE_MIGRATION_REQUIRED.
 */
import fs from 'node:fs';
import { withConfigurationLock, writeConfigurationAtomically } from './config-write.js';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { PathsError, resolveProjectRoot, resolveProjectPath, withPathValidationScope } from './paths.js';

export const STORAGE_LOCATION_FILE = 'storage-location-v1.json';
export const CUSTOM_STORAGE_IDENTITY_FILE = 'xmem-storage-identity-v1.json';

export type StorageLocationMode = 'PROJECT_LOCAL'|'CUSTOM_LOCAL';
export interface StorageLocationPolicy {
  schema_version: 1;
  project_id: string;
  mode: StorageLocationMode;
  storage_root: string;
}
export interface StorageLocationStatus {
  configured: boolean;
  mode: StorageLocationMode;
  storage_root: string;
  default_storage_root: string;
  database_path: string;
  artifacts_path: string;
  location_hash: string|null;
  custom_identity_verified: boolean;
}
export interface StorageLocationConfigureInput {
  consent: true;
  expected_location_hash: string|null;
  mode: StorageLocationMode;
  storage_root: string|null;
}
/** Internal physical-profile binding; never accepted by configuration/MCP input. */
interface PhysicalLocationBinding {
  mode:StorageLocationMode;
  canonical_storage_root:string;
  location_hash:string;
  identity_commit:{presence:'PRESENT'|'ABSENT';sha256:string|null};
  identity_byte_limit:number;
}
type PhysicalLocationScope={projectRoot:string;projectId:string;binding:PhysicalLocationBinding};
let physicalLocationScope:PhysicalLocationScope|undefined;
function compatibleBinding(a:PhysicalLocationBinding,b:PhysicalLocationBinding):void {
  if(!Number.isSafeInteger(b.identity_byte_limit)||b.identity_byte_limit<0)throw new PathsError('STATIC_INPUT_TOO_LARGE','STATIC_INPUT_TOO_LARGE');
  if(a.mode!==b.mode)throw new PathsError('MODE_MISMATCH','MODE_MISMATCH');
  if(a.canonical_storage_root!==b.canonical_storage_root)throw new PathsError('STORAGE_ROOT_MISMATCH','STORAGE_ROOT_MISMATCH');
  if(a.location_hash!==b.location_hash)throw new PathsError('LOCATION_HASH_MISMATCH','LOCATION_HASH_MISMATCH');
  if(a.identity_commit.presence!==b.identity_commit.presence||a.identity_commit.sha256!==b.identity_commit.sha256)throw new PathsError('STATIC_HASH_MISMATCH','STATIC_HASH_MISMATCH');
}
/** Internal synchronous token, not an SDK option or callback injection surface. */
export function enterPhysicalLocationScope(projectRoot:string,projectId:string,binding:PhysicalLocationBinding):{close():void} {
  compatibleBinding(binding,binding);
  const previous=physicalLocationScope,root=path.resolve(projectRoot);
  if(previous){
    if(previous.projectRoot!==root||previous.projectId!==projectId)throw new PathsError('PROJECT_MISMATCH','Physical location scope cannot switch projects');
    compatibleBinding(previous.binding,binding);
  }
  const current:PhysicalLocationScope={projectRoot:root,projectId,binding:{...binding,identity_commit:{...binding.identity_commit},identity_byte_limit:Math.min(binding.identity_byte_limit,previous?.binding.identity_byte_limit??Infinity)}};
  physicalLocationScope=current;
  return{close(){if(physicalLocationScope!==current)throw new PathsError('INVALID_CONFIG','Physical location scopes must close in order');physicalLocationScope=previous;}};
}
function effectiveBinding(projectRoot:string,projectId:string,explicit?:PhysicalLocationBinding):PhysicalLocationBinding|undefined {
  const current=physicalLocationScope;
  if(!current)return explicit;
  if(path.resolve(projectRoot)!==current.projectRoot||projectId!==current.projectId)throw new PathsError('PROJECT_MISMATCH','Physical location scope cannot switch projects');
  if(explicit){compatibleBinding(current.binding,explicit);current.binding.identity_byte_limit=Math.min(current.binding.identity_byte_limit,explicit.identity_byte_limit);}
  return current.binding;
}

function hash(value:unknown):string{return createHash('sha256').update(JSON.stringify(value)).digest('hex');}
function exactObject(value:unknown,keys:string[],label:string):Record<string,unknown>{
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!==[...keys].sort().join(','))throw new PathsError('INVALID_CONFIG',`${label} has unknown or missing fields`);
  return value as Record<string,unknown>;
}
function assertCanonicalProjectRoot(root:string):string{
  // Internal callers normally pass readProjectConfig(...).root. This inexpensive
  // guard avoids a second Windows DriveInfo probe on every hot-path session call.
  if(typeof root!=='string'||!path.isAbsolute(root)||!fs.existsSync(root)||!fs.statSync(root).isDirectory())throw new PathsError('INVALID_ROOT','Project root must be an existing absolute directory');
  const real=fs.realpathSync.native(root);
  if(path.resolve(real).toLowerCase()!==path.resolve(root).toLowerCase())throw new PathsError('LINK_PATH','Project root redirects from its configured path');
  const xmem=path.join(real,'.xmem');
  if(!fs.existsSync(xmem))throw new PathsError('NOT_INITIALIZED','Project .xmem directory is missing');
  const xstat=fs.lstatSync(xmem);
  if(xstat.isSymbolicLink()||!xstat.isDirectory()||path.resolve(fs.realpathSync.native(xmem)).toLowerCase()!==path.resolve(xmem).toLowerCase())throw new PathsError('LINK_PATH','Project .xmem directory must be a non-linked local directory');
  return real;
}
function defaultRootAt(canonicalProjectRoot:string):string{return path.join(canonicalProjectRoot,'.xmem');}
function locationFileAt(canonicalProjectRoot:string):string{return resolveProjectPath(canonicalProjectRoot,'.xmem/'+STORAGE_LOCATION_FILE);}
export function withStorageLocationLock<T>(root:string,operation:()=>T):T{return withConfigurationLock(locationFileAt(root),operation);}
export function defaultMemoryStorageRoot(projectRoot:string):string{return defaultRootAt(resolveProjectRoot(projectRoot));}

function validatePolicy(canonicalProjectRoot:string,projectId:string,value:unknown,expected?:PhysicalLocationBinding):StorageLocationPolicy{
  const x=exactObject(value,['schema_version','project_id','mode','storage_root'],'Storage location policy');
  if(x.schema_version!==1||x.project_id!==projectId||!['PROJECT_LOCAL','CUSTOM_LOCAL'].includes(String(x.mode))||typeof x.storage_root!=='string'||!x.storage_root.trim())throw new PathsError('INVALID_CONFIG','Storage location identity or schema does not match');
  const mode=x.mode as StorageLocationMode,expectedDefault=defaultRootAt(canonicalProjectRoot);
  // Bind this exact parsed object before any custom-root filesystem access.
  if(expected){
    if(mode!==expected.mode)throw new PathsError('MODE_MISMATCH','MODE_MISMATCH');
    if(!path.isAbsolute(x.storage_root)||path.resolve(x.storage_root).toLowerCase()!==path.resolve(expected.canonical_storage_root).toLowerCase())throw new PathsError('STORAGE_ROOT_MISMATCH','STORAGE_ROOT_MISMATCH');
  }
  // Default location is already under a previously validated canonical project root.
  // A custom location is independently revalidated as a local, non-linked directory.
  const resolved=mode==='PROJECT_LOCAL'?expectedDefault:resolveProjectRoot(x.storage_root);
  if(mode==='PROJECT_LOCAL'&&path.resolve(x.storage_root).toLowerCase()!==path.resolve(expectedDefault).toLowerCase())throw new PathsError('INVALID_CONFIG','PROJECT_LOCAL storage must resolve to the project .xmem directory');
  if(mode==='CUSTOM_LOCAL'&&path.resolve(resolved).toLowerCase()===path.resolve(expectedDefault).toLowerCase())throw new PathsError('INVALID_CONFIG','CUSTOM_LOCAL storage must differ from the default project .xmem directory');
  return{schema_version:1,project_id:projectId,mode,storage_root:resolved};
}
function verifyCustomIdentity(storageRoot:string,projectId:string):boolean{
  const file=path.join(storageRoot,CUSTOM_STORAGE_IDENTITY_FILE);
  if(!fs.existsSync(file))return false;
  const stat=fs.lstatSync(file);if(stat.isSymbolicLink()||!stat.isFile())throw new PathsError('INVALID_CONFIG','Custom storage identity must be a regular file');
  let parsed:unknown;try{parsed=JSON.parse(fs.readFileSync(file,'utf8'));}catch{throw new PathsError('INVALID_CONFIG','Custom storage identity is invalid JSON');}
  const x=exactObject(parsed,['schema_version','project_id'],'Custom storage identity');
  if(x.schema_version!==1||x.project_id!==projectId)throw new PathsError('PROJECT_MISMATCH','Custom storage directory belongs to another XMem project');
  return true;
}
function writeCustomIdentity(storageRoot:string,projectId:string):void{
  const file=path.join(storageRoot,CUSTOM_STORAGE_IDENTITY_FILE);
  if(fs.existsSync(file)){verifyCustomIdentity(storageRoot,projectId);return;}
  if(fs.readdirSync(storageRoot).length>0)throw new PathsError('INVALID_INPUT','Custom storage directory must be empty before first use');
  fs.writeFileSync(file,JSON.stringify({schema_version:1,project_id:projectId},null,2)+'\n',{flag:'wx',mode:0o600});
}
function memoryDataExists(storageRoot:string):boolean{
  for(const name of ['xmem.sqlite','xmem.sqlite-wal','xmem.sqlite-shm','xmem.sqlite-journal'])if(fs.existsSync(path.join(storageRoot,name)))return true;
  const artifacts=path.join(storageRoot,'artifacts');
  if(fs.existsSync(artifacts)){const stat=fs.lstatSync(artifacts);if(!stat.isDirectory()||stat.isSymbolicLink())return true;if(fs.readdirSync(artifacts).length>0)return true;}
  return false;
}
function readAt(canonicalProjectRoot:string,projectId:string,expected?:PhysicalLocationBinding):StorageLocationStatus{
  expected=effectiveBinding(canonicalProjectRoot,projectId,expected);
  const defaultRoot=defaultRootAt(canonicalProjectRoot),file=locationFileAt(canonicalProjectRoot);
  if(expected&&!fs.existsSync(file))throw new PathsError('INVALID_CONFIG','Physical storage location must remain configured');
  if(!fs.existsSync(file))return{configured:false,mode:'PROJECT_LOCAL',storage_root:defaultRoot,default_storage_root:defaultRoot,database_path:path.join(defaultRoot,'xmem.sqlite'),artifacts_path:path.join(defaultRoot,'artifacts'),location_hash:null,custom_identity_verified:false};
  let parsed:unknown;try{parsed=JSON.parse(fs.readFileSync(file,'utf8'));}catch{throw new PathsError('INVALID_CONFIG','Storage location policy is invalid JSON');}
  const policy=validatePolicy(canonicalProjectRoot,projectId,parsed,expected);
  if(expected){
    if(policy.storage_root!==expected.canonical_storage_root)throw new PathsError('STORAGE_ROOT_MISMATCH','STORAGE_ROOT_MISMATCH');
    if(hash(policy)!==expected.location_hash)throw new PathsError('LOCATION_HASH_MISMATCH','LOCATION_HASH_MISMATCH');
    if(policy.mode==='CUSTOM_LOCAL'){
      const file=path.join(policy.storage_root,CUSTOM_STORAGE_IDENTITY_FILE),commit=expected.identity_commit;
      if(commit.presence!=='PRESENT')throw new PathsError('STATIC_REQUIRED','STATIC_REQUIRED');
      if(!fs.existsSync(file))throw new PathsError('STATIC_PRESENCE_MISMATCH','STATIC_PRESENCE_MISMATCH');
      const stat=fs.lstatSync(file);
      if(stat.isSymbolicLink()||!stat.isFile()||stat.nlink!==1||path.resolve(fs.realpathSync.native(file)).toLowerCase()!==path.resolve(file).toLowerCase())throw new PathsError('LINKED_OR_NONREGULAR_LEAF','LINKED_OR_NONREGULAR_LEAF');
      if(stat.size>expected.identity_byte_limit)throw new PathsError('STATIC_INPUT_TOO_LARGE','STATIC_INPUT_TOO_LARGE');
      const bytes=fs.readFileSync(file);
      if(bytes.length>expected.identity_byte_limit)throw new PathsError('STATIC_INPUT_TOO_LARGE','STATIC_INPUT_TOO_LARGE');
      if(createHash('sha256').update(bytes).digest('hex')!==commit.sha256)throw new PathsError('STATIC_HASH_MISMATCH','STATIC_HASH_MISMATCH');
    }
  }
  const custom_identity_verified=policy.mode==='CUSTOM_LOCAL'?verifyCustomIdentity(policy.storage_root,projectId):false;
  if(policy.mode==='CUSTOM_LOCAL'&&!custom_identity_verified)throw new PathsError('INVALID_CONFIG','Custom storage identity is missing');
  return{configured:true,mode:policy.mode,storage_root:policy.storage_root,default_storage_root:defaultRoot,database_path:path.join(policy.storage_root,'xmem.sqlite'),artifacts_path:path.join(policy.storage_root,'artifacts'),location_hash:hash(policy),custom_identity_verified};
}
/** Public safe read from an arbitrary caller-supplied project root. */
export function readStorageLocation(projectRoot:string,projectId:string):StorageLocationStatus{return readAt(resolveProjectRoot(projectRoot),projectId);}
/** Hot-path read when the project root already came from readProjectConfig(...).root. */
export function readStorageLocationAtProjectRoot(canonicalProjectRoot:string,projectId:string,expected?:PhysicalLocationBinding):StorageLocationStatus{return readAt(assertCanonicalProjectRoot(canonicalProjectRoot),projectId,expected);}
export function resolveMemoryStorageRoot(canonicalProjectRoot:string,projectId:string):string{return readStorageLocationAtProjectRoot(canonicalProjectRoot,projectId).storage_root;}
export function storageLocationNotice(canonicalProjectRoot:string,projectId:string){
  const status=readStorageLocationAtProjectRoot(canonicalProjectRoot,projectId);
  return{...status,prompt_required:!status.configured,prompt_code:status.configured?null:'STORAGE_LOCATION_CHOICE_REQUIRED',owner_prompt:status.configured?null:`XMem semi-auto is ready. Memory data is stored by default at: ${status.default_storage_root} (database: ${path.join(status.default_storage_root,'xmem.sqlite')}). Ask the user whether to keep this default location. If they want to change it, ask for an existing empty absolute directory on a local drive. Do not choose a location on the user's behalf.`};
}
export function configureStorageLocation(projectRoot:string,projectId:string,input:StorageLocationConfigureInput):StorageLocationStatus&{replayed:boolean}{
  return withPathValidationScope(()=>{
  const root=resolveProjectRoot(projectRoot);
  return withConfigurationLock(locationFileAt(root),()=>{
  if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).sort().join(',')!==['consent','expected_location_hash','mode','storage_root'].sort().join(','))throw new PathsError('INVALID_INPUT','Storage location configure input has unknown or missing fields');
  if(input.consent!==true)throw new PathsError('INVALID_INPUT','Explicit owner consent is required');
  if(!(input.expected_location_hash===null||(typeof input.expected_location_hash==='string'&&/^[a-f0-9]{64}$/.test(input.expected_location_hash))))throw new PathsError('INVALID_INPUT','expected_location_hash must be null or a SHA-256 hash');
  if(!['PROJECT_LOCAL','CUSTOM_LOCAL'].includes(input.mode))throw new PathsError('INVALID_INPUT','Unsupported storage location mode');
  const current=readAt(root,projectId);
  let target:string;
  if(input.mode==='PROJECT_LOCAL'){
    if(input.storage_root!==null)throw new PathsError('INVALID_INPUT','PROJECT_LOCAL does not accept a custom storage_root');
    target=defaultRootAt(root);
  }else{
    if(typeof input.storage_root!=='string'||!input.storage_root.trim())throw new PathsError('INVALID_INPUT','CUSTOM_LOCAL requires an existing absolute local directory');
    target=resolveProjectRoot(input.storage_root);
    if(path.resolve(target).toLowerCase()===path.resolve(defaultRootAt(root)).toLowerCase())throw new PathsError('INVALID_INPUT','CUSTOM_LOCAL must differ from the default project .xmem directory');
  }
  const policy:StorageLocationPolicy={schema_version:1,project_id:projectId,mode:input.mode,storage_root:target},nextHash=hash(policy);
  // Initial identical retry is a no-op; explicit non-null CAS stays strict.
  if(current.configured&&input.expected_location_hash!==null&&input.expected_location_hash!==current.location_hash)throw new PathsError('IDENTITY_CONFLICT','Storage location changed since it was read');
  if(current.configured&&current.location_hash===nextHash)return{...current,replayed:true};
  if(current.configured){
    if(input.expected_location_hash===null||input.expected_location_hash!==current.location_hash)throw new PathsError('IDENTITY_CONFLICT','Storage location changed or already exists; provide its current hash to update');
  }else if(input.expected_location_hash!==null)throw new PathsError('IDENTITY_CONFLICT','No storage location policy exists for the supplied hash');
  const same=path.resolve(current.storage_root).toLowerCase()===path.resolve(target).toLowerCase();
  if(!same&&memoryDataExists(current.storage_root))throw new PathsError('STORAGE_MIGRATION_REQUIRED','Existing XMem memory is present. Storage location cannot be switched without an explicit migration workflow');
  if(input.mode==='CUSTOM_LOCAL')writeCustomIdentity(target,projectId);
  writeConfigurationAtomically(locationFileAt(root),policy);
  return{...readAt(root,projectId),replayed:false};
  });
  });
}
