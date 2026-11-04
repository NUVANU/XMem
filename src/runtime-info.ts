import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { COMPANION_CONTRACT_VERSION } from './companion-contract.js';
import { ENGINEERING_MCP_CONTRACT, ENGINEERING_RETRACTION_CAPABILITY } from './engineering-mcp-version.js';

const sha=(bytes:Uint8Array|string)=>createHash('sha256').update(bytes).digest('hex');
/** Hash the shipped code and lock, not a remembered directory label. No paths in result. */
export function runtimeInfo(profile:'sdk'|'full'|'companion'|'engineering'='sdk') {
  const directory=path.dirname(fileURLToPath(import.meta.url));
  const files=fs.readdirSync(directory).filter(x=>x.endsWith('.js')).sort().map(name=>({name,sha256:sha(fs.readFileSync(path.join(directory,name)))}));
  const packageRoot=path.resolve(directory,'../..');
  const packageBytes=fs.readFileSync(path.join(packageRoot,'package.json'));
  const lockBytes=fs.readFileSync(path.join(packageRoot,'npm-shrinkwrap.json'));
  return {package_version:String(JSON.parse(packageBytes.toString('utf8')).version),contract_version:profile==='engineering'?ENGINEERING_MCP_CONTRACT:COMPANION_CONTRACT_VERSION,
    build_id:sha(JSON.stringify({files,package_sha256:sha(packageBytes),lock_sha256:sha(lockBytes)})),
    build_id_scope:'SHIPPED_JS_PACKAGE_AND_SHRINKWRAP',identity_observation:'ON_DISK_AT_STATUS_CALL_NOT_LOADED_MODULE_ATTESTATION',profile,release_status:'V21_ENGINEERING_CANDIDATE_NOT_RELEASED',
    capabilities:{physical_read_profiles:['PHYSICAL_CLOSED_V1'],physical_read_contract:'xmem-physical-readonly-preflight/1',ordinary_tool_count:profile==='engineering'?15:9,engineering_retraction:{contract:ENGINEERING_RETRACTION_CAPABILITY,sdk:true,mcp:profile==='engineering',actions:['RETRACT','RECONCILE'],developer_only:true,automatic:false},per_call_budget_narrowing:true,source_allowlist_narrowing:true,capture_role_narrowing:true,
      immutable_event_keys:'EXPLICIT_MEMORY_KEY_AND_PREDECESSOR_CAS',cross_task_query:'OWNER_AUTHORIZED_READ_ONLY_SDK',engineering_recall:profile==='engineering'?'BOUND_EXACT_TASK_MCP_AND_SDK_V2':'EXACT_TASK_READ_ONLY_SDK_V2',authenticated_identity:false,automatic_hooks:false}};
}
