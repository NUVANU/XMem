import { z } from 'zod';
import { TOPIC_DISCOVERY_SCHEMA, TOPIC_CAPTURE_SCHEMA, TOPIC_EXPANSION_SCHEMA } from './topic-continuity.js';

export const COMPANION_CONTRACT_VERSION = 'xmem-companion/3' as const;
export const COMPANION_BASELINE_VERSION = 'xmem-companion/1' as const;
const text = z.string().min(1).max(512).refine(x => x.trim().length > 0 && !x.includes('\0'));
const scope = { task_ref:text, task_version:text, role:text.optional() };
const sources = z.array(text).max(512).refine(x => new Set(x).size === x.length).optional();
const budget = z.number().int().nonnegative().max(262144).optional();
const state = z.array(z.string().min(1).max(2048)).max(64).refine(x => new Set(x).size === x.length);
const categories = z.enum(['DECISION','CONSTRAINT','REQUIREMENT_CHANGE','FAILED_APPROACH','ROOT_CAUSE_HYPOTHESIS','IMPORTANT_DISCOVERY','HANDOFF_STATE']);
const project = { project_root:z.string().min(1) };
export const DEPENDENCY_SELECTION_FIELDS={dependency_token:text.optional(),dependency_session_ref:text.optional()};
export const dependencySelectionPaired=(x:{dependency_token?:string;dependency_session_ref?:string})=>(x.dependency_token===undefined)===(x.dependency_session_ref===undefined);
const digest=z.string().regex(/^[a-f0-9]{64}$/);
const registration=z.object({task_ref:text,task_version:text,role:text.optional(),expected_scope:z.object({project_id:text,workspace_id:text,policy_hash:digest,storage_location_hash:digest}).strict(),
  relation_ids:z.array(text).max(32).refine(a=>new Set(a).size===a.length),allowed_source_ids:sources}).strict();
const legacyCapture=z.object({task_ref:text,task_version:text,memory_key:text,category:categories,declared_actor:z.enum(['user','agent']),content:z.string().min(1).refine(x => x.trim().length > 0 && !x.includes('\0') && Buffer.byteLength(x,'utf8') <= 16384),previous_revision_id:text.nullable(),roles:z.array(text).min(1).max(8).refine(x => new Set(x).size === x.length).optional()}).strict();
const legacyRead=z.object({...scope,memory_key:text.nullable(),revision_id:text.nullable(),payload_budget_bytes:z.number().int().nonnegative()}).strict().refine(x => x.memory_key !== null || x.revision_id !== null);

/** One schema source for registrations and caller-side preflight. No aliases. */
export const COMPANION_SCHEMAS = {
  xmem_project_discover:z.object({start_path:z.string().min(1).optional(),topic:TOPIC_DISCOVERY_SCHEMA.optional()}).strict(),
  xmem_standalone_status:z.object(project).strict(),
  xmem_storage_location_status:z.object(project).strict(),
  xmem_session_start:z.object({...project,...DEPENDENCY_SELECTION_FIELDS,input:z.object({...scope,payload_budget_bytes:budget,allowed_source_ids:sources}).strict()}).strict().refine(dependencySelectionPaired),
  xmem_session_capture:z.object({...project,input:z.union([legacyCapture,TOPIC_CAPTURE_SCHEMA])}).strict(),
  xmem_session_read:z.object({...project,input:z.union([legacyRead,TOPIC_EXPANSION_SCHEMA])}).strict(),
  xmem_session_checkpoint:z.object({...project,...DEPENDENCY_SELECTION_FIELDS,input:z.object({...scope,completed:state,pending:state,blocked:state,next_steps:state,payload_budget_bytes:budget,allowed_source_ids:sources}).strict()}).strict().refine(dependencySelectionPaired),
  xmem_dependency_register:z.object({...project,session_ref:text,binding_id:text.optional(),input:registration}).strict(),
  xmem_dependency_revoke:z.object({session_ref:text,dependency_token:text}).strict()
} as const;
export type CompanionToolName = keyof typeof COMPANION_SCHEMAS;
export const COMPANION_TOOL_NAMES = Object.freeze(Object.keys(COMPANION_SCHEMAS) as CompanionToolName[]);
export function validateCompanionCall(name:string,args:unknown):unknown {
  if(!Object.hasOwn(COMPANION_SCHEMAS,name))throw new Error('UNKNOWN_COMPANION_TOOL');
  return COMPANION_SCHEMAS[name as CompanionToolName].parse(args);
}
