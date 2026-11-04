import { z } from 'zod';
import { ENGINEERING_QUERY_SCHEMA, ENGINEERING_RECORD_SCHEMA } from './engineering-memory.js';
import { ENGINEERING_RETRACTION_INTENT_SCHEMA } from './engineering-retraction.js';

import { ENGINEERING_MCP_CONTRACT } from './engineering-mcp-version.js';
export { ENGINEERING_MCP_CONTRACT } from './engineering-mcp-version.js';
export const ENGINEERING_MCP_DEFAULT_BUDGET = 8000;
const text = z.string().min(1).max(512).refine(s => s.trim().length > 0 && !s.includes('\0'));
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const budget = z.number().int().nonnegative().max(262144).optional();
const sources = z.array(text).max(512).refine(a => new Set(a).size === a.length).optional();
const bound = { session_ref:text, binding_id:text };
const reference = z.object({ project_id:text, workspace_id:text, task_ref:text, task_version:text, role:text,
  revision_id:text, source_id:text, source_content_hash:digest, record_content_hash:digest, binding_hash:digest, policy_hash:digest }).strict();
const selectors = ENGINEERING_QUERY_SCHEMA.omit({task_ref:true,task_version:true,role:true,payload_budget_bytes:true});
// Publish complete strict cases; then retain every original Core validation rule.
// An intersection with an open branch can widen unknown-key checks in Zod 4.5.
const recordFields=ENGINEERING_RECORD_SCHEMA.shape;
const captureRecord = z.union([
  z.object({...recordFields,information_type:z.literal('FAILURE'),experience:recordFields.experience.unwrap()}).strict(),
  z.object({...recordFields,information_type:z.enum(['CONSTRAINT','DECISION','INTERFACE','UNKNOWN','NOTE']),experience:z.null()}).strict()
]).superRefine((value,ctx)=>{
  const parsed=ENGINEERING_RECORD_SCHEMA.safeParse(value);
  if(!parsed.success)for(const issue of parsed.error.issues)ctx.addIssue({...issue});
}).describe('For FAILURE, experience is the complete failure object. For every other information_type, experience must be exactly null. Other Core record rules still apply.');

/** Caller session labels and handles are scope checks, never authenticated identities. */
export const ENGINEERING_MCP_SCHEMAS = {
  xmem_engineering_bind:z.object({session_ref:text, project_root:text, expected_project_id:text, expected_workspace_id:text,
    task_ref:text, task_version:text, role:text.optional(), payload_budget_bytes:budget, allowed_source_ids:sources,
    previous_binding_id:text.nullable().default(null)}).strict(),
  xmem_engineering_binding_status:z.object(bound).strict(),
  xmem_engineering_query:z.object({...bound,...selectors.shape,dependency_token:text.optional(),mode:z.literal('preview').default('preview'),payload_budget_bytes:budget}).strict(),
  xmem_engineering_expand:z.object({...bound,dependency_token:text.optional(),reference,view:z.enum(['current','historical']).default('current'),payload_budget_bytes:budget}).strict(),
  xmem_engineering_capture:z.object({...bound,memory_key:text,previous_revision_id:text.nullable(),record:captureRecord}).strict(),
  xmem_engineering_retract:z.object({...bound,action:z.enum(['RETRACT','RECONCILE']),intent:ENGINEERING_RETRACTION_INTENT_SCHEMA,payload_budget_bytes:budget}).strict()
} as const;
export const ENGINEERING_MCP_TOOL_NAMES = Object.freeze(Object.keys(ENGINEERING_MCP_SCHEMAS));
export const ENGINEERING_MCP_OUTPUT_SCHEMA = z.object({
  ok:z.boolean(),
  value:z.object({contract:z.literal(ENGINEERING_MCP_CONTRACT),operation:z.string(),status:z.string(),
    binding:z.object({binding_id:text,session_ref:text,project_root:text,project_id:text,workspace_id:text,task_ref:text,
      task_version:text,role:text,policy_hash:digest,storage_location_hash:digest,payload_budget_bytes:z.number().int().nonnegative(),
      allowed_source_ids:z.array(text).nullable(),verified:z.literal(true),identity_authenticated:z.literal(false),ephemeral:z.literal(true)}).strict(),
    data:z.record(z.string(),z.unknown())}).strict().optional(),
  error:z.object({code:z.string(),message:z.string(),commit_state:z.string().optional(),reconciliation:z.string().optional()}).strict().optional()
}).strict();
