import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { codexAcknowledgeHandoff, codexCleanupApply, codexCleanupPreview, codexCompileContext, codexConfigureStorageLocation, codexDoctor, codexInit, codexPrepareHandoff, codexReadManifest, codexRecoverHandoff, codexStorageCompact, codexStorageLocationStatus, codexStorageStatus, codexTrustedEvidence, codexValidateHandoff, codexVerifyEvidence, type CodexResult } from './codex.js';

import { captureLocalMemory, captureLocalSnapshot, compileLocalContext, recoverLocalHandoff } from './local-api.js';
import { COMPANION_SCHEMAS, COMPANION_TOOL_NAMES,DEPENDENCY_SELECTION_FIELDS,dependencySelectionPaired } from './companion-contract.js';
import { captureStandaloneMemory, captureStandaloneTopic, checkpointStandaloneSession, configureStandalone, discoverStandaloneProject, readStandaloneMemory, standaloneStatus, startStandaloneSession, type StandaloneSessionInput, type StandaloneCheckpointInput } from './standalone.js';
import { discoverStandaloneTopics, expandStandaloneTopic } from './topic-continuity.js';
import type { DependencyReadOptions } from './dependency-read-boundary.js';
import { registerEngineeringMcpTools } from './engineering-mcp.js';
import { createDependencyMcpRegistry } from './dependency-mcp-registry.js';
import { dependencyHandleScope, type EngineeringDependencyOptions } from './engineering-dependencies.js';
import { PathsError,withPathValidationScope } from './paths.js';

const nonEmpty = z.string().min(1);
const source = z.object({ source_id: nonEmpty, kind: z.enum(['executor','file','user','agent','derived']), locator: nonEmpty, version: nonEmpty, content_hash: z.string().regex(/^[a-f0-9]{64}$/) }).strict();
const snapshot = z.object({ schema_version:z.literal('1'), snapshot_id:nonEmpty, project_id:nonEmpty, workspace_id:nonEmpty, captured_at:nonEmpty, manifest:z.object({ completeness:z.enum(['COMPLETE','INCOMPLETE']), missing:z.array(nonEmpty), files_hash:z.string().regex(/^[a-f0-9]{64}$/).nullable(), test_definition_hash:z.string().regex(/^[a-f0-9]{64}$/).nullable(), command:nonEmpty, args:z.array(z.string()), config_hash:z.string().regex(/^[a-f0-9]{64}$/).nullable(), toolchain_hash:z.string().regex(/^[a-f0-9]{64}$/).nullable(), dependencies_hash:z.string().regex(/^[a-f0-9]{64}$/).nullable(), fixtures_hash:z.string().regex(/^[a-f0-9]{64}$/).nullable(), environment_hash:z.string().regex(/^[a-f0-9]{64}$/).nullable(), external_state:z.enum(['CONTROLLED','UNKNOWN']) }).strict() }).strict();
const evidence = z.object({ schema_version:z.literal('1'), evidence_id:nonEmpty, project_id:nonEmpty, workspace_id:nonEmpty, run_id:nonEmpty, snapshot_id:nonEmpty, source, result:z.enum(['PASS','FAIL','ERROR','NOT_RUN']), exit_code:z.number().int().nullable(), artifact_hash:z.string().regex(/^[a-f0-9]{64}$/).nullable(), recorded_at:nonEmpty }).strict();
const request = z.object({ project_id:nonEmpty, workspace_id:nonEmpty, task_ref:nonEmpty, task_version:nonEmpty, role:nonEmpty, target_snapshot_id:nonEmpty, allowed_source_ids:z.array(nonEmpty).refine(x => new Set(x).size === x.length), payload_budget_bytes:z.number().int().nonnegative(), max_depth:z.number().int().nonnegative(), max_nodes:z.number().int().positive() }).strict();
const handoff = z.object({ project_id:nonEmpty, workspace_id:nonEmpty, task_ref:nonEmpty, task_version:nonEmpty, target_snapshot:snapshot, revision_ids:z.array(nonEmpty), evidence_ids:z.array(nonEmpty), failed_attempt_ids:z.array(nonEmpty), context_manifest_hash:nonEmpty, completed:z.array(nonEmpty), pending:z.array(nonEmpty), blocked:z.array(nonEmpty), next_steps:z.array(nonEmpty) }).strict();
const project = { project_root: nonEmpty };
/** MCP is a safe metadata surface, not a raw SourceRef or artifact transport. */
function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (!value || typeof value !== 'object') return value;
  const object = value as Record<string, unknown>;
  if (typeof object.source_id === 'string' && typeof object.kind === 'string' && ('locator' in object || 'version' in object || 'content_hash' in object)) return { source_id: object.source_id, kind: object.kind };
  return Object.fromEntries(Object.entries(object).filter(([key]) => key !== 'locator' && key !== 'version').map(([key, item]) => {
    if (key === 'payload' && typeof item === 'string') return [key, item.split('\n').map(line => { try { return JSON.stringify(redact(JSON.parse(line))); } catch { return line; } }).join('\n')];
    return [key, redact(item)];
  }));
}
/** Private single-use projection for known Core return slots, never user payload objects.
 * Internal identity hashes remain references to the persisted, unredacted material.
 */
function projectContextPayload(original: unknown, safe: unknown): void {
  if(original===null&&safe===null)return;
  const raw=original as Record<string,unknown>, projected=safe as Record<string,unknown>;
  if(!raw||!projected||typeof raw!=='object'||typeof projected!=='object'||Array.isArray(raw)||Array.isArray(projected)||
    Object.prototype.hasOwnProperty.call(raw,'mcp_projection')||raw.kind!=='ContextPack'||raw.compiler_version!=='context-v2'||
    typeof raw.payload!=='string'||typeof projected.payload!=='string'||!Number.isSafeInteger(raw.payload_bytes)||raw.payload_bytes!==Buffer.byteLength(raw.payload,'utf8')||
    typeof raw.content_hash!=='string'||!/^[a-f0-9]{64}$/.test(raw.content_hash)||
    (raw.manifest_hash!==undefined&&(typeof raw.manifest_hash!=='string'||!/^[a-f0-9]{64}$/.test(raw.manifest_hash))))throw new Error('MCP_CONTEXT_PROJECTION_INVALID');
  projected.payload_bytes=Buffer.byteLength(projected.payload,'utf8');
  projected.mcp_projection={schema_version:1,representation:'MCP_REDACTED_CONTEXT_PAYLOAD',
    internal_payload_bytes:raw.payload_bytes,payload_sha256:createHash('sha256').update(projected.payload,'utf8').digest('hex'),
    content_hash_scope:'INTERNAL_CONTEXT_PACK_BODY',
    ...(raw.manifest_hash===undefined?{}:{manifest_hash_scope:'INTERNAL_CONTEXT_MANIFEST'}),
    budget_basis:'INTERNAL_PRE_REDACTION_PAYLOAD_UTF8'};
}

// Only explicit tool registrations below select these two fixed response slots.
// The generic redactor above remains unchanged and never interprets fake pack kinds.
function result(value: CodexResult, contextSlot: 'direct'|'nested'|null=null, internalContextTelemetry=false) {
  const safe=redact(value) as CodexResult;
  if(value.ok&&safe.ok){
    try{
      if(contextSlot==='direct')projectContextPayload(value.value,safe.value);
      if(contextSlot==='nested')projectContextPayload((value.value as Record<string,unknown>).context,(safe.value as Record<string,unknown>).context);
      if(internalContextTelemetry){
        const telemetry=(safe.value as Record<string,unknown>).telemetry;
        if(telemetry&&typeof telemetry==='object'&&!Array.isArray(telemetry))
          (telemetry as Record<string,unknown>).context_payload_measurement='INTERNAL_PRE_MCP_REDACTION_UTF8';
      }
    }catch{return{isError:true,content:[{type:'text' as const,text:JSON.stringify({ok:false,error:{code:'MCP_CONTEXT_PROJECTION_INVALID',message:'Core context could not be projected safely; no public context was returned.'}})}]};}
  }
  return safe.ok?{content:[{type:'text' as const,text:JSON.stringify(safe)}]}:{isError:true,content:[{type:'text' as const,text:JSON.stringify(safe)}]};
}
/** Only the two explicit Topic read routes select this public byte/hash view. */
function topicResult(value:CodexResult){
  const safe=redact(value) as CodexResult;
  if(safe.ok){
    const v=safe.value as Record<string,unknown>;
    if(v.contract!=='xmem-topic-continuity/1'||!Number.isSafeInteger(v.payload_budget_bytes)||!Number.isSafeInteger(v.public_total_budget_bytes))return result({ok:false,error:{code:'TOPIC_PROJECTION_INVALID',message:'Topic result could not be projected safely'}});
    if(typeof v.payload==='string'){v.payload_bytes=Buffer.byteLength(v.payload,'utf8');v.payload_sha256=createHash('sha256').update(v.payload,'utf8').digest('hex');}
    if(v.status==='COMPLETE'&&typeof v.payload!=='string'||Number(v.payload_bytes)>Number(v.payload_budget_bytes)||Buffer.byteLength(JSON.stringify(safe),'utf8')>Number(v.public_total_budget_bytes))return result({ok:false,error:{code:'BUDGET_UNSATISFIABLE',message:'Topic result exceeds the approved public budget'}});
  }
  return safe.ok?{content:[{type:'text' as const,text:JSON.stringify(safe)}]}:{isError:true,content:[{type:'text' as const,text:JSON.stringify(safe)}]};
}

/** Real SDK operation with the same fixed Companion safe response view.
 * This is SDK_WITH_COMPANION_SAFE_VIEW, not a transport or token operation. */
export function startStandaloneSessionCompanionView(projectRoot:string,input:StandaloneSessionInput,options?:DependencyReadOptions):CallToolResult {
  try{assertCompanionViewOptions(options);}catch{return result({ok:false,error:{code:'INPUT_INCOMPLETE',message:'Dependency options unavailable for this fixed SDK view'}});}
  return result(startStandaloneSession(projectRoot,input,options),'nested',true);
}
/** Performs the actual checkpoint once, then applies its original fixed view. */
export function checkpointStandaloneSessionCompanionView(projectRoot:string,input:StandaloneCheckpointInput,options?:DependencyReadOptions):CallToolResult {
  try{assertCompanionViewOptions(options);}catch{return result({ok:false,error:{code:'INPUT_INCOMPLETE',message:'Dependency options unavailable for this fixed SDK view'}});}
  return result(checkpointStandaloneSession(projectRoot,input,options),null,true);
}
function assertCompanionViewOptions(options:DependencyReadOptions|undefined):void {
  if(options===undefined)return;
  if(!options||Object.getPrototypeOf(options)!==Object.prototype||!Object.hasOwn(options,'dependencies')
    ||Reflect.ownKeys(options).some(k=>typeof k!=='string'||!['dependencies','dependency_budget'].includes(k))
    ||Object.values(Object.getOwnPropertyDescriptors(options)).some(d=>!('value'in d)||!d.enumerable))throw new Error('INVALID_DEPENDENCY_OPTIONS');
  dependencyHandleScope(options.dependencies);
}

/** A smaller ordinary-agent surface, not credential or process isolation. */
export const COMPANION_TOOLS = COMPANION_TOOL_NAMES;
export type McpProfile = 'full' | 'companion' | 'engineering';

export function createMcpServer(profile: McpProfile = 'full'): McpServer {
  if (profile !== 'full' && profile !== 'companion' && profile !== 'engineering') throw new Error('INVALID_MCP_PROFILE');
  const server = new McpServer({ name:profile === 'engineering' ? 'xmem-engineering' : profile === 'companion' ? 'xmem-companion' : 'xmem-local', version:'0.0.1' });
  const dependencies=createDependencyMcpRegistry(server);
  const live=(x:{project_root:string;dependency_token?:string;dependency_session_ref?:string},extra:{sessionId?:string},work:(options?:EngineeringDependencyOptions)=>CodexResult,slot:'direct'|'nested'|null=null,telemetry=false)=>{
    try{return withPathValidationScope(()=>result(work(dependencies.options(x.project_root,x.dependency_token,x.dependency_session_ref,extra)),slot,telemetry));}
    catch(error){return result({ok:false,error:{code:error instanceof PathsError?error.code:'INPUT_INCOMPLETE',message:'Dependency enrollment unavailable in this server session'}});}
  };
  // Remove excluded tools before connecting any transport. Keeping registration
  // here reuses the exact schemas, redaction and handlers of the one Core.
  const registerTool: typeof server.registerTool = (name, config, callback) => {
    const tool = server.registerTool(name, config, callback);
    if (profile !== 'full' && !(COMPANION_TOOLS as readonly string[]).includes(name)) tool.remove();
    return tool;
  };
  registerTool('xmem_project_init',{description:'Initialize one local project through M1. Does not run tasks.',inputSchema:z.object(project).strict()}, args => result(codexInit(args.project_root)));
  registerTool('xmem_project_doctor',{description:'Check project identity and SQLite health without creating or migrating a database. Unhealthy or unavailable databases are MCP tool errors with diagnostic metadata. Empty storage is not a missing implementation.',inputSchema:z.object(project).strict()}, args => result(codexDoctor(args.project_root)));
  registerTool('xmem_trusted_evidence_query',{description:'Read trusted local evidence metadata without artifacts or database files.',inputSchema:z.object({...project,evidence_id:nonEmpty}).strict()}, args => result(codexTrustedEvidence(args.project_root,args.evidence_id)));
  registerTool('xmem_trusted_evidence_verify',{description:'VERIFY ONLY. Does not save decisions or register execution evidence. Check supplied evidence against existing local trusted provenance.',inputSchema:z.object({...project,evidence,target_snapshot:snapshot}).strict()}, args => result(codexVerifyEvidence(args.project_root,args.evidence,args.target_snapshot)));
  registerTool('xmem_context_compile',{description:'Compile a bounded context manifest. Caller bytes remain declarations. Selecting an explicit dependency enrollment additionally reads live authorized sources.',inputSchema:z.object({...project,...DEPENDENCY_SELECTION_FIELDS,request,source_bytes:z.array(z.object({source_id:nonEmpty,bytes_base64:nonEmpty}).strict())}).strict().refine(dependencySelectionPaired)}, (args,extra) => live(args,extra,options=>codexCompileContext(args.project_root,{request:args.request,source_bytes:args.source_bytes},options),'direct'));
  registerTool('xmem_context_read_manifest',{description:'Read a persisted derived context manifest.',inputSchema:z.object({...project,content_hash:nonEmpty,request:request.optional()}).strict()}, args => result(codexReadManifest(args.project_root,args.content_hash,args.request),'direct'));
  registerTool('xmem_handoff_prepare',{description:'Prepare a derived immutable handoff. It does not execute or schedule work.',inputSchema:z.object({...project,...DEPENDENCY_SELECTION_FIELDS,input:handoff}).strict().refine(dependencySelectionPaired)}, (args,extra) => live(args,extra,options=>codexPrepareHandoff(args.project_root,args.input,options)));
  registerTool('xmem_handoff_validate',{description:'Validate current handoff material without acting on it.',inputSchema:z.object({...project,...DEPENDENCY_SELECTION_FIELDS,package_id:nonEmpty}).strict().refine(dependencySelectionPaired)}, (args,extra) => live(args,extra,options=>codexValidateHandoff(args.project_root,args.package_id,options)));
  registerTool('xmem_handoff_acknowledge',{description:'Record a receiver acknowledgement after validation; this does not authorize execution.',inputSchema:z.object({...project,...DEPENDENCY_SELECTION_FIELDS,package_id:nonEmpty,acknowledgement:z.object({recipient_id:nonEmpty,action:z.enum(['ACCEPTED','REJECTED']),reason_codes:z.array(nonEmpty)}).strict()}).strict().refine(dependencySelectionPaired)}, (args,extra) => live(args,extra,options=>codexAcknowledgeHandoff(args.project_root,args.package_id,args.acknowledgement,options)));
  registerTool('xmem_handoff_recover',{description:'Revalidate a handoff for session recovery. It never resumes work.',inputSchema:z.object({...project,...DEPENDENCY_SELECTION_FIELDS,package_id:nonEmpty}).strict().refine(dependencySelectionPaired)}, (args,extra) => live(args,extra,options=>codexRecoverHandoff(args.project_root,args.package_id,options)));
  const localMemory = z.object({workspace_id:nonEmpty,task_ref:nonEmpty,task_version:nonEmpty,memory_key:nonEmpty,source_path:nonEmpty,excerpt:z.string().min(1).max(16384),kind:z.enum(['Observation','DecisionRef','ConstraintRef','FailedAttempt','RootCauseHypothesis']),roles:z.array(nonEmpty).min(1).max(8),mandatory:z.boolean(),previous_revision_id:nonEmpty.nullable()}).strict();
  const localSnapshot = z.object({workspace_id:nonEmpty,files:z.array(nonEmpty).min(1).max(32)}).strict();
  registerTool('xmem_memory_capture',{description:'WRITE: after project consent, capture a verbatim excerpt from an explicitly selected local UTF-8 source. Atomically save an observation, ASSERTED/HYPOTHESIS memory and task binding. Not execution proof or owner approval; no arbitrary paths, credentials or command execution.',inputSchema:z.object({...project,input:localMemory}).strict(),annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},args=>result(captureLocalMemory(args.project_root,args.input)));
  registerTool('xmem_snapshot_capture',{description:'WRITE: capture and store hashes of 1–32 explicit project files. Returns the retained immutable Snapshot for handoff. Always INCOMPLETE for test/execution purposes; no commands run.',inputSchema:z.object({...project,input:localSnapshot}).strict(),annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},args=>result(captureLocalSnapshot(args.project_root,args.input)));
  registerTool('xmem_context_compile_local',{description:'Read current permitted local-file sources and persist a context manifest. Requires a stored snapshot and prior memory_capture. Returns EMPTY/PARTIAL/READY diagnostics. Cannot prove execution or bypass missing mandatory context.',inputSchema:z.object({...project,...DEPENDENCY_SELECTION_FIELDS,request}).strict().refine(dependencySelectionPaired),annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},(args,extra)=>live(args,extra,options=>compileLocalContext(args.project_root,args.request,options),'direct'));
  registerTool('xmem_handoff_recover_local',{description:'Revalidate stored handoff plus LIVE local sources and the exact snapshot file list originally captured. Returns context only if valid. No task execution, writes to business code, or permission to resume; VALID is scoped material integrity only.',inputSchema:z.object({...project,...DEPENDENCY_SELECTION_FIELDS,input:z.object({package_id:nonEmpty,snapshot_files:z.array(nonEmpty).min(1).max(32)}).strict()}).strict().refine(dependencySelectionPaired),annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},(args,extra)=>live(args,extra,options=>recoverLocalHandoff(args.project_root,args.input,options),'nested'));

  const categories=z.enum(['DECISION','CONSTRAINT','REQUIREMENT_CHANGE','FAILED_APPROACH','ROOT_CAUSE_HYPOTHESIS','IMPORTANT_DISCOVERY','HANDOFF_STATE']);
  const standalonePolicy=z.object({schema_version:z.literal(1),mode:z.literal('SEMI_AUTO'),enabled:z.boolean(),workspace_id:nonEmpty,default_role:nonEmpty,allowed_roles:z.array(nonEmpty).min(1).max(8),snapshot_files:z.array(nonEmpty).min(1).max(32),payload_budget_bytes:z.number().int().min(1024).max(262144),max_depth:z.number().int().min(0).max(16),max_nodes:z.number().int().min(1).max(512),capture_categories:z.array(categories).min(1),visible_receipts:z.boolean()}).strict();
  registerTool('xmem_project_discover',{description:'From the workspace or start_path, find the initialized project. Optional strict topic performs bounded literal current-only discovery inside approved project/role/source ACL; returned references are previews, not ContextPacks or grants. Read-only closed-image mode; no implicit initialization or capture.',inputSchema:COMPANION_SCHEMAS.xmem_project_discover,annotations:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false}},args=>args.topic===undefined?result(discoverStandaloneProject(args.start_path)):topicResult(discoverStandaloneTopics(args.start_path,args.topic)));
  registerTool('xmem_standalone_configure',{description:'R3 ONE-TIME/OWNER CONTROL: create or compare-and-swap update the project-local semi-auto policy after explicit consent. Does not modify AGENTS.md, business code, PATH, hooks, or trusted evidence.',inputSchema:z.object({...project,input:z.object({consent:z.literal(true),expected_policy_hash:nonEmpty.nullable(),policy:standalonePolicy}).strict()}).strict(),annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},args=>result(configureStandalone(args.project_root,args.input)));
  registerTool('xmem_storage_location_status',{description:'R3.1.1 READ-ONLY: report the default/current XMem memory storage root, database/artifact paths, and whether the owner has explicitly confirmed a location.',inputSchema:COMPANION_SCHEMAS.xmem_storage_location_status,annotations:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false}},args=>result(codexStorageLocationStatus(args.project_root)));
  registerTool('xmem_storage_location_configure',{description:'R3.1.1 OWNER CONTROL: explicitly keep project-local .xmem storage or choose an existing empty absolute local directory. Does not migrate existing memory; location changes after persisted data require a separate migration workflow.',inputSchema:z.object({...project,input:z.object({consent:z.literal(true),expected_location_hash:nonEmpty.nullable(),mode:z.enum(['PROJECT_LOCAL','CUSTOM_LOCAL']),storage_root:nonEmpty.nullable()}).strict()}).strict(),annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},args=>result(codexConfigureStorageLocation(args.project_root,args.input)));
  registerTool('xmem_storage_status',{description:'R3.2 READ-ONLY: report logical ACTIVE/ARCHIVED/PRUNABLE retention tiers, protected provenance counts, and storage/reclaimable bytes. Retention tiers are distinct from MemoryRecord lifecycle. Does not create a database or delete data.',inputSchema:z.object(project).strict(),annotations:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false}},args=>result(codexStorageStatus(args.project_root)));
  registerTool('xmem_cleanup_preview',{description:'R3.2 READ-ONLY: build a deterministic cleanup plan for PRUNABLE material only. ACTIVE and ARCHIVED memory/evidence/audit state are never deletion candidates. No files or database rows are changed.',inputSchema:z.object(project).strict(),annotations:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false}},args=>result(codexCleanupPreview(args.project_root)));
  registerTool('xmem_cleanup_apply',{description:'R3.2 EXPLICIT DESTRUCTIVE APPLY: apply exactly a previously previewed plan hash. Deletes only PRUNABLE rebuildable old context manifests and globally unreferenced/orphan artifact material; never ACTIVE/ARCHIVED memory, evidence, handoffs, failure history, or audit records. No automatic cleanup hook.',inputSchema:z.object({...project,input:z.object({confirm:z.literal(true),plan_hash:z.string().regex(/^[a-f0-9]{64}$/)}).strict()}).strict(),annotations:{readOnlyHint:false,destructiveHint:true,idempotentHint:false,openWorldHint:false}},args=>result(codexCleanupApply(args.project_root,args.input)));
  registerTool('xmem_storage_compact',{description:'R3.2 EXPLICIT STORAGE MAINTENANCE: run SQLite WAL checkpoint/TRUNCATE + optimize after confirmation. Deletes zero logical rows; main-database VACUUM is deliberately deferred because current derived-recency semantics use SQLite row order and verifies SQLite quick_check before/after. No automatic compaction hook.',inputSchema:z.object({...project,input:z.object({confirm:z.literal(true)}).strict()}).strict(),annotations:{readOnlyHint:false,destructiveHint:true,idempotentHint:true,openWorldHint:false}},args=>result(codexStorageCompact(args.project_root,args.input)));
  registerTool('xmem_standalone_status',{description:'R3: read standalone policy/status and return the project-instruction template. Read-only. automatic_hooks=false remains explicit.',inputSchema:COMPANION_SCHEMAS.xmem_standalone_status,annotations:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false}},args=>result(standaloneStatus(args.project_root,profile)));
  registerTool('xmem_session_start',{description:'R3.1.2 SEMI-AUTO: compile/reuse freshness-checked minimal context with latency/token-estimate/dedup telemetry and revalidate continuity. PARTIAL_CONTEXT_CONTROL only; no hidden Host-token claim, background hook, or task execution.',inputSchema:COMPANION_SCHEMAS.xmem_session_start,annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},(args,extra)=>live(args,extra,options=>startStandaloneSession(args.project_root,args.input,options),'nested',true));
  registerTool('xmem_session_capture',{description:'WRITE one bounded high-value host candidate using exact predecessor CAS. Optional input.mode=topic stores a canonical bounded content/key/topic envelope. Plain inputs remain unchanged. Always non-mandatory ASSERTED/HYPOTHESIS; declared actor and receipt do not authenticate an Owner.',inputSchema:COMPANION_SCHEMAS.xmem_session_capture,annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},args=>result('mode'in args.input?captureStandaloneTopic(args.project_root,args.input):captureStandaloneMemory(args.project_root,args.input)));
  registerTool('xmem_session_read',{description:'READ-ONLY exact Core capture reconciliation, or strict input.mode=expand/view=current for one Topic reference. Topic reads recheck current/source/receipt/ACL/conflicts/negative dependencies using one closed image and deadline. Complete bodies are indivisible. Historical exact reads expose no other current revision ID. SAVED is not applicability, authenticated identity, execution proof or an R6 receipt.',inputSchema:COMPANION_SCHEMAS.xmem_session_read,annotations:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false}},args=>'mode'in args.input?topicResult(expandStandaloneTopic(args.project_root,args.input)):result(readStandaloneMemory(args.project_root,args.input)));
  const stateList=z.array(z.string().min(1).max(2048)).max(64);
  registerTool('xmem_session_checkpoint',{description:'R3.1.2 SEMI-AUTO: at a phase boundary, compile/reuse freshness-checked context in one storage operation, persist immutable handoff state, and report XMem telemetry. No trusted test evidence is fabricated.',inputSchema:COMPANION_SCHEMAS.xmem_session_checkpoint,annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},(args,extra)=>live(args,extra,options=>checkpointStandaloneSession(args.project_root,args.input,options),null,true));
  registerTool('xmem_dependency_register',{description:'Explicit ephemeral local caller enrollment of exact dependency relations. Not authenticated Owner approval and grants no source read permission. Engineering profile requires the current binding_id. Restart requires registration again.',inputSchema:COMPANION_SCHEMAS.xmem_dependency_register,annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:false,openWorldHint:false}},(args,extra)=>withPathValidationScope(()=>result(dependencies.register(args,extra))));
  registerTool('xmem_dependency_revoke',{description:'Revoke this server/transport/session enrollment token. It cannot be restored by JSON, a receipt or a handoff.',inputSchema:COMPANION_SCHEMAS.xmem_dependency_revoke,annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:false,openWorldHint:false}},(args,extra)=>result(dependencies.revoke(args,extra)));
  if(profile==='engineering')registerEngineeringMcpTools(server,dependencies);
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  // Legacy invocation remains the full interface. The ordinary-agent profile
  // is an explicit opt-in and never silently falls back to the full interface.
  const args = process.argv.slice(2);
  const profile = args.length === 0 ? 'full' : args.length === 1 && args[0] === '--companion' ? 'companion' : args.length === 1 && args[0] === '--engineering' ? 'engineering' : null;
  if (profile === null) {
    process.stderr.write('INVALID_MCP_ARGUMENTS\n');
    process.exitCode = 1;
  } else createMcpServer(profile).connect(new StdioServerTransport()).catch(() => {
    process.stderr.write('MCP_START_FAILED\n');
    process.exitCode = 1;
  });
}
