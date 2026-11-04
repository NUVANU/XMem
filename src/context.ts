import { createHash } from 'node:crypto';
import { ContractError, validateMemoryRecord, type MemoryRecord, type SourceRef } from './contracts.js';

const hash = (value: Uint8Array | string): string => createHash('sha256').update(value).digest('hex');
const canonical = (value: unknown): unknown => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value as Record<string, unknown>).sort().map(key => [key, canonical((value as Record<string, unknown>)[key])])) : value;
export const canonicalContextJson = (value: unknown): string => JSON.stringify(canonical(value));

/** Explicit task-scoped authorization and selection metadata. */
export interface ContextBinding {
  revision_id: string; project_id: string; workspace_id: string; task_ref: string; task_version: string;
  roles: string[]; allowed_source_ids: string[]; mandatory: boolean; priority: number; conflicts: string[];
}
/** The legacy fields keep direct, in-memory callers usable; storage views always carry binding. */
export interface ContextEntry { record: MemoryRecord; task_ref?: string; task_version?: string; roles?: string[]; mandatory?: boolean; priority?: number; conflicts?: string[]; binding?: ContextBinding; }
export interface ContextEdge { from: string; to: string; type?: string; }
export interface ContextView { entries: readonly ContextEntry[]; edges: readonly ContextEdge[]; snapshot_hash?: string; }
export interface ContextSourceResolver { read(source: SourceRef): Uint8Array | undefined; }
export interface ContextRequest { project_id: string; workspace_id: string; task_ref: string; task_version: string; role: string; target_snapshot_id: string; allowed_source_ids: string[]; payload_budget_bytes: number; max_depth: number; max_nodes: number; }
export type CoverageState = 'included_inline'|'available_by_reference'|'missing'|'stale'|'conflicting'|'deferred';
export interface ContextCoverage { revision_id:string; state:CoverageState; reason:string; }
export interface ContextPack { kind:'ContextPack'; compiler_version:'context-v2'; policy_version:'context-policy-v1'|'context-policy-v2'|'context-policy-v3'|'context-policy-v4'|'context-policy-v5'; budget_unit:'utf8-bytes'; request:ContextRequest; payload:string; payload_bytes:number; content_hash:string; request_hash:string; binding_hash:string; source_snapshot_hash:string; view_snapshot_hash:string; coverage:ContextCoverage[]; traversal_incomplete:boolean; revisions:string[]; }

export type AuthorityClass = 'REPO_OR_FILE'|'RUNTIME_EVIDENCE'|'USER_CONFIRMED_OR_NORMATIVE'|'XMEM_VERIFIED_STATE'|'USER_HOST_MEMORY'|'ORDINARY_XMEM_MEMORY'|'AGENT_INFERENCE';
export interface AuthorityDescriptor { authority_class:AuthorityClass; authority_score:number; }
export interface ContextResolutionSummary {
  candidate_records:number;
  selected_records:number;
  deduplicated_records:number;
  authority_suppressed_records:number;
  unresolved_conflicts:number;
  selected_authority:Record<AuthorityClass,number>;
}

function nonEmpty(value: unknown): value is string { return typeof value === 'string' && value.length > 0; }
function validList(value: unknown): value is string[] { return Array.isArray(value) && value.every(nonEmpty) && new Set(value).size === value.length; }
function validateBinding(value: ContextBinding, record: MemoryRecord): ContextBinding {
  if (!value || !nonEmpty(value.revision_id) || !nonEmpty(value.project_id) || !nonEmpty(value.workspace_id) || !nonEmpty(value.task_ref) || !nonEmpty(value.task_version) || !validList(value.roles) || !validList(value.allowed_source_ids) || typeof value.mandatory !== 'boolean' || !Number.isFinite(value.priority) || !validList(value.conflicts) || value.revision_id !== record.revision_id || value.project_id !== record.project_id) throw new ContractError('INVALID_INPUT', 'Invalid context binding');
  return { ...structuredClone(value), roles:[...value.roles].sort(), allowed_source_ids:[...value.allowed_source_ids].sort(), conflicts:[...value.conflicts].sort() };
}
function bindingFor(entry: ContextEntry, request: ContextRequest): ContextBinding {
  validateMemoryRecord(entry.record);
  if (entry.binding) return validateBinding(entry.binding, entry.record);
  if (!nonEmpty(entry.task_ref) || !nonEmpty(entry.task_version) || !validList(entry.roles) || typeof entry.mandatory !== 'boolean' || !Number.isFinite(entry.priority) || !validList(entry.conflicts)) throw new ContractError('INVALID_INPUT', 'Context entry requires explicit task metadata');
  return validateBinding({ revision_id:entry.record.revision_id, project_id:entry.record.project_id, workspace_id:request.workspace_id, task_ref:entry.task_ref, task_version:entry.task_version, roles:entry.roles, allowed_source_ids:[...request.allowed_source_ids], mandatory:entry.mandatory, priority:entry.priority!, conflicts:entry.conflicts }, entry.record);
}
function validateRequest(input: ContextRequest): ContextRequest {
  if (!input || !nonEmpty(input.project_id) || !nonEmpty(input.workspace_id) || !nonEmpty(input.task_ref) || !nonEmpty(input.task_version) || !nonEmpty(input.role) || !nonEmpty(input.target_snapshot_id) || !validList(input.allowed_source_ids) || !Number.isSafeInteger(input.payload_budget_bytes) || input.payload_budget_bytes < 0 || !Number.isSafeInteger(input.max_nodes) || input.max_nodes < 1 || !Number.isSafeInteger(input.max_depth) || input.max_depth < 0) throw new ContractError('INVALID_INPUT','Invalid context request');
  return { ...structuredClone(input), allowed_source_ids:[...input.allowed_source_ids].sort() };
}

/**
 * Conservative authority mapping for the provenance XMem can actually prove today.
 * It deliberately does not infer product truth from agent prose. File/repo material and
 * executor observations outrank host narrative; user host capture remains unverified.
 */
export function contextAuthority(record:MemoryRecord):AuthorityDescriptor {
  let base:number; let authority_class:AuthorityClass;
  if(record.source.kind==='file'){base=800;authority_class='REPO_OR_FILE';}
  else if(record.source.kind==='executor'){base=700;authority_class='RUNTIME_EVIDENCE';}
  else if(record.source.kind==='user' && record.epistemic_state==='CONFIRMED'){base=600;authority_class='USER_CONFIRMED_OR_NORMATIVE';}
  else if(record.epistemic_state==='CONFIRMED'||record.epistemic_state==='OBSERVED'){base=550;authority_class='XMEM_VERIFIED_STATE';}
  // A declared-user host capture is not authenticated owner confirmation. Normative
  // wording can raise relevance inside this class, but must not outrank verified XMem state.
  else if(record.source.kind==='user'){base=400;authority_class='USER_HOST_MEMORY';}
  else if(record.source.kind==='agent'){base=100;authority_class='AGENT_INFERENCE';}
  else {base=300;authority_class='ORDINARY_XMEM_MEMORY';}
  const epistemic=record.epistemic_state==='CONFIRMED'?30:record.epistemic_state==='OBSERVED'?20:record.epistemic_state==='HYPOTHESIS'?-20:0;
  const role=record.information_role==='NORMATIVE_REF'?10:record.information_role==='FACT'?5:0;
  return {authority_class,authority_score:base+epistemic+role};
}
// Engineering text is opaque: whitespace can change code, literals and constraints.
// Use exact JS string equality, avoiding UTF-8 replacement of lone surrogates.
function dedupKey(record:MemoryRecord):string { return record.content; }
function preference(entry:{record:MemoryRecord;binding:ContextBinding}):[number,number,number,string] {
  return [contextAuthority(entry.record).authority_score,Number(entry.binding.mandatory),entry.binding.priority,entry.record.revision_id];
}
function comparePreference(a:{record:MemoryRecord;binding:ContextBinding},b:{record:MemoryRecord;binding:ContextBinding}):number {
  const aa=preference(a),bb=preference(b); return bb[0]-aa[0] || bb[1]-aa[1] || bb[2]-aa[2] || String(aa[3]).localeCompare(String(bb[3]),'en');
}

/** Compile a fixed read view. It never mutates records or grants access from a role alone. */
export function compileContext(requestInput: ContextRequest, view: ContextView, resolver: ContextSourceResolver): ContextPack {
  const request = validateRequest(requestInput);
  const normalized = view.entries.map(entry => ({ record:structuredClone(entry.record), binding:bindingFor(entry, request) }));
  const byId = new Map<string, typeof normalized[number]>();
  for (const entry of normalized) { if (byId.has(entry.record.revision_id)) throw new ContractError('INVALID_INPUT','Duplicate context revision'); byId.set(entry.record.revision_id, entry); }
  const inTask = (entry: typeof normalized[number]) => entry.binding.project_id === request.project_id && entry.binding.workspace_id === request.workspace_id && entry.binding.task_ref === request.task_ref && entry.binding.task_version === request.task_version;
  const eligible = (entry: typeof normalized[number]) => inTask(entry) && entry.record.lifecycle === 'ACTIVE' && entry.binding.roles.includes(request.role);
  const edges = view.edges.map(edge => { if (!nonEmpty(edge.from) || !nonEmpty(edge.to)) throw new ContractError('INVALID_INPUT','Invalid context edge'); return { from:edge.from, to:edge.to, type:edge.type ?? 'REFERENCES' }; }).sort((a,b) => a.from.localeCompare(b.from,'en') || a.to.localeCompare(b.to,'en') || a.type.localeCompare(b.type,'en'));
  // Apply the existing payload preference before the traversal ceiling as well.
  // Otherwise an optional lexicographically early ID can displace a mandatory
  // root even when every mandatory root fits, or hide stronger authority.
  const roots = [...byId.values()].filter(eligible).sort((a,b) => Number(b.binding.mandatory)-Number(a.binding.mandatory)||contextAuthority(b.record).authority_score-contextAuthority(a.record).authority_score||b.binding.priority-a.binding.priority||a.record.revision_id.localeCompare(b.record.revision_id,'en'));
  const selected = new Map<string, typeof normalized[number]>(); const queue: Array<[string, number]> = roots.map(entry => [entry.record.revision_id, 0]); let traversal_incomplete = false;
  while (queue.length) {
    const [id, depth] = queue.shift()!; if (selected.has(id)) continue;
    const entry = byId.get(id); if (!entry || !eligible(entry)) continue;
    if (selected.size >= request.max_nodes) { traversal_incomplete = true; break; }
    selected.set(id, entry);
    const next = edges.filter(edge => edge.from === id).map(edge => edge.to).filter(nextId => byId.has(nextId)).sort((a,b) => a.localeCompare(b,'en'));
    if (depth >= request.max_depth) { if (next.some(nextId => !selected.has(nextId))) traversal_incomplete = true; } else for (const nextId of next) if (!selected.has(nextId)) queue.push([nextId, depth + 1]);
  }
  for (const entry of roots) if (entry.binding.mandatory && !selected.has(entry.record.revision_id)) throw new ContractError('BUDGET_UNSATISFIABLE','Mandatory entries exceed traversal budget');

  const coverage: ContextCoverage[] = [];
  for (const entry of [...byId.values()].sort((a,b) => a.record.revision_id.localeCompare(b.record.revision_id,'en'))) {
    if (!inTask(entry)) continue;
    if (entry.record.lifecycle !== 'ACTIVE') coverage.push({revision_id:entry.record.revision_id,state:'deferred',reason:'inactive'});
    else if (!entry.binding.roles.includes(request.role)) coverage.push({revision_id:entry.record.revision_id,state:'deferred',reason:'role_mismatch'});
    else if (!selected.has(entry.record.revision_id)) coverage.push({revision_id:entry.record.revision_id,state:'deferred',reason:'traversal_budget'});
  }

  // R3.1.2 authority resolution is computed over connected conflict components.
  // That prevents overlapping declarations (A conflicts B, B conflicts C) from making
  // B both a winner and loser depending on iteration order. Missing declared peers and
  // authority ties remain explicit unresolved conflicts.
  const conflictState=new Map<string,'winner'|'loser'|'unresolved'>();
  const conflictAdjacency=new Map<string,Set<string>>();
  for(const entry of selected.values()){
    if(!entry.binding.conflicts.length)continue;
    const set=conflictAdjacency.get(entry.record.revision_id)??new Set<string>(); conflictAdjacency.set(entry.record.revision_id,set);
    for(const peerId of entry.binding.conflicts){
      if(!selected.has(peerId)){conflictState.set(entry.record.revision_id,'unresolved');continue;}
      set.add(peerId); const reverse=conflictAdjacency.get(peerId)??new Set<string>(); reverse.add(entry.record.revision_id); conflictAdjacency.set(peerId,reverse);
    }
  }
  const visitedConflict=new Set<string>();
  for(const start of conflictAdjacency.keys()){
    if(visitedConflict.has(start))continue;
    const ids:string[]=[],queue=[start]; let componentMissing=false;
    while(queue.length){const id=queue.shift()!;if(visitedConflict.has(id))continue;visitedConflict.add(id);ids.push(id);if(conflictState.get(id)==='unresolved')componentMissing=true;for(const peer of conflictAdjacency.get(id)??[])if(!visitedConflict.has(peer))queue.push(peer);}
    const group=ids.map(id=>selected.get(id)!).filter(Boolean);
    const ranked=[...group].sort((a,b)=>contextAuthority(b.record).authority_score-contextAuthority(a.record).authority_score||a.record.revision_id.localeCompare(b.record.revision_id,'en'));
    const top=ranked.length?contextAuthority(ranked[0].record).authority_score:Number.NEGATIVE_INFINITY,second=ranked.length>1?contextAuthority(ranked[1].record).authority_score:Number.NEGATIVE_INFINITY;
    if(componentMissing||ranked.length<2||top===second){for(const member of group)conflictState.set(member.record.revision_id,'unresolved');}
    else {const winner=ranked[0].record.revision_id;for(const member of group)conflictState.set(member.record.revision_id,member.record.revision_id===winner?'winner':'loser');}
  }
  // Exact-content dedup runs after authority conflict suppression so a duplicate winner
  // can never point at material that was itself suppressed by a stronger conflicting fact.
  const duplicateLosers=new Map<string,string>();
  const dedupGroups=new Map<string,typeof normalized>();
  for(const entry of selected.values()){if(conflictState.get(entry.record.revision_id)==='loser')continue;const key=dedupKey(entry.record),group=dedupGroups.get(key)??[];group.push(entry);dedupGroups.set(key,group);}
  for(const group of dedupGroups.values())if(group.length>1){const ordered=[...group].sort(comparePreference),winner=ordered[0];for(const loser of ordered.slice(1))duplicateLosers.set(loser.record.revision_id,winner.record.revision_id);}

  // Deduplication substitutes content, not the obligation to include it.
  // This set is compilation-local; source authority and persisted bindings stay unchanged.
  const required = new Set([...selected.values()].filter(entry => entry.binding.mandatory).map(entry => entry.record.revision_id));
  for (const [duplicate, representative] of duplicateLosers) if (required.has(duplicate)) required.add(representative);

  const fragments: string[] = []; const included: string[] = []; const sources: Array<{revision_id:string; source:SourceRef}> = [];
  const ordered = [...selected.values()].sort((a,b) => Number(required.has(b.record.revision_id)) - Number(required.has(a.record.revision_id)) || contextAuthority(b.record).authority_score-contextAuthority(a.record).authority_score || b.binding.priority - a.binding.priority || a.record.revision_id.localeCompare(b.record.revision_id,'en'));
  for (const entry of ordered) {
    const { record, binding } = entry; let state: CoverageState = 'included_inline'; let reason = 'selected';
    const duplicateOf=duplicateLosers.get(record.revision_id), conflict=conflictState.get(record.revision_id);
    // Duplicate content cannot discharge an unresolved conflict obligation.
    if(conflict==='unresolved'){state='conflicting';reason='unresolved_conflict';}
    else if(duplicateOf){state='deferred';reason=`duplicate_context:${duplicateOf}`;}
    else if(conflict==='loser'){state='conflicting';reason='lower_authority_conflict';}
    else if (!request.allowed_source_ids.includes(record.source.source_id) || !binding.allowed_source_ids.includes(record.source.source_id)) { state='missing'; reason='outside_access_scope'; }
    else { let bytes: Uint8Array | undefined; try { bytes = resolver.read(record.source); } catch { /* covered below */ } if (!bytes) { state='missing'; reason='source_unavailable'; } else if (hash(bytes) !== record.source.content_hash) { state='stale'; reason='source_changed'; } }
    if (state !== 'included_inline') {
      if (required.has(record.revision_id) && (!duplicateOf || conflict==='unresolved')) throw new ContractError('SOURCE_MISSING',`Mandatory revision unavailable: ${state}`);
      coverage.push({revision_id:record.revision_id,state,reason}); continue;
    }
    const authority=contextAuthority(record);
    const fragment = canonicalContextJson({revision_id:record.revision_id,information_role:record.information_role,epistemic_state:record.epistemic_state,authority_class:authority.authority_class,source:record.source,content:record.content});
    const candidate = fragments.length ? `${fragments.join('\n')}\n${fragment}` : fragment;
    if (Buffer.byteLength(candidate,'utf8') > request.payload_budget_bytes) { if (required.has(record.revision_id)) throw new ContractError('BUDGET_UNSATISFIABLE','Mandatory constraints exceed payload budget'); coverage.push({revision_id:record.revision_id,state:'available_by_reference',reason:'payload_budget'}); continue; }
    fragments.push(fragment); included.push(record.revision_id); sources.push({revision_id:record.revision_id,source:record.source}); coverage.push({revision_id:record.revision_id,state,reason});
  }
  for (const {source} of sources) { let bytes: Uint8Array | undefined; try { bytes = resolver.read(source); } catch { /* source failure */ } if (!bytes || hash(bytes) !== source.content_hash) throw new ContractError('SOURCE_MISSING','Source changed during compilation'); }
  coverage.sort((a,b) => a.revision_id.localeCompare(b.revision_id,'en'));
  const payload = fragments.join('\n'); const binding_hash = hash(canonicalContextJson(normalized.map(entry => entry.binding).sort((a,b) => a.revision_id.localeCompare(b.revision_id,'en'))));
  const source_snapshot_hash = hash(canonicalContextJson(sources.map(({revision_id,source}) => ({revision_id,source_id:source.source_id,content_hash:source.content_hash})).sort((a,b) => a.revision_id.localeCompare(b.revision_id,'en'))));
  const view_snapshot_hash = view.snapshot_hash ?? hash(canonicalContextJson({bindings:normalized.map(entry => entry.binding).sort((a,b) => a.revision_id.localeCompare(b.revision_id,'en')),edges}));
  const body = { kind:'ContextPack' as const, compiler_version:'context-v2' as const, policy_version:'context-policy-v5' as const, budget_unit:'utf8-bytes' as const, request, payload, payload_bytes:Buffer.byteLength(payload,'utf8'), request_hash:hash(canonicalContextJson(request)), binding_hash, source_snapshot_hash, view_snapshot_hash, coverage, traversal_incomplete, revisions:included };
  return { ...body, content_hash:hash(canonicalContextJson(body)) };
}

export function summarizeContextResolution(view:ContextView,pack:ContextPack):ContextResolutionSummary {
  const selectedAuthority:Record<AuthorityClass,number>={REPO_OR_FILE:0,RUNTIME_EVIDENCE:0,USER_CONFIRMED_OR_NORMATIVE:0,XMEM_VERIFIED_STATE:0,USER_HOST_MEMORY:0,ORDINARY_XMEM_MEMORY:0,AGENT_INFERENCE:0};
  const byId=new Map(view.entries.map(entry=>[entry.record.revision_id,entry.record]));
  for(const id of pack.revisions){const record=byId.get(id);if(record)selectedAuthority[contextAuthority(record).authority_class]++;}
  return {
    candidate_records:view.entries.length,
    selected_records:pack.revisions.length,
    deduplicated_records:pack.coverage.filter(item=>item.reason.startsWith('duplicate_context:')).length,
    authority_suppressed_records:pack.coverage.filter(item=>item.reason==='lower_authority_conflict').length,
    unresolved_conflicts:pack.coverage.filter(item=>item.reason==='unresolved_conflict').length,
    selected_authority:selectedAuthority,
  };
}
