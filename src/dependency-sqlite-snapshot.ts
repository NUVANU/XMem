import { createHash } from 'node:crypto';
import type Database from 'better-sqlite3';
import { validateMemoryRecord } from './contracts.js';
import { evaluateDependencySnapshot } from './dependency-snapshot.js';
import type { AdmissionObservation, Budget, EdgeObservation, NodeObservation, SafeRootResult, Scope } from './dependency-snapshot.js';

export interface SqlBudget { roots: number; nodes: number; edgeRows: number; metadataBytes: number; queries: number; }
export const SQL_CAPS: Readonly<SqlBudget> = Object.freeze({ roots: 8, nodes: 32, edgeRows: 64, metadataBytes: 262144, queries: 256 });
export const EVALUATOR_CAPS: Readonly<Budget> = Object.freeze({ nodes: 32, edges: 256, depth: 16, sourceBytes: 1048576, work: 2048 });
export interface AuthorizationObservation {
  scope: Scope; revisionId: string; sourceIdentity: string; bindingHash: string;
  decision: 'ALLOWED' | 'DENIED' | 'UNKNOWN'; policyIdentity: string; observationId: string;
}
export interface SourceObservation {
  sourceIdentity: string; contentHash: string; status: 'VERIFIED' | 'UNAVAILABLE' | 'UNVERIFIABLE';
  observedBytes: number; observationId: string;
}
export interface RelationObservation {
  admission: AdmissionObservation; registeredForRevalidation: boolean;
  payloadHash: string; sourceIdentity: string; sourceContentHash: string;
  sourceStatus: SourceObservation['status']; sourceObservationId: string;
}
export interface SqliteRequest {
  scope: Scope; roots: readonly string[];
  authorization: ReadonlyMap<string, AuthorizationObservation>;
  sources: ReadonlyMap<string, SourceObservation>;
  relations: ReadonlyMap<string, RelationObservation>;
  /** Exact authorized full payloads observed before the live source reads. */
  revisionPayloadHashes:ReadonlyMap<string,string>;
  sqlBudget: SqlBudget; evaluatorBudget: Budget;
}
type Row = Record<string, unknown>;
type SourceRef = { source_id: string; kind: string; locator: string; version: string; content_hash: string };
export interface SqlFrontierNode {
  revisionId: string; bindingHash: string; revisionMetadataHash: string;
  currentRevisionId: string; lifecycleIdentity: string;
  fullRevisionHash:string|null;
  edges: { relationId: string; originalType: string; payloadHash: string; sourceIdentity: string }[];
}
export interface SqliteEvaluation {
  publicResults: readonly SafeRootResult[];
  internalSql: { classification: 'INTERNAL_DO_NOT_EXPOSE'; status: 'OBSERVED' | 'INCOMPLETE' | 'UNVERIFIED';
    consumed: { nodes: number; edgeRows: number; metadataBytes: number; queries: number }; frontier: SqlFrontierNode[] };
  internalEvaluation?: ReturnType<typeof evaluateDependencySnapshot>['internalFrontier'];
}
const text = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= 4096;
const sha = (v: string) => createHash('sha256').update(v).digest('hex');
const canonical = (v: unknown): unknown => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object'
  ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical((v as Row)[k])])) : v;
export const metadataIdentity = (v: unknown): string => sha(JSON.stringify(canonical(v)));
const exact = (v: unknown, keys: string[]): v is Row => !!v && typeof v === 'object' && !Array.isArray(v)
  && Object.keys(v).sort().join(',') === [...keys].sort().join(',');
const scopeKeys = ['projectRoot', 'projectId', 'workspaceId', 'taskId', 'taskVersion', 'role'] as const;
const scopeMatches = (a: Scope, b: Scope) => !!a && scopeKeys.every(k => a[k] === b[k]);
const validHash = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const validSource = (v: unknown): v is SourceRef => exact(v, ['source_id', 'kind', 'locator', 'version', 'content_hash'])
  && ['source_id', 'locator', 'version'].every(k => text(v[k])) && validHash(v.content_hash)
  && ['executor', 'file', 'user', 'agent', 'derived'].includes(String(v.kind));
const validList = (v: unknown): v is string[] => Array.isArray(v) && v.every(text) && new Set(v).size === v.length;
class Incomplete extends Error {}

/** Internal adapter only. Caller owns connection safety, request authority and all
 * external observations. This reads DB metadata in one deferred transaction; it
 * never opens/closes the connection, reads source bytes, issues write SQL or grants
 * permission. projectRoot is matched to caller observations, not attested by DB.
 * Input must be immutable plain data. Never publish internalSql/internalEvaluation.
 */
export function evaluateSqliteDependencySnapshot(db: Database.Database, req: SqliteRequest): SqliteEvaluation {
  if (!req || !req.scope || !scopeKeys.every(k => text(req.scope[k])) || !Array.isArray(req.roots)
    || req.roots.length > 8 || !req.roots.every(text) || !(req.authorization instanceof Map)
    || !(req.sources instanceof Map) || !(req.relations instanceof Map)
    || !(req.revisionPayloadHashes instanceof Map) || req.revisionPayloadHashes.size>32
    || [...req.revisionPayloadHashes].some(([id,digest])=>!text(id)||!validHash(digest))
    || req.authorization.size > 32 || req.sources.size > 32 || req.relations.size > 64
    || !req.sqlBudget || !req.evaluatorBudget
    || Object.entries(SQL_CAPS).some(([k, cap]) => !Number.isSafeInteger(req.sqlBudget[k as keyof SqlBudget]) || req.sqlBudget[k as keyof SqlBudget] < 0 || req.sqlBudget[k as keyof SqlBudget] > cap)
    || Object.entries(EVALUATOR_CAPS).some(([k, cap]) => !Number.isSafeInteger(req.evaluatorBudget[k as keyof Budget]) || req.evaluatorBudget[k as keyof Budget] < 0 || req.evaluatorBudget[k as keyof Budget] > cap)) {
    throw new TypeError('Invalid bounded SQLite request');
  }
  if (db.inTransaction) throw new Error('Existing transaction is unsupported');
  const consumed = { nodes: 0, edgeRows: 0, metadataBytes: 0, queries: 0 };
  const frontier: SqlFrontierNode[] = [];
  const fail = (status: 'INCOMPLETE' | 'UNVERIFIED'): SqliteEvaluation => ({
    publicResults: req.roots.map(() => ({ visibility: 'WITHHELD', dependencyStatus: status })),
    internalSql: { classification: 'INTERNAL_DO_NOT_EXPOSE', status, consumed, frontier },
  });
  const charge = (key: keyof typeof consumed, amount: number) => {
    if (!Number.isSafeInteger(amount) || amount < 0) throw new Error('Invalid metadata');
    if (amount > req.sqlBudget[key] - consumed[key]) throw new Incomplete();
    consumed[key] += amount;
  };
  const get = (sql: string, ...args: (string | number)[]) => {
    charge('queries', 1); return db.prepare(sql).get(...args) as Row | undefined;
  };
  const all = (sql: string, ...args: (string | number)[]) => {
    charge('queries', 1); return db.prepare(sql).all(...args) as Row[];
  };
  const ensure = (condition: unknown) => { if (!condition) throw new Error('Unverifiable metadata'); };
  try {
    if (req.roots.length > req.sqlBudget.roots) throw new Incomplete();
    return db.transaction((): SqliteEvaluation => {
      ensure(get("SELECT CASE WHEN length(CAST(value AS BLOB))=1 THEN value ELSE NULL END AS value FROM xmem_metadata WHERE key='schema_version'")?.value === '9');
      const nodes = new Map<string, NodeObservation>();
      const load = (id: string): void => {
        if (nodes.has(id)) return;
        charge('nodes', 1);
        // Length-only header before any potentially large column or JSON allocation.
        const lengths = get(`SELECT length(CAST(v.payload_json AS BLOB)) AS vb,length(CAST(b.payload_json AS BLOB)) AS bb,
          coalesce(length(CAST(v.record_id AS BLOB)),0)+coalesce(length(CAST(v.project_id AS BLOB)),0)+coalesce(length(CAST(v.previous_revision_id AS BLOB)),0)
          +coalesce(length(CAST(r.project_id AS BLOB)),0)+coalesce(length(CAST(r.current_revision_id AS BLOB)),0)
          +coalesce(length(CAST(c.revision_id AS BLOB)),0)+coalesce(length(CAST(c.record_id AS BLOB)),0)+coalesce(length(CAST(c.project_id AS BLOB)),0)
          +coalesce(length(CAST(b.project_id AS BLOB)),0)+coalesce(length(CAST(b.workspace_id AS BLOB)),0)+coalesce(length(CAST(b.task_ref AS BLOB)),0)
          +coalesce(length(CAST(b.task_version AS BLOB)),0)+coalesce(length(CAST(b.payload_hash AS BLOB)),0) AS hb
          FROM revisions v LEFT JOIN records r ON r.record_id=v.record_id LEFT JOIN revisions c ON c.revision_id=r.current_revision_id LEFT JOIN context_bindings b ON b.revision_id=v.revision_id WHERE v.revision_id=?`, id);
        ensure(lengths && typeof lengths.vb === 'number' && typeof lengths.bb === 'number');
        charge('metadataBytes', Number(lengths!.vb) + Number(lengths!.bb) + Number(lengths!.hb));
        const row = get(`SELECT v.revision_id,v.record_id,v.project_id,v.previous_revision_id,r.project_id AS record_project,r.current_revision_id,
          c.revision_id AS current_target_revision_id,c.record_id AS current_target_record_id,c.project_id AS current_target_project_id,
          b.project_id AS binding_project,b.workspace_id,b.task_ref,b.task_version,b.payload_hash,
          b.payload_json AS binding_json,json_remove(v.payload_json,'$.content') AS revision_json,json_type(v.payload_json,'$.content') AS content_type
          FROM revisions v LEFT JOIN records r ON r.record_id=v.record_id LEFT JOIN revisions c ON c.revision_id=r.current_revision_id LEFT JOIN context_bindings b ON b.revision_id=v.revision_id WHERE v.revision_id=?`, id)!;
        const binding = JSON.parse(String(row.binding_json)) as Row;
        const revision = JSON.parse(String(row.revision_json)) as Row;
        ensure(exact(binding, ['revision_id','project_id','workspace_id','task_ref','task_version','roles','allowed_source_ids','mandatory','priority','conflicts'])
          && JSON.stringify(canonical(binding)) === row.binding_json && metadataIdentity(binding) === row.payload_hash && binding.revision_id === id && binding.project_id === row.binding_project
          && binding.workspace_id === row.workspace_id && binding.task_ref === row.task_ref && binding.task_version === row.task_version
          && validList(binding.roles) && validList(binding.allowed_source_ids) && validList(binding.conflicts)
          && typeof binding.mandatory === 'boolean' && Number.isFinite(binding.priority)
          && ['project_id','workspace_id','task_ref','task_version'].every(k => text(binding[k])));
        ensure(exact(revision, ['schema_version','record_id','revision_id','project_id','kind','source','epistemic_state','lifecycle','information_role','previous_revision_id'])
          && JSON.stringify(canonical(revision)) === row.revision_json && revision.schema_version === '1' && row.content_type === 'text' && revision.revision_id === id && revision.record_id === row.record_id
          && revision.project_id === row.project_id && revision.previous_revision_id === row.previous_revision_id
          && row.record_project === row.project_id && row.binding_project === row.project_id && text(row.current_revision_id)
          && row.current_target_revision_id === row.current_revision_id && row.current_target_record_id === row.record_id && row.current_target_project_id === row.project_id
          && text(row.record_id) && validSource(revision.source)
          && ['Observation','DecisionRef','ConstraintRef','FailedAttempt','RootCauseHypothesis'].includes(String(revision.kind))
          && ['OBSERVED','ASSERTED','HYPOTHESIS','CONFIRMED'].includes(String(revision.epistemic_state))
          && ['ACTIVE','SUPERSEDED','RETRACTED'].includes(String(revision.lifecycle))
          && ['FACT','NORMATIVE_REF','EXPERIENCE','SUGGESTION'].includes(String(revision.information_role)));
        const source = revision.source as SourceRef;
        const sourceIdentity = metadataIdentity(source);
        const actualScope: Scope = { projectRoot: req.scope.projectRoot, projectId: String(row.project_id), workspaceId: String(row.workspace_id), taskId: String(row.task_ref), taskVersion: String(row.task_version), role: req.scope.role };
        const auth = req.authorization.get(id), observedSource = req.sources.get(id);
        const authorized = !!auth && scopeMatches(actualScope, req.scope) && scopeMatches(auth.scope, req.scope)
          && auth.revisionId === id && auth.sourceIdentity === sourceIdentity && auth.bindingHash === row.payload_hash
          && auth.decision === 'ALLOWED' && text(auth.policyIdentity) && text(auth.observationId)
          && (binding.roles as string[]).includes(req.scope.role) && (binding.allowed_source_ids as string[]).includes(source.source_id);
        const sourceMatches = !!observedSource && observedSource.sourceIdentity === sourceIdentity && observedSource.contentHash === source.content_hash
          && text(observedSource.observationId) && Number.isSafeInteger(observedSource.observedBytes) && observedSource.observedBytes >= 0;
        const lifeLength = get(`SELECT length(CAST(event_id AS BLOB))+length(CAST(record_id AS BLOB))+length(CAST(revision_id AS BLOB))
          +length(CAST(lifecycle AS BLOB))+length(CAST(actor AS BLOB))+length(CAST(source AS BLOB))+length(CAST(reason AS BLOB))+length(CAST(occurred_at AS BLOB)) AS bytes
          FROM lifecycle_events WHERE record_id=? ORDER BY rowid DESC LIMIT 1`, String(row.record_id));
        ensure(lifeLength); charge('metadataBytes', Number(lifeLength!.bytes));
        const life = get('SELECT event_id,record_id,revision_id,lifecycle,actor,source,reason,occurred_at FROM lifecycle_events WHERE record_id=? ORDER BY rowid DESC LIMIT 1', String(row.record_id))!;
        ensure(life && life.record_id === row.record_id && life.revision_id === row.current_revision_id && Object.values(life).every(text)
          && ['ACTIVE','SUPERSEDED','RETRACTED'].includes(String(life.lifecycle)));
        const sqlNode: SqlFrontierNode = { revisionId: id, bindingHash: String(row.payload_hash), revisionMetadataHash: metadataIdentity(revision), currentRevisionId: String(row.current_revision_id), lifecycleIdentity: metadataIdentity(life), fullRevisionHash:null, edges: [] };
        frontier.push(sqlNode);
        const mapped: NodeObservation = {
          revisionId: id, scope: actualScope, currentRevisionId: String(row.current_revision_id),
          visibility: { decision: authorized ? 'ALLOWED' : auth?.decision === 'DENIED' ? 'DENIED' : 'UNKNOWN', policyIdentity: text(auth?.policyIdentity) ? auth.policyIdentity : 'UNVERIFIED', observationId: text(auth?.observationId) ? auth.observationId : 'UNVERIFIED' },
          lifecycle: { status: life.lifecycle === 'ACTIVE' ? 'ACTIVE' : 'WITHDRAWN', eventId: String(life.event_id) },
          source: { status: sourceMatches && observedSource!.status === 'VERIFIED' ? 'VERIFIED' : sourceMatches && observedSource!.status === 'UNAVAILABLE' ? 'UNAVAILABLE' : 'UNVERIFIABLE', observationId: sourceMatches ? observedSource!.observationId : 'UNVERIFIED', contentIdentity: sourceIdentity, observedBytes: sourceMatches ? observedSource!.observedBytes : 0 },
          outgoingComplete: false, outgoingObservationId: 'NOT_ENUMERATED', outgoing: [],
        };
        nodes.set(id, mapped);
        if (!authorized) return; // No outgoing/ancestor query beyond this access barrier.
        // Sources have already been physically obtained by the trusted adapter.
        // Recheck the exact authorized body in this later DB snapshot as well;
        // metadata/source hashes alone do not cover a stored file excerpt.
        charge('metadataBytes',Number(lengths!.vb));
        const fullRow=get('SELECT payload_json FROM revisions WHERE revision_id=?',id);
        ensure(fullRow&&typeof fullRow.payload_json==='string'&&Buffer.byteLength(fullRow.payload_json,'utf8')===Number(lengths!.vb));
        const full=validateMemoryRecord(JSON.parse(String(fullRow!.payload_json))),{content:body,...fullMetadata}=full;
        ensure(typeof body==='string'&&JSON.stringify(canonical(full))===fullRow!.payload_json
          &&metadataIdentity(fullMetadata)===metadataIdentity(revision));
        sqlNode.fullRevisionHash=metadataIdentity(full);
        ensure(req.revisionPayloadHashes.get(id)===sqlNode.fullRevisionHash);
        // Each edge costs a length-header row and a payload row; both are counted.
        const remaining = Math.floor((req.sqlBudget.edgeRows - consumed.edgeRows) / 2);
        const edgeLengths = all(`SELECT rowid,length(CAST(payload_json AS BLOB))+length(CAST(relation_id AS BLOB))+length(CAST(project_id AS BLOB))
          +length(CAST(from_revision_id AS BLOB))+length(CAST(to_revision_id AS BLOB)) AS bytes FROM relations WHERE from_revision_id=? ORDER BY relation_id LIMIT ?`, id, remaining + 1);
        if (edgeLengths.length > remaining) throw new Incomplete();
        charge('edgeRows', edgeLengths.length);
        charge('metadataBytes', edgeLengths.reduce((sum, e) => sum + Number(e.bytes), 0));
        const edges = edgeLengths.length ? all('SELECT relation_id,project_id,from_revision_id,to_revision_id,payload_json FROM relations WHERE from_revision_id=? ORDER BY relation_id LIMIT ?', id, remaining + 1) : [];
        charge('edgeRows', edges.length);
        ensure(edges.length === edgeLengths.length);
        const projected: EdgeObservation[] = [];
        for (const stored of edges) {
          const relation = JSON.parse(String(stored.payload_json)) as Row;
          ensure(exact(relation, ['schema_version','relation_id','project_id','from_revision_id','to_revision_id','type','source','epistemic_state'])
            && JSON.stringify(canonical(relation)) === stored.payload_json && relation.schema_version === '1' && relation.relation_id === stored.relation_id && relation.project_id === row.project_id
            && relation.project_id === stored.project_id && relation.from_revision_id === id && relation.from_revision_id === stored.from_revision_id
            && relation.to_revision_id === stored.to_revision_id && text(relation.to_revision_id) && text(relation.relation_id) && validSource(relation.source)
            && ['DERIVED_FROM','SUPPORTED_BY','APPLIES_UNDER','SUPERSEDES','CONFLICTS_WITH','REFERENCES'].includes(String(relation.type))
            && ['OBSERVED','ASSERTED','HYPOTHESIS','CONFIRMED'].includes(String(relation.epistemic_state)));
          const relationSource = relation.source as SourceRef, payloadHash = metadataIdentity(relation), relationSourceIdentity = metadataIdentity(relationSource);
          sqlNode.edges.push({ relationId: String(relation.relation_id), originalType: String(relation.type), payloadHash, sourceIdentity: relationSourceIdentity });
          const supplied = req.relations.get(String(relation.relation_id));
          const match = !!supplied && typeof supplied.registeredForRevalidation === 'boolean' && supplied.payloadHash === payloadHash && supplied.sourceIdentity === relationSourceIdentity
            && supplied.sourceContentHash === relationSource.content_hash && supplied.sourceStatus === 'VERIFIED' && text(supplied.sourceObservationId)
            && !!supplied.admission && scopeMatches(supplied.admission.scope, req.scope) && supplied.admission.fromRevisionId === id
            && supplied.admission.toRevisionId === relation.to_revision_id && supplied.admission.provenanceIdentity === payloadHash
            && ['OBSERVED_ACCEPTED','UNVERIFIED','INVALIDATED'].includes(supplied.admission.status)
            && text(supplied.admission.observationId) && (supplied.admission.receiptId === null || text(supplied.admission.receiptId));
          const admission: AdmissionObservation = match ? supplied!.admission : { status: 'UNVERIFIED', scope: req.scope, fromRevisionId: id, toRevisionId: String(relation.to_revision_id), receiptId: null, provenanceIdentity: payloadHash, observationId: 'UNVERIFIED' };
          const kind = relation.type === 'DERIVED_FROM' || relation.type === 'SUPPORTED_BY' ? relation.type : 'REFERENCES';
          projected.push({ relationId: String(relation.relation_id), kind, toRevisionId: String(relation.to_revision_id), registeredForRevalidation: match && supplied!.registeredForRevalidation === true, admission });
        }
        nodes.set(id, { ...mapped, outgoingComplete: true, outgoingObservationId: metadataIdentity(sqlNode.edges), outgoing: projected });
        for (const edge of projected) if (edge.kind !== 'REFERENCES' && (edge.kind !== 'SUPPORTED_BY' || edge.registeredForRevalidation)
          && edge.admission.status === 'OBSERVED_ACCEPTED' && text(edge.admission.receiptId)) load(edge.toRevisionId);
      };
      for (const root of req.roots) load(root);
      const evaluation = evaluateDependencySnapshot({ snapshotId: metadataIdentity(frontier), scope: req.scope, roots: req.roots, nodes }, req.evaluatorBudget);
      return { publicResults: evaluation.publicResults, internalSql: { classification: 'INTERNAL_DO_NOT_EXPOSE', status: 'OBSERVED', consumed, frontier }, internalEvaluation: evaluation.internalFrontier };
    }).deferred();
  } catch (error) {
    return fail(error instanceof Incomplete ? 'INCOMPLETE' : 'UNVERIFIED');
  }
}
