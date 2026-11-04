import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { assertLocalDrive, PathsError } from './paths.js';
import Database from 'better-sqlite3';
import { type PhysicalReadSession, PhysicalReadError } from './physical-readonly.js';
import { inspectOpenDatabase } from './diagnostics.js';
import { DATABASE_SCHEMA_VERSION } from './storage-version.js';
import { type ErrorCode, type Evidence, type Event, type Lifecycle, type MemoryRecord, type Relation, type Snapshot, type SourceRef, validateEvidence, validateEvent, validateMemoryRecord, validateRelation, validateSnapshot } from './contracts.js';
import { matchFailedAttempt, validateFailedAttempt, validateFailureCheckRequest, type FailedAttempt, type FailureCheckRequest, type FailureMatchDecision } from './failures.js';
import { canonicalContextJson, type ContextBinding, type ContextCoverage, type ContextPack, type ContextRequest, type ContextView } from './context.js';
import { type ExtractionAttempt, type ExtractionCandidate, validateExtractionAttempt, validateExtractionCandidate } from './extraction.js';
import { validateHostCandidateSourceRef } from './host-source.js';
import { engineeringSelectorPredicate, type EngineeringSelectorPlan } from './local-retrieval-path-cache.js';
import { readEnrollmentRelations, observeEngineeringDependencies, assertEngineeringSourceAllowed } from './dependency-runtime.js';
import type { EnrollmentContext, EnrollmentState, EngineeringDependencyLedger } from './engineering-dependencies.js';
import { RETENTION_POLICY_VERSION, createCleanupPlan, type CleanupApplyResult, type CleanupCandidate, type CleanupPlan, type RetentionTierCounts, type StorageCompactResult, type StorageLifecycleStatus } from './lifecycle.js';
import { parseRetractionIntent, retractionEventId, retractionRecordId, captureReceiptCommitment, retractionInformationType, type EngineeringRetractionIntent, type HostCapture } from './engineering-retraction.js';

export const STORAGE_FORMAT_VERSION = '1' as const;
const M2_DATABASE_SCHEMA_VERSION = '2'; const M3_DATABASE_SCHEMA_VERSION = '3'; const M4_DATABASE_SCHEMA_VERSION = '4'; const M5_DATABASE_SCHEMA_VERSION = '5'; const M6_DATABASE_SCHEMA_VERSION = '6'; const M7_DATABASE_SCHEMA_VERSION = '7'; const M8_DATABASE_SCHEMA_VERSION = '8'; const ARTIFACT_DIRECTORY = 'artifacts'; const DATABASE_FILE = 'xmem.sqlite';
const LIFECYCLES: readonly Lifecycle[] = ['ACTIVE', 'SUPERSEDED', 'RETRACTED'];
export type FailureStage = 'artifact_temp_written' | 'artifact_published' | 'transaction_started' | 'event_inserted' | 'receipt_inserted';
export class StorageError extends Error { constructor(public readonly code: ErrorCode, message: string) { super(message); this.name = 'StorageError'; } }
/** Narrow host capability failures do not widen the general lifecycle contract. */
class HostRetractionError extends Error { constructor(public readonly code:string) {super('Host rule retraction guard failed');} }
export interface StorageOptions { root: string; failureStage?: FailureStage; readOnly?: boolean; physicalRead?:PhysicalReadSession; }
export interface IngestRequest { event: Event; evidence?: Evidence; artifact?: Uint8Array; idempotencyKey?: string; }
export interface IngestReceipt { project_id: string; source_id: string; event_id: string; idempotency_key: string; replayed: boolean; sequence_gap: boolean; expected_sequence: number; }
export interface ArtifactRead { hash: string; bytes: Uint8Array; }
/** A local configuration record. Public imports never populate this authority. */
export interface CollectorRegistration { project_id: string; source_id: string; locator: string; version: string; }
export interface TrustedExecutionRequest { event: Event; evidence: Evidence; snapshot: Snapshot; report: Uint8Array; idempotencyKey?: string; }
export interface StoredTrustedExecution { evidence: Evidence; snapshot: Snapshot; artifact: Uint8Array; }
export interface LifecycleEvent { event_id: string; record_id: string; revision_id: string; lifecycle: Lifecycle; actor: string; source: string; reason: string; occurred_at: string; }
/** A storage-backed failure lookup; a non-exact outcome never authorizes a block. */
export interface FailureRegistryDecision { outcome: import('./failures.js').FailureMatchOutcome; decisions: FailureMatchDecision[]; }
export interface ContextManifest extends ContextPack { manifest_hash: string; }
export interface HandoffRevisionRef { record_id:string; revision_id:string; payload_hash:string; source:SourceRef; }
export interface HandoffEvidenceRef { evidence_id:string; payload_hash:string; source:SourceRef; artifact_hash:string|null; snapshot_id:string; }
export interface HandoffFailedAttemptRef { failed_attempt_id:string; payload_hash:string; }
export interface HandoffPackage { kind:'HandoffPackage'; protocol_version:'handoff-v1'; package_id:string; content_hash:string; project_id:string; workspace_id:string; task_ref:string; task_version:string; target_snapshot_id:string; target_snapshot_hash:string; source_refs:SourceRef[]; revision_refs:HandoffRevisionRef[]; evidence_refs:HandoffEvidenceRef[]; failed_attempt_refs:HandoffFailedAttemptRef[]; context_manifest_hash:string; context_coverage:ContextCoverage[]; completed:string[]; pending:string[]; blocked:string[]; next_steps:string[]; }
export type HandoffValidationStatus = 'VALID'|'STALE'|'INCOMPLETE'|'UNKNOWN';
export interface HandoffValidation { package_id:string; content_hash:string; status:HandoffValidationStatus; reason_codes:string[]; }
export interface HandoffReceipt { recipient_id:string; package_id:string; content_hash:string; validation_status:HandoffValidationStatus; action:'ACCEPTED'|'REJECTED'; reason_codes:string[]; receipt_hash:string; replayed:boolean; }
export interface HandoffMaterialRequest { project_id:string; workspace_id:string; task_ref:string; task_version:string; target_snapshot:Snapshot; revision_ids:string[]; evidence_ids:string[]; failed_attempt_ids:string[]; context_manifest_hash:string; completed:string[]; pending:string[]; blocked:string[]; next_steps:string[]; }
export interface ExtractionPromotionRequest { candidate_id: string; record: MemoryRecord; actor: string; reason: string; }
export type GuardAuditKind = 'run_manifest' | 'decision' | 'permit' | 'reservation' | 'checkpoint' | 'execution' | 'receipt' | 'deviation';
export interface GuardAuditRecord { record_id:string; run_id:string; project_id:string; workspace_id:string; occurred_at:string; kind:GuardAuditKind; decision_id:string|null; permit_id:string|null; action_fingerprint:string|null; previous_hash:string|null; payload_hash:string; chain_hash:string; payload:Record<string,unknown>; }
export interface StorageExport { format_version: typeof STORAGE_FORMAT_VERSION; kind: 'xmem-storage-export'; artifacts: Array<{ hash: string; bytes_base64: string }>; events: Event[]; evidences: Evidence[]; snapshots?: Snapshot[]; revisions: MemoryRecord[]; lifecycle_events: LifecycleEvent[]; relations: Relation[]; failed_attempts: FailedAttempt[]; context_bindings?: ContextBinding[]; context_manifests?: ContextManifest[]; handoff_packages?: HandoffPackage[]; handoff_receipts?: Omit<HandoffReceipt,'replayed'>[]; extraction_candidates?: ExtractionCandidate[]; extraction_attempts?: ExtractionAttempt[]; guard_records?: GuardAuditRecord[]; guard_records_hash?: string; receipts: Array<{ project_id: string; source_id: string; idempotency_key: string; event_id: string; payload_hash: string; sequence_gap: boolean; expected_sequence: number }>; }
type ArtifactPublication = { files: Array<{ path:string; hash:string; dev:number; ino:number }>; directories:string[] };
type JsonRow = { payload_json: string }; type ArtifactRow = { hash: string; byte_length: number; relative_path: string }; type ReceiptRow = Omit<StorageExport['receipts'][number], 'sequence_gap'> & { sequence_gap: number };
type FailedAttemptRow = { failed_attempt_id:string; project_id:string; workspace_id:string; action_id:string; observable_args_hash:string; observable_args_json:string; condition_fingerprints_hash:string; condition_fingerprints_json:string; failure_evidence_id:string; payload_hash:string; payload_json:string };
type ExtractionCandidateRow = { candidate_id:string; request_id:string; project_id:string; workspace_id:string; event_id:string; evidence_id:string|null; source_slice_hash:string; payload_hash:string; payload_json:string };
type ExtractionAttemptRow = { attempt_id:string; request_id:string; candidate_id:string|null; project_id:string; workspace_id:string; event_id:string; evidence_id:string|null; source_id:string; source_slice_hash:string; extractor_version:string; extractor_config_hash:string; provider_id:string|null; request_commitment_hash:string; outcome:string; payload_hash:string; payload_json:string };
type StoredCollectorRegistration = CollectorRegistration & { active: boolean };
type StoredSnapshot = { snapshot: Snapshot; payload_hash: string };
type TrustedBackupRows = { collectors: StoredCollectorRegistration[]; snapshots: StoredSnapshot[]; sources: Array<Record<string,string>>; receipts: Array<{receipt_hash:string}&Record<string,string>> };
const sha256 = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');
const FAILED_ATTEMPT_COLUMNS = 'failed_attempt_id,project_id,workspace_id,action_id,observable_args_hash,observable_args_json,condition_fingerprints_hash,condition_fingerprints_json,failure_evidence_id,payload_hash,payload_json';
function canonicalize(value: unknown): unknown { if (Array.isArray(value)) return value.map(canonicalize); if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize((value as Record<string, unknown>)[key])])); return value; }
const canonicalJson = (value: unknown) => JSON.stringify(canonicalize(value));
function requirePlainObject(value: unknown, label: string): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new StorageError('INVALID_INPUT', `${label} must be an object`); return value as Record<string, unknown>; }
function requireExactKeys(value: unknown, keys: readonly string[], label: string): Record<string, unknown> { const object = requirePlainObject(value, label); const actual = Object.keys(object).sort(), expected = [...keys].sort(); const optionalExport=['snapshots','context_bindings','context_manifests','handoff_packages','handoff_receipts','extraction_candidates','extraction_attempts','guard_records','guard_records_hash']; const exportDerived=label==='Export'&&expected.every(key=>actual.includes(key))&&actual.every(key=>expected.includes(key)||optionalExport.includes(key)); if ((!exportDerived && actual.length !== expected.length) || expected.some(key => !actual.includes(key)) || (!exportDerived && actual.some((key, i) => key !== expected[i]))) throw new StorageError('INVALID_INPUT', `${label} has unknown or missing fields`); return object; }
function isInside(root: string, candidate: string): boolean { const relative = path.relative(root, candidate); return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative); }
const nonEmpty = (value: unknown): value is string => typeof value === 'string' && value.trim().length > 0;
const isoTimestamp = (value: unknown): value is string => {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return false;
  const parsed = new Date(value); return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
};

/** Local SQLite authority. Event identity is (project_id, source_id, event_id). */
export class SqliteMemoryStorage {
  readonly root: string; readonly databasePath: string; readonly artifactRoot: string;
  private readonly db: Database.Database; private readonly failureStage?: FailureStage;
  private readonly physicalRead?:PhysicalReadSession;
  constructor(options: StorageOptions) {
    if (!options || !path.isAbsolute(options.root)) throw new StorageError('PATH_OUTSIDE_PROJECT', 'Storage root must be an explicit absolute directory');
    this.physicalRead=options.physicalRead;
    if(options.physicalRead&&!options.readOnly)throw new PhysicalReadError('DENIED','IMAGE_REQUIRES_READ_ONLY');
    options.physicalRead?.check();
    const requested = path.resolve(options.root); this.assertLocalStorageDrive(requested,options.physicalRead); this.assertExistingSafeDirectory(requested, 'Storage root');
    this.root = fs.realpathSync.native(requested); this.databasePath = path.join(this.root, DATABASE_FILE); this.artifactRoot = path.join(this.root, ARTIFACT_DIRECTORY);
    // This lstat preflight happens before SQLite can touch a database sidecar.
    this.assertSafeDatabaseFiles(); if (!options.readOnly && !this.pathExists(this.artifactRoot)) fs.mkdirSync(this.artifactRoot, { mode: 0o700 }); this.assertExistingSafeDirectory(this.artifactRoot, 'Artifact directory'); this.failureStage = options.failureStage;
    if(options.physicalRead)this.db=options.physicalRead.openDatabase(this.root);
    else try { this.db = new Database(this.databasePath, options.readOnly ? {readonly:true,fileMustExist:true} : {}); } catch { throw new StorageError('STORAGE_ERROR', 'Could not open the storage database'); }
    try {
      if (options.readOnly) {
        if(options.physicalRead){const health=inspectOpenDatabase(this.db,options.physicalRead.options.expected.project_id);if(health.status!=='OK')throw new PhysicalReadError(health.status==='UNAVAILABLE'?'UNKNOWN':health.status==='NOT_CREATED'?'DENIED':health.status,health.reason_codes[0]);options.physicalRead.check();}
        const version=this.db.prepare('SELECT value FROM xmem_metadata WHERE key=?').get('schema_version') as {value:string}|undefined;
        if(version?.value!==DATABASE_SCHEMA_VERSION)throw new StorageError('UNSUPPORTED_VERSION','Readback requires the current storage schema; no migration was performed');
        this.db.pragma('query_only = ON');
      } else { this.db.pragma('journal_mode = WAL'); this.db.pragma('foreign_keys = ON'); this.db.pragma('synchronous = FULL'); this.initializeSchema(); }
      this.assertSafeDatabaseFiles();
    } catch (error) { this.close(); throw error; }
  }
  close(): void { if(!this.physicalRead){this.db.close();return;}try{this.db.close();}catch{throw new PhysicalReadError('UNKNOWN','IMAGE_CLOSE_FAILED');} }
  private pathExists(target: string): boolean { try { return fs.lstatSync(target,{throwIfNoEntry:false})!==undefined; } catch (error: unknown) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; } }
  private assertExistingSafeDirectory(target: string, label: string): void { try { const stat = fs.lstatSync(target); if (stat.isSymbolicLink() || !stat.isDirectory()) throw new StorageError('PATH_OUTSIDE_PROJECT', `${label} must be a non-linked directory`); const real = fs.realpathSync.native(target); if (path.resolve(real).toLowerCase() !== path.resolve(target).toLowerCase()) throw new StorageError('PATH_OUTSIDE_PROJECT', `${label} redirects from its configured path`); } catch (error) { if (error instanceof StorageError) throw error; throw new StorageError('PATH_OUTSIDE_PROJECT', `${label} must already exist`); } }
  private assertLocalStorageDrive(target:string,physicalRead?:PhysicalReadSession):void {
    physicalRead?.check();
    if(process.platform!=='win32')return;
    try{assertLocalDrive(target);physicalRead?.check();}
    catch(error){
      if(physicalRead){if(error instanceof PhysicalReadError)throw error;throw new PhysicalReadError(error instanceof PathsError&&['NETWORK_PATH','LINK_PATH'].includes(error.code)?'DENIED':'UNKNOWN','STORAGE_DRIVE_CHECK_UNKNOWN');}
      if(error instanceof PathsError&&error.code==='NETWORK_PATH')throw new StorageError('PATH_OUTSIDE_PROJECT','Storage root must be on a local drive');
      throw new StorageError('PATH_OUTSIDE_PROJECT','Could not verify a local storage drive');
    }
  }
  private assertSafeFileLeaf(target: string, label: string): void { if (!isInside(this.root, target)) throw new StorageError('PATH_OUTSIDE_PROJECT', `${label} is outside the storage root`); try { const stat = fs.lstatSync(target,{throwIfNoEntry:false});if(stat===undefined)return;if (stat.isSymbolicLink() || !stat.isFile()) throw new StorageError('PATH_OUTSIDE_PROJECT', `${label} must be a regular non-linked file`); const real = fs.realpathSync.native(target); if (!isInside(this.root, real)) throw new StorageError('PATH_OUTSIDE_PROJECT', `${label} redirects outside the storage root`); } catch (error: unknown) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; throw error; } }
  private assertSafeDatabaseFiles(): void { for (const suffix of ['', '-wal', '-shm', '-journal']) this.assertSafeFileLeaf(`${this.databasePath}${suffix}`, `Database${suffix}`); }
  private initializeSchema(): void {
    const metadata = this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='xmem_metadata'").get();
    if (!metadata) { const old = this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('events','records','ingestion_receipts') LIMIT 1").get(); if (old) throw new StorageError('UNSUPPORTED_VERSION', 'Storage database has no supported schema version'); this.db.exec('CREATE TABLE xmem_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)'); this.db.prepare('INSERT INTO xmem_metadata(key,value) VALUES(?,?)').run('schema_version', DATABASE_SCHEMA_VERSION); }
    const version = this.db.prepare("SELECT value FROM xmem_metadata WHERE key='schema_version'").get() as { value: string } | undefined;
    if (!version) throw new StorageError('UNSUPPORTED_VERSION', 'Unsupported storage database schema version');
    if (version.value === M2_DATABASE_SCHEMA_VERSION) this.migrateM2ToM4();
    else if (version.value === M3_DATABASE_SCHEMA_VERSION) this.migrateM3ToM4();
    else if (version.value === M4_DATABASE_SCHEMA_VERSION) this.migrateM4ToM5();
    else if (version.value === M5_DATABASE_SCHEMA_VERSION) this.migrateM5ToM6();
    else if (version.value === M6_DATABASE_SCHEMA_VERSION) this.migrateM6ToM7();
    else if (version.value === M7_DATABASE_SCHEMA_VERSION) this.migrateM7ToM8();
    else if (version.value === M8_DATABASE_SCHEMA_VERSION) this.migrateM8ToM9();
    else if (version.value !== DATABASE_SCHEMA_VERSION) throw new StorageError('UNSUPPORTED_VERSION', 'Unsupported storage database schema version');
    this.db.exec(`CREATE TABLE IF NOT EXISTS artifacts (hash TEXT PRIMARY KEY, byte_length INTEGER NOT NULL, relative_path TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS events (project_id TEXT NOT NULL, source_id TEXT NOT NULL, event_id TEXT NOT NULL, workspace_id TEXT NOT NULL, sequence INTEGER NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(project_id,source_id,event_id), UNIQUE(project_id,workspace_id,source_id,sequence));
CREATE TABLE IF NOT EXISTS evidences (evidence_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, payload_json TEXT NOT NULL, artifact_hash TEXT REFERENCES artifacts(hash));
CREATE TABLE IF NOT EXISTS records (record_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, current_revision_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS revisions (revision_id TEXT PRIMARY KEY, record_id TEXT NOT NULL REFERENCES records(record_id), project_id TEXT NOT NULL, previous_revision_id TEXT, payload_json TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lifecycle_events (event_id TEXT PRIMARY KEY, record_id TEXT NOT NULL REFERENCES records(record_id), revision_id TEXT NOT NULL REFERENCES revisions(revision_id), lifecycle TEXT NOT NULL, actor TEXT NOT NULL, source TEXT NOT NULL, reason TEXT NOT NULL, occurred_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS relations (relation_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, from_revision_id TEXT NOT NULL REFERENCES revisions(revision_id), to_revision_id TEXT NOT NULL REFERENCES revisions(revision_id), payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ingestion_receipts (project_id TEXT NOT NULL, source_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, event_id TEXT NOT NULL, payload_hash TEXT NOT NULL, sequence_gap INTEGER NOT NULL, expected_sequence INTEGER NOT NULL, PRIMARY KEY(project_id,source_id,idempotency_key), FOREIGN KEY(project_id,source_id,event_id) REFERENCES events(project_id,source_id,event_id));
CREATE INDEX IF NOT EXISTS events_source_sequence ON events(project_id,workspace_id,source_id,sequence);`);
    this.db.exec(`CREATE TABLE IF NOT EXISTS collector_registrations (project_id TEXT NOT NULL, source_id TEXT NOT NULL, locator TEXT NOT NULL, version TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), PRIMARY KEY(project_id,source_id));
CREATE TABLE IF NOT EXISTS snapshots (snapshot_id TEXT NOT NULL, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(snapshot_id,project_id,workspace_id));
CREATE TABLE IF NOT EXISTS source_versions (evidence_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, run_id TEXT NOT NULL, source_id TEXT NOT NULL, locator TEXT NOT NULL, version TEXT NOT NULL, content_hash TEXT NOT NULL, artifact_hash TEXT NOT NULL, snapshot_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS trusted_collector_receipts (evidence_id TEXT PRIMARY KEY REFERENCES source_versions(evidence_id), receipt_hash TEXT NOT NULL, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, run_id TEXT NOT NULL, source_id TEXT NOT NULL, locator TEXT NOT NULL, version TEXT NOT NULL, content_hash TEXT NOT NULL, artifact_hash TEXT NOT NULL, snapshot_id TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS source_versions_snapshot ON source_versions(snapshot_id,project_id,workspace_id);
CREATE TABLE IF NOT EXISTS failed_attempts (failed_attempt_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, action_id TEXT NOT NULL, observable_args_hash TEXT NOT NULL, observable_args_json TEXT NOT NULL, condition_fingerprints_hash TEXT NOT NULL, condition_fingerprints_json TEXT NOT NULL, failure_evidence_id TEXT NOT NULL REFERENCES evidences(evidence_id), payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS failed_attempts_action ON failed_attempts(project_id,workspace_id,action_id,observable_args_hash,condition_fingerprints_hash,failure_evidence_id);`);
    this.db.exec(`CREATE TABLE IF NOT EXISTS context_bindings (revision_id TEXT PRIMARY KEY REFERENCES revisions(revision_id), project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, task_ref TEXT NOT NULL, task_version TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS context_bindings_scope ON context_bindings(project_id,workspace_id,task_ref,task_version);
CREATE TABLE IF NOT EXISTS context_manifests (content_hash TEXT PRIMARY KEY, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, task_ref TEXT NOT NULL, task_version TEXT NOT NULL, request_hash TEXT NOT NULL, binding_hash TEXT NOT NULL, source_snapshot_hash TEXT NOT NULL, view_snapshot_hash TEXT NOT NULL, manifest_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS handoff_packages (package_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, task_ref TEXT NOT NULL, task_version TEXT NOT NULL, content_hash TEXT NOT NULL UNIQUE, target_snapshot_id TEXT NOT NULL, target_snapshot_hash TEXT NOT NULL, context_manifest_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS handoff_receipts (recipient_id TEXT NOT NULL, package_id TEXT NOT NULL REFERENCES handoff_packages(package_id), content_hash TEXT NOT NULL, validation_status TEXT NOT NULL, action TEXT NOT NULL, reason_codes_json TEXT NOT NULL, receipt_hash TEXT NOT NULL, PRIMARY KEY(recipient_id,package_id));
CREATE INDEX IF NOT EXISTS handoff_packages_scope ON handoff_packages(project_id,workspace_id,task_ref,task_version);`);
    this.db.exec(`CREATE TABLE IF NOT EXISTS extraction_candidates (candidate_id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, event_id TEXT NOT NULL, evidence_id TEXT, source_slice_hash TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS extraction_candidates_scope ON extraction_candidates(project_id,workspace_id,event_id);
CREATE TABLE IF NOT EXISTS extraction_attempts (attempt_id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, candidate_id TEXT REFERENCES extraction_candidates(candidate_id), project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, event_id TEXT NOT NULL, evidence_id TEXT, source_id TEXT NOT NULL, source_slice_hash TEXT NOT NULL, extractor_version TEXT NOT NULL, extractor_config_hash TEXT NOT NULL, provider_id TEXT, request_commitment_hash TEXT NOT NULL, outcome TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS extraction_attempts_scope ON extraction_attempts(project_id,workspace_id,event_id);`);
    this.db.exec(`CREATE TABLE IF NOT EXISTS guard_audit_records (record_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, occurred_at TEXT NOT NULL, kind TEXT NOT NULL, decision_id TEXT, permit_id TEXT, action_fingerprint TEXT, previous_hash TEXT, payload_hash TEXT NOT NULL, chain_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS guard_audit_records_run ON guard_audit_records(run_id,occurred_at,record_id);
CREATE INDEX IF NOT EXISTS guard_audit_records_permit ON guard_audit_records(permit_id,kind);`);
    this.ensureExtractionAttemptCommitmentColumns();
  }
  /** M2 data remains authoritative; the new trust tables start empty until a local collector is configured. */
  private migrateM2ToM4(): void {
    try {
      this.db.transaction(() => {
        this.db.exec(`CREATE TABLE IF NOT EXISTS collector_registrations (project_id TEXT NOT NULL, source_id TEXT NOT NULL, locator TEXT NOT NULL, version TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), PRIMARY KEY(project_id,source_id));
CREATE TABLE IF NOT EXISTS snapshots (snapshot_id TEXT NOT NULL, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(snapshot_id,project_id,workspace_id));
CREATE TABLE IF NOT EXISTS source_versions (evidence_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, run_id TEXT NOT NULL, source_id TEXT NOT NULL, locator TEXT NOT NULL, version TEXT NOT NULL, content_hash TEXT NOT NULL, artifact_hash TEXT NOT NULL, snapshot_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS trusted_collector_receipts (evidence_id TEXT PRIMARY KEY REFERENCES source_versions(evidence_id), receipt_hash TEXT NOT NULL, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, run_id TEXT NOT NULL, source_id TEXT NOT NULL, locator TEXT NOT NULL, version TEXT NOT NULL, content_hash TEXT NOT NULL, artifact_hash TEXT NOT NULL, snapshot_id TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS source_versions_snapshot ON source_versions(snapshot_id,project_id,workspace_id);`);
        this.db.prepare("UPDATE xmem_metadata SET value=? WHERE key='schema_version'").run(DATABASE_SCHEMA_VERSION);
      })();
    } catch (error) { if (error instanceof StorageError) throw error; throw new StorageError('STORAGE_ERROR', 'Could not migrate M2 storage to M4'); }
  }
  private migrateM3ToM4(): void {
    try { this.db.transaction(() => { this.db.exec('ALTER TABLE collector_registrations ADD COLUMN active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))'); this.db.prepare("UPDATE xmem_metadata SET value=? WHERE key='schema_version'").run(DATABASE_SCHEMA_VERSION); })(); }
    catch (error) { if (error instanceof StorageError) throw error; throw new StorageError('STORAGE_ERROR', 'Could not migrate M3 storage to M4'); }
  }
  /** M4 trusted evidence remains historical; M5 adds an empty immutable failure registry. */
  private migrateM4ToM5(): void {
    try { this.db.transaction(() => { this.db.exec(`CREATE TABLE IF NOT EXISTS failed_attempts (failed_attempt_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, action_id TEXT NOT NULL, observable_args_hash TEXT NOT NULL, observable_args_json TEXT NOT NULL, condition_fingerprints_hash TEXT NOT NULL, condition_fingerprints_json TEXT NOT NULL, failure_evidence_id TEXT NOT NULL REFERENCES evidences(evidence_id), payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS failed_attempts_action ON failed_attempts(project_id,workspace_id,action_id,observable_args_hash,condition_fingerprints_hash,failure_evidence_id);`); this.db.prepare("UPDATE xmem_metadata SET value=? WHERE key='schema_version'").run(DATABASE_SCHEMA_VERSION); })(); }
    catch (error) { if (error instanceof StorageError) throw error; throw new StorageError('STORAGE_ERROR', 'Could not migrate M4 storage to M5'); }
  }
  /** M5 authority remains untouched; M6 starts with no derived bindings or packs. */
  private migrateM5ToM6(): void {
    try { this.db.transaction(() => { this.db.exec(`CREATE TABLE IF NOT EXISTS context_bindings (revision_id TEXT PRIMARY KEY REFERENCES revisions(revision_id), project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, task_ref TEXT NOT NULL, task_version TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS context_bindings_scope ON context_bindings(project_id,workspace_id,task_ref,task_version);
CREATE TABLE IF NOT EXISTS context_manifests (content_hash TEXT PRIMARY KEY, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, task_ref TEXT NOT NULL, task_version TEXT NOT NULL, request_hash TEXT NOT NULL, binding_hash TEXT NOT NULL, source_snapshot_hash TEXT NOT NULL, view_snapshot_hash TEXT NOT NULL, manifest_hash TEXT NOT NULL, payload_json TEXT NOT NULL);`); this.db.prepare("UPDATE xmem_metadata SET value=? WHERE key='schema_version'").run(DATABASE_SCHEMA_VERSION); })(); }
    catch (error) { if (error instanceof StorageError) throw error; throw new StorageError('STORAGE_ERROR', 'Could not migrate M5 storage to M6'); }
  }
  /** M6 rows are preserved. M7 introduces empty derived handoff tables. */
  private migrateM6ToM7(): void {
    try { this.db.transaction(() => { this.db.exec(`CREATE TABLE IF NOT EXISTS handoff_packages (package_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, task_ref TEXT NOT NULL, task_version TEXT NOT NULL, content_hash TEXT NOT NULL UNIQUE, target_snapshot_id TEXT NOT NULL, target_snapshot_hash TEXT NOT NULL, context_manifest_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS handoff_receipts (recipient_id TEXT NOT NULL, package_id TEXT NOT NULL REFERENCES handoff_packages(package_id), content_hash TEXT NOT NULL, validation_status TEXT NOT NULL, action TEXT NOT NULL, reason_codes_json TEXT NOT NULL, receipt_hash TEXT NOT NULL, PRIMARY KEY(recipient_id,package_id));
CREATE INDEX IF NOT EXISTS handoff_packages_scope ON handoff_packages(project_id,workspace_id,task_ref,task_version);`); this.db.prepare("UPDATE xmem_metadata SET value=? WHERE key='schema_version'").run(DATABASE_SCHEMA_VERSION); })(); }
    catch (error) { if (error instanceof StorageError) throw error; throw new StorageError('STORAGE_ERROR', 'Could not migrate M6 storage to M7'); }
  }
  /** M7 authority remains unchanged; M8 adds empty immutable extraction audit rows. */
  private migrateM7ToM8(): void {
    try { this.db.transaction(() => { this.db.exec(`CREATE TABLE IF NOT EXISTS extraction_candidates (candidate_id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, event_id TEXT NOT NULL, evidence_id TEXT, source_slice_hash TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS extraction_candidates_scope ON extraction_candidates(project_id,workspace_id,event_id);
CREATE TABLE IF NOT EXISTS extraction_attempts (attempt_id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, candidate_id TEXT REFERENCES extraction_candidates(candidate_id), project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, event_id TEXT NOT NULL, evidence_id TEXT, source_id TEXT NOT NULL, source_slice_hash TEXT NOT NULL, extractor_version TEXT NOT NULL, extractor_config_hash TEXT NOT NULL, provider_id TEXT, request_commitment_hash TEXT NOT NULL, outcome TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS extraction_attempts_scope ON extraction_attempts(project_id,workspace_id,event_id);`); this.db.prepare("UPDATE xmem_metadata SET value=? WHERE key='schema_version'").run(DATABASE_SCHEMA_VERSION); })(); }
    catch (error) { if (error instanceof StorageError) throw error; throw new StorageError('STORAGE_ERROR', 'Could not migrate M7 storage to M8'); }
  }
  /** M8 authority remains unchanged; M9 adds the immutable reference-guard audit chain. */
  private migrateM8ToM9(): void {
    try { this.db.transaction(() => { this.db.exec(`CREATE TABLE IF NOT EXISTS guard_audit_records (record_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, project_id TEXT NOT NULL, workspace_id TEXT NOT NULL, occurred_at TEXT NOT NULL, kind TEXT NOT NULL, decision_id TEXT, permit_id TEXT, action_fingerprint TEXT, previous_hash TEXT, payload_hash TEXT NOT NULL, chain_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS guard_audit_records_run ON guard_audit_records(run_id,occurred_at,record_id);
CREATE INDEX IF NOT EXISTS guard_audit_records_permit ON guard_audit_records(permit_id,kind);`); this.db.prepare("UPDATE xmem_metadata SET value=? WHERE key='schema_version'").run(DATABASE_SCHEMA_VERSION); })(); }
    catch (error) { if (error instanceof StorageError) throw error; throw new StorageError('STORAGE_ERROR', 'Could not migrate M8 storage to M9'); }
  }
  /** M7 was not accepted before this commitment format; make local prerelease v8 databases fail closed. */
  private ensureExtractionAttemptCommitmentColumns(): void {
    const columns=(this.db.prepare('PRAGMA table_info(extraction_attempts)').all() as Array<{name:string}>).map(column=>column.name); const required=['source_id','source_slice_hash','extractor_version','extractor_config_hash','provider_id','request_commitment_hash'];
    if(required.some(column=>!columns.includes(column)) && columns.length>0) throw new StorageError('UNSUPPORTED_VERSION','Extraction attempts lack immutable request commitments');
  }
  private crash(stage: FailureStage): void { if (this.failureStage === stage) process.exit(86); }
  private artifactPath(hash: string): string { if (!/^[a-f0-9]{64}$/.test(hash)) throw new StorageError('INVALID_INPUT', 'Artifact hash must be SHA-256 lowercase hex'); const target = path.join(this.artifactRoot, hash.slice(0, 2), hash); if (!isInside(this.artifactRoot, target)) throw new StorageError('PATH_OUTSIDE_PROJECT', 'Artifact path escapes storage root'); return target; }
  private publishArtifact(bytes: Uint8Array, expectedHash?: string, publication?: ArtifactPublication): { hash: string; byteLength: number; relativePath: string } {
    const hash=sha256(bytes);
    if(expectedHash && expectedHash!==hash)throw new StorageError('IDENTITY_CONFLICT','Artifact bytes do not match evidence');
    const finalPath=this.artifactPath(hash), directory=path.dirname(finalPath);
    if(!this.pathExists(directory)){fs.mkdirSync(directory,{mode:0o700});publication?.directories.push(directory);}
    this.assertExistingSafeDirectory(directory,'Artifact shard directory');
    const retained=()=>{this.assertSafeArtifactFile(finalPath);const existing=fs.readFileSync(finalPath);if(sha256(existing)!==hash)throw new StorageError('ARTIFACT_CORRUPT','Existing content-addressed artifact is corrupt');return{hash,byteLength:existing.byteLength,relativePath:path.relative(this.root,finalPath)};};
    if(this.pathExists(finalPath))return retained();
    const temporary=path.join(directory, '.'+hash+'.'+randomUUID()+'.tmp');
    try {
      const fd=fs.openSync(temporary,'wx',0o600);
      try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
      this.crash('artifact_temp_written');
      const identity=fs.lstatSync(temporary);
      // Exclusive publication must never replace an existing orphan or another writer's file.
      try{fs.linkSync(temporary,finalPath);}catch(error){if((error as NodeJS.ErrnoException).code==='EEXIST')return retained();throw error;}
      publication?.files.push({path:finalPath,hash,dev:identity.dev,ino:identity.ino});
      this.fsyncDirectory(directory);this.crash('artifact_published');
    } finally {if(this.pathExists(temporary))fs.rmSync(temporary,{force:true});}
    return{hash,byteLength:bytes.byteLength,relativePath:path.relative(this.root,finalPath)};
  }
  private rollbackArtifactPublication(publication:ArtifactPublication):void {
    for(const file of publication.files.reverse()){
      this.assertExistingSafeDirectory(path.dirname(file.path),'Artifact shard directory');
      if(!this.pathExists(file.path))continue;
      this.assertSafeArtifactFile(file.path);const stat=fs.lstatSync(file.path);
      if(stat.dev!==file.dev||stat.ino!==file.ino||sha256(fs.readFileSync(file.path))!==file.hash)throw new StorageError('STORAGE_ERROR','Published artifact changed before rollback');
      fs.unlinkSync(file.path);
    }
    for(const directory of publication.directories.reverse()){
      this.assertExistingSafeDirectory(directory,'Artifact shard directory');
      if(fs.readdirSync(directory).length===0)fs.rmdirSync(directory);
    }
  }
  private fsyncDirectory(directory: string): void { if (process.platform === 'win32') return; const fd = fs.openSync(directory, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
  private assertSafeArtifactFile(target: string): void { const stat = fs.lstatSync(target); if (stat.isSymbolicLink() || !stat.isFile()) throw new StorageError('PATH_OUTSIDE_PROJECT', 'Artifact must be a regular non-linked file'); if (!isInside(this.artifactRoot, fs.realpathSync.native(target))) throw new StorageError('PATH_OUTSIDE_PROJECT', 'Artifact redirects outside storage root'); }
  private receipt(event: Event, key: string, replayed: boolean, gap: boolean, expected: number): IngestReceipt { return { project_id: event.project_id, source_id: event.source.source_id, event_id: event.event_id, idempotency_key: key, replayed, sequence_gap: gap, expected_sequence: expected }; }

  ingest(request: IngestRequest): IngestReceipt {
    this.assertSafeDatabaseFiles(); const event = validateEvent(structuredClone(request.event)); const evidence = request.evidence === undefined ? undefined : validateEvidence(structuredClone(request.evidence));
    if (event.evidence_id !== (evidence?.evidence_id ?? null)) throw new StorageError('INVALID_INPUT', 'Event and evidence identities must agree'); if (evidence && (evidence.project_id !== event.project_id || evidence.workspace_id !== event.workspace_id || evidence.run_id !== event.run_id)) throw new StorageError('PROJECT_MISMATCH', 'Evidence and event must have the same project, workspace, and run'); if (request.artifact && (!evidence || !evidence.artifact_hash)) throw new StorageError('INVALID_INPUT', 'Artifact bytes require evidence'); if (evidence?.artifact_hash && !request.artifact) this.readArtifact(evidence.artifact_hash);
    const published = request.artifact ? this.publishArtifact(request.artifact, evidence?.artifact_hash ?? undefined) : undefined; if (evidence?.artifact_hash && published && published.hash !== evidence.artifact_hash) throw new StorageError('IDENTITY_CONFLICT', 'Published artifact identity does not match evidence'); const payloadHash = sha256(canonicalJson({ event, evidence })); const key = request.idempotencyKey ?? event.event_id; if (!nonEmpty(key)) throw new StorageError('INVALID_INPUT', 'An idempotency key is required');
    const transaction = this.db.transaction(() => { this.crash('transaction_started'); const project = event.project_id, source = event.source.source_id, id = event.event_id; const priorReceipt = this.db.prepare('SELECT * FROM ingestion_receipts WHERE project_id=? AND source_id=? AND idempotency_key=?').get(project, source, key) as ReceiptRow | undefined; if (priorReceipt) { const authoritative = this.db.prepare('SELECT payload_hash FROM events WHERE project_id=? AND source_id=? AND event_id=?').get(project, source, id) as { payload_hash: string } | undefined; if (priorReceipt.event_id !== id || priorReceipt.payload_hash !== payloadHash) throw new StorageError('IDENTITY_CONFLICT', 'Idempotency key was reused for different content'); if (!authoritative || authoritative.payload_hash !== priorReceipt.payload_hash) throw new StorageError('STORAGE_ERROR', 'Receipt is not bound to its authoritative event'); return this.receipt(event, key, true, priorReceipt.sequence_gap === 1, priorReceipt.expected_sequence); }
      const priorEvent = this.db.prepare('SELECT payload_hash FROM events WHERE project_id=? AND source_id=? AND event_id=?').get(project, source, id) as { payload_hash: string } | undefined; if (priorEvent) { if (priorEvent.payload_hash !== payloadHash) throw new StorageError('IDENTITY_CONFLICT', 'Event identity already exists with different content'); const bound = this.db.prepare('SELECT payload_hash,sequence_gap,expected_sequence FROM ingestion_receipts WHERE project_id=? AND source_id=? AND event_id=? LIMIT 1').get(project, source, id) as Pick<ReceiptRow, 'payload_hash'|'sequence_gap'|'expected_sequence'> | undefined; if (!bound || bound.payload_hash !== priorEvent.payload_hash) throw new StorageError('STORAGE_ERROR', 'Event exists without a bound receipt'); this.db.prepare('INSERT INTO ingestion_receipts(project_id,source_id,idempotency_key,event_id,payload_hash,sequence_gap,expected_sequence) VALUES(?,?,?,?,?,?,?)').run(project, source, key, id, payloadHash, bound.sequence_gap, bound.expected_sequence); return this.receipt(event, key, true, bound.sequence_gap === 1, bound.expected_sequence); }
      const row = this.db.prepare('SELECT MAX(sequence) AS maximum FROM events WHERE project_id=? AND workspace_id=? AND source_id=?').get(project, event.workspace_id, source) as { maximum: number | null }; const expected = (row.maximum ?? -1) + 1, gap = event.sequence !== expected; if (evidence) this.insertEvidence(evidence, published); this.db.prepare('INSERT INTO events(project_id,source_id,event_id,workspace_id,sequence,payload_hash,payload_json) VALUES(?,?,?,?,?,?,?)').run(project,source,id,event.workspace_id,event.sequence,payloadHash,canonicalJson(event)); this.crash('event_inserted'); this.db.prepare('INSERT INTO ingestion_receipts(project_id,source_id,idempotency_key,event_id,payload_hash,sequence_gap,expected_sequence) VALUES(?,?,?,?,?,?,?)').run(project,source,key,id,payloadHash,gap ? 1 : 0,expected); this.crash('receipt_inserted'); return this.receipt(event,key,false,gap,expected); });
    try { return transaction(); } catch (error) { if (error instanceof StorageError) throw error; throw new StorageError('STORAGE_ERROR', 'Database transaction failed'); }
  }
  /** Read-only raw authority for the optional extraction adapter. */
  getStoredEvent(projectId: string, sourceId: string, eventId: string): Event | undefined { this.assertSafeDatabaseFiles(); if(!nonEmpty(projectId)||!nonEmpty(sourceId)||!nonEmpty(eventId)) throw new StorageError('INVALID_INPUT','Event identity is required'); const row=this.db.prepare('SELECT payload_json,payload_hash FROM events WHERE project_id=? AND source_id=? AND event_id=?').get(projectId,sourceId,eventId) as {payload_json:string;payload_hash:string}|undefined; if(!row) return undefined; try { const event=validateEvent(JSON.parse(row.payload_json)); if(sha256(canonicalJson({event,evidence:event.evidence_id===null?undefined:this.getStoredEvidence(event.evidence_id)}))!==row.payload_hash) throw new StorageError('IDENTITY_CONFLICT','Stored event hash is corrupt'); return structuredClone(event); } catch(error) { if(error instanceof StorageError) throw error; throw new StorageError('IDENTITY_CONFLICT','Stored event payload is corrupt'); } }
  getStoredEvidence(evidenceId: string): Evidence | undefined { this.assertSafeDatabaseFiles(); if(!nonEmpty(evidenceId)) throw new StorageError('INVALID_INPUT','Evidence identity is required'); const row=this.db.prepare('SELECT payload_json FROM evidences WHERE evidence_id=?').get(evidenceId) as JsonRow|undefined; if(!row)return undefined; try{return structuredClone(validateEvidence(JSON.parse(row.payload_json)));}catch{throw new StorageError('IDENTITY_CONFLICT','Stored evidence payload is corrupt');} }
  private insertEvidence(evidence: Evidence, published?: { hash: string; byteLength: number; relativePath: string }): void { const current = this.db.prepare('SELECT payload_json FROM evidences WHERE evidence_id=?').get(evidence.evidence_id) as JsonRow | undefined, payload = canonicalJson(evidence); if (current) { if (current.payload_json !== payload) throw new StorageError('IDENTITY_CONFLICT', 'Evidence identity already exists with different content'); return; } if (published) this.db.prepare('INSERT OR IGNORE INTO artifacts(hash,byte_length,relative_path) VALUES(?,?,?)').run(published.hash,published.byteLength,published.relativePath); if (evidence.artifact_hash && !this.db.prepare('SELECT hash FROM artifacts WHERE hash=?').get(evidence.artifact_hash)) throw new StorageError('ARTIFACT_MISSING','Evidence references no registered artifact'); this.db.prepare('INSERT INTO evidences(evidence_id,project_id,payload_json,artifact_hash) VALUES(?,?,?,?)').run(evidence.evidence_id,evidence.project_id,payload,evidence.artifact_hash); }

  /** Register a collector locally. This configuration is deliberately excluded from portable imports. */
  registerCollector(input: CollectorRegistration): CollectorRegistration {
    this.assertSafeDatabaseFiles();
    const registration = this.validateCollector(input);
    const prior = this.db.prepare('SELECT project_id,source_id,locator,version,active FROM collector_registrations WHERE project_id=? AND source_id=?').get(registration.project_id, registration.source_id) as StoredCollectorRegistration | undefined;
    if (prior) { const { active: _active, ...identity } = prior; if (canonicalJson(identity) !== canonicalJson(registration)) throw new StorageError('IDENTITY_CONFLICT', 'Collector identity is already configured differently'); if (!prior.active) this.db.prepare('UPDATE collector_registrations SET active=1 WHERE project_id=? AND source_id=?').run(registration.project_id, registration.source_id); return structuredClone(registration); }
    this.db.prepare('INSERT INTO collector_registrations(project_id,source_id,locator,version,active) VALUES(?,?,?,?,1)').run(registration.project_id, registration.source_id, registration.locator, registration.version);
    return structuredClone(registration);
  }
  /** Revocation preserves local history while making reports untrusted for future checks. */
  unregisterCollector(projectId: string, sourceId: string): void {
    this.assertSafeDatabaseFiles(); if (!nonEmpty(projectId) || !nonEmpty(sourceId)) throw new StorageError('INVALID_INPUT', 'Collector identity is required');
    this.db.prepare('UPDATE collector_registrations SET active=0 WHERE project_id=? AND source_id=?').run(projectId, sourceId);
  }
  recordSnapshot(input: Snapshot): Snapshot {
    this.assertSafeDatabaseFiles(); const snapshot = validateSnapshot(structuredClone(input)), payload = canonicalJson(snapshot), hash = sha256(payload);
    const prior = this.db.prepare('SELECT payload_json,payload_hash FROM snapshots WHERE snapshot_id=? AND project_id=? AND workspace_id=?').get(snapshot.snapshot_id, snapshot.project_id, snapshot.workspace_id) as { payload_json:string; payload_hash:string } | undefined;
    if (prior) {
      const retained = validateSnapshot(JSON.parse(prior.payload_json));
      if (prior.payload_hash !== sha256(canonicalJson(retained)) || retained.snapshot_id !== snapshot.snapshot_id || retained.project_id !== snapshot.project_id || retained.workspace_id !== snapshot.workspace_id) throw new StorageError('IDENTITY_CONFLICT', 'Stored snapshot is corrupt');
      if (prior.payload_json === payload && prior.payload_hash === hash) return retained;
      // captureSnapshot content IDs exclude observed time. Retain the FIRST immutable
      // snapshot, never overwrite it. Opaque caller IDs still require exact equality.
      const identity = {project_id:snapshot.project_id,workspace_id:snapshot.workspace_id,manifest:snapshot.manifest};
      if (snapshot.snapshot_id === sha256(canonicalJson(identity)) && canonicalJson(retained.manifest) === canonicalJson(snapshot.manifest)) return retained;
      throw new StorageError('IDENTITY_CONFLICT', 'Snapshot identity already exists with different content');
    }
    this.db.prepare('INSERT INTO snapshots(snapshot_id,project_id,workspace_id,payload_hash,payload_json) VALUES(?,?,?,?,?)').run(snapshot.snapshot_id, snapshot.project_id, snapshot.workspace_id, hash, payload);
    return snapshot;
  }
  /** Read one immutable snapshot with its stored integrity checked. */
  getSnapshot(snapshotId: string, projectId: string, workspaceId: string): Snapshot | undefined {
    this.assertSafeDatabaseFiles();
    const row = this.db.prepare('SELECT payload_json,payload_hash FROM snapshots WHERE snapshot_id=? AND project_id=? AND workspace_id=?').get(snapshotId,projectId,workspaceId) as {payload_json:string;payload_hash:string}|undefined;
    if (!row) return undefined;
    const value = validateSnapshot(JSON.parse(row.payload_json));
    if (value.snapshot_id!==snapshotId || value.project_id!==projectId || value.workspace_id!==workspaceId || row.payload_hash!==sha256(canonicalJson(value))) throw new StorageError('IDENTITY_CONFLICT','Stored snapshot integrity mismatch');
    return structuredClone(value);
  }
  /** Atomic file-assertion intake; never registers collectors or trusted executions. */
  recordMemoryCapture(recordInput: MemoryRecord, bindingInput: ContextBinding): { revision_id:string; record_id:string; source_id:string; replayed:boolean; is_current:boolean } {
    this.assertSafeDatabaseFiles();
    const record=validateMemoryRecord(structuredClone(recordInput)), binding=this.validateContextBinding(structuredClone(bindingInput));
    if (record.project_id!==binding.project_id || record.revision_id!==binding.revision_id) throw new StorageError('PROJECT_MISMATCH','Capture and binding must share identity');
    if (record.source.kind!=='file' || !record.source.locator.startsWith('xmem-local-file-v1:') || !['ASSERTED','HYPOTHESIS'].includes(record.epistemic_state) || record.lifecycle!=='ACTIVE') throw new StorageError('UNTRUSTED_SOURCE','File intake cannot establish confirmed facts or trusted execution');
    return this.db.transaction(() => {
      const prior=this.db.prepare('SELECT payload_json FROM revisions WHERE revision_id=?').get(record.revision_id) as JsonRow|undefined;
      const eventId='capture-'+record.revision_id;
      if (prior) {
        if (prior.payload_json!==canonicalJson(record)) throw new StorageError('IDENTITY_CONFLICT','Capture identity changed');
        const event=this.getStoredEvent(record.project_id,record.source.source_id,eventId);
        const existing=this.readStoredContextBindings('WHERE revision_id=?',[record.revision_id]);
        if (!event || event.content!==record.content || canonicalJson(event.source)!==canonicalJson(record.source) || event.workspace_id!==binding.workspace_id || event.kind!=='observation' || event.evidence_id!==null || existing.length!==1 || canonicalJson(existing[0])!==canonicalJson(binding)) throw new StorageError('IDENTITY_CONFLICT','Capture replay has incomplete or conflicting material');
      } else {
        const next=this.db.prepare('SELECT max(sequence) AS last FROM events WHERE project_id=? AND workspace_id=? AND source_id=?').get(record.project_id,binding.workspace_id,record.source.source_id) as {last:number|null};
        const event:Event={schema_version:'1',event_id:eventId,project_id:record.project_id,workspace_id:binding.workspace_id,run_id:eventId,source:record.source,sequence:(next.last??-1)+1,occurred_at:new Date().toISOString(),completeness:'TRUNCATED',kind:'observation',content:record.content,evidence_id:null};
        this.ingest({event,idempotencyKey:eventId});
        this.appendRevision(record,'Explicit file excerpt capture; source assertion, not execution proof or owner approval');
        this.bindContextRevision(binding);
      }
      const current=this.db.prepare('SELECT current_revision_id FROM records WHERE record_id=?').get(record.record_id) as {current_revision_id:string};
      return {revision_id:record.revision_id,record_id:record.record_id,source_id:record.source.source_id,replayed:!!prior,is_current:current.current_revision_id===record.revision_id};
    }).immediate();
  }
  /** Atomic host-candidate intake for the R3 semi-auto adapter.
   * Host text remains ASSERTED/HYPOTHESIS, never trusted execution or owner-authenticated truth.
   * It is deliberately non-mandatory so an agent cannot create a blocking constraint by itself.
   */
  recordHostMemoryCapture(recordInput: MemoryRecord, bindingInput: ContextBinding): { revision_id:string; record_id:string; source_id:string; replayed:boolean; is_current:boolean } {
    this.assertSafeDatabaseFiles();
    const record=validateMemoryRecord(structuredClone(recordInput)), binding=this.validateContextBinding(structuredClone(bindingInput));
    if (record.project_id!==binding.project_id || record.revision_id!==binding.revision_id) throw new StorageError('PROJECT_MISMATCH','Capture and binding must share identity');
    const hostSource=validateHostCandidateSourceRef(record.project_id,record.source);
    if (!hostSource || sha256(record.content)!==hostSource.digest || !['ASSERTED','HYPOTHESIS'].includes(record.epistemic_state) || record.lifecycle!=='ACTIVE' || binding.mandatory) throw new StorageError('UNTRUSTED_SOURCE','Host candidate intake cannot establish mandatory constraints, confirmed facts, or trusted execution');
    return this.db.transaction(() => {
      const prior=this.db.prepare('SELECT payload_json FROM revisions WHERE revision_id=?').get(record.revision_id) as JsonRow|undefined;
      const eventId='host-capture-'+record.revision_id;
      if (prior) {
        if (prior.payload_json!==canonicalJson(record)) throw new StorageError('IDENTITY_CONFLICT','Host capture identity changed');
        const event=this.getStoredEvent(record.project_id,record.source.source_id,eventId);
        const existing=this.readStoredContextBindings('WHERE revision_id=?',[record.revision_id]);
        if (!event || event.content!==record.content || canonicalJson(event.source)!==canonicalJson(record.source) || event.workspace_id!==binding.workspace_id || event.kind!=='observation' || event.evidence_id!==null || existing.length!==1 || canonicalJson(existing[0])!==canonicalJson(binding)) throw new StorageError('IDENTITY_CONFLICT','Host capture replay has incomplete or conflicting material');
      } else {
        // The predecessor CAS and lifecycle check precede ingest in this SAME
        // IMMEDIATE transaction. A withdrawn rule cannot be revived by correction.
        const predecessor=this.db.prepare('SELECT project_id,current_revision_id FROM records WHERE record_id=?').get(record.record_id) as {project_id:string;current_revision_id:string}|undefined;
        if(predecessor){
          if(predecessor.project_id!==record.project_id||predecessor.current_revision_id!==record.previous_revision_id)throw new StorageError('IDENTITY_CONFLICT','Host correction must extend exact current revision');
          const lifecycle=this.db.prepare('SELECT revision_id,lifecycle FROM lifecycle_events WHERE record_id=? ORDER BY rowid DESC LIMIT 1').get(record.record_id) as {revision_id:string;lifecycle:Lifecycle}|undefined;
          if(!lifecycle||lifecycle.revision_id!==predecessor.current_revision_id)throw new StorageError('IDENTITY_CONFLICT','Host predecessor lifecycle is incomplete');
          if(lifecycle.lifecycle==='RETRACTED')throw new HostRetractionError('RETRACTED_PREDECESSOR');
          if(lifecycle.lifecycle!=='ACTIVE')throw new StorageError('IDENTITY_CONFLICT','Host predecessor must be ACTIVE');
        }else if(record.previous_revision_id!==null)throw new StorageError('IDENTITY_CONFLICT','Initial host revision cannot name a predecessor');
        const next=this.db.prepare('SELECT max(sequence) AS last FROM events WHERE project_id=? AND workspace_id=? AND source_id=?').get(record.project_id,binding.workspace_id,record.source.source_id) as {last:number|null};
        const event:Event={schema_version:'1',event_id:eventId,project_id:record.project_id,workspace_id:binding.workspace_id,run_id:eventId,source:record.source,sequence:(next.last??-1)+1,occurred_at:new Date().toISOString(),completeness:'TRUNCATED',kind:'observation',content:record.content,evidence_id:null};
        this.ingest({event,idempotencyKey:eventId});
        this.appendRevision(record,'R3 host candidate capture; asserted/hypothesis only, not owner authentication or execution proof');
        this.bindContextRevision(binding);
      }
      // Replayed captures must not acknowledge a deleted/corrupt durable receipt.
      // Reuse the same scoped retained-material validation used by public readback.
      const retained=this.readHostMemoryCapture({project_id:record.project_id,workspace_id:binding.workspace_id,task_ref:binding.task_ref,task_version:binding.task_version,role:binding.roles[0],record_id:record.record_id,revision_id:record.revision_id});
      if(!retained)throw new StorageError('IDENTITY_CONFLICT','Host capture could not be reconciled after persistence');
      const current=this.db.prepare('SELECT current_revision_id FROM records WHERE record_id=?').get(record.record_id) as {current_revision_id:string};
      return {revision_id:record.revision_id,record_id:record.record_id,source_id:record.source.source_id,replayed:!!prior,is_current:current.current_revision_id===record.revision_id};
    }).immediate();
  }

  /** One transaction-consistent, scoped read of an existing host capture.
   * A durable Core intake receipt is not an R6 Worker receipt or proof of applicability.
   * Missing/denied identities deliberately share the same no-match result.
   */
  readHostMemoryCapture(request:{project_id:string;workspace_id:string;task_ref:string;task_version:string;role:string;record_id:string|null;revision_id:string|null},onSourceRead?:(bytes:Buffer|undefined)=>void) {
    this.assertSafeDatabaseFiles();
    for(const key of ['project_id','workspace_id','task_ref','task_version','role'] as const)
      if(!nonEmpty(request?.[key]))throw new StorageError('INVALID_INPUT','Capture read scope is required');
    if((request.record_id!==null&&!nonEmpty(request.record_id))||(request.record_id===null&&request.revision_id===null))throw new StorageError('INVALID_INPUT','A record or exact revision is required');
    if(request.revision_id!==null&&!nonEmpty(request.revision_id))throw new StorageError('INVALID_INPUT','Invalid read revision');
    return this.db.transaction(()=>{
      const recordId=request.record_id??(this.db.prepare('SELECT record_id FROM revisions WHERE project_id=? AND revision_id=?').get(request.project_id,request.revision_id) as {record_id:string}|undefined)?.record_id;
      if(!recordId)return undefined;
      const current=this.db.prepare('SELECT current_revision_id FROM records WHERE project_id=? AND record_id=?').get(request.project_id,recordId) as {current_revision_id:string}|undefined;
      if(!current)return undefined;
      const revisionId=request.revision_id??current.current_revision_id;
      const bindings=this.readStoredContextBindings('WHERE project_id=? AND workspace_id=? AND task_ref=? AND task_version=? AND revision_id=?',[request.project_id,request.workspace_id,request.task_ref,request.task_version,revisionId]);
      if(bindings.length===0||!bindings.some(binding=>binding.roles.includes(request.role)))return undefined;
      const row=this.db.prepare('SELECT payload_json FROM revisions WHERE project_id=? AND record_id=? AND revision_id=?').get(request.project_id,recordId,revisionId) as JsonRow|undefined;
      if(!row)return undefined;
      const record=validateMemoryRecord(JSON.parse(row.payload_json));
      if(record.project_id!==request.project_id||record.record_id!==recordId||record.revision_id!==revisionId)throw new StorageError('IDENTITY_CONFLICT','Stored revision identity is inconsistent');
      if(bindings.length!==1)throw new StorageError('IDENTITY_CONFLICT','Host capture binding is ambiguous');
      const binding=bindings[0];
      if(!binding.allowed_source_ids.includes(record.source.source_id))return undefined;
      if(binding.mandatory||record.lifecycle!=='ACTIVE'||!validateHostCandidateSourceRef(request.project_id,record.source)||!['ASSERTED','HYPOTHESIS'].includes(record.epistemic_state))throw new StorageError('IDENTITY_CONFLICT','Stored host capture contract is inconsistent');
      const eventId='host-capture-'+record.revision_id;
      const event=this.getStoredEvent(request.project_id,record.source.source_id,eventId);
      const receipt=this.db.prepare('SELECT * FROM ingestion_receipts WHERE project_id=? AND source_id=? AND idempotency_key=?').get(request.project_id,record.source.source_id,eventId) as ReceiptRow|undefined;
      const bytes=this.readHostCandidateSource(request.project_id,record.source);
      onSourceRead?.(bytes);
      if(!event||!receipt||event.project_id!==request.project_id||event.event_id!==eventId||receipt.sequence_gap!==0||receipt.expected_sequence!==event.sequence||receipt.event_id!==eventId||receipt.payload_hash!==sha256(canonicalJson({event,evidence:undefined}))||event.workspace_id!==request.workspace_id||event.run_id!==eventId||event.kind!=='observation'||event.evidence_id!==null||event.content!==record.content||canonicalJson(event.source)!==canonicalJson(record.source)||!bytes||sha256(bytes)!==record.source.content_hash||bytes.toString('utf8')!==record.content)
        throw new StorageError('IDENTITY_CONFLICT','Host capture receipt, source or event is incomplete or inconsistent');
      const lifecycle=this.db.prepare('SELECT event_id,record_id,revision_id,lifecycle,actor,source,reason,occurred_at FROM lifecycle_events WHERE record_id=? ORDER BY rowid DESC LIMIT 1').get(record.record_id) as LifecycleEvent|undefined;
      if(!lifecycle||lifecycle.revision_id!==current.current_revision_id)throw new StorageError('IDENTITY_CONFLICT','Host capture current lifecycle is inconsistent');
      this.validateLifecycle(lifecycle);
      return {record,binding,current_revision_id:current.current_revision_id,current_lifecycle:lifecycle.lifecycle,is_current:revisionId===current.current_revision_id,
        durable_receipt:{kind:'CORE_HOST_CAPTURE' as const,event_id:eventId,idempotency_key:eventId,event_payload_hash:receipt.payload_hash}};
    }).deferred();
  }

  /** Exact logical key and reference, with the original host receipt revalidated. */
  private retractionCapture(intent:EngineeringRetractionIntent,allowedSources?:string[]):HostCapture|undefined {
    const s=intent.scope,r=intent.target;
    if(s.role!=='developer')throw new HostRetractionError('UNTRUSTED_SOURCE');
    if(allowedSources&&!allowedSources.includes(r.source_id))return undefined;
    let found:HostCapture|undefined;
    try{found=this.readHostMemoryCapture({...s,record_id:retractionRecordId(intent),revision_id:r.revision_id});}
    catch{throw new HostRetractionError('INCOMPLETE_OR_INCONSISTENT');}
    if(!found)return undefined;
    retractionInformationType(found);
    if(found.record.source.source_id!==r.source_id||found.record.source.content_hash!==r.source_content_hash||sha256(found.record.content)!==r.record_content_hash||sha256(canonicalContextJson(found.binding))!==r.binding_hash)throw new HostRetractionError('PREVIEW_CHANGED');
    return found;
  }

  /** Resolve durable operation identity before comparing the entire immutable intent.
   * Current source/role ACL is checked on the ORIGINAL event target before exposure.
   */
  private retainedHostRetraction(intent:EngineeringRetractionIntent,allowedSources?:string[]) {
    const event=this.db.prepare('SELECT event_id,record_id,revision_id,lifecycle,actor,source,reason,occurred_at FROM lifecycle_events WHERE event_id=?').get(retractionEventId(intent)) as LifecycleEvent|undefined;
    if(!event)return undefined;
    let original:EngineeringRetractionIntent,envelope:any;
    try{this.validateLifecycle(event);envelope=JSON.parse(event.reason);original=parseRetractionIntent(envelope.intent);}
    catch{throw new HostRetractionError('INCOMPLETE_OR_INCONSISTENT');}
    const found=this.retractionCapture(original,allowedSources);
    if(!found)return {denied:true as const};
    const expected={format:'xmem-engineering-retraction-event/1',intent:original,request_hash:sha256(canonicalContextJson(original)),record_id:retractionRecordId(original),capture_receipt_commitment:captureReceiptCommitment(found)};
    if(event.event_id!==retractionEventId(original)||event.record_id!==expected.record_id||event.revision_id!==original.target.revision_id||event.lifecycle!=='RETRACTED'||event.actor!=='engineering-role:developer:unverified'||event.source!=='xmem-engineering-retraction/1'||event.reason!==canonicalContextJson(expected))throw new HostRetractionError('INCOMPLETE_OR_INCONSISTENT');
    if(canonicalContextJson(original)!==canonicalContextJson(intent))throw new HostRetractionError('IDENTITY_CONFLICT');
    return{denied:false as const,event,found};
  }

  /** Strictly read-only reconciliation: no event repair, timestamps, or store creation. */
  readHostMemoryRetraction<T>(input:EngineeringRetractionIntent,guards:{allowed_source_ids?:string[];validateCurrent:(found:HostCapture)=>void;receipt:(event:LifecycleEvent,found:HostCapture,replayed:boolean)=>T}) {
    this.assertSafeDatabaseFiles();const intent=parseRetractionIntent(input);
    return this.db.transaction(()=>{
      const prior=this.retainedHostRetraction(intent,guards.allowed_source_ids);
      if(prior&&!prior.denied){guards.validateCurrent(prior.found);return guards.receipt(prior.event,prior.found,true);}
      const found=prior?.denied?undefined:this.retractionCapture(intent,guards.allowed_source_ids);
      if(found)guards.validateCurrent(found);
      return{contract:'xmem-engineering/2',capability:'xmem-engineering-retraction/1',status:found?'NO_MATCHING_OPERATION':'NOT_FOUND_WITHIN_SCOPE',persisted:'UNKNOWN',commit_state:'COMMIT_UNKNOWN',read_only:true,replayed:false,payload:null,payload_bytes:0,payload_sha256:null};
    }).deferred();
  }

  /** Narrow host CAS only. No general lifecycle/record selection or schema changes. */
  retractHostMemoryCapture<T>(input:EngineeringRetractionIntent,guards:{validateCurrent:(found:HostCapture)=>void;validateWrite:()=>void;receipt:(event:LifecycleEvent,found:HostCapture,replayed:boolean)=>T}):T {
    this.assertSafeDatabaseFiles();const intent=parseRetractionIntent(input);
    return this.db.transaction(()=>{
      const prior=this.retainedHostRetraction(intent);
      if(prior&&!prior.denied){guards.validateCurrent(prior.found);return guards.receipt(prior.event,prior.found,true);}
      if(prior?.denied)throw new HostRetractionError('NOT_FOUND_WITHIN_SCOPE');
      const found=this.retractionCapture(intent);
      if(!found)throw new HostRetractionError('NOT_FOUND_WITHIN_SCOPE');
      guards.validateCurrent(found);guards.validateWrite();
      if(!found.is_current||found.current_revision_id!==intent.target.revision_id)throw new HostRetractionError('PREVIEW_CHANGED');
      if(found.current_lifecycle!=='ACTIVE')throw new HostRetractionError('TARGET_NOT_ACTIVE');
      const event:LifecycleEvent={event_id:retractionEventId(intent),record_id:found.record.record_id,revision_id:found.record.revision_id,lifecycle:'RETRACTED',actor:'engineering-role:developer:unverified',source:'xmem-engineering-retraction/1',
        reason:canonicalContextJson({format:'xmem-engineering-retraction-event/1',intent,request_hash:sha256(canonicalContextJson(intent)),record_id:found.record.record_id,capture_receipt_commitment:captureReceiptCommitment(found)}),occurred_at:new Date().toISOString()};
      // The COMPLETE eventual receipt must fit before any write. This is also the
      // second real public-basis read, under policy/location/IMMEDIATE locks.
      guards.receipt(event,{...found,current_lifecycle:'RETRACTED'},false);
      guards.validateWrite();
      this.insertLifecycle(event);
      const retained=this.retainedHostRetraction(intent);
      if(!retained||retained.denied)throw new HostRetractionError('INCOMPLETE_OR_INCONSISTENT');
      guards.validateCurrent(retained.found);
      return guards.receipt(retained.event,retained.found,false);
    }).immediate();
  }

  /** A bounded authorized batch observes one SQLite snapshot. No task binding is added. */
  readHostMemoryCaptureBatch(requests:Array<Parameters<SqliteMemoryStorage['readHostMemoryCapture']>[0]>) {
    if(!Array.isArray(requests)||requests.length>64)throw new StorageError('INVALID_INPUT','Capture read batch exceeds node limit');
    return this.db.transaction(()=>requests.map(request=>this.readHostMemoryCapture(request))).deferred();
  }

  /** Filter original ACL/source metadata before spending a body-selection quota.
   * The authorization-reference bound is separate from the 64-body node bound.
   * No denied IDs/counts leave the SDK's filtered public view.
   */
  readAuthorizedHostCaptureBatch(requests:Array<Parameters<SqliteMemoryStorage['readHostMemoryCapture']>[0]&{source_id:string}>,limit:number,
    beforeRead?:(request:Parameters<SqliteMemoryStorage['readHostMemoryCapture']>[0]&{source_id:string})=>void,onSourceRead?:(bytes:Buffer|undefined)=>void) {
    this.assertSafeDatabaseFiles();
    if(!Array.isArray(requests)||requests.length>512||!Number.isSafeInteger(limit)||limit<1||limit>64)throw new StorageError('INVALID_INPUT','Invalid authorized capture batch');
    return this.db.transaction(()=>{
      const permitted:number[]=[];
      for(let i=0;i<requests.length;i++){
        const r=requests[i];
        for(const key of ['project_id','workspace_id','task_ref','task_version','role','source_id','revision_id'] as const)if(!nonEmpty(r?.[key]))throw new StorageError('INVALID_INPUT','Explicit sharing reference required');
        const bindings=this.readStoredContextBindings('WHERE project_id=? AND workspace_id=? AND task_ref=? AND task_version=? AND revision_id=?',[r.project_id,r.workspace_id,r.task_ref,r.task_version,r.revision_id]);
        if(!bindings.some(b=>b.roles.includes(r.role)&&b.allowed_source_ids.includes(r.source_id)))continue;
        const source=this.db.prepare("SELECT json_extract(v.payload_json,'$.source.source_id') AS source_id FROM revisions v JOIN records r ON r.project_id=v.project_id AND r.record_id=v.record_id WHERE v.project_id=? AND v.revision_id=?").get(r.project_id,r.revision_id) as {source_id:string}|undefined;
        if(source?.source_id===r.source_id)permitted.push(i);
      }
      const indices=permitted.slice(0,limit),captures=indices.map(i=>{beforeRead?.(requests[i]);return this.readHostMemoryCapture(requests[i],onSourceRead);});
      return{permitted_count:permitted.length,indices,captures};
    }).deferred();
  }

  /** Resolve R3 host-candidate source bytes from authoritative retained events. */
  /** Narrow project-local Topic directory. SQL applies live ACL, source and
   * ACTIVE current filters before returning bounded pointers, never bodies. */
  readTopicCurrentCandidates(request:{project_id:string;workspace_id:string;role:string;allowed_source_ids?:string[];after_revision_id:string;limit:number}) {
    this.assertSafeDatabaseFiles();
    if(!nonEmpty(request.project_id)||!nonEmpty(request.workspace_id)||!nonEmpty(request.role)||typeof request.after_revision_id!=='string'||!Number.isSafeInteger(request.limit)||request.limit<1||request.limit>32||request.allowed_source_ids!==undefined&&(!Array.isArray(request.allowed_source_ids)||request.allowed_source_ids.length>512||!request.allowed_source_ids.every(nonEmpty)))throw new StorageError('INVALID_INPUT','Invalid Topic directory bounds');
    return this.db.transaction(()=>{
      const rows=this.db.prepare(`SELECT b.task_ref,b.task_version,v.revision_id,
        json_extract(v.payload_json,'$.source.source_id') AS source_id,
        json_extract(v.payload_json,'$.source.kind') AS source_kind
        FROM context_bindings b JOIN revisions v ON v.project_id=b.project_id AND v.revision_id=b.revision_id
        JOIN records r ON r.project_id=v.project_id AND r.record_id=v.record_id AND r.current_revision_id=v.revision_id
        WHERE b.project_id=? AND b.workspace_id=? AND v.revision_id>?
        AND EXISTS(SELECT 1 FROM json_each(b.payload_json,'$.roles') a WHERE a.value=?)
        AND EXISTS(SELECT 1 FROM json_each(b.payload_json,'$.allowed_source_ids') a WHERE a.value=json_extract(v.payload_json,'$.source.source_id'))
        AND (? IS NULL OR EXISTS(SELECT 1 FROM json_each(?) a WHERE a.value=json_extract(v.payload_json,'$.source.source_id')))
        AND (SELECT lifecycle FROM lifecycle_events l WHERE l.record_id=r.record_id ORDER BY l.rowid DESC LIMIT 1)='ACTIVE'
        ORDER BY v.revision_id LIMIT ?`).all(request.project_id,request.workspace_id,request.after_revision_id,request.role,request.allowed_source_ids===undefined?null:1,JSON.stringify(request.allowed_source_ids??[]),request.limit) as Array<{task_ref:string;task_version:string;revision_id:string;source_id:string;source_kind:string}>;
      for(const row of rows)if(![row.task_ref,row.task_version,row.revision_id,row.source_id,row.source_kind].every(nonEmpty))throw new StorageError('IDENTITY_CONFLICT','Topic pointer identity is incomplete');
      // Do not read a 33rd metadata sentinel. A full page is conservatively incomplete.
      return{items:rows,more:rows.length===request.limit};
    }).deferred();
  }

  readHostCandidateSource(projectId:string, source:SourceRef):Buffer|undefined {
    this.assertSafeDatabaseFiles();
    if(!nonEmpty(projectId))throw new StorageError('INVALID_INPUT','Project identity is required');
    const parsed=validateHostCandidateSourceRef(projectId,source); if(!parsed)return undefined;
    const rows=this.db.prepare('SELECT event_id FROM events WHERE project_id=? AND source_id=? ORDER BY rowid').all(projectId,source.source_id) as Array<{event_id:string}>;
    if(!rows.length)return undefined;
    let content:string|undefined;
    for(const row of rows){const event=this.getStoredEvent(projectId,source.source_id,row.event_id);if(!event||canonicalJson(event.source)!==canonicalJson(source)||event.kind!=='observation'||event.evidence_id!==null||sha256(event.content)!==parsed.digest)throw new StorageError('IDENTITY_CONFLICT','Host candidate event source is inconsistent');if(content!==undefined&&content!==event.content)throw new StorageError('IDENTITY_CONFLICT','Host candidate source maps to different content');content=event.content;}
    return content===undefined?undefined:Buffer.from(content,'utf8');
  }

  /**
   * Persist a report only after it is bound to a local configured collector, immutable artifact,
   * complete snapshot, and the same project/workspace/run identity as its event.
   */
  recordTrustedExecution(input: TrustedExecutionRequest): IngestReceipt {
    this.assertSafeDatabaseFiles();
    const event = validateEvent(structuredClone(input.event)); const evidence = validateEvidence(structuredClone(input.evidence)); const snapshot = validateSnapshot(structuredClone(input.snapshot));
    if (evidence.source.kind !== 'executor' || canonicalJson(event.source) !== canonicalJson(evidence.source)) throw new StorageError('UNTRUSTED_SOURCE', 'Trusted execution requires matching executor source identities');
    if (event.evidence_id !== evidence.evidence_id || event.project_id !== evidence.project_id || event.workspace_id !== evidence.workspace_id || event.run_id !== evidence.run_id) throw new StorageError('PROJECT_MISMATCH', 'Event and evidence must bind the same project, workspace, and run');
    if (snapshot.snapshot_id !== evidence.snapshot_id || snapshot.project_id !== evidence.project_id || snapshot.workspace_id !== evidence.workspace_id) throw new StorageError('PROJECT_MISMATCH', 'Snapshot must bind the evidence project and workspace');
    if (snapshot.manifest.completeness !== 'COMPLETE' || snapshot.manifest.external_state !== 'CONTROLLED') throw new StorageError('INPUT_INCOMPLETE', 'Trusted execution requires a complete controlled snapshot');
    if (!evidence.artifact_hash || sha256(input.report) !== evidence.artifact_hash || evidence.source.content_hash !== evidence.artifact_hash) throw new StorageError('ARTIFACT_CORRUPT', 'Report bytes must match both evidence and source hashes');
    const collector = this.db.prepare('SELECT project_id,source_id,locator,version FROM collector_registrations WHERE project_id=? AND source_id=? AND active=1').get(evidence.project_id, evidence.source.source_id) as CollectorRegistration | undefined;
    if (!collector || collector.locator !== evidence.source.locator || collector.version !== evidence.source.version) throw new StorageError('UNTRUSTED_SOURCE', 'Executor source is not an active configured collector identity');
    const receipt = this.ingest({ event, evidence, artifact: input.report, idempotencyKey: input.idempotencyKey });
    const source = evidence.source, receiptValue = { evidence_id:evidence.evidence_id, project_id:evidence.project_id, workspace_id:evidence.workspace_id, run_id:evidence.run_id, source_id:source.source_id, locator:source.locator, version:source.version, content_hash:source.content_hash, artifact_hash:evidence.artifact_hash, snapshot_id:snapshot.snapshot_id };
    const receiptHash = sha256(canonicalJson(receiptValue));
    this.db.transaction(() => {
      this.recordSnapshot(snapshot);
      const oldSource = this.db.prepare('SELECT project_id,workspace_id,run_id,source_id,locator,version,content_hash,artifact_hash,snapshot_id FROM source_versions WHERE evidence_id=?').get(evidence.evidence_id);
      if (oldSource) { if (canonicalJson(oldSource) !== canonicalJson(Object.fromEntries(Object.entries(receiptValue).filter(([key]) => key !== 'evidence_id')))) throw new StorageError('IDENTITY_CONFLICT', 'Evidence source version is immutable'); }
      else this.db.prepare('INSERT INTO source_versions(evidence_id,project_id,workspace_id,run_id,source_id,locator,version,content_hash,artifact_hash,snapshot_id) VALUES(?,?,?,?,?,?,?,?,?,?)').run(evidence.evidence_id,evidence.project_id,evidence.workspace_id,evidence.run_id,source.source_id,source.locator,source.version,source.content_hash,evidence.artifact_hash,snapshot.snapshot_id);
      const oldReceipt = this.db.prepare('SELECT receipt_hash,project_id,workspace_id,run_id,source_id,locator,version,content_hash,artifact_hash,snapshot_id FROM trusted_collector_receipts WHERE evidence_id=?').get(evidence.evidence_id) as ({ receipt_hash:string } & Record<string,string>) | undefined;
      if (oldReceipt) { const { receipt_hash, ...comparable } = oldReceipt; if (receipt_hash !== receiptHash || canonicalJson(comparable) !== canonicalJson(Object.fromEntries(Object.entries(receiptValue).filter(([key]) => key !== 'evidence_id'))) ) throw new StorageError('IDENTITY_CONFLICT', 'Trusted receipt is immutable'); }
      else this.db.prepare('INSERT INTO trusted_collector_receipts(evidence_id,receipt_hash,project_id,workspace_id,run_id,source_id,locator,version,content_hash,artifact_hash,snapshot_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(evidence.evidence_id,receiptHash,evidence.project_id,evidence.workspace_id,evidence.run_id,source.source_id,source.locator,source.version,source.content_hash,evidence.artifact_hash,snapshot.snapshot_id);
    })();
    return receipt;
  }
  /** Returns only a locally configured, complete, integrity-checked execution. */
  resolveTrustedExecution(evidenceId: string): StoredTrustedExecution | undefined {
    this.assertSafeDatabaseFiles(); if (!nonEmpty(evidenceId)) return undefined;
    try {
      const source = this.db.prepare('SELECT project_id,workspace_id,run_id,source_id,locator,version,content_hash,artifact_hash,snapshot_id FROM source_versions WHERE evidence_id=?').get(evidenceId) as Record<string,string> | undefined;
      const receipt = this.db.prepare('SELECT receipt_hash,project_id,workspace_id,run_id,source_id,locator,version,content_hash,artifact_hash,snapshot_id FROM trusted_collector_receipts WHERE evidence_id=?').get(evidenceId) as ({receipt_hash:string}&Record<string,string>) | undefined;
      const evidenceRow = this.db.prepare('SELECT payload_json FROM evidences WHERE evidence_id=?').get(evidenceId) as JsonRow | undefined;
      if (!source || !receipt || !evidenceRow) return undefined;
      const receiptValue = { evidence_id:evidenceId, ...source }; if (receipt.receipt_hash !== sha256(canonicalJson(receiptValue))) return undefined;
      const { receipt_hash: _receiptHash, ...comparable } = receipt; if (canonicalJson(comparable) !== canonicalJson(source)) return undefined;
      const collector = this.db.prepare('SELECT locator,version FROM collector_registrations WHERE project_id=? AND source_id=? AND active=1').get(source.project_id,source.source_id) as {locator:string;version:string}|undefined;
      if (!collector || collector.locator !== source.locator || collector.version !== source.version) return undefined;
      const evidence = validateEvidence(JSON.parse(evidenceRow.payload_json));
      if (evidence.project_id !== source.project_id || evidence.workspace_id !== source.workspace_id || evidence.run_id !== source.run_id || evidence.snapshot_id !== source.snapshot_id || canonicalJson(evidence.source) !== canonicalJson({source_id:source.source_id,kind:'executor',locator:source.locator,version:source.version,content_hash:source.content_hash}) || evidence.artifact_hash !== source.artifact_hash) return undefined;
      const snapshotRow = this.db.prepare('SELECT payload_json,payload_hash FROM snapshots WHERE snapshot_id=? AND project_id=? AND workspace_id=?').get(source.snapshot_id,source.project_id,source.workspace_id) as (JsonRow & {payload_hash:string}) | undefined;
      if (!snapshotRow) return undefined; const snapshot = validateSnapshot(JSON.parse(snapshotRow.payload_json));
      if (snapshotRow.payload_hash !== sha256(canonicalJson(snapshot)) || snapshot.snapshot_id!==source.snapshot_id || snapshot.project_id!==source.project_id || snapshot.workspace_id!==source.workspace_id) return undefined;
      if (snapshot.manifest.completeness !== 'COMPLETE' || snapshot.manifest.external_state !== 'CONTROLLED') return undefined;
      const artifact = this.readArtifact(source.artifact_hash).bytes;
      if (sha256(artifact) !== source.content_hash) return undefined;
      return { evidence, snapshot, artifact };
    } catch { return undefined; }
  }
  /** The denormalized registry columns are integrity commitments, never query hints alone. */
  private decodeStoredFailedAttempt(row: FailedAttemptRow): FailedAttempt {
    let attempt: FailedAttempt;
    try { attempt = validateFailedAttempt(JSON.parse(row.payload_json)); } catch { throw new StorageError('IDENTITY_CONFLICT', 'Stored failed attempt payload is invalid'); }
    const payload = canonicalJson(attempt), observableArgs = canonicalJson(attempt.action.observable_args), conditions = canonicalJson(attempt.condition_fingerprints);
    if (row.failed_attempt_id !== attempt.failed_attempt_id || row.project_id !== attempt.project_id || row.workspace_id !== attempt.workspace_id || row.action_id !== attempt.action.action_id || row.observable_args_json !== observableArgs || row.observable_args_hash !== sha256(observableArgs) || row.condition_fingerprints_json !== conditions || row.condition_fingerprints_hash !== sha256(conditions) || row.failure_evidence_id !== attempt.failure_evidence.evidence_id || row.payload_hash !== sha256(payload)) throw new StorageError('IDENTITY_CONFLICT', 'Stored failed attempt integrity binding does not match its payload');
    return attempt;
  }
  private readStoredFailedAttempts(database: Database.Database = this.db, where = '', parameters: unknown[] = []): FailedAttempt[] {
    const rows = database.prepare(`SELECT ${FAILED_ATTEMPT_COLUMNS} FROM failed_attempts ${where} ORDER BY rowid`).all(...parameters) as FailedAttemptRow[];
    return rows.map(row => this.decodeStoredFailedAttempt(row));
  }
  /**
   * Append one immutable failure observation. Its embedded evidence must exactly match
   * an already authoritative evidence row; this prevents an agent-supplied JSON copy
   * from being treated as a separate proof.
   */
  recordFailedAttempt(input: FailedAttempt): FailedAttempt {
    this.assertSafeDatabaseFiles(); const attempt = validateFailedAttempt(structuredClone(input)); const payload = canonicalJson(attempt), payloadHash = sha256(payload);
    const evidenceRow = this.db.prepare('SELECT project_id,payload_json FROM evidences WHERE evidence_id=?').get(attempt.failure_evidence.evidence_id) as ({project_id:string;payload_json:string}|undefined);
    if (!evidenceRow) throw new StorageError('SOURCE_MISSING', 'Failed attempt evidence must already be stored');
    if (evidenceRow.project_id !== attempt.project_id || evidenceRow.payload_json !== canonicalJson(attempt.failure_evidence)) throw new StorageError('IDENTITY_CONFLICT', 'Failed attempt evidence must bind the authoritative stored evidence');
    const prior = this.db.prepare(`SELECT ${FAILED_ATTEMPT_COLUMNS} FROM failed_attempts WHERE failed_attempt_id=?`).get(attempt.failed_attempt_id) as (FailedAttemptRow|undefined);
    if (prior) { this.decodeStoredFailedAttempt(prior); if (prior.payload_hash !== payloadHash || prior.payload_json !== payload) throw new StorageError('IDENTITY_CONFLICT', 'Failed attempt identity is immutable'); return attempt; }
    this.db.prepare('INSERT INTO failed_attempts(failed_attempt_id,project_id,workspace_id,action_id,observable_args_hash,observable_args_json,condition_fingerprints_hash,condition_fingerprints_json,failure_evidence_id,payload_hash,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(attempt.failed_attempt_id,attempt.project_id,attempt.workspace_id,attempt.action.action_id,sha256(canonicalJson(attempt.action.observable_args)),canonicalJson(attempt.action.observable_args),sha256(canonicalJson(attempt.condition_fingerprints)),canonicalJson(attempt.condition_fingerprints),attempt.failure_evidence.evidence_id,payloadHash,payload);
    return attempt;
  }
  /** Reads immutable same-scope records. Corrupt rows are not returned as usable records. */
  queryFailedAttempts(requestInput: FailureCheckRequest): FailedAttempt[] {
    this.assertSafeDatabaseFiles(); const request = validateFailureCheckRequest(structuredClone(requestInput));
    const exactArgsHash = sha256(canonicalJson(request.action.observable_args));
    const exact: FailedAttempt[] = [], related: FailedAttempt[] = [];
    const rows = this.db.prepare(`SELECT ${FAILED_ATTEMPT_COLUMNS} FROM failed_attempts WHERE project_id=? AND workspace_id=? ORDER BY rowid`).all(request.project_id,request.workspace_id) as FailedAttemptRow[];
    for (const row of rows) try { const attempt = this.decodeStoredFailedAttempt(row); if (attempt.project_id !== request.project_id || attempt.workspace_id !== request.workspace_id) continue; if (attempt.action.action_id === request.action.action_id && sha256(canonicalJson(attempt.action.observable_args)) === exactArgsHash) exact.push(attempt); else if (attempt.error_signature !== null && attempt.error_signature === request.error_signature) related.push(attempt); } catch { /* Corrupt historical data is deliberately unavailable. */ }
    return [...exact, ...related].map(value => structuredClone(value));
  }
  /** Evaluates storage-held records through storage-held M3 provenance, never caller claims. */
  decideFailedAttempt(requestInput: FailureCheckRequest): FailureRegistryDecision {
    const request = validateFailureCheckRequest(structuredClone(requestInput)); const attempts = this.queryFailedAttempts(request);
    const decisions = attempts.map(attempt => matchFailedAttempt(attempt, request, { resolve: evidenceId => this.resolveTrustedExecution(evidenceId) }));
    const rank: Record<FailureRegistryDecision['outcome'], number> = { EXACT_KNOWN_FAILURE: 4, CONDITION_CHANGED: 3, POSSIBLY_RELATED: 2, UNKNOWN: 1 };
    const outcome = decisions.reduce<FailureRegistryDecision['outcome']>((best, current) => rank[current.outcome] > rank[best] ? current.outcome : best, 'UNKNOWN');
    return { outcome, decisions };
  }
  private validateCollector(input: CollectorRegistration): CollectorRegistration {
    if (!input || !nonEmpty(input.project_id) || !nonEmpty(input.source_id) || !nonEmpty(input.locator) || !nonEmpty(input.version) || Object.keys(input).sort().join(',') !== 'locator,project_id,source_id,version') throw new StorageError('INVALID_INPUT', 'Collector registration is invalid');
    return structuredClone(input);
  }

  private decodeStoredExtractionCandidate(row: ExtractionCandidateRow): ExtractionCandidate {
    try { const candidate=validateExtractionCandidate(JSON.parse(row.payload_json)); const payload=canonicalJson(candidate); if(row.payload_hash!==sha256(payload)||candidate.candidate_id!==row.candidate_id||candidate.request_id!==row.request_id||candidate.project_id!==row.project_id||candidate.workspace_id!==row.workspace_id||candidate.event_id!==row.event_id||candidate.evidence_id!==row.evidence_id||candidate.source_slice.content_hash!==row.source_slice_hash) throw new StorageError('IDENTITY_CONFLICT','Extraction candidate row is corrupt'); return candidate; }
    catch(error){if(error instanceof StorageError)throw error;throw new StorageError('IDENTITY_CONFLICT','Extraction candidate payload is corrupt');}
  }
  private decodeStoredExtractionAttempt(row: ExtractionAttemptRow): ExtractionAttempt {
    try { const attempt=validateExtractionAttempt(JSON.parse(row.payload_json)); const payload=canonicalJson(attempt), commitment=canonicalJson(attempt.request); if(row.payload_hash!==sha256(payload)||attempt.attempt_id!==row.attempt_id||attempt.request_id!==row.request_id||attempt.candidate_id!==row.candidate_id||attempt.project_id!==row.project_id||attempt.workspace_id!==row.workspace_id||attempt.event_id!==row.event_id||attempt.evidence_id!==row.evidence_id||attempt.request.source.source_id!==row.source_id||attempt.request.source_slice.content_hash!==row.source_slice_hash||attempt.request.extractor_version!==row.extractor_version||sha256(canonicalJson(attempt.request.extractor_config))!==row.extractor_config_hash||attempt.request.provider_id!==row.provider_id||sha256(commitment)!==row.request_commitment_hash||attempt.outcome!==row.outcome) throw new StorageError('IDENTITY_CONFLICT','Extraction attempt row is corrupt'); return attempt; }
    catch(error){if(error instanceof StorageError)throw error;throw new StorageError('IDENTITY_CONFLICT','Extraction attempt payload is corrupt');}
  }
  private readStoredExtractionCandidates(database: Database.Database = this.db): ExtractionCandidate[] { const rows=database.prepare('SELECT candidate_id,request_id,project_id,workspace_id,event_id,evidence_id,source_slice_hash,payload_hash,payload_json FROM extraction_candidates ORDER BY rowid').all() as ExtractionCandidateRow[]; return rows.map(row=>structuredClone(this.decodeStoredExtractionCandidate(row))); }
  private readStoredExtractionAttempts(database: Database.Database = this.db): ExtractionAttempt[] { const rows=database.prepare('SELECT attempt_id,request_id,candidate_id,project_id,workspace_id,event_id,evidence_id,source_id,source_slice_hash,extractor_version,extractor_config_hash,provider_id,request_commitment_hash,outcome,payload_hash,payload_json FROM extraction_attempts ORDER BY rowid').all() as ExtractionAttemptRow[]; return rows.map(row=>structuredClone(this.decodeStoredExtractionAttempt(row))); }
  /** Persist one terminal extraction outcome. Reusing a request identity is a replay only when all bound content agrees. */
  persistExtractionOutcome(candidateInput: ExtractionCandidate | null, attemptInput: ExtractionAttempt): { candidate: ExtractionCandidate | null; attempt: ExtractionAttempt; replayed: boolean } {
    this.assertSafeDatabaseFiles(); const candidate=candidateInput===null?null:validateExtractionCandidate(structuredClone(candidateInput)), attempt=validateExtractionAttempt(structuredClone(attemptInput));
    if((candidate===null)!==(attempt.candidate_id===null)||candidate&& (attempt.candidate_id!==candidate.candidate_id||attempt.request_id!==candidate.request_id||attempt.project_id!==candidate.project_id||attempt.workspace_id!==candidate.workspace_id||attempt.event_id!==candidate.event_id||attempt.evidence_id!==candidate.evidence_id))throw new StorageError('INVALID_INPUT','Extraction candidate and attempt must bind exactly');
    const event=this.getStoredEvent(attempt.project_id,attempt.request.source.source_id,attempt.event_id); if(!event||event.workspace_id!==attempt.workspace_id||event.evidence_id!==attempt.evidence_id||canonicalJson(event.source)!==canonicalJson(attempt.request.source)||attempt.request.source_slice.locator!==event.source.locator||attempt.request.source_slice.content_hash!==event.source.content_hash)throw new StorageError('SOURCE_MISSING','Extraction outcome must bind an authoritative event and source slice');
    if(candidate&&(canonicalJson(candidate.source)!==canonicalJson(event.source)||candidate.source_slice.locator!==attempt.request.source_slice.locator||candidate.source_slice.content_hash!==attempt.request.source_slice.content_hash||candidate.extractor_version!==attempt.request.extractor_version||canonicalJson(candidate.extractor_config)!==canonicalJson(attempt.request.extractor_config)))throw new StorageError('IDENTITY_CONFLICT','Extraction candidate is not bound to its request commitment');
    if(attempt.evidence_id!==null){const evidence=this.getStoredEvidence(attempt.evidence_id);if(!evidence||evidence.project_id!==attempt.project_id||evidence.workspace_id!==attempt.workspace_id||evidence.run_id!==event.run_id)throw new StorageError('IDENTITY_CONFLICT','Extraction attempt is not bound to authoritative evidence');}
    const tx=this.db.transaction(()=>{const prior=this.db.prepare('SELECT attempt_id,request_id,candidate_id,project_id,workspace_id,event_id,evidence_id,source_id,source_slice_hash,extractor_version,extractor_config_hash,provider_id,request_commitment_hash,outcome,payload_hash,payload_json FROM extraction_attempts WHERE request_id=?').get(attempt.request_id) as ExtractionAttemptRow|undefined; if(prior){const old=this.decodeStoredExtractionAttempt(prior);if(canonicalJson(old)!==canonicalJson(attempt))throw new StorageError('IDENTITY_CONFLICT','Extraction request identity was reused with changed payload');if(candidate){const stored=this.db.prepare('SELECT candidate_id,request_id,project_id,workspace_id,event_id,evidence_id,source_slice_hash,payload_hash,payload_json FROM extraction_candidates WHERE candidate_id=?').get(candidate.candidate_id) as ExtractionCandidateRow|undefined;if(!stored||canonicalJson(this.decodeStoredExtractionCandidate(stored))!==canonicalJson(candidate))throw new StorageError('IDENTITY_CONFLICT','Extraction replay candidate is not immutable');}return{candidate,attempt,replayed:true};}
      if(candidate){const payload=canonicalJson(candidate),old=this.db.prepare('SELECT candidate_id,request_id,project_id,workspace_id,event_id,evidence_id,source_slice_hash,payload_hash,payload_json FROM extraction_candidates WHERE candidate_id=? OR request_id=?').all(candidate.candidate_id,candidate.request_id) as ExtractionCandidateRow[];if(old.length)throw new StorageError('IDENTITY_CONFLICT','Extraction candidate identity already exists');this.db.prepare('INSERT INTO extraction_candidates(candidate_id,request_id,project_id,workspace_id,event_id,evidence_id,source_slice_hash,payload_hash,payload_json) VALUES(?,?,?,?,?,?,?,?,?)').run(candidate.candidate_id,candidate.request_id,candidate.project_id,candidate.workspace_id,candidate.event_id,candidate.evidence_id,candidate.source_slice.content_hash,sha256(payload),payload);}
      const payload=canonicalJson(attempt), commitment=canonicalJson(attempt.request);this.db.prepare('INSERT INTO extraction_attempts(attempt_id,request_id,candidate_id,project_id,workspace_id,event_id,evidence_id,source_id,source_slice_hash,extractor_version,extractor_config_hash,provider_id,request_commitment_hash,outcome,payload_hash,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(attempt.attempt_id,attempt.request_id,attempt.candidate_id,attempt.project_id,attempt.workspace_id,attempt.event_id,attempt.evidence_id,attempt.request.source.source_id,attempt.request.source_slice.content_hash,attempt.request.extractor_version,sha256(canonicalJson(attempt.request.extractor_config)),attempt.request.provider_id,sha256(commitment),attempt.outcome,sha256(payload),payload);return{candidate,attempt,replayed:false};});
    try{return tx();}catch(error){if(error instanceof StorageError)throw error;throw new StorageError('STORAGE_ERROR','Could not persist extraction outcome');}
  }
  getExtractionCandidate(candidateId:string):ExtractionCandidate|undefined { this.assertSafeDatabaseFiles();if(!nonEmpty(candidateId))throw new StorageError('INVALID_INPUT','Extraction candidate identity is required');const row=this.db.prepare('SELECT candidate_id,request_id,project_id,workspace_id,event_id,evidence_id,source_slice_hash,payload_hash,payload_json FROM extraction_candidates WHERE candidate_id=?').get(candidateId) as ExtractionCandidateRow|undefined;return row?structuredClone(this.decodeStoredExtractionCandidate(row)):undefined; }
  /** Explicitly turns one retained candidate into a normal append-only memory revision. */
  promoteExtractionCandidate(input: ExtractionPromotionRequest): { created:boolean; revision_id:string } { this.assertSafeDatabaseFiles();if(!input||!nonEmpty(input.candidate_id)||!nonEmpty(input.actor)||!nonEmpty(input.reason))throw new StorageError('INVALID_INPUT','Candidate promotion needs candidate, actor, and reason');const candidate=this.getExtractionCandidate(input.candidate_id);if(!candidate)throw new StorageError('SOURCE_MISSING','Extraction candidate does not exist');const record=validateMemoryRecord(structuredClone(input.record));if(record.project_id!==candidate.project_id||canonicalJson(record.source)!==canonicalJson(candidate.source)||record.kind!==candidate.output.kind||record.content!==candidate.output.content||record.epistemic_state!==candidate.output.epistemic_state||record.information_role!==candidate.output.information_role)throw new StorageError('IDENTITY_CONFLICT','Promotion record must preserve candidate source and proposed content');
    return this.db.transaction(()=>{const existing=this.db.prepare('SELECT project_id,current_revision_id FROM records WHERE record_id=?').get(record.record_id) as {project_id:string;current_revision_id:string}|undefined;if(this.db.prepare('SELECT revision_id FROM revisions WHERE revision_id=?').get(record.revision_id))throw new StorageError('IDENTITY_CONFLICT','Revision identity already exists');if(!existing){if(record.previous_revision_id!==null)throw new StorageError('IDENTITY_CONFLICT','Initial revision cannot name a predecessor');this.db.prepare('INSERT INTO records(record_id,project_id,current_revision_id) VALUES(?,?,?)').run(record.record_id,record.project_id,record.revision_id);}else{if(existing.project_id!==record.project_id||existing.current_revision_id!==record.previous_revision_id)throw new StorageError('IDENTITY_CONFLICT','Promotion revision must extend current state');this.db.prepare('UPDATE records SET current_revision_id=? WHERE record_id=?').run(record.revision_id,record.record_id);}this.db.prepare('INSERT INTO revisions(revision_id,record_id,project_id,previous_revision_id,payload_json,created_at) VALUES(?,?,?,?,?,?)').run(record.revision_id,record.record_id,record.project_id,record.previous_revision_id,canonicalJson(record),new Date().toISOString());this.insertLifecycle({event_id:randomUUID(),record_id:record.record_id,revision_id:record.revision_id,lifecycle:record.lifecycle,actor:input.actor,source:`extraction-candidate:${candidate.candidate_id}`,reason:input.reason,occurred_at:new Date().toISOString()});return{created:!existing,revision_id:record.revision_id};})();
  }

  appendRevision(recordInput: MemoryRecord, reason = 'recorded'): { created: boolean; revision_id: string } { this.assertSafeDatabaseFiles(); const record = validateMemoryRecord(structuredClone(recordInput)); if (!nonEmpty(reason)) throw new StorageError('INVALID_INPUT','Lifecycle reason is required'); return this.db.transaction(() => { const existing = this.db.prepare('SELECT project_id,current_revision_id FROM records WHERE record_id=?').get(record.record_id) as { project_id:string; current_revision_id:string } | undefined; if (this.db.prepare('SELECT revision_id FROM revisions WHERE revision_id=?').get(record.revision_id)) throw new StorageError('IDENTITY_CONFLICT','Revision identity already exists'); if (!existing) { if (record.previous_revision_id !== null) throw new StorageError('IDENTITY_CONFLICT','Initial revision cannot name a predecessor'); this.db.prepare('INSERT INTO records(record_id,project_id,current_revision_id) VALUES(?,?,?)').run(record.record_id,record.project_id,record.revision_id); } else { if (existing.project_id !== record.project_id) throw new StorageError('PROJECT_MISMATCH','Record identity cannot move projects'); if (existing.current_revision_id !== record.previous_revision_id) throw new StorageError('IDENTITY_CONFLICT','Revision must extend current state'); this.db.prepare('UPDATE records SET current_revision_id=? WHERE record_id=?').run(record.revision_id,record.record_id); } this.db.prepare('INSERT INTO revisions(revision_id,record_id,project_id,previous_revision_id,payload_json,created_at) VALUES(?,?,?,?,?,?)').run(record.revision_id,record.record_id,record.project_id,record.previous_revision_id,canonicalJson(record),new Date().toISOString()); this.insertLifecycle({event_id:randomUUID(),record_id:record.record_id,revision_id:record.revision_id,lifecycle:record.lifecycle,actor:'storage',source:record.source.source_id,reason,occurred_at:new Date().toISOString()}); return {created:!existing,revision_id:record.revision_id}; })(); }
  appendLifecycle(recordId: string, lifecycle: Lifecycle, reason: string, actor = 'storage', source = 'local'): LifecycleEvent { this.assertSafeDatabaseFiles(); return this.db.transaction(() => { if (!nonEmpty(recordId) || !LIFECYCLES.includes(lifecycle) || !nonEmpty(reason) || !nonEmpty(actor) || !nonEmpty(source)) throw new StorageError('INVALID_INPUT','Lifecycle event needs state, actor, source, and reason'); const record = this.db.prepare('SELECT current_revision_id FROM records WHERE record_id=?').get(recordId) as {current_revision_id:string}|undefined; if (!record) throw new StorageError('SOURCE_MISSING','Record does not exist'); const entry: LifecycleEvent={event_id:randomUUID(),record_id:recordId,revision_id:record.current_revision_id,lifecycle,actor,source,reason,occurred_at:new Date().toISOString()}; this.insertLifecycle(entry); return entry; })(); }
  private validateOwnership(recordId:string, revisionId:string): void { const revision=this.db.prepare('SELECT project_id,record_id FROM revisions WHERE revision_id=?').get(revisionId) as {project_id:string;record_id:string}|undefined; const record=this.db.prepare('SELECT project_id FROM records WHERE record_id=?').get(recordId) as {project_id:string}|undefined; if (!revision || !record) throw new StorageError('SOURCE_MISSING','Lifecycle reference does not exist'); if (revision.record_id!==recordId || revision.project_id!==record.project_id) throw new StorageError('PROJECT_MISMATCH','Lifecycle revision must belong to its record and project'); }
  private insertLifecycle(entry: LifecycleEvent): void { this.validateLifecycle(entry); this.validateOwnership(entry.record_id,entry.revision_id); const prior=this.db.prepare('SELECT event_id,record_id,revision_id,lifecycle,actor,source,reason,occurred_at FROM lifecycle_events WHERE event_id=?').get(entry.event_id) as LifecycleEvent|undefined; if (prior) { if (canonicalJson(prior)!==canonicalJson(entry)) throw new StorageError('IDENTITY_CONFLICT','Lifecycle identity already exists with different content'); return; } this.db.prepare('INSERT INTO lifecycle_events(event_id,record_id,revision_id,lifecycle,actor,source,reason,occurred_at) VALUES(?,?,?,?,?,?,?,?)').run(entry.event_id,entry.record_id,entry.revision_id,entry.lifecycle,entry.actor,entry.source,entry.reason,entry.occurred_at); }
  addRelation(input: Relation): void { this.assertSafeDatabaseFiles(); const relation=validateRelation(structuredClone(input)), payload=canonicalJson(relation); const prior=this.db.prepare('SELECT payload_json FROM relations WHERE relation_id=?').get(relation.relation_id) as JsonRow|undefined; if(prior){if(prior.payload_json!==payload)throw new StorageError('IDENTITY_CONFLICT','Relation identity already exists with different content');return;} const endpoints=this.db.prepare('SELECT project_id FROM revisions WHERE revision_id IN (?,?)').all(relation.from_revision_id,relation.to_revision_id) as Array<{project_id:string}>; if(endpoints.length!==2)throw new StorageError('SOURCE_MISSING','Relation revisions must already exist'); if(endpoints.some(x=>x.project_id!==relation.project_id))throw new StorageError('PROJECT_MISMATCH','Relation endpoints must belong to its project'); this.db.prepare('INSERT INTO relations(relation_id,project_id,from_revision_id,to_revision_id,payload_json) VALUES(?,?,?,?,?)').run(relation.relation_id,relation.project_id,relation.from_revision_id,relation.to_revision_id,payload); }
  private validateContextBinding(input: unknown): ContextBinding {
    const value = requireExactKeys(input, ['revision_id','project_id','workspace_id','task_ref','task_version','roles','allowed_source_ids','mandatory','priority','conflicts'], 'Context binding');
    const lists = ['roles','allowed_source_ids','conflicts'] as const;
    if (!nonEmpty(value.revision_id) || !nonEmpty(value.project_id) || !nonEmpty(value.workspace_id) || !nonEmpty(value.task_ref) || !nonEmpty(value.task_version) || lists.some(key => !Array.isArray(value[key]) || !(value[key] as unknown[]).every(nonEmpty) || new Set(value[key] as string[]).size !== (value[key] as string[]).length) || typeof value.mandatory !== 'boolean' || !Number.isFinite(value.priority)) throw new StorageError('INVALID_INPUT','Invalid context binding');
    return { ...(value as unknown as ContextBinding), roles:[...(value.roles as string[])].sort(), allowed_source_ids:[...(value.allowed_source_ids as string[])].sort(), conflicts:[...(value.conflicts as string[])].sort() };
  }
  /** Bind a canonical revision to an explicit task/workspace/role/source policy. */
  bindContextRevision(input: ContextBinding): ContextBinding {
    this.assertSafeDatabaseFiles(); const binding = this.validateContextBinding(structuredClone(input)); const revision = this.db.prepare('SELECT project_id FROM revisions WHERE revision_id=?').get(binding.revision_id) as {project_id:string}|undefined;
    if (!revision) throw new StorageError('SOURCE_MISSING','Context binding revision does not exist'); if (revision.project_id !== binding.project_id) throw new StorageError('PROJECT_MISMATCH','Context binding revision belongs to another project');
    const payload_json = canonicalContextJson(binding), payload_hash = sha256(payload_json); const prior = this.db.prepare('SELECT payload_json,payload_hash FROM context_bindings WHERE revision_id=?').get(binding.revision_id) as {payload_json:string;payload_hash:string}|undefined;
    if (prior) { if (prior.payload_json !== payload_json || prior.payload_hash !== payload_hash) throw new StorageError('IDENTITY_CONFLICT','Context binding is immutable'); return structuredClone(binding); }
    this.db.prepare('INSERT INTO context_bindings(revision_id,project_id,workspace_id,task_ref,task_version,payload_hash,payload_json) VALUES(?,?,?,?,?,?,?)').run(binding.revision_id,binding.project_id,binding.workspace_id,binding.task_ref,binding.task_version,payload_hash,payload_json); return structuredClone(binding);
  }
  /** Alias retained for adapters that describe metadata rather than the binding action. */
  registerContextBinding(input: ContextBinding): ContextBinding { return this.bindContextRevision(input); }
  private readStoredContextBindings(where = '', params: unknown[] = [], database: Database.Database = this.db): ContextBinding[] {
    const rows = database.prepare(`SELECT revision_id,project_id,workspace_id,task_ref,task_version,payload_hash,payload_json FROM context_bindings ${where} ORDER BY revision_id`).all(...params) as Array<ContextBinding & {payload_hash:string;payload_json:string}>;
    return rows.map(row => { const binding = this.validateContextBinding(JSON.parse(row.payload_json)); if (binding.revision_id !== row.revision_id || binding.project_id !== row.project_id || binding.workspace_id !== row.workspace_id || binding.task_ref !== row.task_ref || binding.task_version !== row.task_version || row.payload_hash !== sha256(canonicalContextJson(binding))) throw new StorageError('IDENTITY_CONFLICT','Stored context binding integrity mismatch'); return binding; });
  }
  private readStoredContextManifests(database: Database.Database = this.db): ContextManifest[] {
    const rows=database.prepare('SELECT content_hash,project_id,workspace_id,task_ref,task_version,request_hash,binding_hash,source_snapshot_hash,view_snapshot_hash,manifest_hash,payload_json FROM context_manifests ORDER BY content_hash').all() as Array<ContextManifest & {project_id:string;workspace_id:string;task_ref:string;task_version:string;payload_json:string}>;
    return rows.map(row=>{const manifest=this.validateContextManifest(JSON.parse(row.payload_json)); const request=manifest.request; if(manifest.content_hash!==row.content_hash||request.project_id!==row.project_id||request.workspace_id!==row.workspace_id||request.task_ref!==row.task_ref||request.task_version!==row.task_version||manifest.request_hash!==row.request_hash||manifest.binding_hash!==row.binding_hash||manifest.source_snapshot_hash!==row.source_snapshot_hash||manifest.view_snapshot_hash!==row.view_snapshot_hash||manifest.manifest_hash!==row.manifest_hash)throw new StorageError('IDENTITY_CONFLICT','Stored context manifest integrity mismatch');return manifest;});
  }
  /** Load only revisions explicitly registered to this exact task. Keep all
   * bound history for integrity/mandatory checks; do not decode unrelated task
   * history or materialize every project's lifecycle log in JavaScript. */
  private readBoundContextRows(bindings: ContextBinding[]): Array<{revision_id:string;record_id:string;payload_json:string;current_revision_id:string;current_lifecycle:Lifecycle}> {
    if (!bindings.length) return [];
    return this.db.prepare(`WITH selected AS (
      SELECT v.revision_id,v.record_id,v.payload_json,r.current_revision_id
      FROM json_each(?) ids JOIN revisions v ON v.revision_id=ids.value
      JOIN records r ON r.record_id=v.record_id AND r.project_id=v.project_id
      WHERE v.project_id=?
    ), latest AS (
      SELECT l.record_id,MAX(l.rowid) AS latest_rowid FROM lifecycle_events l
      WHERE l.record_id IN (SELECT record_id FROM selected) GROUP BY l.record_id
    ) SELECT s.*,l.lifecycle AS current_lifecycle FROM selected s
      LEFT JOIN latest ON latest.record_id=s.record_id
      LEFT JOIN lifecycle_events l ON l.rowid=latest.latest_rowid
      ORDER BY s.revision_id`).all(JSON.stringify(bindings.map(binding=>binding.revision_id)),bindings[0].project_id) as Array<{revision_id:string;record_id:string;payload_json:string;current_revision_id:string;current_lifecycle:Lifecycle}>;
  }
  /** Read-only, fixed database view. The caller cannot use a role by itself to expand access. */
  readContextView(request: Pick<ContextRequest,'project_id'|'workspace_id'|'task_ref'|'task_version'|'role'|'allowed_source_ids'>): ContextView {
    this.assertSafeDatabaseFiles(); if (!request || !nonEmpty(request.project_id) || !nonEmpty(request.workspace_id) || !nonEmpty(request.task_ref) || !nonEmpty(request.task_version) || !nonEmpty(request.role) || !Array.isArray(request.allowed_source_ids) || !request.allowed_source_ids.every(nonEmpty)) throw new StorageError('INVALID_INPUT','Invalid context view request');
    const bindings = this.readStoredContextBindings('WHERE project_id=? AND workspace_id=? AND task_ref=? AND task_version=?',[request.project_id,request.workspace_id,request.task_ref,request.task_version]);
    const revisionRows=this.readBoundContextRows(bindings);
    const records = new Map(revisionRows.map(row => { const record=validateMemoryRecord(JSON.parse(row.payload_json)); const active=row.current_revision_id===row.revision_id && row.current_lifecycle==='ACTIVE'; return [row.revision_id,{...record,lifecycle:active?'ACTIVE':'SUPERSEDED' as Lifecycle}]; }));
    // A denied task/role mandatory constraint must not silently disappear. Return
    // a generic blocker without disclosing the hidden source, revision, or content.
    for (const binding of bindings) {
      const record=records.get(binding.revision_id);
      if (binding.mandatory && binding.roles.includes(request.role) && (!record || (record.lifecycle==='ACTIVE' && (!request.allowed_source_ids.includes(record.source.source_id) || !binding.allowed_source_ids.includes(record.source.source_id))))) throw new StorageError('INPUT_INCOMPLETE','Required task context is unavailable within the requested scope');
    }
    const permitted = bindings.filter(binding => binding.roles.includes(request.role) && binding.allowed_source_ids.some(id => request.allowed_source_ids.includes(id))).map(binding => ({ binding, record:records.get(binding.revision_id) })).filter((entry): entry is {binding:ContextBinding;record:MemoryRecord} => !!entry.record && entry.record.lifecycle === 'ACTIVE' && request.allowed_source_ids.includes(entry.record.source.source_id) && entry.binding.allowed_source_ids.includes(entry.record.source.source_id));
    const ids = new Set(permitted.map(entry => entry.record.revision_id)); const relations = this.db.prepare('SELECT payload_json FROM relations WHERE project_id=? ORDER BY relation_id').all(request.project_id) as JsonRow[];
    const edges = relations.map(row => validateRelation(JSON.parse(row.payload_json))).filter(relation => ids.has(relation.from_revision_id) && ids.has(relation.to_revision_id)).map(relation => ({from:relation.from_revision_id,to:relation.to_revision_id,type:relation.type}));
    const snapshot_hash = sha256(canonicalContextJson({entries:permitted.map(entry => ({record:entry.record,binding:entry.binding})),edges})); return {entries:permitted.map(entry => ({record:structuredClone(entry.record),binding:structuredClone(entry.binding)})),edges,snapshot_hash};
  }
  /** V2.1 read-only candidate scan. SQL filters exact scope, current lifecycle and
   * original ACL and explicit selectors before the 512-body ceiling. No denied
   * or irrelevant counts leave this view.
   * This is deliberately separate from the established ContextPack read path. */
  readEngineeringContextView(request: {project_id:string;workspace_id:string;task_ref:string;task_version:string;role:string;allowed_source_ids?:string[];revision_id?:string;include_history?:boolean;selectors?:{files:string[];modules:string[];topics:string[];terms:string[]}},selectorPlan?:EngineeringSelectorPlan): {view:ContextView;incomplete:boolean} {
    this.assertSafeDatabaseFiles();
    for(const key of ['project_id','workspace_id','task_ref','task_version','role'] as const)if(!nonEmpty(request?.[key]))throw new StorageError('INVALID_INPUT','Exact engineering scope required');
    if(request.allowed_source_ids!==undefined&&(!Array.isArray(request.allowed_source_ids)||request.allowed_source_ids.length>512||!request.allowed_source_ids.every(nonEmpty)))throw new StorageError('INVALID_INPUT','Invalid source narrowing');
    if(request.revision_id!==undefined&&!nonEmpty(request.revision_id))throw new StorageError('INVALID_INPUT','Invalid revision');
    if(request.include_history!==undefined&&(typeof request.include_history!=='boolean'||!request.revision_id))throw new StorageError('INVALID_INPUT','Historical metadata requires one exact revision');
    if(request.selectors){
      for(const key of ['files','modules','topics','terms'] as const)if(!Array.isArray(request.selectors[key])||request.selectors[key].length>(key==='terms'?128:16)||!request.selectors[key].every(nonEmpty))throw new StorageError('INVALID_INPUT','Invalid engineering selector');
    }
    // The fixed compiler alone creates plans. Live SQL always applies ACL/current/source filters.
    this.db.function('xmem_engineering_selected',{deterministic:true},engineeringSelectorPredicate(request.selectors,selectorPlan));
    // These keys only diversify the bounded candidate view. Every revision is
    // still independently checked by the established compiler; nothing is
    // semantically merged, granted authority or removed from stored history.
    this.db.function('xmem_engineering_body_key',{deterministic:true},(payload:unknown)=>{
      try{return sha256(canonicalContextJson(JSON.parse(String(payload)).content));}catch{return sha256(String(payload));}
    });
    this.db.function('xmem_engineering_type_order',{deterministic:true},(payload:unknown)=>{
      try{
        const saved=JSON.parse(String(payload));let projected:unknown;
        try{const value=JSON.parse(saved.content);if(value?.format==='xmem-engineering/1')projected=value.information_type;}catch{ /* Legacy bodies use their stored kind. */ }
        const classes=['CONSTRAINT','DECISION','INTERFACE','FAILURE','UNKNOWN','NOTE'];
        if(typeof projected==='string'&&classes.includes(projected))return classes.indexOf(projected);
        return saved.kind==='ConstraintRef'?0:saved.kind==='DecisionRef'?1:saved.kind==='FailedAttempt'?3:saved.kind==='RootCauseHypothesis'?4:5;
      }catch{return 5;}
    });
    return this.db.transaction(()=>{
      const rows=this.db.prepare(`WITH permitted AS (SELECT v.revision_id AS stored_revision_id,v.record_id AS stored_record_id,b.payload_json AS binding_json,b.payload_hash AS binding_hash,v.payload_json AS record_json,
        json_extract(b.payload_json,'$.mandatory') AS is_required,xmem_engineering_body_key(v.payload_json) AS body_key,xmem_engineering_type_order(v.payload_json) AS type_order,
        r.current_revision_id AS current_revision_id,(SELECT lifecycle FROM lifecycle_events l WHERE l.record_id=r.record_id ORDER BY l.rowid DESC LIMIT 1) AS current_lifecycle,
        EXISTS(SELECT 1 FROM json_each(b.payload_json,'$.allowed_source_ids') s WHERE s.value=json_extract(v.payload_json,'$.source.source_id')) AS source_permitted
        FROM context_bindings b JOIN revisions v ON v.revision_id=b.revision_id AND v.project_id=b.project_id
        JOIN records r ON r.record_id=v.record_id AND r.project_id=v.project_id AND (r.current_revision_id=v.revision_id OR ?=1)
        WHERE b.project_id=? AND b.workspace_id=? AND b.task_ref=? AND b.task_version=?
        AND EXISTS(SELECT 1 FROM json_each(b.payload_json,'$.roles') a WHERE a.value=?)
        AND ((SELECT lifecycle FROM lifecycle_events l WHERE l.record_id=r.record_id ORDER BY l.rowid DESC LIMIT 1)='ACTIVE' OR ?=1)
        AND (? IS NULL OR v.revision_id=?)
        AND (json_extract(b.payload_json,'$.mandatory')=1 OR xmem_engineering_selected(json_extract(v.payload_json,'$.content'))=1)
        AND ((EXISTS(SELECT 1 FROM json_each(b.payload_json,'$.allowed_source_ids') s WHERE s.value=json_extract(v.payload_json,'$.source.source_id'))
          AND (? IS NULL OR EXISTS(SELECT 1 FROM json_each(?) a WHERE a.value=json_extract(v.payload_json,'$.source.source_id'))))
          OR json_extract(b.payload_json,'$.mandatory')=1)
        ), body_ranked AS (
          SELECT *,row_number() OVER(PARTITION BY is_required,body_key ORDER BY stored_revision_id) AS body_position FROM permitted
        ), class_ranked AS (
          SELECT *,row_number() OVER(PARTITION BY is_required,type_order ORDER BY body_position,stored_revision_id) AS class_position FROM body_ranked
        ) SELECT * FROM class_ranked ORDER BY is_required DESC,class_position,type_order,stored_revision_id LIMIT 513`).all(
          Number(request.include_history===true),request.project_id,request.workspace_id,request.task_ref,request.task_version,request.role,Number(request.include_history===true),
          request.revision_id??null,request.revision_id??null,
          request.allowed_source_ids===undefined?null:1,JSON.stringify(request.allowed_source_ids??[])) as Array<{stored_revision_id:string;stored_record_id:string;binding_json:string;binding_hash:string;record_json:string;source_permitted:number;current_revision_id:string;current_lifecycle:Lifecycle}>;
      let bytes=0;
      const entries=rows.slice(0,512).map(row=>{
        const binding=this.validateContextBinding(JSON.parse(row.binding_json)),record=validateMemoryRecord(JSON.parse(row.record_json));
        if(sha256(canonicalContextJson(binding))!==row.binding_hash||record.revision_id!==row.stored_revision_id||record.record_id!==row.stored_record_id||binding.revision_id!==record.revision_id||binding.project_id!==record.project_id||binding.project_id!==request.project_id||binding.workspace_id!==request.workspace_id||binding.task_ref!==request.task_ref||binding.task_version!==request.task_version)throw new StorageError('IDENTITY_CONFLICT','Engineering view integrity mismatch');
        if(!row.source_permitted||request.allowed_source_ids!==undefined&&!request.allowed_source_ids.includes(record.source.source_id))throw new StorageError('INPUT_INCOMPLETE','Required task context unavailable within requested sources');
        const size=Buffer.byteLength(record.content,'utf8');bytes+=size;
        if(size>16384||bytes>8*1024*1024)throw new StorageError('INPUT_INCOMPLETE','Engineering candidate processing bound exceeded');
        const isCurrent=row.current_revision_id===record.revision_id&&row.current_lifecycle==='ACTIVE';
        return{record:isCurrent?record:{...record,lifecycle:'SUPERSEDED' as const},binding};
      });
      return{view:{entries,edges:[],snapshot_hash:sha256(canonicalContextJson(entries))},incomplete:rows.length>512};
    }).deferred();
  }
  /** Conservative negative guard, not positive dependency enrollment or ancestor traversal. */
  readEngineeringDependencyBoundary(request:Pick<ContextRequest,'project_id'|'workspace_id'|'task_ref'|'task_version'|'role'>&{allowed_source_ids?:string[];allow_history?:boolean},entries:readonly ContextView['entries'][number][]):string {
    this.assertSafeDatabaseFiles();
    if(this.db.inTransaction)throw new StorageError('INPUT_INCOMPLETE','Dependency guard requires an independent read snapshot');
    for(const key of ['project_id','workspace_id','task_ref','task_version','role'] as const)if(!nonEmpty(request?.[key]))throw new StorageError('INVALID_INPUT','Exact dependency scope required');
    if(entries.length>512)throw new StorageError('INPUT_INCOMPLETE','Dependency root bound exceeded');
    const ids=entries.map(e=>e.record.revision_id);if(new Set(ids).size!==ids.length)throw new StorageError('IDENTITY_CONFLICT','Duplicate dependency roots');
    return this.db.transaction(()=>{
      const roots=this.db.prepare(`SELECT v.revision_id,v.record_id,v.project_id,r.current_revision_id,
        c.record_id AS current_record_id,c.project_id AS current_project_id,b.payload_hash AS binding_hash,
        json_extract(v.payload_json,'$.source.source_id') AS source_id,
        l.event_id,l.revision_id AS event_revision_id,l.lifecycle,
        EXISTS(SELECT 1 FROM json_each(b.payload_json,'$.allowed_source_ids') s WHERE s.value=json_extract(v.payload_json,'$.source.source_id')) AS source_permitted
        FROM revisions v JOIN json_each(?) selected ON selected.value=v.revision_id
        JOIN records r ON r.record_id=v.record_id AND r.project_id=v.project_id
        LEFT JOIN revisions c ON c.revision_id=r.current_revision_id
        JOIN context_bindings b ON b.revision_id=v.revision_id AND b.project_id=v.project_id
        LEFT JOIN lifecycle_events l ON l.rowid=(SELECT max(x.rowid) FROM lifecycle_events x WHERE x.record_id=v.record_id)
        WHERE b.project_id=? AND b.workspace_id=? AND b.task_ref=? AND b.task_version=?
        AND EXISTS(SELECT 1 FROM json_each(b.payload_json,'$.roles') role WHERE role.value=?)
        ORDER BY v.revision_id LIMIT 513`).all(JSON.stringify(ids),request.project_id,request.workspace_id,request.task_ref,request.task_version,request.role) as Array<{revision_id:string;record_id:string;project_id:string;current_revision_id:string;current_record_id:string;current_project_id:string;binding_hash:string;source_id:string;event_id:string;event_revision_id:string;lifecycle:string;source_permitted:number}>;
      if(roots.length!==ids.length)throw new StorageError('INPUT_INCOMPLETE','Dependency roots unavailable within live scope');
      const original=new Map(entries.map(e=>[e.record.revision_id,e]));
      for(const root of roots){const entry=original.get(root.revision_id)!;
        if(root.project_id!==request.project_id||root.current_record_id!==root.record_id||root.current_project_id!==root.project_id||root.event_revision_id!==root.current_revision_id||!['ACTIVE','SUPERSEDED','RETRACTED'].includes(root.lifecycle)||request.allow_history!==true&&(root.current_revision_id!==root.revision_id||root.lifecycle!=='ACTIVE')||!nonEmpty(root.event_id)||root.binding_hash!==sha256(canonicalContextJson(entry.binding))||root.source_id!==entry.record.source.source_id)throw new StorageError('IDENTITY_CONFLICT','Dependency root changed');
        if(!root.source_permitted||request.allowed_source_ids!==undefined&&!request.allowed_source_ids.includes(root.source_id))throw new StorageError('INPUT_INCOMPLETE','Dependency root permission narrowed');
      }
      // Check row sentinel and byte lengths before retrieving relation JSON.
      const headers=this.db.prepare(`SELECT relation_id,project_id,from_revision_id,to_revision_id,length(CAST(payload_json AS BLOB)) AS bytes
        FROM relations WHERE from_revision_id IN(SELECT value FROM json_each(?)) ORDER BY relation_id LIMIT 257`).all(JSON.stringify(ids)) as Array<{relation_id:string;project_id:string;from_revision_id:string;to_revision_id:string;bytes:number}>;
      let bytes=Buffer.byteLength(canonicalContextJson(roots),'utf8')+Buffer.byteLength(canonicalContextJson(headers),'utf8');
      if(headers.length>256||headers.some(h=>!Number.isSafeInteger(h.bytes)||h.bytes<1)||headers.reduce((s,h)=>s+h.bytes,bytes)>262144)throw new StorageError('INPUT_INCOMPLETE','Dependency metadata bound exceeded');
      const payloads=this.db.prepare('SELECT relation_id,payload_json FROM relations WHERE relation_id IN(SELECT value FROM json_each(?)) ORDER BY relation_id').all(JSON.stringify(headers.map(h=>h.relation_id))) as Array<{relation_id:string;payload_json:string}>;
      if(payloads.length!==headers.length)throw new StorageError('IDENTITY_CONFLICT','Dependency collection changed');
      const relations=payloads.map((row,index)=>{const header=headers[index],relation=validateRelation(JSON.parse(row.payload_json));
        bytes+=Buffer.byteLength(row.payload_json,'utf8');
        if(bytes>262144||Buffer.byteLength(row.payload_json,'utf8')!==header.bytes||row.relation_id!==header.relation_id||relation.relation_id!==header.relation_id||relation.project_id!==header.project_id||relation.project_id!==request.project_id||relation.from_revision_id!==header.from_revision_id||relation.to_revision_id!==header.to_revision_id||!original.has(relation.from_revision_id)||canonicalJson(relation)!==row.payload_json)throw new StorageError('IDENTITY_CONFLICT','Dependency relation integrity mismatch');
        return relation;
      });
      if(relations.some(r=>r.type==='DERIVED_FROM'||r.type==='SUPPORTED_BY'))throw new StorageError('INPUT_INCOMPLETE','Dependency registration authority unavailable');
      return sha256(canonicalContextJson({roots,relations}));
    }).deferred();
  }
  /** Internal SDK enrollment. Already-open connection safety is retained here. */
  readEngineeringEnrollment(context:EnrollmentContext,relationIds:readonly string[]):ReturnType<typeof readEnrollmentRelations>{
    this.assertSafeDatabaseFiles();return readEnrollmentRelations(this.db,context,relationIds);
  }
  /** Internal positive path; public results contain no frontier/ancestor identities. */
  observeEngineeringDependencyGraph(context:EnrollmentContext,roots:readonly string[],state:EnrollmentState,ledger:EngineeringDependencyLedger,reader:(source:SourceRef)=>Buffer|undefined):string {
    this.assertSafeDatabaseFiles();return observeEngineeringDependencies(this.db,context,roots,state,ledger,reader);
  }
  assertEngineeringDependencySourceAllowed(context:EnrollmentContext,source:SourceRef,ledger:EngineeringDependencyLedger):void {
    this.assertSafeDatabaseFiles();assertEngineeringSourceAllowed(this.db,context,source,ledger);
  }
  getContextView(request: Pick<ContextRequest,'project_id'|'workspace_id'|'task_ref'|'task_version'|'role'|'allowed_source_ids'>): ContextView { return this.readContextView(request); }
  /** R3 host helper: discover only source IDs already authorized by active bindings for one configured role. No content or locators are returned. */
  listActiveContextSourceIds(request: {project_id:string;workspace_id:string;task_ref:string;task_version:string;role:string}): {source_ids:string[];revision_ids:string[]} {
    this.assertSafeDatabaseFiles();
    if (!request || !nonEmpty(request.project_id)||!nonEmpty(request.workspace_id)||!nonEmpty(request.task_ref)||!nonEmpty(request.task_version)||!nonEmpty(request.role)) throw new StorageError('INVALID_INPUT','Invalid standalone context scope');
    const bindings=this.readStoredContextBindings('WHERE project_id=? AND workspace_id=? AND task_ref=? AND task_version=?',[request.project_id,request.workspace_id,request.task_ref,request.task_version]);
    const rows=new Map(this.readBoundContextRows(bindings).map(row=>[row.revision_id,{row,record:validateMemoryRecord(JSON.parse(row.payload_json))}]));
    const selected=bindings.filter(binding=>binding.roles.includes(request.role)).flatMap(binding=>{const item=rows.get(binding.revision_id);if(!item||item.row.current_revision_id!==binding.revision_id||item.row.current_lifecycle!=='ACTIVE')return [];if(!binding.allowed_source_ids.includes(item.record.source.source_id))throw new StorageError('IDENTITY_CONFLICT','Binding does not authorize its active record source');return [{revision_id:binding.revision_id,source_id:item.record.source.source_id}];});
    return {source_ids:[...new Set(selected.map(x=>x.source_id))].sort(),revision_ids:[...new Set(selected.map(x=>x.revision_id))].sort()};
  }
  private validateContextManifest(input: unknown): ContextManifest {
    const pack = structuredClone(input) as ContextManifest; const keys = ['kind','compiler_version','policy_version','budget_unit','request','payload','payload_bytes','content_hash','request_hash','binding_hash','source_snapshot_hash','view_snapshot_hash','coverage','traversal_incomplete','revisions','manifest_hash'];
    if (!pack || Object.keys(pack).sort().join(',') !== [...keys].sort().join(',') || pack.kind !== 'ContextPack' || pack.compiler_version !== 'context-v2' || !['context-policy-v1','context-policy-v2','context-policy-v3','context-policy-v4','context-policy-v5'].includes(pack.policy_version) || pack.budget_unit !== 'utf8-bytes' || !nonEmpty(pack.content_hash) || !nonEmpty(pack.manifest_hash) || !nonEmpty(pack.request_hash) || !nonEmpty(pack.binding_hash) || !nonEmpty(pack.source_snapshot_hash) || !nonEmpty(pack.view_snapshot_hash) || !Number.isSafeInteger(pack.payload_bytes) || pack.payload_bytes !== Buffer.byteLength(pack.payload,'utf8') || !Array.isArray(pack.coverage) || !Array.isArray(pack.revisions)) throw new StorageError('INVALID_INPUT','Invalid context manifest');
    const {content_hash,manifest_hash,...body} = pack; if (content_hash !== sha256(canonicalContextJson(body)) || manifest_hash !== sha256(canonicalContextJson({...body,content_hash}))) throw new StorageError('IDENTITY_CONFLICT','Context manifest hash mismatch'); return pack;
  }
  /** Persist derived audit material only. This never writes events, evidence, records, or relations. */
  persistContextManifest(pack: ContextPack): ContextManifest {
    this.assertSafeDatabaseFiles(); const draft = {...structuredClone(pack),manifest_hash:sha256(canonicalContextJson(pack))}; const manifest = this.validateContextManifest(draft); const request = manifest.request;
    const view = this.readContextView(request); if (view.snapshot_hash !== manifest.view_snapshot_hash) throw new StorageError('SOURCE_MISSING','Context manifest database snapshot is stale');
    const prior = this.db.prepare('SELECT payload_json,manifest_hash FROM context_manifests WHERE content_hash=?').get(manifest.content_hash) as {payload_json:string;manifest_hash:string}|undefined; const payload_json=canonicalContextJson(manifest);
    if (prior) { if (prior.payload_json !== payload_json || prior.manifest_hash !== manifest.manifest_hash) throw new StorageError('IDENTITY_CONFLICT','Context manifest identity conflicts'); return structuredClone(manifest); }
    this.db.prepare('INSERT INTO context_manifests(content_hash,project_id,workspace_id,task_ref,task_version,request_hash,binding_hash,source_snapshot_hash,view_snapshot_hash,manifest_hash,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(manifest.content_hash,request.project_id,request.workspace_id,request.task_ref,request.task_version,manifest.request_hash,manifest.binding_hash,manifest.source_snapshot_hash,manifest.view_snapshot_hash,manifest.manifest_hash,payload_json); return structuredClone(manifest);
  }
  saveContextManifest(pack: ContextPack): ContextManifest { return this.persistContextManifest(pack); }
  getContextManifest(contentHash: string, request?: ContextRequest): ContextManifest | undefined {
    this.assertSafeDatabaseFiles(); if(!nonEmpty(contentHash)) throw new StorageError('INVALID_INPUT','Context manifest identity is required'); const manifest=this.readStoredContextManifests().find(item=>item.content_hash===contentHash); if (!manifest) return undefined; if (request) { if (canonicalContextJson(manifest.request) !== canonicalContextJson({...request,allowed_source_ids:[...request.allowed_source_ids].sort()})) throw new StorageError('IDENTITY_CONFLICT','Context manifest request does not match'); const view=this.readContextView(request); if (view.snapshot_hash !== manifest.view_snapshot_hash) throw new StorageError('SOURCE_MISSING','Context manifest database snapshot is stale'); } return structuredClone(manifest);
  }
  /** R3.1.2 fast-path lookup. Only exact request identity and the current context policy are reusable. */
  getLatestReusableContextManifest(request: ContextRequest): ContextManifest | undefined {
    this.assertSafeDatabaseFiles();
    const normalized={...structuredClone(request),allowed_source_ids:[...request.allowed_source_ids].sort()};
    const rows=this.db.prepare('SELECT payload_json FROM context_manifests WHERE project_id=? AND workspace_id=? AND task_ref=? AND task_version=? ORDER BY rowid DESC').all(request.project_id,request.workspace_id,request.task_ref,request.task_version) as JsonRow[];
    for(const row of rows){
      const manifest=this.validateContextManifest(JSON.parse(row.payload_json));
      if(manifest.policy_version!=='context-policy-v5')continue;
      if(canonicalContextJson(manifest.request)!==canonicalContextJson(normalized))continue;
      return structuredClone(manifest);
    }
    return undefined;
  }
  /** Latest scope material is telemetry only; it must never be used as an authority shortcut. */
  getLatestContextManifestForScope(projectId:string,workspaceId:string,taskRef:string,taskVersion:string):ContextManifest|undefined {
    this.assertSafeDatabaseFiles();
    if(![projectId,workspaceId,taskRef,taskVersion].every(nonEmpty))throw new StorageError('INVALID_INPUT','Context scope is required');
    const row=this.db.prepare('SELECT payload_json FROM context_manifests WHERE project_id=? AND workspace_id=? AND task_ref=? AND task_version=? ORDER BY rowid DESC LIMIT 1').get(projectId,workspaceId,taskRef,taskVersion) as JsonRow|undefined;
    return row?structuredClone(this.validateContextManifest(JSON.parse(row.payload_json))):undefined;
  }
  private validHash(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }
  /** Source declarations are an exact derived index of the revision/evidence references. */
  private canonicalHandoffSources(revisions: readonly HandoffRevisionRef[], evidence: readonly HandoffEvidenceRef[]): SourceRef[] {
    const all=[...revisions.map(ref=>ref.source),...evidence.map(ref=>ref.source)].map(ref=>structuredClone(ref));
    all.sort((left,right)=>canonicalJson(left).localeCompare(canonicalJson(right),'en'));
    return all.filter((value,index)=>index===0||canonicalJson(value)!==canonicalJson(all[index-1]));
  }
  private validateHandoffPackage(input: unknown): HandoffPackage {
    const x=requireExactKeys(input,['kind','protocol_version','package_id','content_hash','project_id','workspace_id','task_ref','task_version','target_snapshot_id','target_snapshot_hash','source_refs','revision_refs','evidence_refs','failed_attempt_refs','context_manifest_hash','context_coverage','completed','pending','blocked','next_steps'],'Handoff package');
    const ids=['package_id','project_id','workspace_id','task_ref','task_version','target_snapshot_id','context_manifest_hash'];
    if(x.kind!=='HandoffPackage'||x.protocol_version!=='handoff-v1'||ids.some(key=>!nonEmpty(x[key]))||!this.validHash(x.content_hash)||!this.validHash(x.target_snapshot_hash)||!Array.isArray(x.source_refs)||!Array.isArray(x.revision_refs)||!Array.isArray(x.evidence_refs)||!Array.isArray(x.failed_attempt_refs)||!Array.isArray(x.context_coverage))throw new StorageError('INVALID_INPUT','Invalid handoff package');
    const strings=['completed','pending','blocked','next_steps'] as const;
    for(const key of strings)if(!Array.isArray(x[key])||!(x[key] as unknown[]).every(nonEmpty)||new Set(x[key] as string[]).size!==(x[key] as string[]).length)throw new StorageError('INVALID_INPUT','Invalid handoff text list');
    const packageValue=x as unknown as HandoffPackage;
    const revisions=packageValue.revision_refs.map(ref=>{if(!ref||!nonEmpty(ref.record_id)||!nonEmpty(ref.revision_id)||!this.validHash(ref.payload_hash))throw new StorageError('INVALID_INPUT','Invalid handoff revision');return ref;});
    const evidence=packageValue.evidence_refs.map(ref=>{if(!ref||!nonEmpty(ref.evidence_id)||!this.validHash(ref.payload_hash)||!nonEmpty(ref.snapshot_id)||!(ref.artifact_hash===null||this.validHash(ref.artifact_hash)))throw new StorageError('INVALID_INPUT','Invalid handoff evidence');return ref;});
    const failures=packageValue.failed_attempt_refs.map(ref=>{if(!ref||!nonEmpty(ref.failed_attempt_id)||!this.validHash(ref.payload_hash))throw new StorageError('INVALID_INPUT','Invalid handoff failure');return ref;});
    const sources=packageValue.source_refs.map(ref=>{if(!ref||!nonEmpty(ref.source_id)||!nonEmpty(ref.locator)||!nonEmpty(ref.version)||!this.validHash(ref.content_hash))throw new StorageError('INVALID_INPUT','Invalid handoff source');return ref;});
    if(new Set(revisions.map(ref=>ref.revision_id)).size!==revisions.length||new Set(evidence.map(ref=>ref.evidence_id)).size!==evidence.length||new Set(failures.map(ref=>ref.failed_attempt_id)).size!==failures.length||new Set(sources.map(ref=>`${ref.source_id}\0${ref.locator}\0${ref.version}\0${ref.content_hash}`)).size!==sources.length)throw new StorageError('INVALID_INPUT','Handoff references must be unique');
    if(canonicalJson(sources)!==canonicalJson(this.canonicalHandoffSources(revisions,evidence)))throw new StorageError('IDENTITY_CONFLICT','Handoff source references are not bound to package material');
    for(const coverage of packageValue.context_coverage)if(!coverage||!nonEmpty(coverage.revision_id)||!['included_inline','available_by_reference','missing','stale','conflicting','deferred'].includes(coverage.state)||!nonEmpty(coverage.reason))throw new StorageError('INVALID_INPUT','Invalid handoff coverage');
    const {content_hash,package_id:_packageId,...body}=packageValue; if(content_hash!==sha256(canonicalJson(body)))throw new StorageError('IDENTITY_CONFLICT','Handoff package content hash mismatch');
    if(packageValue.package_id!==`handoff-${content_hash}`)throw new StorageError('IDENTITY_CONFLICT','Handoff package identity is not canonical');
    return structuredClone(packageValue);
  }
  private readStoredHandoffPackages(database: Database.Database = this.db): HandoffPackage[] {
    const rows=database.prepare('SELECT package_id,project_id,workspace_id,task_ref,task_version,content_hash,target_snapshot_id,target_snapshot_hash,context_manifest_hash,payload_json FROM handoff_packages ORDER BY package_id').all() as Array<Record<string,string>>;
    return rows.map(row=>{const pack=this.validateHandoffPackage(JSON.parse(row.payload_json));if(pack.package_id!==row.package_id||pack.project_id!==row.project_id||pack.workspace_id!==row.workspace_id||pack.task_ref!==row.task_ref||pack.task_version!==row.task_version||pack.content_hash!==row.content_hash||pack.target_snapshot_id!==row.target_snapshot_id||pack.target_snapshot_hash!==row.target_snapshot_hash||pack.context_manifest_hash!==row.context_manifest_hash)throw new StorageError('IDENTITY_CONFLICT','Stored handoff package integrity mismatch');return pack;});
  }
  private readStoredHandoffReceipts(database: Database.Database = this.db): Omit<HandoffReceipt,'replayed'>[] {
    const packs=new Map(this.readStoredHandoffPackages(database).map(pack=>[pack.package_id,pack])); const rows=database.prepare('SELECT recipient_id,package_id,content_hash,validation_status,action,reason_codes_json,receipt_hash FROM handoff_receipts ORDER BY recipient_id,package_id').all() as Array<{recipient_id:string;package_id:string;content_hash:string;validation_status:HandoffValidationStatus;action:'ACCEPTED'|'REJECTED';reason_codes_json:string;receipt_hash:string}>;
    return rows.map(row=>{let reason_codes:unknown;try{reason_codes=JSON.parse(row.reason_codes_json);}catch{throw new StorageError('IDENTITY_CONFLICT','Stored handoff receipt reason codes are invalid');}if(!nonEmpty(row.recipient_id)||!packs.has(row.package_id)||packs.get(row.package_id)!.content_hash!==row.content_hash||!['VALID','STALE','INCOMPLETE','UNKNOWN'].includes(row.validation_status)||!['ACCEPTED','REJECTED'].includes(row.action)||!Array.isArray(reason_codes)||!reason_codes.every(nonEmpty)||new Set(reason_codes).size!==reason_codes.length)throw new StorageError('IDENTITY_CONFLICT','Stored handoff receipt integrity mismatch');const body={recipient_id:row.recipient_id,package_id:row.package_id,content_hash:row.content_hash,validation_status:row.validation_status,action:row.action,reason_codes};if(row.receipt_hash!==sha256(canonicalJson(body)))throw new StorageError('IDENTITY_CONFLICT','Stored handoff receipt hash mismatch');return{...body,receipt_hash:row.receipt_hash} as Omit<HandoffReceipt,'replayed'>;});
  }
  buildHandoffMaterial(input: HandoffMaterialRequest): Omit<HandoffPackage,'kind'|'protocol_version'|'package_id'|'content_hash'> {
    this.assertSafeDatabaseFiles(); const request=structuredClone(input); if(!request||!nonEmpty(request.project_id)||!nonEmpty(request.workspace_id)||!nonEmpty(request.task_ref)||!nonEmpty(request.task_version)||!Array.isArray(request.revision_ids)||!Array.isArray(request.evidence_ids)||!Array.isArray(request.failed_attempt_ids)||!nonEmpty(request.context_manifest_hash))throw new StorageError('INVALID_INPUT','Invalid handoff material request');
    const target=validateSnapshot(request.target_snapshot); if(target.project_id!==request.project_id||target.workspace_id!==request.workspace_id)throw new StorageError('PROJECT_MISMATCH','Handoff snapshot scope mismatch'); const target_hash=sha256(canonicalJson(target));
    const storedTarget=this.db.prepare('SELECT payload_json,payload_hash FROM snapshots WHERE snapshot_id=? AND project_id=? AND workspace_id=?').get(target.snapshot_id,target.project_id,target.workspace_id) as {payload_json:string;payload_hash:string}|undefined;
    if(!storedTarget)throw new StorageError('SOURCE_MISSING','Handoff target snapshot is not stored'); if(storedTarget.payload_hash!==target_hash||storedTarget.payload_json!==canonicalJson(target))throw new StorageError('IDENTITY_CONFLICT','Handoff target snapshot integrity mismatch');
    const revision_refs=request.revision_ids.map(revision_id=>{const row=this.db.prepare('SELECT record_id,project_id,payload_json FROM revisions WHERE revision_id=?').get(revision_id) as {record_id:string;project_id:string;payload_json:string}|undefined;if(!row)throw new StorageError('SOURCE_MISSING','Handoff revision is missing');const record=validateMemoryRecord(JSON.parse(row.payload_json));if(row.project_id!==request.project_id||record.project_id!==request.project_id)throw new StorageError('PROJECT_MISMATCH','Handoff revision belongs to another project');return{record_id:row.record_id,revision_id,payload_hash:sha256(canonicalJson(record)),source:record.source};}).sort((a,b)=>a.revision_id.localeCompare(b.revision_id,'en'));
    const evidence_refs=request.evidence_ids.map(evidence_id=>{const row=this.db.prepare('SELECT project_id,payload_json FROM evidences WHERE evidence_id=?').get(evidence_id) as {project_id:string;payload_json:string}|undefined;if(!row)throw new StorageError('SOURCE_MISSING','Handoff evidence is missing');const evidence=validateEvidence(JSON.parse(row.payload_json));if(row.project_id!==request.project_id||evidence.project_id!==request.project_id||evidence.workspace_id!==request.workspace_id)throw new StorageError('PROJECT_MISMATCH','Handoff evidence belongs to another scope');if(evidence.artifact_hash)this.readArtifact(evidence.artifact_hash);return{evidence_id,payload_hash:sha256(canonicalJson(evidence)),source:evidence.source,artifact_hash:evidence.artifact_hash,snapshot_id:evidence.snapshot_id};}).sort((a,b)=>a.evidence_id.localeCompare(b.evidence_id,'en'));
    const failed_attempt_refs=request.failed_attempt_ids.map(failed_attempt_id=>{const row=this.db.prepare(`SELECT ${FAILED_ATTEMPT_COLUMNS} FROM failed_attempts WHERE failed_attempt_id=?`).get(failed_attempt_id) as FailedAttemptRow|undefined;if(!row)throw new StorageError('SOURCE_MISSING','Handoff failed attempt is missing');const attempt=this.decodeStoredFailedAttempt(row);if(attempt.project_id!==request.project_id||attempt.workspace_id!==request.workspace_id)throw new StorageError('PROJECT_MISMATCH','Handoff failed attempt belongs to another scope');return{failed_attempt_id,payload_hash:row.payload_hash};}).sort((a,b)=>a.failed_attempt_id.localeCompare(b.failed_attempt_id,'en'));
    const manifest=this.readStoredContextManifests().find(item=>item.content_hash===request.context_manifest_hash);if(!manifest)throw new StorageError('SOURCE_MISSING','Handoff context manifest is missing');if(manifest.request.project_id!==request.project_id||manifest.request.workspace_id!==request.workspace_id||manifest.request.task_ref!==request.task_ref||manifest.request.task_version!==request.task_version||manifest.request.target_snapshot_id!==target.snapshot_id)throw new StorageError('PROJECT_MISMATCH','Handoff context manifest scope mismatch');if(revision_refs.some(ref=>!manifest.revisions.includes(ref.revision_id)))throw new StorageError('PROJECT_MISMATCH','Handoff revision is outside the task context manifest');const view=this.readContextView(manifest.request);if(view.snapshot_hash!==manifest.view_snapshot_hash)throw new StorageError('SOURCE_MISSING','Handoff context manifest is stale');
    const sources=this.canonicalHandoffSources(revision_refs,evidence_refs);
    const lists=['completed','pending','blocked','next_steps'] as const;for(const key of lists)if(!Array.isArray(request[key])||!request[key].every(nonEmpty)||new Set(request[key]).size!==request[key].length)throw new StorageError('INVALID_INPUT','Handoff list is invalid');
    return {project_id:request.project_id,workspace_id:request.workspace_id,task_ref:request.task_ref,task_version:request.task_version,target_snapshot_id:target.snapshot_id,target_snapshot_hash:target_hash,source_refs:sources,revision_refs,evidence_refs,failed_attempt_refs,context_manifest_hash:manifest.content_hash,context_coverage:structuredClone(manifest.coverage),completed:[...request.completed].sort(),pending:[...request.pending].sort(),blocked:[...request.blocked].sort(),next_steps:[...request.next_steps].sort()};
  }
  persistHandoffPackage(input: HandoffPackage): HandoffPackage { this.assertSafeDatabaseFiles(); const pack=this.validateHandoffPackage(input); const payload_json=canonicalJson(pack); const prior=this.db.prepare('SELECT payload_json,content_hash FROM handoff_packages WHERE package_id=?').get(pack.package_id) as {payload_json:string;content_hash:string}|undefined; if(prior){if(prior.payload_json!==payload_json||prior.content_hash!==pack.content_hash)throw new StorageError('IDENTITY_CONFLICT','Handoff package identity conflicts');return structuredClone(pack);} this.db.prepare('INSERT INTO handoff_packages(package_id,project_id,workspace_id,task_ref,task_version,content_hash,target_snapshot_id,target_snapshot_hash,context_manifest_hash,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?)').run(pack.package_id,pack.project_id,pack.workspace_id,pack.task_ref,pack.task_version,pack.content_hash,pack.target_snapshot_id,pack.target_snapshot_hash,pack.context_manifest_hash,payload_json);return structuredClone(pack); }
  getHandoffPackage(packageId:string):HandoffPackage|undefined { this.assertSafeDatabaseFiles();if(!nonEmpty(packageId))throw new StorageError('INVALID_INPUT','Handoff package identity is required');return this.readStoredHandoffPackages().find(pack=>pack.package_id===packageId); }
  /** Latest immutable handoff for one exact task scope; used only as optional R3 session continuity metadata. */
  getLatestHandoffPackage(projectId:string,workspaceId:string,taskRef:string,taskVersion:string,role?:string):HandoffPackage|undefined {
    this.assertSafeDatabaseFiles();
    if (![projectId,workspaceId,taskRef,taskVersion].every(nonEmpty)||(role!==undefined&&!nonEmpty(role))) throw new StorageError('INVALID_INPUT','Handoff scope is required');
    // Role is bound by the immutable context manifest, not by a caller declaration
    // inside the handoff. Preserve legacy callers' scope when no role is supplied.
    const rows=this.db.prepare('SELECT package_id FROM handoff_packages WHERE project_id=? AND workspace_id=? AND task_ref=? AND task_version=? ORDER BY rowid DESC').iterate(projectId,workspaceId,taskRef,taskVersion) as Iterable<{package_id:string}>;
    for(const row of rows){const pack=this.getHandoffPackage(row.package_id);if(!pack)throw new StorageError('IDENTITY_CONFLICT','Stored handoff disappeared');if(role===undefined||this.getContextManifest(pack.context_manifest_hash)?.request.role===role)return pack;}
    return undefined;
  }
  validateHandoff(packageId:string): HandoffValidation { this.assertSafeDatabaseFiles(); let pack:HandoffPackage|undefined;try{pack=this.getHandoffPackage(packageId);}catch{return{package_id:packageId,content_hash:'',status:'UNKNOWN',reason_codes:['STORAGE_INTEGRITY_ERROR']};}if(!pack)return{package_id:packageId,content_hash:'',status:'INCOMPLETE',reason_codes:['PACKAGE_MISSING']};const fail=(status:HandoffValidationStatus,code:string):HandoffValidation=>({package_id:pack.package_id,content_hash:pack.content_hash,status,reason_codes:[code]});try{const snapshot=this.db.prepare('SELECT payload_json,payload_hash FROM snapshots WHERE snapshot_id=? AND project_id=? AND workspace_id=?').get(pack.target_snapshot_id,pack.project_id,pack.workspace_id) as {payload_json:string;payload_hash:string}|undefined;if(!snapshot)return fail('INCOMPLETE','TARGET_SNAPSHOT_MISSING');const parsed=validateSnapshot(JSON.parse(snapshot.payload_json));if(snapshot.payload_hash!==sha256(canonicalJson(parsed)))return fail('UNKNOWN','TARGET_SNAPSHOT_CORRUPT');if(snapshot.payload_hash!==pack.target_snapshot_hash)return fail('STALE','TARGET_SNAPSHOT_DRIFT');for(const ref of pack.revision_refs){const row=this.db.prepare('SELECT record_id,project_id,payload_json FROM revisions WHERE revision_id=?').get(ref.revision_id) as {record_id:string;project_id:string;payload_json:string}|undefined;if(!row)return fail('INCOMPLETE','REVISION_MISSING');const record=validateMemoryRecord(JSON.parse(row.payload_json));if(row.record_id!==ref.record_id||row.project_id!==pack.project_id||canonicalJson(record.source)!==canonicalJson(ref.source)||sha256(canonicalJson(record))!==ref.payload_hash)return fail('STALE','REVISION_DRIFT');const current=this.db.prepare('SELECT current_revision_id FROM records WHERE record_id=?').get(ref.record_id) as {current_revision_id:string}|undefined;const lifecycle=this.db.prepare('SELECT lifecycle FROM lifecycle_events WHERE record_id=? ORDER BY rowid DESC LIMIT 1').get(ref.record_id) as {lifecycle:Lifecycle}|undefined;if(!current||!lifecycle)return fail('INCOMPLETE','REVISION_SOURCE_MISSING');if(current.current_revision_id!==ref.revision_id||lifecycle.lifecycle==='RETRACTED')return fail('STALE','REVISION_RETRACTED');}for(const ref of pack.evidence_refs){const row=this.db.prepare('SELECT project_id,payload_json FROM evidences WHERE evidence_id=?').get(ref.evidence_id) as {project_id:string;payload_json:string}|undefined;if(!row)return fail('INCOMPLETE','EVIDENCE_MISSING');const evidence=validateEvidence(JSON.parse(row.payload_json));if(row.project_id!==pack.project_id||evidence.workspace_id!==pack.workspace_id||canonicalJson(evidence.source)!==canonicalJson(ref.source)||evidence.snapshot_id!==ref.snapshot_id||evidence.artifact_hash!==ref.artifact_hash||sha256(canonicalJson(evidence))!==ref.payload_hash)return fail('STALE','EVIDENCE_DRIFT');if(evidence.artifact_hash)this.readArtifact(evidence.artifact_hash);}for(const ref of pack.failed_attempt_refs){const row=this.db.prepare(`SELECT ${FAILED_ATTEMPT_COLUMNS} FROM failed_attempts WHERE failed_attempt_id=?`).get(ref.failed_attempt_id) as FailedAttemptRow|undefined;if(!row)return fail('INCOMPLETE','FAILED_ATTEMPT_MISSING');const attempt=this.decodeStoredFailedAttempt(row);if(attempt.project_id!==pack.project_id||attempt.workspace_id!==pack.workspace_id)return fail('STALE','FAILED_ATTEMPT_SCOPE_DRIFT');if(row.payload_hash!==ref.payload_hash)return fail('STALE','FAILED_ATTEMPT_DRIFT');}const manifest=this.readStoredContextManifests().find(item=>item.content_hash===pack.context_manifest_hash);if(!manifest)return fail('INCOMPLETE','CONTEXT_MANIFEST_MISSING');if(canonicalJson(manifest.coverage)!==canonicalJson(pack.context_coverage)||manifest.request.project_id!==pack.project_id||manifest.request.workspace_id!==pack.workspace_id||manifest.request.task_ref!==pack.task_ref||manifest.request.task_version!==pack.task_version||manifest.request.target_snapshot_id!==pack.target_snapshot_id||pack.revision_refs.some(ref=>!manifest.revisions.includes(ref.revision_id)))return fail('STALE','CONTEXT_MANIFEST_DRIFT');if(this.readContextView(manifest.request).snapshot_hash!==manifest.view_snapshot_hash)return fail('STALE','CONTEXT_SOURCE_DRIFT');return{package_id:pack.package_id,content_hash:pack.content_hash,status:'VALID',reason_codes:['MATERIAL_CURRENT']};}catch(error){if(error instanceof StorageError&&['ARTIFACT_MISSING','SOURCE_MISSING'].includes(error.code))return fail('INCOMPLETE','SOURCE_MISSING');return fail('UNKNOWN','STORAGE_INTEGRITY_ERROR');}}
  acknowledgeHandoff(packageId:string,recipientId:string,action:'ACCEPTED'|'REJECTED',reasonCodes:string[]):HandoffReceipt { this.assertSafeDatabaseFiles();if(!nonEmpty(packageId)||!nonEmpty(recipientId)||!['ACCEPTED','REJECTED'].includes(action)||!Array.isArray(reasonCodes)||!reasonCodes.every(nonEmpty)||new Set(reasonCodes).size!==reasonCodes.length)throw new StorageError('INVALID_INPUT','Invalid handoff receipt');const validation=this.validateHandoff(packageId);const pack=this.getHandoffPackage(packageId);if(!pack)throw new StorageError('SOURCE_MISSING','Handoff package is missing');const reason_codes=[...reasonCodes].sort();const prior=this.db.prepare('SELECT content_hash,validation_status,action,reason_codes_json,receipt_hash FROM handoff_receipts WHERE recipient_id=? AND package_id=?').get(recipientId,packageId) as {content_hash:string;validation_status:HandoffValidationStatus;action:'ACCEPTED'|'REJECTED';reason_codes_json:string;receipt_hash:string}|undefined;if(prior){let old:Omit<HandoffReceipt,'replayed'>;try{old=this.validateImportedHandoffReceipt({recipient_id:recipientId,package_id:packageId,content_hash:prior.content_hash,validation_status:prior.validation_status,action:prior.action,reason_codes:JSON.parse(prior.reason_codes_json),receipt_hash:prior.receipt_hash});}catch(error){if(error instanceof StorageError)throw error;throw new StorageError('IDENTITY_CONFLICT','Stored handoff receipt is invalid');}const requested={recipient_id:recipientId,package_id:packageId,content_hash:pack.content_hash,action,reason_codes};const existing={recipient_id:old.recipient_id,package_id:old.package_id,content_hash:old.content_hash,action:old.action,reason_codes:old.reason_codes};if(canonicalJson(existing)!==canonicalJson(requested))throw new StorageError('IDENTITY_CONFLICT','Handoff receipt identity conflicts');return{...old,replayed:true};}const body={recipient_id:recipientId,package_id:packageId,content_hash:pack.content_hash,validation_status:validation.status,action,reason_codes};const receipt_hash=sha256(canonicalJson(body));this.db.prepare('INSERT INTO handoff_receipts(recipient_id,package_id,content_hash,validation_status,action,reason_codes_json,receipt_hash) VALUES(?,?,?,?,?,?,?)').run(recipientId,packageId,pack.content_hash,validation.status,action,canonicalJson(reason_codes),receipt_hash);return{...body,receipt_hash,replayed:false}; }
  private guardChainHash(record: Omit<GuardAuditRecord,'chain_hash'|'payload'>): string { return sha256(canonicalJson(record)); }
  private validateGuardAuditRecord(input: unknown): GuardAuditRecord {
    const x=requireExactKeys(input,['record_id','run_id','project_id','workspace_id','occurred_at','kind','decision_id','permit_id','action_fingerprint','previous_hash','payload_hash','chain_hash','payload'],'Guard audit record');
    if(!nonEmpty(x.record_id)||!nonEmpty(x.run_id)||!nonEmpty(x.project_id)||!nonEmpty(x.workspace_id)||!isoTimestamp(x.occurred_at)||!['run_manifest','decision','permit','reservation','checkpoint','execution','receipt','deviation'].includes(String(x.kind))||(x.decision_id!==null&&!nonEmpty(x.decision_id))||(x.permit_id!==null&&!nonEmpty(x.permit_id))||(x.action_fingerprint!==null&&!this.validHash(x.action_fingerprint))||(x.previous_hash!==null&&!this.validHash(x.previous_hash))||!this.validHash(x.payload_hash)||!this.validHash(x.chain_hash)||!requirePlainObject(x.payload,'Guard audit payload'))throw new StorageError('INVALID_INPUT','Invalid guard audit record');
    const record=x as unknown as GuardAuditRecord;
    if(record.payload_hash!==sha256(canonicalJson(record.payload)))throw new StorageError('IDENTITY_CONFLICT','Guard audit payload hash mismatch');
    const {chain_hash: _chain, payload, ...chainBody}=record;
    if(record.chain_hash!==this.guardChainHash(chainBody))throw new StorageError('IDENTITY_CONFLICT','Guard audit chain hash mismatch');
    if((record.kind==='permit' && (record.record_id!==record.permit_id||record.decision_id===null||record.action_fingerprint===null)) || (record.kind==='receipt' && (record.permit_id===null||record.decision_id===null||record.action_fingerprint===null)))throw new StorageError('INVALID_INPUT','Guard permit and receipt bindings are required');
    return structuredClone(record);
  }
  private readStoredGuardRecords(database: Database.Database = this.db, runId?: string): GuardAuditRecord[] {
    const rows=(runId===undefined?database.prepare('SELECT record_id,run_id,project_id,workspace_id,occurred_at,kind,decision_id,permit_id,action_fingerprint,previous_hash,payload_hash,chain_hash,payload_json FROM guard_audit_records ORDER BY run_id,rowid').all():database.prepare('SELECT record_id,run_id,project_id,workspace_id,occurred_at,kind,decision_id,permit_id,action_fingerprint,previous_hash,payload_hash,chain_hash,payload_json FROM guard_audit_records WHERE run_id=? ORDER BY rowid').all(runId)) as Array<Omit<GuardAuditRecord,'payload'> & {payload_json:string}>;
    const chains=new Map<string,{hash:string;project:string;workspace:string}>();
    return rows.map(row=>{let record:GuardAuditRecord;try{const {payload_json,...body}=row;record=this.validateGuardAuditRecord({...body,payload:JSON.parse(payload_json)});}catch(error){if(error instanceof StorageError)throw error;throw new StorageError('IDENTITY_CONFLICT','Stored guard audit record is invalid');}const prior=chains.get(record.run_id);if((prior?.hash??null)!==record.previous_hash||(prior&&(prior.project!==record.project_id||prior.workspace!==record.workspace_id)))throw new StorageError('IDENTITY_CONFLICT','Guard audit chain is discontinuous');chains.set(record.run_id,{hash:record.chain_hash,project:record.project_id,workspace:record.workspace_id});return record;});
  }
  appendGuardAuditRecord(input: GuardAuditRecord): GuardAuditRecord {
    this.assertSafeDatabaseFiles(); const record=this.validateGuardAuditRecord(input);
    const tx=this.db.transaction(()=>{this.readStoredGuardRecords(this.db,record.run_id);const prior=this.db.prepare('SELECT chain_hash FROM guard_audit_records WHERE run_id=? ORDER BY rowid DESC LIMIT 1').get(record.run_id) as {chain_hash:string}|undefined;if((prior?.chain_hash??null)!==record.previous_hash)throw new StorageError('IDENTITY_CONFLICT','Guard audit record does not extend the run chain');const existing=this.db.prepare('SELECT record_id FROM guard_audit_records WHERE record_id=?').get(record.record_id);if(existing)throw new StorageError('IDENTITY_CONFLICT','Guard audit record identity already exists');this.db.prepare('INSERT INTO guard_audit_records(record_id,run_id,project_id,workspace_id,occurred_at,kind,decision_id,permit_id,action_fingerprint,previous_hash,payload_hash,chain_hash,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(record.record_id,record.run_id,record.project_id,record.workspace_id,record.occurred_at,record.kind,record.decision_id,record.permit_id,record.action_fingerprint,record.previous_hash,record.payload_hash,record.chain_hash,canonicalJson(record.payload));});
    try{tx();return record;}catch(error){if(error instanceof StorageError)throw error;throw new StorageError('STORAGE_ERROR','Could not append guard audit record');}
  }
  readGuardAuditRecords(runId: string): GuardAuditRecord[] { this.assertSafeDatabaseFiles(); if(!nonEmpty(runId))throw new StorageError('INVALID_INPUT','Guard run identity is required'); return this.readStoredGuardRecords(this.db,runId); }
  consumeGuardPermit(receiptInput: GuardAuditRecord): GuardAuditRecord {
    this.assertSafeDatabaseFiles(); const receipt=this.validateGuardAuditRecord(receiptInput); if(receipt.kind!=='receipt'||receipt.permit_id===null)throw new StorageError('INVALID_INPUT','A guard receipt must consume a permit');
    const tx=this.db.transaction(()=>{const records=this.readStoredGuardRecords(this.db,receipt.run_id),permit=records.find(record=>record.kind==='permit'&&record.record_id===receipt.permit_id);if(!permit||!records.some(record=>record.kind==='reservation'&&record.permit_id===receipt.permit_id)||permit.project_id!==receipt.project_id||permit.workspace_id!==receipt.workspace_id||permit.decision_id!==receipt.decision_id||permit.action_fingerprint!==receipt.action_fingerprint)throw new StorageError('IDENTITY_CONFLICT','Guard receipt is not bound to its reservation');if(this.db.prepare("SELECT 1 FROM guard_audit_records WHERE kind='receipt' AND permit_id=? LIMIT 1").get(receipt.permit_id))throw new StorageError('IDENTITY_CONFLICT','Guard permit was already consumed');this.appendGuardAuditRecord(receipt);});
    try{tx();return receipt;}catch(error){if(error instanceof StorageError)throw error;throw new StorageError('STORAGE_ERROR','Could not consume guard permit');}
  }
  reserveGuardPermit(input: GuardAuditRecord): GuardAuditRecord { this.assertSafeDatabaseFiles(); const reservation=this.validateGuardAuditRecord(input); if(reservation.kind!=='reservation'||reservation.permit_id===null)throw new StorageError('INVALID_INPUT','A reservation must bind a permit'); const tx=this.db.transaction(()=>{const records=this.readStoredGuardRecords(this.db,reservation.run_id),permit=records.find(record=>record.kind==='permit'&&record.record_id===reservation.permit_id);if(!permit||permit.project_id!==reservation.project_id||permit.workspace_id!==reservation.workspace_id||permit.decision_id!==reservation.decision_id||permit.action_fingerprint!==reservation.action_fingerprint||records.some(record=>record.kind==='reservation'&&record.permit_id===reservation.permit_id)||records.some(record=>(record.kind==='receipt'||record.kind==='checkpoint')&&record.permit_id===reservation.permit_id))throw new StorageError('IDENTITY_CONFLICT','Guard permit is unavailable');this.appendGuardAuditRecord(reservation);}); try{tx();return reservation;}catch(error){if(error instanceof StorageError)throw error;throw new StorageError('STORAGE_ERROR','Could not reserve guard permit');} }
  /** R3.2 retention tiers are storage policy, not MemoryRecord.lifecycle. */
  private emptyRetentionTierCounts(): RetentionTierCounts {
    return {memory_records:0,historical_revisions:0,context_manifests:0,handoff_packages:0,evidences:0,failed_attempts:0,snapshots:0,artifact_rows:0,artifact_files:0};
  }
  private sizeIfRegularFile(target:string):number {
    try { const stat=fs.lstatSync(target); if(stat.isSymbolicLink()||!stat.isFile())throw new StorageError('PATH_OUTSIDE_PROJECT','Storage sidecar must be a regular non-linked file'); return stat.size; }
    catch(error:unknown){if((error as NodeJS.ErrnoException).code==='ENOENT')return 0;if(error instanceof StorageError)throw error;throw new StorageError('STORAGE_ERROR','Could not inspect storage file size');}
  }
  private artifactFileInventory():Array<{id:string;absolute_path:string;estimated_bytes:number;fingerprint:string}> {
    const out:Array<{id:string;absolute_path:string;estimated_bytes:number;fingerprint:string}>=[], stack=[this.artifactRoot];
    while(stack.length){const directory=stack.pop()!;this.assertExistingSafeDirectory(directory,'Artifact inventory directory');let entries:fs.Dirent[];try{entries=fs.readdirSync(directory,{withFileTypes:true});}catch{throw new StorageError('STORAGE_ERROR','Could not enumerate artifact directory');}
      for(const entry of entries){const absolute=path.join(directory,entry.name);let stat:fs.Stats;try{stat=fs.lstatSync(absolute);}catch{throw new StorageError('STORAGE_ERROR','Could not inspect artifact entry');}
        if(stat.isSymbolicLink())throw new StorageError('PATH_OUTSIDE_PROJECT','Linked artifact entries are unsupported');
        if(stat.isDirectory()){const real=fs.realpathSync.native(absolute);if(!isInside(this.artifactRoot,real))throw new StorageError('PATH_OUTSIDE_PROJECT','Artifact directory redirects outside storage root');stack.push(absolute);continue;}
        if(!stat.isFile())throw new StorageError('PATH_OUTSIDE_PROJECT','Artifact tree may contain only regular files and directories');
        this.assertSafeArtifactFile(absolute);const relative=path.relative(this.root,absolute).split(path.sep).join('/');
        out.push({id:relative,absolute_path:absolute,estimated_bytes:stat.size,fingerprint:sha256(canonicalJson({relative,size:stat.size,mtime_ms:stat.mtimeMs,dev:stat.dev,ino:stat.ino}))});
      }
    }
    return out.sort((a,b)=>a.id.localeCompare(b.id));
  }
  private lifecycleInventory(projectId:string):{status:StorageLifecycleStatus;candidates:CleanupCandidate[]} {
    this.assertSafeDatabaseFiles();if(!nonEmpty(projectId))throw new StorageError('INVALID_INPUT','Project identity is required');
    const active=this.emptyRetentionTierCounts(),archived=this.emptyRetentionTierCounts(),prunable=this.emptyRetentionTierCounts();
    const latestLifecycleRows=this.db.prepare(`SELECT r.record_id,r.current_revision_id,(SELECT lifecycle FROM lifecycle_events l WHERE l.record_id=r.record_id ORDER BY rowid DESC LIMIT 1) AS lifecycle FROM records r WHERE r.project_id=? ORDER BY r.record_id`).all(projectId) as Array<{record_id:string;current_revision_id:string;lifecycle:Lifecycle|null}>;
    for(const row of latestLifecycleRows){if(row.lifecycle==='ACTIVE')active.memory_records++;else archived.memory_records++;}
    archived.historical_revisions=(this.db.prepare('SELECT count(*) AS n FROM revisions v JOIN records r ON r.record_id=v.record_id WHERE v.project_id=? AND v.revision_id<>r.current_revision_id').get(projectId) as {n:number}).n;

    const manifestRows=this.db.prepare('SELECT rowid AS row_id,content_hash,workspace_id,task_ref,task_version,payload_json FROM context_manifests WHERE project_id=? ORDER BY rowid').all(projectId) as Array<{row_id:number;content_hash:string;workspace_id:string;task_ref:string;task_version:string;payload_json:string}>;
    const latestManifestByScope=new Map<string,string>();for(const row of manifestRows)latestManifestByScope.set(canonicalJson([row.workspace_id,row.task_ref,row.task_version]),row.content_hash);
    const handoffPackages=this.readStoredHandoffPackages().filter(pack=>pack.project_id===projectId),handoffById=new Map(handoffPackages.map(pack=>[pack.package_id,pack])),latestHandoffByScope=new Map<string,HandoffPackage>();
    const handoffOrder=this.db.prepare('SELECT package_id FROM handoff_packages WHERE project_id=? ORDER BY rowid').all(projectId) as Array<{package_id:string}>;for(const row of handoffOrder){const pack=handoffById.get(row.package_id);if(!pack)throw new StorageError('IDENTITY_CONFLICT','Stored handoff package is missing from validated inventory');latestHandoffByScope.set(canonicalJson([pack.workspace_id,pack.task_ref,pack.task_version]),pack);}
    const referencedManifestIds=new Set(handoffPackages.map(pack=>pack.context_manifest_hash));
    const candidates:CleanupCandidate[]=[];
    for(const row of manifestRows){const scope=canonicalJson([row.workspace_id,row.task_ref,row.task_version]);if(latestManifestByScope.get(scope)===row.content_hash){active.context_manifests++;continue;}if(referencedManifestIds.has(row.content_hash)){archived.context_manifests++;continue;}const estimated_bytes=Buffer.byteLength(row.payload_json);prunable.context_manifests++;candidates.push({kind:'CONTEXT_MANIFEST',id:row.content_hash,reason_code:'REBUILDABLE_OLD_CONTEXT',estimated_bytes,fingerprint:sha256(canonicalJson({content_hash:row.content_hash,payload_json:row.payload_json}))});}
    active.handoff_packages=latestHandoffByScope.size;archived.handoff_packages=Math.max(0,handoffPackages.length-active.handoff_packages);

    const activeEvidenceIds=new Set<string>(),activeFailedAttemptIds=new Set<string>(),activeSnapshotIds=new Set<string>();
    for(const pack of latestHandoffByScope.values()){activeSnapshotIds.add(pack.target_snapshot_id);for(const ref of pack.evidence_refs)activeEvidenceIds.add(ref.evidence_id);for(const ref of pack.failed_attempt_refs)activeFailedAttemptIds.add(ref.failed_attempt_id);}
    for(const row of manifestRows){const scope=canonicalJson([row.workspace_id,row.task_ref,row.task_version]);if(latestManifestByScope.get(scope)!==row.content_hash)continue;try{const parsed=JSON.parse(row.payload_json) as ContextManifest;activeSnapshotIds.add(parsed.request.target_snapshot_id);}catch{throw new StorageError('IDENTITY_CONFLICT','Stored context manifest is invalid');}}
    const evidenceRows=this.db.prepare('SELECT evidence_id,payload_json,artifact_hash FROM evidences WHERE project_id=? ORDER BY rowid').all(projectId) as Array<{evidence_id:string;payload_json:string;artifact_hash:string|null}>;
    for(const row of evidenceRows){let evidence:Evidence;try{evidence=validateEvidence(JSON.parse(row.payload_json));}catch{throw new StorageError('IDENTITY_CONFLICT','Stored evidence is invalid');}if(activeEvidenceIds.has(row.evidence_id)){active.evidences++;activeSnapshotIds.add(evidence.snapshot_id);}else archived.evidences++;}
    const failedAttemptIds=(this.db.prepare('SELECT failed_attempt_id FROM failed_attempts WHERE project_id=? ORDER BY rowid').all(projectId) as Array<{failed_attempt_id:string}>).map(row=>row.failed_attempt_id);for(const id of failedAttemptIds)(activeFailedAttemptIds.has(id)?active:archived).failed_attempts++;
    const snapshotIds=(this.db.prepare('SELECT snapshot_id FROM snapshots WHERE project_id=? ORDER BY rowid').all(projectId) as Array<{snapshot_id:string}>).map(row=>row.snapshot_id);for(const id of snapshotIds)(activeSnapshotIds.has(id)?active:archived).snapshots++;

    const registered=this.db.prepare('SELECT hash,byte_length,relative_path FROM artifacts ORDER BY hash').all() as ArtifactRow[], allReferencedHashes=new Set<string>();
    for(const row of this.db.prepare('SELECT artifact_hash FROM evidences WHERE artifact_hash IS NOT NULL').all() as Array<{artifact_hash:string}>)allReferencedHashes.add(row.artifact_hash);
    for(const row of this.db.prepare('SELECT artifact_hash FROM source_versions').all() as Array<{artifact_hash:string}>)allReferencedHashes.add(row.artifact_hash);
    for(const row of this.db.prepare('SELECT artifact_hash FROM trusted_collector_receipts').all() as Array<{artifact_hash:string}>)allReferencedHashes.add(row.artifact_hash);
    const activeArtifactHashes=new Set(evidenceRows.filter(row=>activeEvidenceIds.has(row.evidence_id)&&row.artifact_hash!==null).map(row=>row.artifact_hash as string));
    const registeredPaths=new Map<string,ArtifactRow>();const pathKey=(absolute:string)=>process.platform==='win32'?path.resolve(absolute).toLowerCase():path.resolve(absolute);
    for(const row of registered){const absolute=path.resolve(this.root,row.relative_path);if(!isInside(this.artifactRoot,absolute))throw new StorageError('PATH_OUTSIDE_PROJECT','Registered artifact path escapes root');registeredPaths.set(pathKey(absolute),row);if(allReferencedHashes.has(row.hash)){if(activeArtifactHashes.has(row.hash))active.artifact_rows++;else archived.artifact_rows++;}else{this.readArtifact(row.hash);prunable.artifact_rows++;candidates.push({kind:'ARTIFACT_ROW',id:row.hash,reason_code:'UNREFERENCED_ARTIFACT_ROW',estimated_bytes:row.byte_length,fingerprint:sha256(canonicalJson(row))});}}
    const artifactFiles=this.artifactFileInventory();let artifactBytes=0;for(const file of artifactFiles){artifactBytes+=file.estimated_bytes;const row=registeredPaths.get(pathKey(file.absolute_path));if(!row){prunable.artifact_files++;candidates.push({kind:'ARTIFACT_FILE',id:file.id,reason_code:'ORPHAN_ARTIFACT_FILE',estimated_bytes:file.estimated_bytes,fingerprint:file.fingerprint});continue;}if(allReferencedHashes.has(row.hash)){if(activeArtifactHashes.has(row.hash))active.artifact_files++;else archived.artifact_files++;}else prunable.artifact_files++;}

    const count=(sql:string,...args:unknown[]) => (this.db.prepare(sql).get(...args) as {n:number}).n;
    const protectedCounts={events:count('SELECT count(*) AS n FROM events WHERE project_id=?',projectId),lifecycle_events:count('SELECT count(*) AS n FROM lifecycle_events l JOIN records r ON r.record_id=l.record_id WHERE r.project_id=?',projectId),relations:count('SELECT count(*) AS n FROM relations WHERE project_id=?',projectId),ingestion_receipts:count('SELECT count(*) AS n FROM ingestion_receipts WHERE project_id=?',projectId),context_bindings:count('SELECT count(*) AS n FROM context_bindings WHERE project_id=?',projectId),handoff_receipts:count('SELECT count(*) AS n FROM handoff_receipts hr JOIN handoff_packages hp ON hp.package_id=hr.package_id WHERE hp.project_id=?',projectId),extraction_candidates:count('SELECT count(*) AS n FROM extraction_candidates WHERE project_id=?',projectId),extraction_attempts:count('SELECT count(*) AS n FROM extraction_attempts WHERE project_id=?',projectId),guard_records:count('SELECT count(*) AS n FROM guard_audit_records WHERE project_id=?',projectId),collector_registrations:count('SELECT count(*) AS n FROM collector_registrations WHERE project_id=?',projectId),trusted_source_versions:count('SELECT count(*) AS n FROM source_versions WHERE project_id=?',projectId),trusted_collector_receipts:count('SELECT count(*) AS n FROM trusted_collector_receipts WHERE project_id=?',projectId)};
    const database=this.sizeIfRegularFile(this.databasePath),wal=this.sizeIfRegularFile(`${this.databasePath}-wal`),shm=this.sizeIfRegularFile(`${this.databasePath}-shm`),journal=this.sizeIfRegularFile(`${this.databasePath}-journal`),estimatedPrunable=candidates.reduce((sum,item)=>sum+item.estimated_bytes,0);
    candidates.sort((a,b)=>a.kind.localeCompare(b.kind)||a.id.localeCompare(b.id));
    return{status:{kind:'xmem-storage-lifecycle-status',policy_version:RETENTION_POLICY_VERSION,project_id:projectId,archive_is_logical:true,physical_delete_only_prunable:true,semantic_memory_lifecycle_is_distinct:true,tiers:{ACTIVE:active,ARCHIVED:archived,PRUNABLE:prunable},protected:protectedCounts,storage_bytes:{database,wal,shm,journal,artifacts:artifactBytes,total:database+wal+shm+journal+artifactBytes,estimated_prunable:estimatedPrunable},cleanup_scope:{deletes_active:false,deletes_archived:false,prunable_kinds:['CONTEXT_MANIFEST','ARTIFACT_ROW','ARTIFACT_FILE']}},candidates};
  }
  getStorageLifecycleStatus(projectId:string):StorageLifecycleStatus { return structuredClone(this.lifecycleInventory(projectId).status); }
  previewCleanup(projectId:string):CleanupPlan { return createCleanupPlan(projectId,this.lifecycleInventory(projectId).candidates); }
  applyCleanup(projectId:string,expectedPlanHash:string):CleanupApplyResult {
    this.assertSafeDatabaseFiles();if(!/^[a-f0-9]{64}$/.test(expectedPlanHash))throw new StorageError('INVALID_INPUT','Cleanup plan hash must be SHA-256 lowercase hex');const plan=this.previewCleanup(projectId);if(plan.plan_hash!==expectedPlanHash)throw new StorageError('IDENTITY_CONFLICT','Cleanup plan changed; request a new preview before applying');
    const contextIds=plan.candidates.filter(item=>item.kind==='CONTEXT_MANIFEST').map(item=>item.id),artifactHashes=plan.candidates.filter(item=>item.kind==='ARTIFACT_ROW').map(item=>item.id),orphanFiles=plan.candidates.filter(item=>item.kind==='ARTIFACT_FILE');
    // Verify registered content-addressed artifacts before deleting their registrations.
    for(const hash of artifactHashes)this.readArtifact(hash);
    const tx=this.db.transaction(()=>{for(const id of contextIds){const referenced=this.db.prepare('SELECT 1 FROM handoff_packages WHERE context_manifest_hash=? LIMIT 1').get(id);if(referenced)throw new StorageError('IDENTITY_CONFLICT','Context manifest became referenced during cleanup');this.db.prepare('DELETE FROM context_manifests WHERE content_hash=? AND project_id=?').run(id,projectId);}for(const hash of artifactHashes){const referenced=this.db.prepare(`SELECT 1 WHERE EXISTS(SELECT 1 FROM evidences WHERE artifact_hash=?) OR EXISTS(SELECT 1 FROM source_versions WHERE artifact_hash=?) OR EXISTS(SELECT 1 FROM trusted_collector_receipts WHERE artifact_hash=?)`).get(hash,hash,hash);if(referenced)throw new StorageError('IDENTITY_CONFLICT','Artifact became referenced during cleanup');this.db.prepare('DELETE FROM artifacts WHERE hash=?').run(hash);}});try{tx();}catch(error){if(error instanceof StorageError)throw error;throw new StorageError('STORAGE_ERROR','Could not apply cleanup transaction');}
    let deletedOrphanFiles=0,physicalArtifactBytesRemoved=0,fileCleanupIncomplete=false;const reasonCodes:string[]=[];
    try { for(const hash of artifactHashes){const absolute=this.artifactPath(hash);if(this.pathExists(absolute)){this.assertSafeArtifactFile(absolute);const stat=fs.statSync(absolute);fs.unlinkSync(absolute);physicalArtifactBytesRemoved+=stat.size;}}for(const candidate of orphanFiles){const absolute=path.resolve(this.root,...candidate.id.split('/'));if(!isInside(this.artifactRoot,absolute))throw new StorageError('PATH_OUTSIDE_PROJECT','Orphan cleanup path escapes artifact root');if(!this.pathExists(absolute))continue;const stat=fs.lstatSync(absolute);if(stat.isSymbolicLink()||!stat.isFile())throw new StorageError('PATH_OUTSIDE_PROJECT','Orphan cleanup target must be a regular non-linked file');const relative=path.relative(this.root,absolute).split(path.sep).join('/'),fingerprint=sha256(canonicalJson({relative,size:stat.size,mtime_ms:stat.mtimeMs,dev:stat.dev,ino:stat.ino}));if(fingerprint!==candidate.fingerprint)throw new StorageError('IDENTITY_CONFLICT','Orphan artifact changed after cleanup preview');this.assertSafeArtifactFile(absolute);fs.unlinkSync(absolute);physicalArtifactBytesRemoved+=stat.size;deletedOrphanFiles++;}for(const entry of fs.readdirSync(this.artifactRoot,{withFileTypes:true})){if(!entry.isDirectory()||entry.isSymbolicLink())continue;const dir=path.join(this.artifactRoot,entry.name);this.assertExistingSafeDirectory(dir,'Artifact shard directory');if(fs.readdirSync(dir).length===0)fs.rmdirSync(dir);}}catch{fileCleanupIncomplete=true;reasonCodes.push('ARTIFACT_FILE_CLEANUP_INCOMPLETE_RERUN_PREVIEW');}
    let remaining:number|null=null;try{remaining=this.previewCleanup(projectId).candidates.length;}catch{fileCleanupIncomplete=true;if(!reasonCodes.includes('ARTIFACT_FILE_CLEANUP_INCOMPLETE_RERUN_PREVIEW'))reasonCodes.push('ARTIFACT_FILE_CLEANUP_INCOMPLETE_RERUN_PREVIEW');}
    return{kind:'xmem-cleanup-result',policy_version:RETENTION_POLICY_VERSION,project_id:projectId,applied_plan_hash:expectedPlanHash,deleted:{CONTEXT_MANIFEST:contextIds.length,ARTIFACT_ROW:artifactHashes.length,ARTIFACT_FILE:deletedOrphanFiles},estimated_bytes_targeted:plan.estimated_reclaimable_bytes,physical_artifact_bytes_removed:physicalArtifactBytesRemoved,remaining_prunable_candidates:remaining,artifact_file_cleanup_incomplete:fileCleanupIncomplete,reason_codes:reasonCodes.length?reasonCodes:['CLEANUP_APPLIED']};
  }
  compactStorage(projectId:string):StorageCompactResult {
    this.assertSafeDatabaseFiles();if(!nonEmpty(projectId))throw new StorageError('INVALID_INPUT','Project identity is required');const rowCount=()=>{let n=0;for(const row of this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all() as Array<{name:string}>){if(!/^[a-z0-9_]+$/.test(row.name))throw new StorageError('IDENTITY_CONFLICT','Unexpected SQLite table name');n+=(this.db.prepare(`SELECT count(*) AS n FROM ${row.name}`).get() as {n:number}).n;}return n;};const rowsBefore=rowCount(),before=this.sizeIfRegularFile(this.databasePath)+this.sizeIfRegularFile(`${this.databasePath}-wal`)+this.sizeIfRegularFile(`${this.databasePath}-shm`)+this.sizeIfRegularFile(`${this.databasePath}-journal`),checked=this.db.pragma('quick_check',{simple:true});if(checked!=='ok')throw new StorageError('STORAGE_ERROR','SQLite quick_check failed before compaction');let checkpoint:{busy:number;log:number;checkpointed:number};try{const rows=this.db.pragma('wal_checkpoint(TRUNCATE)') as Array<{busy:number;log:number;checkpointed:number}>;checkpoint=rows[0]??{busy:1,log:0,checkpointed:0};if(checkpoint.busy!==0)throw new StorageError('STORAGE_ERROR','SQLite WAL checkpoint was busy');this.db.pragma('optimize');}catch(error){if(error instanceof StorageError)throw error;throw new StorageError('STORAGE_ERROR','SQLite compaction failed');}const afterCheck=this.db.pragma('quick_check',{simple:true});if(afterCheck!=='ok')throw new StorageError('STORAGE_ERROR','SQLite quick_check failed after compaction');if(rowCount()!==rowsBefore)throw new StorageError('IDENTITY_CONFLICT','SQLite logical row count changed during compaction');this.assertSafeDatabaseFiles();const after=this.sizeIfRegularFile(this.databasePath)+this.sizeIfRegularFile(`${this.databasePath}-wal`)+this.sizeIfRegularFile(`${this.databasePath}-shm`)+this.sizeIfRegularFile(`${this.databasePath}-journal`);return{kind:'xmem-storage-compact-result',project_id:projectId,sqlite_quick_check:'PASS',before_bytes:before,after_bytes:after,reclaimed_bytes:Math.max(0,before-after),logical_rows_deleted:0,wal_checkpoint:{busy:0,log_frames:checkpoint.log,checkpointed_frames:checkpoint.checkpointed},method:'WAL_CHECKPOINT_TRUNCATE_AND_OPTIMIZE',main_database_vacuum_run:false,reason_codes:['MAIN_DATABASE_VACUUM_DEFERRED_TO_PRESERVE_ROWID_RECENCY']};
  }

  readArtifact(hash:string):ArtifactRead { this.assertSafeDatabaseFiles(); const row=this.db.prepare('SELECT hash,byte_length,relative_path FROM artifacts WHERE hash=?').get(hash) as ArtifactRow|undefined; if(!row)throw new StorageError('ARTIFACT_MISSING','Artifact is not registered'); const target=path.resolve(this.root,row.relative_path); if(!isInside(this.artifactRoot,target))throw new StorageError('PATH_OUTSIDE_PROJECT','Registered artifact path escapes root'); try{this.assertSafeArtifactFile(target);}catch(error){if(error instanceof StorageError)throw error;throw new StorageError('ARTIFACT_MISSING','Artifact is missing');} const bytes=fs.readFileSync(target); if(bytes.byteLength!==row.byte_length||sha256(bytes)!==row.hash)throw new StorageError('ARTIFACT_CORRUPT','Artifact contents do not match registration'); return {hash:row.hash,bytes}; }
  private assertSafeBackupLeaf(root:string,target:string):void { if(!isInside(root,target))throw new StorageError('PATH_OUTSIDE_PROJECT','Backup path escapes root'); try{const stat=fs.lstatSync(target);if(stat.isSymbolicLink()||!stat.isFile())throw new StorageError('PATH_OUTSIDE_PROJECT','Backup target must be regular');if(!isInside(root,fs.realpathSync.native(target)))throw new StorageError('PATH_OUTSIDE_PROJECT','Backup target redirects');}catch(error:unknown){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;} }
  private requireExistingBackupFile(root: string, target: string, label: string): void { this.assertSafeBackupLeaf(root, target); if (!this.pathExists(target)) throw new StorageError('ARTIFACT_MISSING', `${label} is missing`); }
  private assertSafeBackupDatabaseFiles(root:string,database:string):void { for(const suffix of ['', '-wal','-shm','-journal'])this.assertSafeBackupLeaf(root,`${database}${suffix}`); }
  private writeAtomic(finalPath:string,bytes:Uint8Array):void { const temp=path.join(path.dirname(finalPath),`.${path.basename(finalPath)}.${randomUUID()}.tmp`),fd=fs.openSync(temp,'wx',0o600);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(temp,finalPath);this.fsyncDirectory(path.dirname(finalPath)); }
  async backup(targetRoot:string):Promise<{database:string;manifest:string;artifacts:number}>{this.assertSafeDatabaseFiles();if(!path.isAbsolute(targetRoot))throw new StorageError('PATH_OUTSIDE_PROJECT','Backup root must be absolute');this.assertExistingSafeDirectory(path.resolve(targetRoot),'Backup root');const target=fs.realpathSync.native(path.resolve(targetRoot));if(target.toLowerCase()===this.root.toLowerCase())throw new StorageError('PATH_OUTSIDE_PROJECT','Backup root must differ');const database=path.join(target,DATABASE_FILE),manifest=path.join(target,'backup-manifest.json');this.assertSafeBackupDatabaseFiles(target,database);this.assertSafeBackupLeaf(target,manifest);await this.db.backup(database);this.assertSafeBackupDatabaseFiles(target,database);const snap=new Database(database,{readonly:true});let rows:ArtifactRow[];let guard_records_hash:string;try{guard_records_hash=sha256(canonicalJson(this.readStoredGuardRecords(snap)));rows=snap.prepare('SELECT hash,byte_length,relative_path FROM artifacts ORDER BY hash').all() as ArtifactRow[];}finally{snap.close();}for(const row of rows){const dest=path.join(target,row.relative_path);if(!isInside(target,dest))throw new StorageError('PATH_OUTSIDE_PROJECT','Backup artifact escapes target');if(!this.pathExists(path.dirname(dest)))fs.mkdirSync(path.dirname(dest),{recursive:true,mode:0o700});this.assertExistingSafeDirectory(path.dirname(dest),'Backup artifact directory');this.assertSafeBackupLeaf(target,dest);this.writeAtomic(dest,this.readArtifact(row.hash).bytes);}this.writeAtomic(manifest,Buffer.from(canonicalJson({format_version:STORAGE_FORMAT_VERSION,database:DATABASE_FILE,artifacts:rows,guard_records_hash})));return{database,manifest,artifacts:rows.length};}
  private readTrustedBackupRows(backup: Database.Database, version: string): TrustedBackupRows {
    if ([DATABASE_SCHEMA_VERSION,M8_DATABASE_SCHEMA_VERSION,M7_DATABASE_SCHEMA_VERSION,M6_DATABASE_SCHEMA_VERSION,M5_DATABASE_SCHEMA_VERSION].includes(version)) this.readStoredFailedAttempts(backup);
    if (version === M2_DATABASE_SCHEMA_VERSION) return { collectors:[], snapshots:[], sources:[], receipts:[] };
    const tables = ['collector_registrations','snapshots','source_versions','trusted_collector_receipts'];
    for (const name of tables) if (!backup.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(name)) throw new StorageError('UNSUPPORTED_VERSION', 'Backup M3 trust tables are missing');
    const collectors = version === M3_DATABASE_SCHEMA_VERSION
      ? (backup.prepare('SELECT project_id,source_id,locator,version FROM collector_registrations ORDER BY project_id,source_id').all() as CollectorRegistration[]).map(registration => ({ ...this.validateCollector(registration), active:true }))
      : (backup.prepare('SELECT project_id,source_id,locator,version,active FROM collector_registrations ORDER BY project_id,source_id').all() as Array<CollectorRegistration & {active:number}>).map(row => { const {active,...registration}=row; if(active!==0&&active!==1) throw new StorageError('INVALID_INPUT','Stored collector state is invalid'); return {...this.validateCollector(registration),active:active===1}; });
    const snapshots = (backup.prepare('SELECT snapshot_id,project_id,workspace_id,payload_hash,payload_json FROM snapshots ORDER BY rowid').all() as Array<{snapshot_id:string;project_id:string;workspace_id:string;payload_hash:string;payload_json:string}>).map(row => { const snapshot=validateSnapshot(JSON.parse(row.payload_json)); if(snapshot.snapshot_id!==row.snapshot_id||snapshot.project_id!==row.project_id||snapshot.workspace_id!==row.workspace_id||!/^[a-f0-9]{64}$/.test(row.payload_hash)||row.payload_hash!==sha256(canonicalJson(snapshot))) throw new StorageError('IDENTITY_CONFLICT','Stored snapshot does not match its immutable payload hash'); return {snapshot,payload_hash:row.payload_hash}; });
    const fields = 'project_id,workspace_id,run_id,source_id,locator,version,content_hash,artifact_hash,snapshot_id';
    const sources = backup.prepare(`SELECT ${fields} FROM source_versions ORDER BY evidence_id`).all() as Array<Record<string,string>>;
    const ids = backup.prepare('SELECT evidence_id FROM source_versions ORDER BY evidence_id').all() as Array<{evidence_id:string}>;
    const receipts = backup.prepare(`SELECT receipt_hash,${fields} FROM trusted_collector_receipts ORDER BY evidence_id`).all() as Array<{receipt_hash:string}&Record<string,string>>;
    if (sources.length !== ids.length || sources.length !== receipts.length) throw new StorageError('IDENTITY_CONFLICT','Backup trusted receipt coverage is inconsistent');
    return { collectors, snapshots, sources: sources.map((row,index) => ({ evidence_id:ids[index].evidence_id, ...this.validateTrustRow(row) })), receipts: receipts.map((row,index) => { const { receipt_hash, ...fields } = row; if (!/^[a-f0-9]{64}$/.test(receipt_hash)) throw new StorageError('INVALID_INPUT','Stored receipt hash is invalid'); return { evidence_id:ids[index].evidence_id, receipt_hash, ...this.validateTrustRow(fields) }; }) };
  }
  private validateTrustRow(row: Record<string,unknown>): Record<string,string> {
    const keys=['project_id','workspace_id','run_id','source_id','locator','version','content_hash','artifact_hash','snapshot_id'];
    if (Object.keys(row).sort().join(',') !== [...keys].sort().join(',') || keys.some(key => !nonEmpty(row[key])) || !/^[a-f0-9]{64}$/.test(String(row.content_hash)) || !/^[a-f0-9]{64}$/.test(String(row.artifact_hash))) throw new StorageError('INVALID_INPUT','Stored trust record is invalid');
    return row as Record<string,string>;
  }
  private restoreTrustedBackupRows(rows: TrustedBackupRows): void {
    this.db.transaction(() => {
      for (const collector of rows.collectors) this.restoreCollector(collector);
      for (const {snapshot,payload_hash} of rows.snapshots) { this.recordSnapshot(snapshot); const restored=this.db.prepare('SELECT payload_hash FROM snapshots WHERE snapshot_id=? AND project_id=? AND workspace_id=?').get(snapshot.snapshot_id,snapshot.project_id,snapshot.workspace_id) as {payload_hash:string}|undefined; if(!restored||restored.payload_hash!==payload_hash) throw new StorageError('IDENTITY_CONFLICT','Snapshot hash changed during restore'); }
      for (let index=0; index<rows.sources.length; index++) {
        const source=rows.sources[index], receipt=rows.receipts[index];
        const receiptValue={ evidence_id:source.evidence_id, ...source };
        if (receipt.evidence_id!==source.evidence_id || receipt.receipt_hash!==sha256(canonicalJson(receiptValue)) || canonicalJson(Object.fromEntries(Object.entries(receipt).filter(([key])=>key!=='receipt_hash'&&key!=='evidence_id'))) !== canonicalJson(Object.fromEntries(Object.entries(source).filter(([key])=>key!=='evidence_id')))) throw new StorageError('IDENTITY_CONFLICT','Backup trusted receipt is invalid');
        const collector=this.db.prepare('SELECT locator,version FROM collector_registrations WHERE project_id=? AND source_id=?').get(source.project_id,source.source_id) as {locator:string;version:string}|undefined;
        const evidenceRow=this.db.prepare('SELECT payload_json FROM evidences WHERE evidence_id=?').get(source.evidence_id) as JsonRow|undefined;
        const snapshotRow=this.db.prepare('SELECT payload_json FROM snapshots WHERE snapshot_id=? AND project_id=? AND workspace_id=?').get(source.snapshot_id,source.project_id,source.workspace_id) as JsonRow|undefined;
        if ((collector && (collector.locator!==source.locator || collector.version!==source.version)) || !evidenceRow || !snapshotRow) throw new StorageError('IDENTITY_CONFLICT','Backup trusted binding is incomplete');
        const evidence=validateEvidence(JSON.parse(evidenceRow.payload_json)), snapshot=validateSnapshot(JSON.parse(snapshotRow.payload_json));
        if (evidence.source.kind!=='executor' || evidence.project_id!==source.project_id || evidence.workspace_id!==source.workspace_id || evidence.run_id!==source.run_id || evidence.snapshot_id!==source.snapshot_id || evidence.artifact_hash!==source.artifact_hash || canonicalJson(evidence.source)!==canonicalJson({source_id:source.source_id,kind:'executor',locator:source.locator,version:source.version,content_hash:source.content_hash}) || snapshot.manifest.completeness!=='COMPLETE' || snapshot.manifest.external_state!=='CONTROLLED') throw new StorageError('IDENTITY_CONFLICT','Backup trusted binding changed');
        this.readArtifact(source.artifact_hash);
        this.db.prepare('INSERT OR IGNORE INTO source_versions(evidence_id,project_id,workspace_id,run_id,source_id,locator,version,content_hash,artifact_hash,snapshot_id) VALUES(?,?,?,?,?,?,?,?,?,?)').run(source.evidence_id,source.project_id,source.workspace_id,source.run_id,source.source_id,source.locator,source.version,source.content_hash,source.artifact_hash,source.snapshot_id);
        this.db.prepare('INSERT OR IGNORE INTO trusted_collector_receipts(evidence_id,receipt_hash,project_id,workspace_id,run_id,source_id,locator,version,content_hash,artifact_hash,snapshot_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(source.evidence_id,receipt.receipt_hash,source.project_id,source.workspace_id,source.run_id,source.source_id,source.locator,source.version,source.content_hash,source.artifact_hash,source.snapshot_id);
      }
    })();
  }
  private restoreCollector(input: StoredCollectorRegistration): void {
    const {active,...registration}=input; this.validateCollector(registration);
    const prior=this.db.prepare('SELECT project_id,source_id,locator,version,active FROM collector_registrations WHERE project_id=? AND source_id=?').get(registration.project_id,registration.source_id) as StoredCollectorRegistration|undefined;
    if(prior){const {active:_active,...identity}=prior;if(canonicalJson(identity)!==canonicalJson(registration))throw new StorageError('IDENTITY_CONFLICT','Backup collector identity conflicts');if(prior.active!==active)this.db.prepare('UPDATE collector_registrations SET active=? WHERE project_id=? AND source_id=?').run(active?1:0,registration.project_id,registration.source_id);return;}
    this.db.prepare('INSERT INTO collector_registrations(project_id,source_id,locator,version,active) VALUES(?,?,?,?,?)').run(registration.project_id,registration.source_id,registration.locator,registration.version,active?1:0);
  }
  /** Restore a validated backup into this store through the same strict import path. */
  restore(backupRoot: string): void {
    this.assertSafeDatabaseFiles(); if (!path.isAbsolute(backupRoot)) throw new StorageError('PATH_OUTSIDE_PROJECT','Backup root must be absolute'); const root=path.resolve(backupRoot), manifest=path.join(root,'backup-manifest.json'), database=path.join(root,DATABASE_FILE); this.assertExistingSafeDirectory(root,'Backup root'); this.requireExistingBackupFile(root,manifest,'Backup manifest'); this.requireExistingBackupFile(root,database,'Backup database'); this.assertSafeBackupDatabaseFiles(root,database);
    let declaration:Record<string,unknown>; try{const parsed=requirePlainObject(JSON.parse(fs.readFileSync(manifest,'utf8')),'Backup manifest');declaration=requireExactKeys(parsed,['format_version','database','artifacts',...(Object.hasOwn(parsed,'guard_records_hash')?['guard_records_hash']:[])],'Backup manifest');}catch(error){if(error instanceof StorageError)throw error;throw new StorageError('INVALID_INPUT','Backup manifest is invalid');} if(declaration.format_version!==STORAGE_FORMAT_VERSION||declaration.database!==DATABASE_FILE||!Array.isArray(declaration.artifacts))throw new StorageError('UNSUPPORTED_VERSION','Backup manifest version is unsupported');
    let backup:Database.Database;try{backup=new Database(database,{readonly:true,fileMustExist:true});}catch{throw new StorageError('STORAGE_ERROR','Backup database could not be opened');}
    try { const version=backup.prepare("SELECT value FROM xmem_metadata WHERE key='schema_version'").get() as {value:string}|undefined; if(!version||![DATABASE_SCHEMA_VERSION,M8_DATABASE_SCHEMA_VERSION,M7_DATABASE_SCHEMA_VERSION,M6_DATABASE_SCHEMA_VERSION,M5_DATABASE_SCHEMA_VERSION,M4_DATABASE_SCHEMA_VERSION,M3_DATABASE_SCHEMA_VERSION,M2_DATABASE_SCHEMA_VERSION].includes(version.value))throw new StorageError('UNSUPPORTED_VERSION','Backup database schema is unsupported');
      const trusted=this.readTrustedBackupRows(backup,version.value), rows=backup.prepare('SELECT hash,byte_length,relative_path FROM artifacts ORDER BY hash').all() as ArtifactRow[], declared=(declaration.artifacts as unknown[]).map(x=>requireExactKeys(x,['hash','byte_length','relative_path'],'Backup artifact')); if(canonicalJson(declared)!==canonicalJson(rows))throw new StorageError('IDENTITY_CONFLICT','Backup manifest does not match its database');
      const artifacts=rows.map(row=>{const file=path.resolve(root,row.relative_path);if(!isInside(root,file))throw new StorageError('PATH_OUTSIDE_PROJECT','Backup artifact escapes root');this.requireExistingBackupFile(root,file,'Backup artifact');const bytes=fs.readFileSync(file);if(bytes.byteLength!==row.byte_length||sha256(bytes)!==row.hash)throw new StorageError('ARTIFACT_CORRUPT','Backup artifact does not match manifest');return{hash:row.hash,bytes_base64:Buffer.from(bytes).toString('base64')};});
      const parse=<T>(table:string):T[]=>(backup.prepare(`SELECT payload_json FROM ${table} ORDER BY rowid`).all() as JsonRow[]).map(row=>JSON.parse(row.payload_json)as T); const lifecycle_events=backup.prepare('SELECT event_id,record_id,revision_id,lifecycle,actor,source,reason,occurred_at FROM lifecycle_events ORDER BY rowid').all() as LifecycleEvent[], receipts=(backup.prepare('SELECT project_id,source_id,idempotency_key,event_id,payload_hash,sequence_gap,expected_sequence FROM ingestion_receipts ORDER BY rowid').all() as ReceiptRow[]).map(row=>({...row,sequence_gap:row.sequence_gap===1}));
      const context_bindings=[DATABASE_SCHEMA_VERSION,M8_DATABASE_SCHEMA_VERSION,M7_DATABASE_SCHEMA_VERSION,M6_DATABASE_SCHEMA_VERSION].includes(version.value)?this.readStoredContextBindings('',[],backup):[], context_manifests=[DATABASE_SCHEMA_VERSION,M8_DATABASE_SCHEMA_VERSION,M7_DATABASE_SCHEMA_VERSION,M6_DATABASE_SCHEMA_VERSION].includes(version.value)?this.readStoredContextManifests(backup):[], handoff_packages=[DATABASE_SCHEMA_VERSION,M8_DATABASE_SCHEMA_VERSION,M7_DATABASE_SCHEMA_VERSION].includes(version.value)?this.readStoredHandoffPackages(backup):[], handoff_receipts=[DATABASE_SCHEMA_VERSION,M8_DATABASE_SCHEMA_VERSION,M7_DATABASE_SCHEMA_VERSION].includes(version.value)?this.readStoredHandoffReceipts(backup):[], extraction_candidates=[DATABASE_SCHEMA_VERSION,M8_DATABASE_SCHEMA_VERSION].includes(version.value)?this.readStoredExtractionCandidates(backup):[], extraction_attempts=[DATABASE_SCHEMA_VERSION,M8_DATABASE_SCHEMA_VERSION].includes(version.value)?this.readStoredExtractionAttempts(backup):[], guard_records=version.value===DATABASE_SCHEMA_VERSION?this.readStoredGuardRecords(backup):[];
      this.importValidatedData({format_version:STORAGE_FORMAT_VERSION,kind:'xmem-storage-export',artifacts,events:parse<Event>('events'),evidences:parse<Evidence>('evidences'),snapshots:trusted.snapshots.map(row=>row.snapshot),revisions:parse<MemoryRecord>('revisions'),lifecycle_events,relations:parse<Relation>('relations'),failed_attempts:[DATABASE_SCHEMA_VERSION,M8_DATABASE_SCHEMA_VERSION,M7_DATABASE_SCHEMA_VERSION,M6_DATABASE_SCHEMA_VERSION,M5_DATABASE_SCHEMA_VERSION].includes(version.value)?parse<FailedAttempt>('failed_attempts'):[],context_bindings,context_manifests,handoff_packages,handoff_receipts,extraction_candidates,extraction_attempts,guard_records,guard_records_hash:declaration.guard_records_hash,receipts},trusted);
    } catch(error){if(error instanceof StorageError)throw error;throw new StorageError('STORAGE_ERROR','Backup database is invalid');}finally{backup.close();}
  }
  exportData():StorageExport {this.assertSafeDatabaseFiles();const guard_records=this.readStoredGuardRecords();const artifacts=(this.db.prepare('SELECT hash FROM artifacts ORDER BY hash').all()as Array<{hash:string}>).map(({hash})=>({hash,bytes_base64:Buffer.from(this.readArtifact(hash).bytes).toString('base64')}));const parse=<T>(table:string):T[]=>(this.db.prepare(`SELECT payload_json FROM ${table} ORDER BY rowid`).all()as JsonRow[]).map(row=>JSON.parse(row.payload_json)as T);const snapshots=(this.db.prepare('SELECT payload_json FROM snapshots ORDER BY rowid').all()as JsonRow[]).map(row=>validateSnapshot(JSON.parse(row.payload_json)));const lifecycle_events=this.db.prepare('SELECT event_id,record_id,revision_id,lifecycle,actor,source,reason,occurred_at FROM lifecycle_events ORDER BY rowid').all()as LifecycleEvent[];const receipts=(this.db.prepare('SELECT project_id,source_id,idempotency_key,event_id,payload_hash,sequence_gap,expected_sequence FROM ingestion_receipts ORDER BY rowid').all()as ReceiptRow[]).map(row=>({...row,sequence_gap:row.sequence_gap===1}));return{format_version:STORAGE_FORMAT_VERSION,kind:'xmem-storage-export',artifacts,events:parse<Event>('events'),evidences:parse<Evidence>('evidences'),snapshots,revisions:parse<MemoryRecord>('revisions'),lifecycle_events,relations:parse<Relation>('relations'),failed_attempts:this.readStoredFailedAttempts(),context_bindings:this.readStoredContextBindings(),context_manifests:this.readStoredContextManifests(),handoff_packages:this.readStoredHandoffPackages(),handoff_receipts:this.readStoredHandoffReceipts(),extraction_candidates:this.readStoredExtractionCandidates(),extraction_attempts:this.readStoredExtractionAttempts(),guard_records,guard_records_hash:sha256(canonicalJson(guard_records)),receipts};}
  importData(input:unknown):void { this.importValidatedData(input); }
  private importValidatedData(input:unknown, trusted?:TrustedBackupRows):void {
    this.assertSafeDatabaseFiles(); const value=requireExactKeys(input,['format_version','kind','artifacts','events','evidences','revisions','lifecycle_events','relations','failed_attempts','receipts'],'Export');
    if(value.format_version!==STORAGE_FORMAT_VERSION)throw new StorageError('UNSUPPORTED_VERSION','Unsupported storage export version'); if(value.kind!=='xmem-storage-export')throw new StorageError('INVALID_INPUT','Invalid storage export kind');
    for(const key of ['artifacts','events','evidences','snapshots','revisions','lifecycle_events','relations','failed_attempts','receipts','context_bindings','context_manifests','handoff_packages','handoff_receipts','extraction_candidates','extraction_attempts','guard_records']as const)if(value[key]!==undefined&&!Array.isArray(value[key]))throw new StorageError('INVALID_INPUT',`${key} must be an array`);
    const artifacts=(value.artifacts as unknown[]).map(item=>{const a=requireExactKeys(item,['hash','bytes_base64'],'Export artifact');if(!nonEmpty(a.hash)||typeof a.bytes_base64!=='string')throw new StorageError('INVALID_INPUT','Invalid export artifact');const bytes=Buffer.from(a.bytes_base64,'base64');if(Buffer.from(bytes).toString('base64').replace(/=+$/,'')!==a.bytes_base64.replace(/=+$/,''))throw new StorageError('INVALID_INPUT','Invalid artifact encoding');if(!this.validHash(a.hash))throw new StorageError('INVALID_INPUT','Invalid artifact hash');if(sha256(bytes)!==a.hash)throw new StorageError('IDENTITY_CONFLICT','Artifact bytes do not match evidence');return{hash:a.hash,bytes};});
    const events=(value.events as unknown[]).map(validateEvent),evidences=(value.evidences as unknown[]).map(validateEvidence),snapshots=((value.snapshots??[]) as unknown[]).map(value=>validateSnapshot(value)),revisions=(value.revisions as unknown[]).map(validateMemoryRecord),relations=(value.relations as unknown[]).map(validateRelation),failedAttempts=(value.failed_attempts as unknown[]).map(validateFailedAttempt),lifecycle=(value.lifecycle_events as unknown[]).map(x=>this.validateLifecycle(x)),receipts=(value.receipts as unknown[]).map(x=>this.validateReceipt(x)),bindings=((value.context_bindings??[]) as unknown[]).map(x=>this.validateContextBinding(x)),manifests=((value.context_manifests??[]) as unknown[]).map(x=>this.validateContextManifest(x)),handoffPackages=((value.handoff_packages??[]) as unknown[]).map(x=>this.validateHandoffPackage(x)),handoffReceipts=((value.handoff_receipts??[]) as unknown[]).map(x=>this.validateImportedHandoffReceipt(x)),extractionCandidates=((value.extraction_candidates??[]) as unknown[]).map(x=>validateExtractionCandidate(x)),extractionAttempts=((value.extraction_attempts??[]) as unknown[]).map(x=>validateExtractionAttempt(x)),guardRecords=((value.guard_records??[]) as unknown[]).map(x=>this.validateGuardAuditRecord(x));
    if((guardRecords.length>0||value.guard_records_hash!==undefined)&&value.guard_records_hash!==sha256(canonicalJson(guardRecords)))throw new StorageError('IDENTITY_CONFLICT','Guard export set commitment mismatch');
    const snapshotMap=new Map<string,Snapshot>();for(const snapshot of snapshots){const key=`${snapshot.snapshot_id}\0${snapshot.project_id}\0${snapshot.workspace_id}`;if(snapshotMap.has(key))throw new StorageError('IDENTITY_CONFLICT','Export repeats a snapshot identity');snapshotMap.set(key,snapshot);}
    this.validateImportIntegrity(events,evidences,receipts); const importedEvidence=new Map(evidences.map(e=>[e.evidence_id,e])); for(const attempt of failedAttempts){const evidence=importedEvidence.get(attempt.failure_evidence.evidence_id);if(!evidence||canonicalJson(evidence)!==canonicalJson(attempt.failure_evidence))throw new StorageError('IDENTITY_CONFLICT','Imported failed attempt evidence is not bound to the export');} this.validateGuardImport(guardRecords,evidences,failedAttempts,snapshotMap);
    const eventByIdentity=new Map(events.map(event=>[`${event.project_id}\0${event.source.source_id}\0${event.event_id}`,event])), candidateById=new Map(extractionCandidates.map(candidate=>[candidate.candidate_id,candidate])); if(candidateById.size!==extractionCandidates.length||new Set(extractionCandidates.map(candidate=>candidate.request_id)).size!==extractionCandidates.length||new Set(extractionAttempts.map(attempt=>attempt.request_id)).size!==extractionAttempts.length)throw new StorageError('IDENTITY_CONFLICT','Extraction export repeats immutable identities'); for(const candidate of extractionCandidates){const event=eventByIdentity.get(`${candidate.project_id}\0${candidate.source.source_id}\0${candidate.event_id}`);if(!event||event.workspace_id!==candidate.workspace_id||event.evidence_id!==candidate.evidence_id||canonicalJson(event.source)!==canonicalJson(candidate.source)||candidate.source_slice.locator!==event.source.locator||candidate.source_slice.content_hash!==event.source.content_hash)throw new StorageError('IDENTITY_CONFLICT','Imported extraction candidate is not bound to raw authority');} for(const extractionAttempt of extractionAttempts){const event=eventByIdentity.get(`${extractionAttempt.project_id}\0${extractionAttempt.request.source.source_id}\0${extractionAttempt.event_id}`),candidate=extractionAttempt.candidate_id===null?null:candidateById.get(extractionAttempt.candidate_id);if(!event||event.workspace_id!==extractionAttempt.workspace_id||event.evidence_id!==extractionAttempt.evidence_id||canonicalJson(event.source)!==canonicalJson(extractionAttempt.request.source)||extractionAttempt.request.source_slice.locator!==event.source.locator||extractionAttempt.request.source_slice.content_hash!==event.source.content_hash||(extractionAttempt.outcome==='SUCCESS'&&!candidate)||(extractionAttempt.outcome!=='SUCCESS'&&candidate!==null)||candidate&&(candidate.request_id!==extractionAttempt.request_id||candidate.project_id!==extractionAttempt.project_id||candidate.workspace_id!==extractionAttempt.workspace_id||candidate.event_id!==extractionAttempt.event_id||candidate.evidence_id!==extractionAttempt.evidence_id||canonicalJson(candidate.source)!==canonicalJson(extractionAttempt.request.source)||candidate.extractor_version!==extractionAttempt.request.extractor_version||canonicalJson(candidate.extractor_config)!==canonicalJson(extractionAttempt.request.extractor_config)))throw new StorageError('IDENTITY_CONFLICT','Imported extraction attempt is not bound to its candidate and raw authority');}
    const revisionById=new Map(revisions.map(r=>[r.revision_id,r])); for(const binding of bindings){const record=revisionById.get(binding.revision_id);if(!record||record.project_id!==binding.project_id)throw new StorageError('IDENTITY_CONFLICT','Imported context binding is not bound to an exported revision');} for(const manifest of manifests)if(!bindings.some(binding=>binding.project_id===manifest.request.project_id&&binding.workspace_id===manifest.request.workspace_id&&binding.task_ref===manifest.request.task_ref&&binding.task_version===manifest.request.task_version))throw new StorageError('IDENTITY_CONFLICT','Imported context manifest has no bound revisions');
    const evidenceById=new Map(evidences.map(e=>[e.evidence_id,e])), manifestByHash=new Map(manifests.map(m=>[m.content_hash,m])); for(const pack of handoffPackages){for(const ref of pack.revision_refs){const record=revisionById.get(ref.revision_id);if(!record||record.record_id!==ref.record_id||record.project_id!==pack.project_id||canonicalJson(record.source)!==canonicalJson(ref.source)||sha256(canonicalJson(record))!==ref.payload_hash)throw new StorageError('IDENTITY_CONFLICT','Imported handoff revision binding is invalid');}for(const ref of pack.evidence_refs){const evidence=evidenceById.get(ref.evidence_id);if(!evidence||evidence.project_id!==pack.project_id||evidence.workspace_id!==pack.workspace_id||canonicalJson(evidence.source)!==canonicalJson(ref.source)||evidence.snapshot_id!==ref.snapshot_id||evidence.artifact_hash!==ref.artifact_hash||sha256(canonicalJson(evidence))!==ref.payload_hash)throw new StorageError('IDENTITY_CONFLICT','Imported handoff evidence binding is invalid');}for(const ref of pack.failed_attempt_refs){const attempt=failedAttempts.find(x=>x.failed_attempt_id===ref.failed_attempt_id);if(!attempt||attempt.project_id!==pack.project_id||attempt.workspace_id!==pack.workspace_id||sha256(canonicalJson(attempt))!==ref.payload_hash)throw new StorageError('IDENTITY_CONFLICT','Imported handoff failure binding is invalid');}const manifest=manifestByHash.get(pack.context_manifest_hash);if(!manifest||canonicalJson(manifest.coverage)!==canonicalJson(pack.context_coverage)||manifest.request.project_id!==pack.project_id||manifest.request.workspace_id!==pack.workspace_id||manifest.request.task_ref!==pack.task_ref||manifest.request.task_version!==pack.task_version||manifest.request.target_snapshot_id!==pack.target_snapshot_id||pack.revision_refs.some(ref=>!manifest.revisions.includes(ref.revision_id)))throw new StorageError('IDENTITY_CONFLICT','Imported handoff context binding is invalid');}const packageById=new Map(handoffPackages.map(pack=>[pack.package_id,pack]));for(const receipt of handoffReceipts){const pack=packageById.get(receipt.package_id);if(!pack||pack.content_hash!==receipt.content_hash)throw new StorageError('IDENTITY_CONFLICT','Imported handoff receipt is not bound to a package');}
    const supplied=new Set(artifacts.map(x=>x.hash));for(const evidence of evidences)if(evidence.artifact_hash&&!supplied.has(evidence.artifact_hash))this.readArtifact(evidence.artifact_hash);const publication:ArtifactPublication={files:[],directories:[]};
    try { const published=artifacts.map(x=>this.publishArtifact(x.bytes,x.hash,publication));
    const tx=this.db.transaction(()=>{for(const a of published)this.db.prepare('INSERT OR IGNORE INTO artifacts(hash,byte_length,relative_path) VALUES(?,?,?)').run(a.hash,a.byteLength,a.relativePath);for(const snapshot of snapshots)this.recordSnapshot(snapshot);for(const r of revisions)this.importRevision(r);for(const r of relations)this.addRelation(r);for(const e of evidences)this.insertEvidence(e);for(const e of events)this.importEvent(e,evidences.find(x=>x.evidence_id===e.evidence_id));for(const f of failedAttempts)this.recordFailedAttempt(f);for(const l of lifecycle)this.insertLifecycle(l);for(const r of receipts)this.importReceipt(r);for(const binding of bindings)this.bindContextRevision(binding);for(const manifest of manifests)this.importContextManifest(manifest);for(const pack of handoffPackages)this.importHandoffPackage(pack);for(const receipt of handoffReceipts)this.importHandoffReceipt(receipt);for(const extractionAttempt of extractionAttempts)this.persistExtractionOutcome(extractionAttempt.candidate_id===null?null:candidateById.get(extractionAttempt.candidate_id)!,extractionAttempt);for(const record of guardRecords)this.appendGuardAuditRecord(record);if(trusted)this.restoreTrustedBackupRows(trusted);});tx();}catch(error){this.rollbackArtifactPublication(publication);if(error instanceof StorageError)throw error;throw new StorageError('STORAGE_ERROR','Export could not be imported');}
  }
  private importContextManifest(manifest: ContextManifest): void { const request=manifest.request; const prior=this.db.prepare('SELECT payload_json,manifest_hash FROM context_manifests WHERE content_hash=?').get(manifest.content_hash) as {payload_json:string;manifest_hash:string}|undefined, payload_json=canonicalContextJson(manifest); if(prior){if(prior.payload_json!==payload_json||prior.manifest_hash!==manifest.manifest_hash)throw new StorageError('IDENTITY_CONFLICT','Imported context manifest conflicts');return;} this.db.prepare('INSERT INTO context_manifests(content_hash,project_id,workspace_id,task_ref,task_version,request_hash,binding_hash,source_snapshot_hash,view_snapshot_hash,manifest_hash,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(manifest.content_hash,request.project_id,request.workspace_id,request.task_ref,request.task_version,manifest.request_hash,manifest.binding_hash,manifest.source_snapshot_hash,manifest.view_snapshot_hash,manifest.manifest_hash,payload_json); }
  private validateImportedHandoffReceipt(input: unknown): Omit<HandoffReceipt,'replayed'> { const x=requireExactKeys(input,['recipient_id','package_id','content_hash','validation_status','action','reason_codes','receipt_hash'],'Handoff receipt');if(!nonEmpty(x.recipient_id)||!nonEmpty(x.package_id)||!this.validHash(x.content_hash)||!['VALID','STALE','INCOMPLETE','UNKNOWN'].includes(String(x.validation_status))||!['ACCEPTED','REJECTED'].includes(String(x.action))||!Array.isArray(x.reason_codes)||!(x.reason_codes as unknown[]).every(nonEmpty)||new Set(x.reason_codes as string[]).size!==(x.reason_codes as string[]).length||!this.validHash(x.receipt_hash))throw new StorageError('INVALID_INPUT','Invalid handoff receipt');const receipt=x as unknown as Omit<HandoffReceipt,'replayed'>;const {receipt_hash,...body}=receipt;if(receipt_hash!==sha256(canonicalJson(body)))throw new StorageError('IDENTITY_CONFLICT','Handoff receipt hash mismatch');return structuredClone(receipt); }
  private importHandoffPackage(pack:HandoffPackage):void { const prior=this.db.prepare('SELECT payload_json,content_hash FROM handoff_packages WHERE package_id=?').get(pack.package_id) as {payload_json:string;content_hash:string}|undefined;const payload_json=canonicalJson(pack);if(prior){if(prior.payload_json!==payload_json||prior.content_hash!==pack.content_hash)throw new StorageError('IDENTITY_CONFLICT','Imported handoff package conflicts');return;}this.db.prepare('INSERT INTO handoff_packages(package_id,project_id,workspace_id,task_ref,task_version,content_hash,target_snapshot_id,target_snapshot_hash,context_manifest_hash,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?)').run(pack.package_id,pack.project_id,pack.workspace_id,pack.task_ref,pack.task_version,pack.content_hash,pack.target_snapshot_id,pack.target_snapshot_hash,pack.context_manifest_hash,payload_json); }
  private importHandoffReceipt(receipt:Omit<HandoffReceipt,'replayed'>):void { const prior=this.db.prepare('SELECT content_hash,validation_status,action,reason_codes_json,receipt_hash FROM handoff_receipts WHERE recipient_id=? AND package_id=?').get(receipt.recipient_id,receipt.package_id) as {content_hash:string;validation_status:HandoffValidationStatus;action:'ACCEPTED'|'REJECTED';reason_codes_json:string;receipt_hash:string}|undefined;if(prior){const old=this.validateImportedHandoffReceipt({recipient_id:receipt.recipient_id,package_id:receipt.package_id,content_hash:prior.content_hash,validation_status:prior.validation_status,action:prior.action,reason_codes:JSON.parse(prior.reason_codes_json),receipt_hash:prior.receipt_hash});if(canonicalJson(old)!==canonicalJson(receipt))throw new StorageError('IDENTITY_CONFLICT','Imported handoff receipt conflicts');return;}this.db.prepare('INSERT INTO handoff_receipts(recipient_id,package_id,content_hash,validation_status,action,reason_codes_json,receipt_hash) VALUES(?,?,?,?,?,?,?)').run(receipt.recipient_id,receipt.package_id,receipt.content_hash,receipt.validation_status,receipt.action,canonicalJson(receipt.reason_codes),receipt.receipt_hash); }
  private validateImportIntegrity(events:Event[],evidences:Evidence[],receipts:StorageExport['receipts']):void {const evidence=new Map(evidences.map(x=>[x.evidence_id,x])),seen=new Set<string>(),cursor=new Map<string,number>();for(const event of events){const proof=event.evidence_id===null?undefined:evidence.get(event.evidence_id);if(event.evidence_id!==null&&(!proof||proof.project_id!==event.project_id||proof.workspace_id!==event.workspace_id||proof.run_id!==event.run_id))throw new StorageError('INVALID_INPUT','Export event/evidence references are inconsistent');const id=`${event.project_id}\0${event.source.source_id}\0${event.event_id}`;if(seen.has(id))throw new StorageError('IDENTITY_CONFLICT','Export repeats an event identity');seen.add(id);const source=`${event.project_id}\0${event.workspace_id}\0${event.source.source_id}`,expected=cursor.get(source)??0,entries=receipts.filter(r=>r.project_id===event.project_id&&r.source_id===event.source.source_id&&r.event_id===event.event_id),hash=sha256(canonicalJson({event,evidence:proof}));if(!entries.length)throw new StorageError('INVALID_INPUT','Every imported event requires a receipt');for(const r of entries)if(r.payload_hash!==hash||r.expected_sequence!==expected||r.sequence_gap!==(event.sequence!==expected))throw new StorageError('IDENTITY_CONFLICT','Imported receipt is not bound to canonical event and source cursor');cursor.set(source,Math.max(expected-1,event.sequence)+1);}for(const r of receipts)if(!seen.has(`${r.project_id}\0${r.source_id}\0${r.event_id}`))throw new StorageError('INVALID_INPUT','Receipt references no imported event');}
  private importRevision(record:MemoryRecord):void {const current=this.db.prepare('SELECT payload_json FROM revisions WHERE revision_id=?').get(record.revision_id)as JsonRow|undefined,payload=canonicalJson(record);if(current){if(current.payload_json!==payload)throw new StorageError('IDENTITY_CONFLICT','Imported revision conflicts');return;}const parent=this.db.prepare('SELECT current_revision_id,project_id FROM records WHERE record_id=?').get(record.record_id)as {current_revision_id:string;project_id:string}|undefined;if(!parent){if(record.previous_revision_id!==null)throw new StorageError('IDENTITY_CONFLICT','Imported first revision has a missing predecessor');this.db.prepare('INSERT INTO records(record_id,project_id,current_revision_id) VALUES(?,?,?)').run(record.record_id,record.project_id,record.revision_id);}else{if(parent.project_id!==record.project_id||parent.current_revision_id!==record.previous_revision_id)throw new StorageError('IDENTITY_CONFLICT','Imported revision does not extend current state');this.db.prepare('UPDATE records SET current_revision_id=? WHERE record_id=?').run(record.revision_id,record.record_id);}this.db.prepare('INSERT INTO revisions(revision_id,record_id,project_id,previous_revision_id,payload_json,created_at) VALUES(?,?,?,?,?,?)').run(record.revision_id,record.record_id,record.project_id,record.previous_revision_id,payload,new Date().toISOString());}
  private importEvent(event:Event,evidence?:Evidence):void {const hash=sha256(canonicalJson({event,evidence})),prior=this.db.prepare('SELECT payload_hash FROM events WHERE project_id=? AND source_id=? AND event_id=?').get(event.project_id,event.source.source_id,event.event_id)as {payload_hash:string}|undefined;if(prior){if(prior.payload_hash!==hash)throw new StorageError('IDENTITY_CONFLICT','Imported event conflicts');return;}this.db.prepare('INSERT INTO events(project_id,source_id,event_id,workspace_id,sequence,payload_hash,payload_json) VALUES(?,?,?,?,?,?,?)').run(event.project_id,event.source.source_id,event.event_id,event.workspace_id,event.sequence,hash,canonicalJson(event));}
  private importReceipt(r:StorageExport['receipts'][number]):void {const prior=this.db.prepare('SELECT event_id,payload_hash,sequence_gap,expected_sequence FROM ingestion_receipts WHERE project_id=? AND source_id=? AND idempotency_key=?').get(r.project_id,r.source_id,r.idempotency_key)as {event_id:string;payload_hash:string;sequence_gap:number;expected_sequence:number}|undefined;if(prior){if(prior.event_id!==r.event_id||prior.payload_hash!==r.payload_hash||(prior.sequence_gap===1)!==r.sequence_gap||prior.expected_sequence!==r.expected_sequence)throw new StorageError('IDENTITY_CONFLICT','Imported receipt conflicts');return;}this.db.prepare('INSERT INTO ingestion_receipts(project_id,source_id,idempotency_key,event_id,payload_hash,sequence_gap,expected_sequence) VALUES(?,?,?,?,?,?,?)').run(r.project_id,r.source_id,r.idempotency_key,r.event_id,r.payload_hash,r.sequence_gap?1:0,r.expected_sequence);}
  private validateLifecycle(input:unknown):LifecycleEvent {const x=requireExactKeys(input,['event_id','record_id','revision_id','lifecycle','actor','source','reason','occurred_at'],'Lifecycle event');if(!nonEmpty(x.event_id)||!nonEmpty(x.record_id)||!nonEmpty(x.revision_id)||!LIFECYCLES.includes(x.lifecycle as Lifecycle)||!nonEmpty(x.actor)||!nonEmpty(x.source)||!nonEmpty(x.reason)||!isoTimestamp(x.occurred_at))throw new StorageError('INVALID_INPUT','Invalid lifecycle event');return x as unknown as LifecycleEvent;}
  private validateGuardBinding(input:unknown):Record<string,unknown> {
    const b=requireExactKeys(input,['request_id','task_id','run_id','project_id','workspace_id','target_snapshot_hash','condition_fingerprints_hash','action_fingerprint','policy_version','reference_id','input_commitment_hash'],'Guard binding');
    const {input_commitment_hash,...body}=b;
    if(!['request_id','task_id','run_id','project_id','workspace_id','reference_id'].every(key=>nonEmpty(b[key]))||b.policy_version!=='declared-inputs-v1'||!['target_snapshot_hash','condition_fingerprints_hash','action_fingerprint'].every(key=>this.validHash(b[key]))||input_commitment_hash!==sha256(canonicalJson(body)))throw new StorageError('IDENTITY_CONFLICT','Guard input commitment mismatch');
    return b;
  }
  private validateGuardImport(records:GuardAuditRecord[], evidences:Evidence[], attempts:FailedAttempt[], snapshots:Map<string,Snapshot>):void {
    const evidence=new Map(evidences.map(item=>[item.evidence_id,item]));
    const failed=new Map(attempts.map(item=>[item.failed_attempt_id,item]));
    const groups=new Map<string,GuardAuditRecord[]>();
    for(const record of records){const group=groups.get(record.run_id)??[];group.push(record);groups.set(record.run_id,group);}
    for(const [run,chain] of groups){
      if(chain.length===0||chain[0].kind!=='run_manifest'||chain.filter(record=>record.kind==='run_manifest').length!==1)throw new StorageError('IDENTITY_CONFLICT','Guard run lacks a manifest');
      let previous:string|null=null;
      for(const record of chain){if(record.previous_hash!==previous)throw new StorageError('IDENTITY_CONFLICT','Guard import chain is discontinuous');previous=record.chain_hash;}
      const manifest=chain[0], body=manifest.payload;
      if(manifest.decision_id!==null||manifest.permit_id!==null||manifest.action_fingerprint!==null)throw new StorageError('IDENTITY_CONFLICT','Guard manifest carries action authority');
      if(Object.keys(body).sort().join(',')!=='target_snapshot_hash,target_snapshot_id,task_id'||!nonEmpty(body.task_id)||!nonEmpty(body.target_snapshot_id)||!this.validHash(body.target_snapshot_hash))throw new StorageError('IDENTITY_CONFLICT','Guard manifest is malformed');
      const snapshot=snapshots.get(`${String(body.target_snapshot_id)}\0${manifest.project_id}\0${manifest.workspace_id}`);
      if(!snapshot||snapshot.project_id!==manifest.project_id||snapshot.workspace_id!==manifest.workspace_id||sha256(canonicalJson(snapshot))!==body.target_snapshot_hash)throw new StorageError('IDENTITY_CONFLICT','Guard manifest snapshot is not bound to a stored snapshot');
      const decisions=new Map<string,GuardAuditRecord>(), permits=new Map<string,GuardAuditRecord>(), reservations=new Set<string>(), invalidated=new Set<string>(), executionState=new Map<string,'STARTED'|'FAILED'|'SUCCEEDED'|'UNKNOWN'>(), receipts=new Set<string>();
      for(const record of chain){
        if(record.project_id!==manifest.project_id||record.workspace_id!==manifest.workspace_id)throw new StorageError('IDENTITY_CONFLICT','Guard run scope changes');
        const p=record.payload as Record<string,unknown>;
        if(record.kind==='decision'){
          const b=this.validateGuardBinding(p.binding), result=String(p.result);
          if(record.record_id!==record.decision_id||record.permit_id!==null||record.action_fingerprint===null||!b||!['ALLOW','PAUSE','BLOCK'].includes(result)||b.run_id!==run||b.project_id!==record.project_id||b.workspace_id!==record.workspace_id||record.action_fingerprint!==b.action_fingerprint||(p.input_commitment_hash!==undefined&&p.input_commitment_hash!==b.input_commitment_hash)||(result!=='PAUSE'&&(b.task_id!==body.task_id||b.target_snapshot_hash!==body.target_snapshot_hash)))throw new StorageError('IDENTITY_CONFLICT','Guard decision binding is invalid');
          if(result==='ALLOW'){
            const reference=p.reference_kind==='EVIDENCE'?evidence.get(String(p.reference_id)):p.reference_kind==='FAILED_ATTEMPT'?failed.get(String(p.reference_id)):undefined;
            if(!reference||p.reference_id!==b.reference_id||p.reference_hash!==sha256(canonicalJson(reference)))throw new StorageError('IDENTITY_CONFLICT','Guard allow decision is not bound to authority');
          }
          decisions.set(record.record_id,record);
        } else if(record.kind==='permit') {
          const decision=record.decision_id===null?undefined:decisions.get(record.decision_id), permit=p.permit as Record<string,unknown>, action=p.action as Record<string,unknown>;
          if(!decision||(decision.payload as Record<string,unknown>).result!=='ALLOW'||!permit||!action||!p.binding||record.record_id!==record.permit_id||permit.permit_id!==record.permit_id||permit.decision_id!==record.decision_id||permit.run_id!==run||permit.project_id!==record.project_id||permit.workspace_id!==record.workspace_id||permit.target_snapshot_hash!==body.target_snapshot_hash||permit.action_fingerprint!==record.action_fingerprint||permit.condition_fingerprints_hash!==(p.binding as Record<string,unknown>).condition_fingerprints_hash||canonicalJson(p.binding)!==canonicalJson((decision.payload as Record<string,unknown>).binding)||action.action_id!=='controlled-write-marker'||!nonEmpty(action.marker_id)||!this.validHash(action.value_hash)||!this.validHash(action.observable_args_hash)||Object.keys(action).sort().join(',')!=='action_id,marker_id,observable_args_hash,value_hash'||sha256(canonicalJson(action))!==record.action_fingerprint||record.action_fingerprint!==decision.action_fingerprint||record.action_fingerprint!==(p.binding as Record<string,unknown>).action_fingerprint)throw new StorageError('IDENTITY_CONFLICT','Guard permit is not bound to an ALLOW decision');
          permits.set(record.record_id,record);
        } else if(record.kind==='reservation') {
          const permit=record.permit_id===null?undefined:permits.get(record.permit_id);
          if(!permit||invalidated.has(String(record.permit_id))||reservations.has(String(record.permit_id))||record.decision_id!==permit.decision_id||record.action_fingerprint!==permit.action_fingerprint||p.state!=='RESERVED'||p.target_snapshot_hash!==(permit.payload.permit as Record<string,unknown>).target_snapshot_hash||p.condition_fingerprints_hash!==(permit.payload.permit as Record<string,unknown>).condition_fingerprints_hash)throw new StorageError('IDENTITY_CONFLICT','Guard reservation is not bound to a permit');
          reservations.add(String(record.permit_id));
        } else if(record.kind==='execution') {
          const permit=record.permit_id===null?undefined:permits.get(record.permit_id), action=permit?.payload.action as Record<string,unknown>|undefined;
          const prior=executionState.get(String(record.permit_id));
          if(!permit||!reservations.has(String(record.permit_id))||record.decision_id!==permit.decision_id||record.action_fingerprint!==permit.action_fingerprint||!action||p.action_id!==action.action_id||p.marker_id!==action.marker_id||(p.value_hash!==undefined&&p.value_hash!==action.value_hash)||!['STARTED','FAILED','SUCCEEDED','UNKNOWN'].includes(String(p.state))||(p.state==='STARTED'&&prior!==undefined)||((p.state==='FAILED'||p.state==='SUCCEEDED'||p.state==='UNKNOWN')&&prior!=='STARTED')||(p.state==='UNKNOWN'&&p.reason!=='ACTION_OUTCOME_UNKNOWN'))throw new StorageError('IDENTITY_CONFLICT','Guard execution action is not bound to its permit');
          executionState.set(String(record.permit_id),p.state as 'STARTED'|'FAILED'|'SUCCEEDED'|'UNKNOWN');
        } else if(record.kind==='receipt') {
          const permit=record.permit_id===null?undefined:permits.get(record.permit_id), action=permit?.payload.action as Record<string,unknown>|undefined;
          if(!permit||receipts.has(String(record.permit_id))||!reservations.has(String(record.permit_id))||executionState.get(String(record.permit_id))!=='SUCCEEDED'||record.decision_id!==permit.decision_id||record.action_fingerprint!==permit.action_fingerprint||p.outcome!=='EXECUTED'||!action||p.action_id!==action.action_id||p.marker_id!==action.marker_id||p.value_hash!==action.value_hash)throw new StorageError('IDENTITY_CONFLICT','Guard receipt is not bound to successful execution');
          receipts.add(String(record.permit_id));
        } else if(record.kind==='checkpoint') {
          const permit=record.permit_id===null?undefined:permits.get(record.permit_id);
          this.validateGuardBinding(p.attempted_binding);
          if(!permit||!this.validHash(p.attempted_permit_hash)||record.decision_id!==permit.decision_id||record.action_fingerprint!==permit.action_fingerprint||p.checkpoint!=='consumed'||p.outcome!=='PAUSED'||p.reason!=='POST_CHECK_DRIFT'||canonicalJson(p.binding)!==canonicalJson(permit.payload.binding))throw new StorageError('IDENTITY_CONFLICT','Guard checkpoint is not bound to its permit');
          invalidated.add(String(record.permit_id));
        } else if(record.kind==='deviation') {
          throw new StorageError('IDENTITY_CONFLICT','Guard import contains an unbound deviation');
        }
      }
    }
  }
  private validateReceipt(input:unknown):StorageExport['receipts'][number]{const x=requireExactKeys(input,['project_id','source_id','idempotency_key','event_id','payload_hash','sequence_gap','expected_sequence'],'Receipt');if(!nonEmpty(x.project_id)||!nonEmpty(x.source_id)||!nonEmpty(x.idempotency_key)||!nonEmpty(x.event_id)||!/^[a-f0-9]{64}$/.test(String(x.payload_hash))||typeof x.sequence_gap!=='boolean'||!Number.isInteger(x.expected_sequence)||(x.expected_sequence as number)<0)throw new StorageError('INVALID_INPUT','Invalid receipt');return x as unknown as StorageExport['receipts'][number];}
}
