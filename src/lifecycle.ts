import { createHash } from 'node:crypto';

/** R3.2 storage-retention lifecycle.
 *
 * This is deliberately distinct from MemoryRecord.lifecycle
 * (ACTIVE | SUPERSEDED | RETRACTED). Retention tiers describe whether persisted
 * material is current, historical-but-retained, or safe to physically remove.
 */
export const RETENTION_POLICY_VERSION = 'retention-policy-v1' as const;
export type RetentionTier = 'ACTIVE' | 'ARCHIVED' | 'PRUNABLE';
export type CleanupCandidateKind = 'CONTEXT_MANIFEST' | 'ARTIFACT_ROW' | 'ARTIFACT_FILE';

export interface CleanupCandidate {
  kind: CleanupCandidateKind;
  id: string;
  reason_code: 'REBUILDABLE_OLD_CONTEXT' | 'UNREFERENCED_ARTIFACT_ROW' | 'ORPHAN_ARTIFACT_FILE';
  estimated_bytes: number;
  fingerprint: string;
}

export interface RetentionTierCounts {
  memory_records: number;
  historical_revisions: number;
  context_manifests: number;
  handoff_packages: number;
  evidences: number;
  failed_attempts: number;
  snapshots: number;
  artifact_rows: number;
  artifact_files: number;
}

export interface StorageLifecycleStatus {
  kind: 'xmem-storage-lifecycle-status';
  policy_version: typeof RETENTION_POLICY_VERSION;
  project_id: string;
  archive_is_logical: true;
  physical_delete_only_prunable: true;
  semantic_memory_lifecycle_is_distinct: true;
  tiers: Record<RetentionTier, RetentionTierCounts>;
  protected: {
    events: number;
    lifecycle_events: number;
    relations: number;
    ingestion_receipts: number;
    context_bindings: number;
    handoff_receipts: number;
    extraction_candidates: number;
    extraction_attempts: number;
    guard_records: number;
    collector_registrations: number;
    trusted_source_versions: number;
    trusted_collector_receipts: number;
  };
  storage_bytes: {
    database: number;
    wal: number;
    shm: number;
    journal: number;
    artifacts: number;
    total: number;
    estimated_prunable: number;
  };
  cleanup_scope: {
    deletes_active: false;
    deletes_archived: false;
    prunable_kinds: readonly ['CONTEXT_MANIFEST','ARTIFACT_ROW','ARTIFACT_FILE'];
  };
}

export interface CleanupPlan {
  kind: 'xmem-cleanup-plan';
  policy_version: typeof RETENTION_POLICY_VERSION;
  project_id: string;
  plan_hash: string;
  observed_at: string;
  candidates: CleanupCandidate[];
  counts: Record<CleanupCandidateKind, number>;
  estimated_reclaimable_bytes: number;
  guarantees: {
    active_deleted: false;
    archived_deleted: false;
    context_manifest_references_preserved: true;
    evidence_and_audit_material_preserved: true;
  };
}

export interface CleanupApplyResult {
  kind: 'xmem-cleanup-result';
  policy_version: typeof RETENTION_POLICY_VERSION;
  project_id: string;
  applied_plan_hash: string;
  deleted: Record<CleanupCandidateKind, number>;
  estimated_bytes_targeted: number;
  physical_artifact_bytes_removed: number;
  remaining_prunable_candidates: number | null;
  artifact_file_cleanup_incomplete: boolean;
  reason_codes: string[];
}

export interface StorageCompactResult {
  kind: 'xmem-storage-compact-result';
  project_id: string;
  sqlite_quick_check: 'PASS';
  before_bytes: number;
  after_bytes: number;
  reclaimed_bytes: number;
  logical_rows_deleted: 0;
  wal_checkpoint: { busy: 0; log_frames: number; checkpointed_frames: number };
  method: 'WAL_CHECKPOINT_TRUNCATE_AND_OPTIMIZE';
  main_database_vacuum_run: false;
  reason_codes: readonly ['MAIN_DATABASE_VACUUM_DEFERRED_TO_PRESERVE_ROWID_RECENCY'];
}


function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value as Record<string,unknown>).sort().map(key=>[key,canonicalize((value as Record<string,unknown>)[key])]));
  return value;
}
function canonicalJson(value: unknown): string { return JSON.stringify(canonicalize(value)); }
export function cleanupPlanHash(projectId:string,candidates:readonly CleanupCandidate[]):string {
  return createHash('sha256').update(canonicalJson({policy_version:RETENTION_POLICY_VERSION,project_id:projectId,candidates})).digest('hex');
}
export function createCleanupPlan(projectId:string,candidatesInput:readonly CleanupCandidate[]):CleanupPlan {
  const candidates=structuredClone([...candidatesInput]).sort((a,b)=>a.kind.localeCompare(b.kind)||a.id.localeCompare(b.id));
  const counts:Record<CleanupCandidateKind,number>={CONTEXT_MANIFEST:0,ARTIFACT_ROW:0,ARTIFACT_FILE:0};for(const candidate of candidates)counts[candidate.kind]++;
  return{kind:'xmem-cleanup-plan',policy_version:RETENTION_POLICY_VERSION,project_id:projectId,plan_hash:cleanupPlanHash(projectId,candidates),observed_at:new Date().toISOString(),candidates,counts,estimated_reclaimable_bytes:candidates.reduce((sum,item)=>sum+item.estimated_bytes,0),guarantees:{active_deleted:false,archived_deleted:false,context_manifest_references_preserved:true,evidence_and_audit_material_preserved:true}};
}
