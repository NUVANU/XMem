/** Read-only SQLite health probe. Does not create or migrate a database. */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { resolveProjectRoot } from './paths.js';
import { DATABASE_SCHEMA_VERSION } from './storage-version.js';
import type Database from 'better-sqlite3';

export type StorageHealthStatus = 'NOT_CREATED' | 'OK' | 'MIGRATION_REQUIRED' | 'UNSUPPORTED_VERSION' | 'CORRUPT' | 'UNAVAILABLE';
export interface StorageHealth {
  status: StorageHealthStatus; schema_version: string | null; sqlite_check: 'PASS' | 'NOT_RUN' | 'FAIL';
  counts: Record<string, number> | null; memory_state: 'EMPTY' | 'NO_ACTIVE_BINDINGS' | 'AVAILABLE' | 'UNKNOWN';
  reason_codes: string[];
}
export function notCreatedStorageHealth():StorageHealth {
  return {status:'NOT_CREATED',schema_version:null,sqlite_check:'NOT_RUN',counts:{events:0,revisions:0,context_bindings:0,snapshots:0,handoff_packages:0,evidences:0,active_bindings:0},memory_state:'EMPTY',reason_codes:['NO_DATABASE_YET']};
}
/** The original doctor's schema/health SQL, also used on explicit readonly images. */
export function inspectOpenDatabase(db:Database.Database,projectId:string):StorageHealth {
  const base=notCreatedStorageHealth();
  const checked = db.pragma('quick_check', { simple:true });
  if (checked !== 'ok') return {...base,status:'CORRUPT',sqlite_check:'FAIL',counts:null,memory_state:'UNKNOWN',reason_codes:['SQLITE_QUICK_CHECK_FAILED']};
  const version = db.prepare("SELECT value FROM xmem_metadata WHERE key='schema_version'").get() as {value:string}|undefined;
  if (!version) return {...base,status:'UNSUPPORTED_VERSION',sqlite_check:'PASS',counts:null,memory_state:'UNKNOWN',reason_codes:['SCHEMA_MARKER_MISSING']};
  if (version.value !== DATABASE_SCHEMA_VERSION) return {...base,status:['2','3','4','5','6','7','8'].includes(version.value)?'MIGRATION_REQUIRED':'UNSUPPORTED_VERSION',schema_version:version.value,sqlite_check:'PASS',counts:null,memory_state:'UNKNOWN',reason_codes:['NO_MIGRATION_IN_DOCTOR']};
  const counts: Record<string, number> = {};
  for (const table of ['events','revisions','context_bindings','snapshots','handoff_packages','evidences']) counts[table] = (db.prepare(`SELECT count(*) AS n FROM ${table} WHERE project_id=?`).get(projectId) as {n:number}).n;
  counts.active_bindings = (db.prepare(`SELECT count(*) AS n FROM context_bindings b JOIN records r ON r.current_revision_id=b.revision_id WHERE b.project_id=? AND (SELECT lifecycle FROM lifecycle_events l WHERE l.record_id=r.record_id ORDER BY rowid DESC LIMIT 1)='ACTIVE'`).get(projectId) as {n:number}).n;
  const memory_state = counts.revisions === 0 ? 'EMPTY' : counts.active_bindings === 0 ? 'NO_ACTIVE_BINDINGS' : 'AVAILABLE';
  return {status:'OK',schema_version:version.value,sqlite_check:'PASS',counts,memory_state,reason_codes:memory_state==='AVAILABLE'?['SQLITE_OK_NOT_END_TO_END_CERTIFICATION']:[memory_state==='EMPTY'?'NO_MEMORY_RECORDED':'NO_ACTIVE_BINDINGS']};
}
export function inspectStorage(storageRoot: string, projectId: string): StorageHealth {
  const root = resolveProjectRoot(storageRoot);
  const file = path.join(root, 'xmem.sqlite');
  for (const suffix of ['','-wal','-shm','-journal']) {
    const candidate = path.join(root, 'xmem.sqlite' + suffix);
    if (fs.existsSync(candidate) && !fs.lstatSync(candidate).isFile()) return {status:'CORRUPT',schema_version:null,sqlite_check:'NOT_RUN',counts:null,memory_state:'UNKNOWN',reason_codes:['DATABASE_PATH_NOT_REGULAR']};
  }
  // A project with no database has exactly zero persisted rows. Returning explicit
  // zero counts keeps the diagnostic truthful while allowing callers to prove that
  // rejected capture attempts did not fabricate memory/evidence.
  const emptyCounts: Record<string,number> = {events:0,revisions:0,context_bindings:0,snapshots:0,handoff_packages:0,evidences:0,active_bindings:0};
  const base: StorageHealth = {status:'NOT_CREATED',schema_version:null,sqlite_check:'NOT_RUN',counts:emptyCounts,memory_state:'EMPTY',reason_codes:['NO_DATABASE_YET']};
  if (!fs.existsSync(file)) return base;
  let db: Database.Database | undefined;
  let open: typeof Database;
  try { open = createRequire(import.meta.url)('better-sqlite3') as typeof Database; }
  catch { return {...base,status:'UNAVAILABLE',counts:null,memory_state:'UNKNOWN',reason_codes:['SQLITE_RUNTIME_UNAVAILABLE']}; }
  try {
    db = new open(file, { readonly:true, fileMustExist:true, timeout:1500 });
    db.pragma('query_only = ON');
    return inspectOpenDatabase(db,projectId);
  } catch (error) {
    const code = (error as {code?:string}).code;
    return {...base,status:code==='SQLITE_CORRUPT'||code==='SQLITE_NOTADB'?'CORRUPT':'UNAVAILABLE',sqlite_check:'FAIL',counts:null,memory_state:'UNKNOWN',reason_codes:[code==='SQLITE_CORRUPT'||code==='SQLITE_NOTADB'?'SQLITE_CORRUPT':'DATABASE_CHECK_FAILED']};
  } finally { db?.close(); }
}
