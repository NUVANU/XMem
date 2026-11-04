/** Bounded, explicit local-file intake. No network, shell, database, or model calls. */
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';
import { PathsError, resolveProjectPath } from './paths.js';
import type { SourceRef, MemoryRecord } from './contracts.js';

export const LOCAL_SOURCE_PREFIX = 'xmem-local-file-v1:';
export const MAX_SOURCE_BYTES = 1024 * 1024;
export const MAX_EXCERPT_BYTES = 16 * 1024;
export const MAX_SNAPSHOT_FILES = 32;
export type CaptureKind = MemoryRecord['kind'];
export interface LocalMemoryInput {
  workspace_id: string; task_ref: string; task_version: string; memory_key: string;
  source_path: string; excerpt: string; kind: CaptureKind; roles: string[];
  mandatory: boolean; previous_revision_id: string | null;
}
export interface LocalSnapshotInput { workspace_id: string; files: string[]; }
export const hashBytes = (value: string | Uint8Array): string => createHash('sha256').update(value).digest('hex');
const text = (value: unknown): value is string => typeof value === 'string' && value.trim().length > 0 && value.length <= 512 && !value.includes('\0');
function object(input: unknown, keys: string[]): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).sort().join(',') !== keys.sort().join(',')) throw new PathsError('INVALID_INPUT', 'Input has unknown or missing fields');
  return input as Record<string, unknown>;
}
export function validateLocalMemoryInput(input: unknown): LocalMemoryInput {
  const x = object(input, ['workspace_id','task_ref','task_version','memory_key','source_path','excerpt','kind','roles','mandatory','previous_revision_id']);
  if (!['workspace_id','task_ref','task_version','memory_key','source_path'].every(k => text(x[k])) || typeof x.excerpt !== 'string' || !x.excerpt.trim() || x.excerpt.includes('\0') || Buffer.byteLength(x.excerpt, 'utf8') > MAX_EXCERPT_BYTES || !['Observation','DecisionRef','ConstraintRef','FailedAttempt','RootCauseHypothesis'].includes(String(x.kind)) || !Array.isArray(x.roles) || x.roles.length < 1 || x.roles.length > 8 || !x.roles.every(text) || new Set(x.roles).size !== x.roles.length || typeof x.mandatory !== 'boolean' || !(x.previous_revision_id === null || text(x.previous_revision_id))) throw new PathsError('INVALID_INPUT', 'Invalid local memory input');
  rejectObviousSecret(x.excerpt);
  return { ...(structuredClone(x) as unknown as LocalMemoryInput), roles: [...x.roles].sort() as string[] };
}
export function validateLocalSnapshotInput(input: unknown): LocalSnapshotInput {
  const x = object(input, ['workspace_id','files']);
  if (!text(x.workspace_id) || !Array.isArray(x.files) || x.files.length < 1 || x.files.length > MAX_SNAPSHOT_FILES || !x.files.every(text)) throw new PathsError('INVALID_INPUT', 'Snapshot requires a workspace and 1–32 explicit local files');
  const files = (x.files as string[]).map(normalizeLocalSourcePath).sort();
  if (new Set(files).size !== files.length) throw new PathsError('INVALID_INPUT', 'Duplicate snapshot paths');
  return { workspace_id: x.workspace_id, files };
}
export function normalizeLocalSourcePath(relative: string): string {
  if (typeof relative !== 'string' || !relative || path.posix.isAbsolute(relative) || path.win32.isAbsolute(relative)) throw new PathsError('UNSAFE_PATH', 'Use an explicit project-relative source path');
  const parts = relative.replaceAll('\\', '/').split('/');
  const blocked = new Set(['.git','.xmem','.ssh','.aws','node_modules','secrets','credentials']);
  if (parts.some(p => !p || p === '.' || p === '..' || blocked.has(p.toLowerCase()) || /^\.env(?:\.|$)/i.test(p) || /^(?:\.npmrc|\.pypirc|\.git-credentials|id_rsa|id_ed25519|credentials\.json)$/i.test(p) || /\.(?:pem|key|p12|pfx|sqlite|sqlite3|db)$/i.test(p))) throw new PathsError('UNSAFE_SOURCE', 'Private, runtime, dependency, or credential sources are not accepted');
  return parts.join('/');
}
export function rejectObviousSecret(value: string): void {
  // Conservative guard only, not a complete DLP or secret-scanning guarantee.
  if (/-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----|\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,})\b/.test(value) || /\b(?:api[_-]?key|password|access[_-]?token|client[_-]?secret)\s*[:=]\s*["']?[^\s"',;]{8,}/i.test(value)) throw new PathsError('SENSITIVE_INPUT', 'Potential credential in excerpt; use a redacted source first');
}
export function readLocalSource(root: string, relative: string): { relative: string; bytes: Buffer; text: string } {
  const normalized = normalizeLocalSourcePath(relative);
  const filename = resolveProjectPath(root, normalized);
  let fd: number | undefined;
  try {
    fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size > MAX_SOURCE_BYTES) throw new PathsError('SOURCE_LIMIT', 'Source must be a regular file no larger than 1 MiB');
    const buffer = Buffer.alloc(MAX_SOURCE_BYTES + 1);
    let length = 0;
    while (length < buffer.length) { const n = fs.readSync(fd, buffer, length, buffer.length - length, null); if (!n) break; length += n; }
    const after = fs.fstatSync(fd);
    if (length > MAX_SOURCE_BYTES || before.size !== after.size || before.mtimeMs !== after.mtimeMs) throw new PathsError('SOURCE_DRIFT', 'Source changed or exceeded the size bound during read');
    const bytes = buffer.subarray(0, length);
    let decoded: string;
    try { decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { throw new PathsError('INVALID_SOURCE_ENCODING', 'Only UTF-8 text sources are supported'); }
    if (decoded.includes('\0')) throw new PathsError('INVALID_SOURCE_ENCODING', 'Binary sources are not supported');
    // Repeat existing path checks before accepting the opened file.
    if (resolveProjectPath(root, normalized) !== filename) throw new PathsError('SOURCE_DRIFT', 'Source path changed');
    const current = fs.statSync(filename);
    if (current.dev !== after.dev || current.ino !== after.ino) throw new PathsError('SOURCE_DRIFT', 'Source was replaced during read');
    return { relative: normalized, bytes, text: decoded };
  } catch (error) {
    if (error instanceof PathsError) throw error;
    throw new PathsError('SOURCE_MISSING', 'Requested local source is missing or unreadable');
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
export function localSourceRef(projectId: string, relative: string, bytes: Uint8Array): SourceRef {
  const normalized = normalizeLocalSourcePath(relative), content_hash = hashBytes(bytes);
  return { source_id: `local-file-${hashBytes(JSON.stringify([projectId, normalized]))}`, kind: 'file', locator: LOCAL_SOURCE_PREFIX + normalized, version: content_hash, content_hash };
}
export function readSourceReference(root: string, projectId: string, source: SourceRef): Buffer | undefined {
  if (source.kind !== 'file' || !source.locator.startsWith(LOCAL_SOURCE_PREFIX)) return undefined;
  const data = readLocalSource(root, source.locator.slice(LOCAL_SOURCE_PREFIX.length));
  if (localSourceRef(projectId, data.relative, data.bytes).source_id !== source.source_id) throw new PathsError('IDENTITY_CONFLICT', 'Local source identity mismatch');
  return data.bytes;
}
