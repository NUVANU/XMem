import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

export class PathsError extends Error {
  constructor(public readonly code: string, message: string) { super(message); this.name = 'PathsError'; }
}
export function serializeError(error: unknown) {
  return { ok: false as const, error: { code: error instanceof PathsError ? error.code : 'IO_ERROR', message: error instanceof PathsError ? error.message : 'Filesystem operation failed' } };
}
function reject(code: string, message: string): never { throw new PathsError(code, message); }
function components(value: string): string[] { return value.split(/[\\/]/); }
// Win32 treats these as device names even with an extension. Its recognized
// COM/LPT suffixes also include superscript one through three.
const WINDOWS_DEVICE_COMPONENT = /^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\s*\..*)?$/i;
function validateParts(parts: string[]) {
  for (const part of parts) {
    if (!part || part === '.' || part === '..' || /[<>:"|?*\x00-\x1f]/.test(part) || /[. ]$/.test(part) || WINDOWS_DEVICE_COMPONENT.test(part)) reject('UNSAFE_PATH', 'Path contains an unsafe component');
  }
}
type LocalDriveScope = Map<string, string>;
let activeLocalDriveScope: LocalDriveScope | null = null;
let activeRemaining: (() => number) | undefined;
function scopeTimeout(): number {
  const remaining = activeRemaining?.() ?? 10000;
  if (!Number.isFinite(remaining) || remaining < 1) reject('PATH_DEADLINE_EXPIRED', 'Path validation deadline expired');
  return Math.min(10000, Math.floor(remaining));
}
/**
 * Synchronous public operations may validate the same Windows drive many times while
 * resolving config, policy, source and storage paths. Share only successful DriveInfo
 * verdicts inside one operation; the scope is discarded before the next operation.
 * This removes repeated PowerShell startup cost without weakening per-operation drive
 * validation. Symlink/junction checks still run on every path resolution.
 */
export function withPathValidationScope<T>(operation: () => T, remaining?: () => number): T {
  const priorScope = activeLocalDriveScope, priorRemaining = activeRemaining;
  if (!activeLocalDriveScope) activeLocalDriveScope = new Map();
  activeRemaining = priorRemaining && remaining ? () => Math.min(priorRemaining(), remaining()) : priorRemaining ?? remaining;
  try { return operation(); }
  finally { activeLocalDriveScope = priorScope; activeRemaining = priorRemaining; }
}
function driveFingerprint(drive: string): string {
  const stat = fs.statSync(drive);
  return `${stat.dev}:${stat.ino}:${stat.birthtimeMs}`;
}
export function assertLocalDrive(absolute: string): void {
  scopeTimeout();
  if (process.platform !== 'win32') return;
  const drive = path.parse(absolute).root;
  if (!/^[A-Za-z]:\\$/.test(drive)) reject('NETWORK_PATH', 'Only local drive paths are supported');
  let fingerprint: string;
  try { fingerprint = driveFingerprint(drive); }
  catch { reject('DRIVE_UNKNOWN', 'Could not fingerprint local storage drive'); }
  const key = drive.toUpperCase();
  scopeTimeout();
  if (activeLocalDriveScope?.get(key) === fingerprint) return;
  try {
    // Direct .NET construction/output avoids cmdlet and output-pipeline overhead.
    // The same DriveInfo query still runs for every uncached operation/fingerprint.
    const type = execFileSync(powerShellHost(), ['-MTA', '-NoProfile', '-NonInteractive', '-Command', `[Console]::Out.Write([System.IO.DriveInfo]::new('${drive}').DriveType.ToString())`], { encoding: 'utf8', windowsHide: true, timeout: scopeTimeout() }).trim();
    scopeTimeout();
    if (type !== 'Fixed' && type !== 'Removable') reject('NETWORK_PATH', 'Storage drive must be verified local');
    activeLocalDriveScope?.set(key, fingerprint);
  } catch (error) {
    activeLocalDriveScope?.delete(key);
    if (error instanceof PathsError) throw error;
    reject('DRIVE_UNKNOWN', 'Could not verify local storage drive');
  }
}
// Walk every existing ancestor, including those preceding a missing leaf.
function assertNoLinks(absolute: string): void {
  const root = path.parse(absolute).root;
  let current = root;
  for (const part of path.relative(root, absolute).split(path.sep).filter(Boolean)) {
    current = current.endsWith(path.sep) ? current + part : current + path.sep + part;
    try {
      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink()) reject('LINK_PATH', 'Symbolic links and junctions are unsupported');
      if (path.resolve(fs.realpathSync.native(current)).toLowerCase() !== current.toLowerCase()) reject('LINK_PATH', 'Redirected paths are unsupported');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') break;
      throw error;
    }
  }
}
/** Discover afresh only when a real probe is needed. PATH remains part of the
 * trusted process launch context; canonical paths do not authenticate publishers.
 * Do not call resolveProjectRoot/assertLocalDrive here: that would recurse. */
export function powerShellHost(): string {
  const directories = (process.env.PATH ?? '').split(path.delimiter).map(entry => {
    const value = entry.trim();
    return value.startsWith('"') && value.endsWith('"') && value.length >= 2 ? value.slice(1, -1) : value;
  });
  for (const executable of ['pwsh.exe', 'powershell.exe']) {
    for (const directory of directories) {
      // Never search cwd, relative/drive-relative entries, UNC/device paths or
      // expand environment expressions from PATH.
      if (!/^[A-Za-z]:[\\/]/.test(directory) || !path.isAbsolute(directory)) continue;
      // Presence lookup deliberately retains raw components. Only ENOENT is
      // absence; an inaccessible or otherwise broken candidate is a refusal.
      try { fs.lstatSync(directory + path.sep + executable); }
      catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue; throw error; }
      const root = path.parse(directory).root;
      validateParts(components(directory.slice(root.length)).filter((part, index, all) => !(part === '' && index === all.length - 1)));
      const candidate = path.resolve(directory, executable);
      const stat = fs.lstatSync(candidate);
      if (stat.isSymbolicLink()) reject('LINK_PATH', 'PowerShell host must not be linked');
      if (!stat.isFile()) reject('DRIVE_UNKNOWN', 'PowerShell host must be a regular file');
      if (path.resolve(fs.realpathSync.native(candidate)).toLowerCase() !== path.resolve(candidate).toLowerCase()) reject('LINK_PATH', 'Redirected PowerShell host paths are unsupported');
      return candidate;
    }
  }
  reject('DRIVE_UNKNOWN', 'No supported PowerShell host was found in absolute local PATH entries');
}
export function resolveProjectRoot(root: string): string {
  if (typeof root !== 'string' || !root || /^(?:\\\\|\/\/)/.test(root) || !path.isAbsolute(root)) reject('INVALID_ROOT', 'Project root must be an absolute local path');
  const parsed = path.parse(root);
  validateParts(components(root.slice(parsed.root.length)).filter((part, index, all) => !(part === '' && index === all.length - 1)));
  const resolved = path.resolve(root);
  assertLocalDrive(resolved);
  assertNoLinks(resolved);
  if (!fs.statSync(resolved).isDirectory()) reject('INVALID_ROOT', 'Project root must be an existing directory');
  return fs.realpathSync.native(resolved);
}
export function resolveProjectPath(root: string, relative: string): string {
  const canonical = resolveProjectRoot(root);
  if (typeof relative !== 'string' || !relative || path.isAbsolute(relative) || path.win32.isAbsolute(relative)) reject('UNSAFE_PATH', 'Project path must be relative');
  validateParts(components(relative));
  const resolved = path.resolve(canonical, ...components(relative));
  const within = path.relative(canonical, resolved);
  if (within === '..' || within.startsWith(`..${path.sep}`) || path.isAbsolute(within)) reject('OUTSIDE_PROJECT', 'Path is outside the project');
  assertNoLinks(resolved);
  return resolved;
}
