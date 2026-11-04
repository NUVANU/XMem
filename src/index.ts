import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import { inspectStorage } from './diagnostics.js';
import { readStorageLocationAtProjectRoot } from './storage-location.js';
import { physicalDoctor, type PhysicalReadOptions } from './physical-readonly.js';
import { PathsError, resolveProjectRoot, resolveProjectPath, withPathValidationScope } from './paths.js';
export { PathsError, resolveProjectRoot, resolveProjectPath, serializeError } from './paths.js';
export { retractEngineeringMemory, reconcileEngineeringRetraction, ENGINEERING_RETRACTION_CONTRACT, ENGINEERING_RETRACTION_INTENT_SCHEMA, ENGINEERING_RETRACTION_INPUT_SCHEMA } from './engineering-retraction.js';
export type { EngineeringRetractionIntent, EngineeringRetractionInput } from './engineering-retraction.js';
export interface ProjectConfig { schema_version: 1; project_id: string; root: string }
function readConfig(root: string): ProjectConfig {
  const file = resolveProjectPath(root, '.xmem/config.json');
  if (!fs.existsSync(file)) throw new PathsError('NOT_INITIALIZED', 'Project is not initialized');
  let config: unknown;
  try { config = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { throw new PathsError('INVALID_CONFIG', 'Project config is invalid JSON'); }
  const c = config as Partial<ProjectConfig> | null;
  if (!c || typeof c !== 'object' || Array.isArray(c) || Object.keys(c).sort().join(',') !== 'project_id,root,schema_version' || c.schema_version !== 1 || typeof c.project_id !== 'string' || !/^[0-9a-f-]{36}$/.test(c.project_id) || c.root !== root) throw new PathsError('INVALID_CONFIG', 'Project config identity or schema does not match');
  return c as ProjectConfig;
}
export function initProject(projectRoot: string) {
  return withPathValidationScope(()=>{
  const root = resolveProjectRoot(projectRoot);
  const dir = resolveProjectPath(root, '.xmem');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
  const configPath = resolveProjectPath(root, '.xmem/config.json');
  let created = false;
  if (!fs.existsSync(configPath)) {
    const config: ProjectConfig = { schema_version: 1, project_id: randomUUID(), root };
    try { fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', { flag: 'wx' }); created = true; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
  }
  return { ok: true as const, created, config: readConfig(root) };
  });
}
export function readProjectConfig(projectRoot: string): ProjectConfig { return readConfig(resolveProjectRoot(projectRoot)); }
export function doctorProject(projectRoot:string):ReturnType<typeof defaultDoctor>;
export function doctorProject(projectRoot:string,options:PhysicalReadOptions):ReturnType<typeof physicalDoctor>;
export function doctorProject(projectRoot: string,options?:PhysicalReadOptions) {
  if(options!==undefined)return physicalDoctor(projectRoot,options);
  return defaultDoctor(projectRoot);
}
function defaultDoctor(projectRoot:string) {
  const root = resolveProjectRoot(projectRoot);
  const config = readConfig(root), storage_location = readStorageLocationAtProjectRoot(root, config.project_id), storage = inspectStorage(storage_location.storage_root, config.project_id);
  return { ok: ['OK','NOT_CREATED'].includes(storage.status), config, checks: { project_boundary: 'PASS', local_drive: process.platform === 'win32' ? 'PASS' : 'NOT_VERIFIED', storage: storage.status }, storage_location, storage, capabilities: { local_file_capture: true, standalone_semiauto: true, storage_location_choice: true, automatic_hooks: false, extraction_provider: 'NOT_CONFIGURED_BY_THIS_ADAPTER', execution_verification: 'REQUIRES_TRUSTED_COLLECTOR' } };
}
