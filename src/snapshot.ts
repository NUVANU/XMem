import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolveProjectPath } from './paths.js';
import { contentHash } from './evidence.js';
import { validateSnapshot, type Snapshot } from './contracts.js';

export interface SnapshotInputs {
  project_id: string; workspace_id: string; root: string;
  files: string[]; test_definitions: string[]; configuration: string[]; dependencies: string[]; fixtures: string[];
  command: string; args: string[]; toolchain: Record<string,string>; environment: Record<string,string>;
  /** Explicitly asserted declared domain, not proof of unknown dependency completeness. */
  declared_complete: boolean; missing: string[]; external_state: 'CONTROLLED'|'UNKNOWN';
}
/** Values must be non-sensitive version identifiers. Secrets are not accepted as a retention strategy. */
export function captureSnapshot(input: SnapshotInputs): Snapshot {
  const contents = new Map<string,string>();
  const readGroup = (paths: string[]): string => {
    const entries = [...new Set(paths)].sort().map(relative => {
      const filename = resolveProjectPath(input.root, relative);
      const digest = createHash('sha256').update(readFileSync(filename)).digest('hex');
      if (contents.has(filename) && contents.get(filename)!==digest) throw Error('SOURCE_DRIFT');
      contents.set(filename,digest);
      return [relative.replaceAll('\\','/'),digest];
    });
    return contentHash(entries);
  };
  const missing = [...new Set(input.missing)].sort();
  if (!input.declared_complete && !missing.length) missing.push('undeclared_dependencies');
  if (input.external_state==='UNKNOWN' && !missing.includes('external_state')) missing.push('external_state');
  const manifest: Snapshot['manifest'] = {
    completeness:input.declared_complete && !missing.length ? 'COMPLETE':'INCOMPLETE', missing,
    files_hash:readGroup(input.files),test_definition_hash:readGroup(input.test_definitions),
    config_hash:readGroup(input.configuration),dependencies_hash:readGroup(input.dependencies),fixtures_hash:readGroup(input.fixtures),
    command:input.command,args:[...input.args],toolchain_hash:contentHash(input.toolchain),environment_hash:contentHash(input.environment),external_state:input.external_state,
  };
  // A second content pass catches drift during capture, independent of Git status or mtime.
  for (const [filename,digest] of contents) if(createHash('sha256').update(readFileSync(filename)).digest('hex')!==digest) throw Error('SOURCE_DRIFT');
  return validateSnapshot({ schema_version:'1', snapshot_id:contentHash({project_id:input.project_id,workspace_id:input.workspace_id,manifest}),project_id:input.project_id,workspace_id:input.workspace_id,captured_at:new Date().toISOString(),manifest });
}
