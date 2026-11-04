#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { initProject, doctorProject, PathsError, serializeError } from './index.js';
import { configureStandalone, standaloneStatus, type StandaloneEnableInput } from './standalone.js';
import { codexConfigureStorageLocation, codexStorageLocationStatus } from './codex.js';
import type { StorageLocationConfigureInput } from './storage-location.js';

export const CLI_USAGE = 'Usage: xmem <init|doctor|standalone-status|storage-location-status> --project <absolute-path>; xmem <standalone-configure|storage-location-configure> --project <absolute-path> --input <absolute-json-file>';
/** Owner-selected JSON is data, never an executable setup script. */
function readOwnerInput(filename: string): unknown {
  if (!path.isAbsolute(filename)) throw new PathsError('INVALID_ARGUMENT', 'Owner input file must be absolute');
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536) throw new PathsError('INVALID_INPUT', 'Owner input must be a regular non-linked JSON file of at most 65536 bytes');
  let input: unknown;
  try { input = JSON.parse(fs.readFileSync(filename, 'utf8')); }
  catch { throw new PathsError('INVALID_INPUT', 'Owner input must be valid JSON'); }
  return input;
}
export function runCli(args: string[]): { exitCode: number; result: unknown } {
  try {
    const [command, projectFlag, root, inputFlag, filename] = args;
    const readCommands = ['init', 'doctor', 'standalone-status', 'storage-location-status'];
    const writeCommands = ['standalone-configure', 'storage-location-configure'];
    if (projectFlag !== '--project' || !root ||
      !(args.length === 3 && readCommands.includes(command) || args.length === 5 && writeCommands.includes(command) && inputFlag === '--input' && filename))
      throw new PathsError('INVALID_ARGUMENT', CLI_USAGE);
    let result: { ok: boolean };
    if (command === 'init') result = initProject(root);
    else if (command === 'doctor') result = doctorProject(root);
    else if (command === 'standalone-status') result = standaloneStatus(root);
    else if (command === 'storage-location-status') result = codexStorageLocationStatus(root);
    else {
      const input = readOwnerInput(filename!);
      result = command === 'standalone-configure'
        ? configureStandalone(root, input as StandaloneEnableInput)
        : codexConfigureStorageLocation(root, input as StorageLocationConfigureInput);
    }
    return { exitCode: result.ok ? 0 : 1, result };
  } catch (error) { return { exitCode: 1, result: serializeError(error) }; }
}
function invokedAsCli(): boolean {
  try { return !!process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href; }
  catch { return false; }
}
if (invokedAsCli()) {
  const { exitCode, result } = runCli(process.argv.slice(2));
  process.stdout.write(JSON.stringify(result) + '\n');
  process.exitCode = exitCode;
}
