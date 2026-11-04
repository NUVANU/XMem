import type { ExecutionProvenance } from './evidence.js';
import { SqliteMemoryStorage } from './storage.js';

/**
 * The only M3 adapter that grants local collector trust. It derives trust from
 * storage-held configuration and receipts, never from fields supplied by JSON.
 */
export class StorageExecutionProvenance implements ExecutionProvenance {
  constructor(private readonly storage: SqliteMemoryStorage) {}
  resolve(evidenceId: string) {
    return this.storage.resolveTrustedExecution(evidenceId);
  }
}
