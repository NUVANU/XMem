/** Opaque identity for R3 host-candidate material.
 *
 * Candidate bytes are retained by the existing SQLite event/revision storage,
 * not by a second filesystem store. They remain untrusted ASSERTED/HYPOTHESIS
 * material and are never execution evidence or owner authentication.
 */
import type { SourceRef } from './contracts.js';
import { PathsError } from './paths.js';
import { hashBytes, rejectObviousSecret } from './local-source.js';

export const HOST_SOURCE_PREFIX = 'xmem-host-candidate-v1:';
export const HOST_SOURCE_MAX_BYTES = 16 * 1024;
export type HostDeclaredActor = 'user' | 'agent';

function validateContent(content: unknown): asserts content is string {
  if (typeof content !== 'string' || !content.trim() || content.includes('\0') || Buffer.byteLength(content,'utf8') > HOST_SOURCE_MAX_BYTES) throw new PathsError('INVALID_INPUT',`Candidate content must be non-empty UTF-8 text <= ${HOST_SOURCE_MAX_BYTES} bytes`);
  rejectObviousSecret(content);
}

export function hostCandidateSourceRef(projectId:string, actor:HostDeclaredActor, content:string):SourceRef {
  if (typeof projectId!=='string'||!projectId.trim()||!['user','agent'].includes(actor)) throw new PathsError('INVALID_INPUT','Invalid host source identity');
  validateContent(content);
  const digest=hashBytes(Buffer.from(content,'utf8'));
  const source_id=`host-candidate-${hashBytes(JSON.stringify([projectId,actor,digest]))}`;
  return{source_id,kind:actor,locator:`${HOST_SOURCE_PREFIX}${actor}:${digest}`,version:digest,content_hash:digest};
}

export function validateHostCandidateSourceRef(projectId:string,source:SourceRef):{actor:HostDeclaredActor;digest:string}|null {
  if(!['user','agent'].includes(source.kind)||!source.locator.startsWith(HOST_SOURCE_PREFIX))return null;
  const match=/^(user|agent):([a-f0-9]{64})$/.exec(source.locator.slice(HOST_SOURCE_PREFIX.length));
  if(!match||match[1]!==source.kind)throw new PathsError('IDENTITY_CONFLICT','Host source identity is malformed');
  const actor=match[1] as HostDeclaredActor,digest=match[2],expected=`host-candidate-${hashBytes(JSON.stringify([projectId,actor,digest]))}`;
  if(source.source_id!==expected||source.version!==digest||source.content_hash!==digest)throw new PathsError('IDENTITY_CONFLICT','Host source identity mismatch');
  return{actor,digest};
}
