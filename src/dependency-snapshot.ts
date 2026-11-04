/** Internal, single-observation evaluator. Never an authorization or freshness permit.
 * Inputs must be immutable plain data obtained by a trusted, separately authorized
 * adapter. No IO, authentication, hash checking, second observation or cache here.
 * Only publicResults may cross an API boundary; internalFrontier contains secrets.
 */
export interface Scope {
  readonly projectRoot: string;
  readonly projectId: string;
  readonly workspaceId: string;
  readonly taskId: string;
  readonly taskVersion: string;
  readonly role: string;
}
export interface AdmissionObservation {
  readonly status: 'OBSERVED_ACCEPTED' | 'UNVERIFIED' | 'INVALIDATED';
  readonly scope: Scope;
  readonly fromRevisionId: string;
  readonly toRevisionId: string;
  readonly receiptId: string | null;
  readonly provenanceIdentity: string;
  readonly observationId: string;
}
export interface EdgeObservation {
  readonly relationId: string;
  readonly kind: 'DERIVED_FROM' | 'SUPPORTED_BY' | 'REFERENCES';
  readonly toRevisionId: string;
  readonly registeredForRevalidation: boolean;
  readonly admission: AdmissionObservation;
}
export interface NodeObservation {
  readonly revisionId: string;
  readonly scope: Scope;
  readonly currentRevisionId: string | null;
  readonly visibility: {
    readonly decision: 'ALLOWED' | 'DENIED' | 'UNKNOWN';
    readonly policyIdentity: string;
    readonly observationId: string;
  };
  readonly lifecycle: {
    readonly status: 'ACTIVE' | 'WITHDRAWN' | 'UNVERIFIABLE';
    readonly eventId: string;
  };
  readonly source: {
    readonly status: 'VERIFIED' | 'UNAVAILABLE' | 'UNVERIFIABLE';
    readonly observationId: string;
    readonly contentIdentity: string;
    readonly observedBytes: number;
  };
  readonly outgoingComplete: boolean;
  readonly outgoingObservationId: string;
  readonly outgoing: readonly EdgeObservation[];
}
export interface Budget {
  readonly nodes: number;
  readonly edges: number;
  readonly depth: number;
  readonly sourceBytes: number;
  readonly work: number;
}
export interface Snapshot {
  readonly snapshotId: string;
  readonly scope: Scope;
  readonly roots: readonly string[];
  readonly nodes: ReadonlyMap<string, NodeObservation>;
}
export type DependencyStatus = 'NO_REGISTERED_DEPENDENCIES' | 'REGISTERED_DEPENDENCIES_CHECKED'
  | 'UNVERIFIED' | 'REQUIRES_REVALIDATION' | 'INCOMPLETE';
export interface SafeRootResult {
  /** Applies to current AND historical bodies. A visible claim still grants nothing. */
  readonly visibility: 'WITHHELD' | 'CALLER_REPORTED_VISIBLE';
  readonly dependencyStatus: DependencyStatus;
}
type FrontierEntry = Readonly<{ revisionId: string; observation: NodeObservation | null }>;
const CAPS: Budget = { nodes: 1024, edges: 4096, depth: 64, sourceBytes: 67108864, work: 100000 };
const SCOPE_KEYS = ['projectRoot', 'projectId', 'workspaceId', 'taskId', 'taskVersion', 'role'] as const;
const token = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= 4096;
const integer = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0;
const validScope = (s: Scope) => !!s && SCOPE_KEYS.every(k => token(s[k]));
const sameScope = (a: Scope, b: Scope) => SCOPE_KEYS.every(k => a[k] === b[k]);
const copyScope = (s: Scope): Scope => Object.freeze({ projectRoot: s.projectRoot, projectId: s.projectId,
  workspaceId: s.workspaceId, taskId: s.taskId, taskVersion: s.taskVersion, role: s.role });

/** All roots share these budgets. Repeated paths re-pay edge/work costs; nodes and
 * source observation bytes are charged once. These are not actual IO byte limits.
 * Frontier includes empty outgoing sets, current pointers and observation/event
 * identities. It is NOT a commitment or an ABA/concurrency safety proof.
 */
export function evaluateDependencySnapshot(snapshot: Snapshot, budget: Budget): {
  publicResults: readonly SafeRootResult[];
  internalFrontier: Readonly<{
    classification: 'INTERNAL_DO_NOT_EXPOSE'; algorithm: 'dependency-snapshot/1';
    snapshotId: string; scope: Scope; roots: readonly string[]; budget: Budget;
    observations: readonly FrontierEntry[]; consumed: Budget;
  }>;
} {
  if (!snapshot || !token(snapshot.snapshotId) || !validScope(snapshot.scope)
    || !Array.isArray(snapshot.roots) || snapshot.roots.length > 256 || !snapshot.roots.every(token)
    || !(snapshot.nodes instanceof Map) || !budget
    || Object.keys(CAPS).some(k => !integer(budget[k as keyof Budget]) || budget[k as keyof Budget] > CAPS[k as keyof Budget])) {
    throw new TypeError('Invalid bounded snapshot request');
  }
  const used = { nodes: 0, edges: 0, depth: 0, sourceBytes: 0, work: 0 };
  const frontier = new Map<string, FrontierEntry>();
  let exhausted = false;
  const spend = (key: 'nodes' | 'edges' | 'sourceBytes' | 'work', count: number) => {
    if (exhausted || count > budget[key] - used[key]) { exhausted = true; return false; }
    used[key] += count;
    return true;
  };
  // Metadata shape validation, not evidence validation. Input is internal plain data.
  const validNode = (n: NodeObservation): boolean => !!n && token(n.revisionId) && validScope(n.scope)
    && (n.currentRevisionId === null || token(n.currentRevisionId))
    && !!n.visibility && ['ALLOWED', 'DENIED', 'UNKNOWN'].includes(n.visibility.decision)
    && token(n.visibility.policyIdentity) && token(n.visibility.observationId)
    && !!n.lifecycle && ['ACTIVE', 'WITHDRAWN', 'UNVERIFIABLE'].includes(n.lifecycle.status) && token(n.lifecycle.eventId)
    && !!n.source && ['VERIFIED', 'UNAVAILABLE', 'UNVERIFIABLE'].includes(n.source.status)
    && token(n.source.observationId) && token(n.source.contentIdentity) && integer(n.source.observedBytes)
    && typeof n.outgoingComplete === 'boolean' && token(n.outgoingObservationId) && Array.isArray(n.outgoing);
  const validEdge = (e: EdgeObservation): boolean => !!e && token(e.relationId)
    && ['DERIVED_FROM', 'SUPPORTED_BY', 'REFERENCES'].includes(e.kind) && token(e.toRevisionId)
    && typeof e.registeredForRevalidation === 'boolean' && !!e.admission && validScope(e.admission.scope)
    && ['OBSERVED_ACCEPTED', 'UNVERIFIED', 'INVALIDATED'].includes(e.admission.status)
    && token(e.admission.fromRevisionId) && token(e.admission.toRevisionId)
    && (e.admission.receiptId === null || token(e.admission.receiptId))
    && token(e.admission.provenanceIdentity) && token(e.admission.observationId);
  const publicResults = snapshot.roots.map(root => {
    let incomplete = false, unverified = false, stale = false, withheld = false, registered = false;
    const active = new Set<string>();
    const visit = (id: string, depth: number): void => {
      if (!spend('work', 1)) { incomplete = true; return; }
      if (depth > budget.depth || active.has(id)) { incomplete = true; return; }
      used.depth = Math.max(used.depth, depth);
      let observation = frontier.get(id)?.observation;
      if (!frontier.has(id)) {
        if (!spend('nodes', 1)) { incomplete = true; return; }
        const raw = snapshot.nodes.get(id);
        if (!raw || !validNode(raw) || raw.revisionId !== id) {
          // Null records absence/unusable observation; never a complete positive proof.
          frontier.set(id, Object.freeze({ revisionId: id, observation: null }));
          unverified = true; withheld = true; return;
        }
        if (!spend('sourceBytes', raw.source.observedBytes)
          || !spend('edges', raw.outgoing.length) || !spend('work', raw.outgoing.length)) {
          incomplete = true; return;
        }
        const edgeIds = new Set<string>();
        if (raw.outgoing.some(e => !validEdge(e) || edgeIds.has(e.relationId) || !edgeIds.add(e.relationId))) {
          frontier.set(id, Object.freeze({ revisionId: id, observation: null }));
          unverified = true; withheld = true; return;
        }
        observation = Object.freeze({
          revisionId: raw.revisionId, scope: copyScope(raw.scope), currentRevisionId: raw.currentRevisionId,
          visibility: Object.freeze({ decision: raw.visibility.decision, policyIdentity: raw.visibility.policyIdentity, observationId: raw.visibility.observationId }),
          lifecycle: Object.freeze({ status: raw.lifecycle.status, eventId: raw.lifecycle.eventId }),
          source: Object.freeze({ status: raw.source.status, observationId: raw.source.observationId,
            contentIdentity: raw.source.contentIdentity, observedBytes: raw.source.observedBytes }), outgoingComplete: raw.outgoingComplete,
          outgoingObservationId: raw.outgoingObservationId,
          outgoing: Object.freeze(raw.outgoing.map(e => Object.freeze({
            relationId: e.relationId, kind: e.kind, toRevisionId: e.toRevisionId,
            registeredForRevalidation: e.registeredForRevalidation,
            admission: Object.freeze({ status: e.admission.status, scope: copyScope(e.admission.scope),
              fromRevisionId: e.admission.fromRevisionId, toRevisionId: e.admission.toRevisionId,
              receiptId: e.admission.receiptId, provenanceIdentity: e.admission.provenanceIdentity, observationId: e.admission.observationId }),
          }))),
        });
        frontier.set(id, Object.freeze({ revisionId: id, observation }));
      } else if (observation && (!spend('edges', observation.outgoing.length) || !spend('work', observation.outgoing.length))) {
        incomplete = true; return;
      }
      if (!observation) { unverified = true; withheld = true; return; }
      if (!observation.outgoingComplete) incomplete = true;
      if (!sameScope(observation.scope, snapshot.scope) || observation.visibility.decision !== 'ALLOWED') {
        withheld = true; stale = true; return; // No ancestor traversal beyond an access barrier.
      }
      if (!observation.outgoingComplete) return;
      if (observation.currentRevisionId !== id || observation.lifecycle.status !== 'ACTIVE' || observation.source.status !== 'VERIFIED') stale = true;
      active.add(id);
      for (const edge of observation.outgoing) {
        if (edge.kind === 'REFERENCES') continue;
        if (edge.kind === 'SUPPORTED_BY' && !edge.registeredForRevalidation) { unverified = true; withheld = true; continue; }
        const admission = edge.admission;
        if (!sameScope(admission.scope, snapshot.scope) || admission.fromRevisionId !== id || admission.toRevisionId !== edge.toRevisionId) {
          unverified = true; withheld = true; continue;
        }
        if (admission.status !== 'OBSERVED_ACCEPTED' || !admission.receiptId) {
          if (admission.status === 'INVALIDATED') stale = true;
          else unverified = true;
          withheld = true; continue;
        }
        registered = true;
        visit(edge.toRevisionId, depth + 1);
        if (exhausted) break;
      }
      active.delete(id);
    };
    visit(root, 0);
    return Object.freeze({
      visibility: withheld || incomplete || unverified ? 'WITHHELD' : 'CALLER_REPORTED_VISIBLE',
      dependencyStatus: incomplete ? 'INCOMPLETE' : stale ? 'REQUIRES_REVALIDATION' : unverified ? 'UNVERIFIED'
        : registered ? 'REGISTERED_DEPENDENCIES_CHECKED' : 'NO_REGISTERED_DEPENDENCIES',
    } satisfies SafeRootResult);
  });
  return {
    publicResults: Object.freeze(publicResults),
    internalFrontier: Object.freeze({
      classification: 'INTERNAL_DO_NOT_EXPOSE', algorithm: 'dependency-snapshot/1', snapshotId: snapshot.snapshotId,
      scope: copyScope(snapshot.scope), roots: Object.freeze([...snapshot.roots]),
      budget: Object.freeze({ nodes: budget.nodes, edges: budget.edges, depth: budget.depth, sourceBytes: budget.sourceBytes, work: budget.work }),
      observations: Object.freeze([...frontier.values()]), consumed: Object.freeze({ ...used }),
    }),
  };
}
