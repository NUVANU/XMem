/** Internal SDK integration on an already safely opened connection. Never expose
 * frontier, relation IDs or authorization observations as a public response. */
import type Database from 'better-sqlite3';
import { validateMemoryRecord, validateRelation, type Relation, type SourceRef } from './contracts.js';
import { canonicalContextJson, type ContextBinding } from './context.js';
import { hashBytes } from './local-source.js';
import { PathsError } from './paths.js';
import { evaluateSqliteDependencySnapshot,metadataIdentity,SQL_CAPS,EVALUATOR_CAPS,type AuthorizationObservation,type RelationObservation,type SourceObservation } from './dependency-sqlite-snapshot.js';
import { assertEnrollmentActive,EngineeringDependencyLedger,type EnrollmentContext,type EnrollmentState } from './engineering-dependencies.js';
type Row=Record<string,any>;
function stop():never {throw new PathsError('INPUT_INCOMPLETE','Dependency verification unavailable within the requested scope');}
const exact=(v:any,keys:string[])=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...keys].sort().join(',');
const text=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=4096;
const list=(v:unknown):v is string[]=>Array.isArray(v)&&v.every(text)&&new Set(v).size===v.length;
interface Node {id:string; source:SourceRef; binding:ContextBinding; metadata:Row; fullRevisionHash:string; current:string; life:Row; edges:Relation[];}
const sourcePredicateConnections=new WeakSet<object>();

/** Recheck immediately before each resolver read; a previous graph observation
 * is not a reusable permission permit. This returns no source locator or body. */
export function assertEngineeringSourceAllowed(db:Database.Database,context:EnrollmentContext,source:SourceRef,ledger:EngineeringDependencyLedger):void {
  context.authorization?.assertLive(undefined,source);
  if(context.allowedSourceIds!==undefined&&!context.allowedSourceIds.includes(source.source_id))stop();
  if(!sourcePredicateConnections.has(db)){
    db.function('xmem_dependency_binding_valid',{deterministic:true},(payload:unknown,digest:unknown)=>{
      if(typeof payload!=='string'||typeof digest!=='string'||hashBytes(payload)!==digest)return 0;
      try{const b=JSON.parse(payload);return Number(exact(b,['revision_id','project_id','workspace_id','task_ref','task_version','roles','allowed_source_ids','mandatory','priority','conflicts'])&&canonicalContextJson(b)===payload&&list(b.roles)&&list(b.allowed_source_ids)&&list(b.conflicts)&&typeof b.mandatory==='boolean'&&Number.isFinite(b.priority));}catch{return 0;}
    });sourcePredicateConnections.add(db);
  }
  ledger.spendSql('queries',1);
  const s=context.scope;
  const row=db.prepare(`SELECT 1 AS permitted FROM revisions v JOIN records r ON r.record_id=v.record_id AND r.project_id=v.project_id
    JOIN context_bindings b ON b.revision_id=v.revision_id AND b.project_id=v.project_id
    JOIN lifecycle_events l ON l.rowid=(SELECT max(x.rowid) FROM lifecycle_events x WHERE x.record_id=v.record_id)
    WHERE v.project_id=? AND b.workspace_id=? AND b.task_ref=? AND b.task_version=?
    AND CASE WHEN length(CAST(b.payload_json AS BLOB))<=65536 THEN xmem_dependency_binding_valid(b.payload_json,b.payload_hash) ELSE 0 END=1
    AND json_extract(b.payload_json,'$.revision_id')=v.revision_id AND json_extract(b.payload_json,'$.project_id')=b.project_id
    AND json_extract(b.payload_json,'$.workspace_id')=b.workspace_id AND json_extract(b.payload_json,'$.task_ref')=b.task_ref AND json_extract(b.payload_json,'$.task_version')=b.task_version
    AND r.current_revision_id=v.revision_id AND l.revision_id=v.revision_id AND l.lifecycle='ACTIVE'
    AND EXISTS(SELECT 1 FROM json_each(b.payload_json,'$.roles') x WHERE x.value=?)
    AND EXISTS(SELECT 1 FROM json_each(b.payload_json,'$.allowed_source_ids') x WHERE x.value=?)
    AND json_extract(v.payload_json,'$.source')=? LIMIT 1`).get(s.projectId,s.workspaceId,s.taskId,s.taskVersion,s.role,source.source_id,canonicalContextJson(source))as Row|undefined;
  if(!row?.permitted)stop();
}

/** Length-checked metadata first; only an authorized exact scope may then load
 * the bounded full revision for its hash. This helper performs no source IO. */
function nodeMetadata(db:Database.Database,id:string,context:EnrollmentContext,ledger:EngineeringDependencyLedger,edges:boolean):Node {
  if(context.authorization){
    if(!context.authorization.allowedRevisionIds.includes(id))stop();
    context.authorization.assertLive(id);
  }
  ledger.spendSql('nodes',1);
  const get=(sql:string,...args:any[])=>{ledger.spendSql('queries',1);return db.prepare(sql).get(...args)as Row|undefined;};
  const scope=context.scope;
  const h=get(`SELECT length(CAST(v.payload_json AS BLOB)) AS vb,length(CAST(b.payload_json AS BLOB)) AS bb,
    length(CAST(l.event_id AS BLOB))+length(CAST(l.record_id AS BLOB))+length(CAST(l.revision_id AS BLOB))+length(CAST(l.lifecycle AS BLOB))
    +length(CAST(l.actor AS BLOB))+length(CAST(l.source AS BLOB))+length(CAST(l.reason AS BLOB))+length(CAST(l.occurred_at AS BLOB)) AS lb,
    coalesce(length(CAST(v.record_id AS BLOB)),0)+coalesce(length(CAST(v.project_id AS BLOB)),0)+coalesce(length(CAST(v.previous_revision_id AS BLOB)),0)
    +coalesce(length(CAST(b.project_id AS BLOB)),0)+coalesce(length(CAST(b.workspace_id AS BLOB)),0)+coalesce(length(CAST(b.task_ref AS BLOB)),0)+coalesce(length(CAST(b.task_version AS BLOB)),0)
    +coalesce(length(CAST(b.payload_hash AS BLOB)),0)+coalesce(length(CAST(r.project_id AS BLOB)),0)+coalesce(length(CAST(r.current_revision_id AS BLOB)),0)
    +coalesce(length(CAST(c.record_id AS BLOB)),0)+coalesce(length(CAST(c.project_id AS BLOB)),0) AS hb
    FROM revisions v LEFT JOIN context_bindings b ON b.revision_id=v.revision_id LEFT JOIN records r ON r.record_id=v.record_id
    LEFT JOIN revisions c ON c.revision_id=r.current_revision_id
    LEFT JOIN lifecycle_events l ON l.rowid=(SELECT max(x.rowid) FROM lifecycle_events x WHERE x.record_id=v.record_id)
    WHERE v.revision_id=?`,id);
  if(!h||!['vb','bb','lb','hb'].every(k=>Number.isSafeInteger(h[k])&&h[k]>=0)||h.vb<1||h.bb<1||h.lb<1)stop();
  ledger.spendSql('metadataBytes',h.vb+h.bb+h.lb+h.hb);
  const r=get(`SELECT v.record_id,v.project_id,v.previous_revision_id,json_remove(v.payload_json,'$.content') AS metadata,
    b.payload_json AS binding,b.payload_hash,b.project_id AS bp,b.workspace_id AS bw,b.task_ref AS bt,b.task_version AS bv,
    r.project_id AS rp,r.current_revision_id,c.record_id AS cr,c.project_id AS cp,
    l.event_id,l.record_id AS lr,l.revision_id AS lv,l.lifecycle,l.actor,l.source,l.reason,l.occurred_at
    FROM revisions v LEFT JOIN context_bindings b ON b.revision_id=v.revision_id
    LEFT JOIN records r ON r.record_id=v.record_id LEFT JOIN revisions c ON c.revision_id=r.current_revision_id
    LEFT JOIN lifecycle_events l ON l.rowid=(SELECT max(x.rowid) FROM lifecycle_events x WHERE x.record_id=v.record_id)
    WHERE v.revision_id=?`,id);
  if(!r)stop();
  const b=JSON.parse(r.binding),m=JSON.parse(r.metadata);
  if(!exact(b,['revision_id','project_id','workspace_id','task_ref','task_version','roles','allowed_source_ids','mandatory','priority','conflicts'])
    ||canonicalContextJson(b)!==r.binding||hashBytes(r.binding)!==r.payload_hash||!list(b.roles)||!list(b.allowed_source_ids)||!list(b.conflicts)
    ||typeof b.mandatory!=='boolean'||!Number.isFinite(b.priority)||b.revision_id!==id||b.project_id!==r.bp||b.workspace_id!==r.bw||b.task_ref!==r.bt||b.task_version!==r.bv)stop();
  // Validate source shape and all revision metadata before any resolver can see it.
  const checked=validateMemoryRecord({...m,content:'metadata-only'});
  if(checked.revision_id!==id||checked.record_id!==r.record_id||checked.project_id!==r.project_id||checked.previous_revision_id!==r.previous_revision_id
    ||r.project_id!==scope.projectId||r.rp!==r.project_id||r.cr!==r.record_id||r.cp!==r.project_id
    ||b.project_id!==scope.projectId||b.workspace_id!==scope.workspaceId||b.task_ref!==scope.taskId||b.task_version!==scope.taskVersion
    ||!b.roles.includes(scope.role)||!b.allowed_source_ids.includes(checked.source.source_id)
    ||context.allowedSourceIds!==undefined&&!context.allowedSourceIds.includes(checked.source.source_id))stop();
  context.authorization?.assertLive(id,checked.source);
  const life={event_id:r.event_id,record_id:r.lr,revision_id:r.lv,lifecycle:r.lifecycle,actor:r.actor,source:r.source,reason:r.reason,occurred_at:r.occurred_at};
  if(Object.values(life).some(v=>!text(v))||life.record_id!==r.record_id||life.revision_id!==r.current_revision_id||!['ACTIVE','SUPERSEDED','RETRACTED'].includes(life.lifecycle))stop();
  ledger.spendSql('metadataBytes',Math.max(0,Buffer.byteLength(canonicalContextJson(life),'utf8')-h.lb));
  const result:Node={id,source:checked.source,binding:b,metadata:m,fullRevisionHash:'NOT_READ_FOR_ENROLLMENT',current:r.current_revision_id,life,edges:[]};
  // Only after current scope/source authorization, bind exact revision bytes too:
  // file source hashes alone do not cover an independently stored excerpt body.
  ledger.spendSql('metadataBytes',h.vb);
  const body=get('SELECT payload_json FROM revisions WHERE revision_id=?',id);
  if(!body||typeof body.payload_json!=='string'||Buffer.byteLength(body.payload_json,'utf8')!==h.vb)stop();
  const complete=validateMemoryRecord(JSON.parse(body.payload_json)),{content:ignored,...completeMetadata}=complete;
  if(canonicalContextJson(complete)!==body.payload_json||canonicalContextJson(completeMetadata)!==canonicalContextJson(m))stop();
  result.fullRevisionHash=hashBytes(body.payload_json);
  if(!edges)return result;
  ledger.spendSql('queries',1);
  const headers=db.prepare(`SELECT rowid,length(CAST(payload_json AS BLOB)) AS bytes,
    length(CAST(relation_id AS BLOB))+length(CAST(project_id AS BLOB))+length(CAST(from_revision_id AS BLOB))+length(CAST(to_revision_id AS BLOB)) AS hb
    FROM relations WHERE from_revision_id=? ORDER BY relation_id LIMIT 33`).all(id)as Row[];
  if(headers.length>32)stop();ledger.spendSql('edgeRows',headers.length);
  for(const e of headers){if(!Number.isSafeInteger(e.bytes)||e.bytes<1||!Number.isSafeInteger(e.hb)||e.hb<1)stop();ledger.spendSql('metadataBytes',e.bytes+e.hb);}
  if(headers.length){
    ledger.spendSql('queries',1);
    const rows=db.prepare('SELECT rowid,relation_id,project_id,from_revision_id,to_revision_id,payload_json FROM relations WHERE from_revision_id=? ORDER BY relation_id LIMIT 33').all(id)as Row[];
    ledger.spendSql('edgeRows',rows.length);if(rows.length!==headers.length)stop();
    result.edges=rows.map((row,index)=>{const h=headers[index],relation=validateRelation(JSON.parse(row.payload_json));
      if(row.rowid!==h.rowid||Buffer.byteLength(row.payload_json,'utf8')!==h.bytes||canonicalContextJson(relation)!==row.payload_json||relation.relation_id!==row.relation_id
        ||relation.project_id!==scope.projectId||relation.project_id!==row.project_id||relation.from_revision_id!==id||relation.from_revision_id!==row.from_revision_id||relation.to_revision_id!==row.to_revision_id)stop();return relation;});
  }
  return result;
}

/** Explicit enrollment observes only exact, currently authorized endpoints. */
export function readEnrollmentRelations(db:Database.Database,context:EnrollmentContext,ids:readonly string[]):{relations:Relation[];nodePins:ReadonlyMap<string,string>} {
  if(db.inTransaction||ids.length>32||new Set(ids).size!==ids.length||!ids.every(text))stop();
  const ledger=new EngineeringDependencyLedger(undefined,16);
  const endpoints=new Map<string,Node>();
  const endpoint=(id:string)=>{let n=endpoints.get(id);if(!n){n=nodeMetadata(db,id,context,ledger,false);endpoints.set(id,n);}return n;};
  return db.transaction(()=>{const relations=ids.map(id=>{
    ledger.spendSql('queries',1);const h=db.prepare(`SELECT length(CAST(payload_json AS BLOB)) AS bytes,
      length(CAST(relation_id AS BLOB))+length(CAST(project_id AS BLOB))+length(CAST(from_revision_id AS BLOB))+length(CAST(to_revision_id AS BLOB)) AS hb FROM relations WHERE relation_id=?`).get(id)as Row|undefined;
    if(!h||!Number.isSafeInteger(h.bytes)||h.bytes<1||!Number.isSafeInteger(h.hb)||h.hb<1)stop();ledger.spendSql('metadataBytes',h.bytes+h.hb);
    ledger.spendSql('queries',1);const row=db.prepare('SELECT relation_id,project_id,from_revision_id,to_revision_id,payload_json FROM relations WHERE relation_id=?').get(id)as Row|undefined;
    if(!row||typeof row.payload_json!=='string'||Buffer.byteLength(row.payload_json,'utf8')!==h.bytes)stop();const edge=validateRelation(JSON.parse(row.payload_json));
    if(canonicalContextJson(edge)!==row.payload_json||edge.relation_id!==id||edge.project_id!==context.scope.projectId||edge.project_id!==row.project_id||edge.from_revision_id!==row.from_revision_id||edge.to_revision_id!==row.to_revision_id||!['DERIVED_FROM','SUPPORTED_BY'].includes(edge.type))stop();
    const from=endpoint(edge.from_revision_id),to=endpoint(edge.to_revision_id);
    if(from.current!==from.id||to.current!==to.id||from.life.lifecycle!=='ACTIVE'||to.life.lifecycle!=='ACTIVE'
      ||![from.source,to.source].some(s=>canonicalContextJson(s)===canonicalContextJson(edge.source)))stop();
    return edge;
  });return{relations,nodePins:new Map([...endpoints].map(([id,n])=>[id,metadataIdentity({revision:n.fullRevisionHash,binding:n.binding})]))};}).deferred();
}

/** Actual live observations, then the independently reviewed adapter/evaluator. */
export function observeEngineeringDependencies(db:Database.Database,context:EnrollmentContext,roots:readonly string[],state:EnrollmentState,
  ledger:EngineeringDependencyLedger,reader:(source:SourceRef)=>Buffer|undefined):string {
  if(db.inTransaction||roots.length>8||new Set(roots).size!==roots.length)stop();
  const epoch=state.epoch;assertEnrollmentActive(state,epoch);
  const nodes=new Map<string,Node>();let discoveryRows=0,discoveryBytes=0;const sqlBefore={...ledger.sql};
  ledger.beginSqlPhase();try{db.transaction(()=>{
    const visit=(id:string,depth:number):void=>{
      if(depth>ledger.evaluationLimits.depth)stop();if(nodes.has(id))return;if(nodes.size>=32)stop();
      const node=nodeMetadata(db,id,context,ledger,true);nodes.set(id,node);
      const pin=state.nodePins.get(id);if(pin&&pin!==metadataIdentity({revision:node.fullRevisionHash,binding:node.binding}))stop();
      if(node.current!==id||node.life.lifecycle!=='ACTIVE')stop();
      discoveryRows+=node.edges.length*2;if(discoveryRows>64)stop();
      for(const edge of node.edges){
        if(edge.type!=='DERIVED_FROM'&&edge.type!=='SUPPORTED_BY')continue;
        const enrolled=state.relations.get(edge.relation_id);if(!enrolled||canonicalContextJson(enrolled)!==canonicalContextJson(edge))stop();
        visit(edge.to_revision_id,depth+1);
      }
    };
    for(const root of roots)visit(root,0);
    discoveryBytes=ledger.sql.metadataBytes-sqlBefore.metadataBytes;
    if(discoveryBytes>SQL_CAPS.metadataBytes||ledger.sql.queries-sqlBefore.queries>SQL_CAPS.queries)stop();
  }).deferred();}finally{ledger.endSqlPhase();}
  const authorizedSources=new Map<string,SourceRef>();for(const n of nodes.values())authorizedSources.set(metadataIdentity(n.source),n.source);
  for(const n of nodes.values())for(const e of n.edges)if((e.type==='DERIVED_FROM'||e.type==='SUPPORTED_BY')&&!authorizedSources.has(metadataIdentity(e.source)))stop();
  const sourceBytes=new Map<string,Buffer>();for(const [identity,source]of authorizedSources){const bytes=ledger.read(source,reader);if(!bytes||hashBytes(bytes)!==source.content_hash)stop();sourceBytes.set(identity,bytes);}
  const authorization=new Map<string,AuthorizationObservation>(),sources=new Map<string,SourceObservation>(),relations=new Map<string,RelationObservation>();
  for(const n of nodes.values()){
    const identity=metadataIdentity(n.source),observationId=metadataIdentity({source:identity,bytes:hashBytes(sourceBytes.get(identity)!)});
    authorization.set(n.id,{scope:context.scope,revisionId:n.id,sourceIdentity:identity,bindingHash:metadataIdentity(n.binding),decision:'ALLOWED',policyIdentity:context.policyHash,observationId:metadataIdentity({binding:n.binding,policy:context.policyHash})});
    sources.set(n.id,{sourceIdentity:identity,contentHash:n.source.content_hash,status:'VERIFIED',observedBytes:sourceBytes.get(identity)!.byteLength,observationId});
    for(const e of n.edges){if(e.type!=='DERIVED_FROM'&&e.type!=='SUPPORTED_BY')continue;
      const payloadHash=metadataIdentity(e),sourceIdentity=metadataIdentity(e.source);
      relations.set(e.relation_id,{admission:{status:'OBSERVED_ACCEPTED',scope:context.scope,fromRevisionId:e.from_revision_id,toRevisionId:e.to_revision_id,receiptId:state.enrollmentId,provenanceIdentity:payloadHash,observationId:metadataIdentity({enrollment:state.enrollmentId,epoch,payloadHash})},registeredForRevalidation:true,payloadHash,sourceIdentity,sourceContentHash:e.source.content_hash,sourceStatus:'VERIFIED',sourceObservationId:metadataIdentity({sourceIdentity,bytes:hashBytes(sourceBytes.get(sourceIdentity)!)})});
    }
  }
  assertEnrollmentActive(state,epoch);
  const sqlBudget={...SQL_CAPS};for(const k of ['nodes','edgeRows','metadataBytes','queries']as const)sqlBudget[k]=Math.min(SQL_CAPS[k],ledger.sqlLimits[k]-ledger.sql[k]);
  const evaluatorBudget={...EVALUATOR_CAPS,depth:Math.min(EVALUATOR_CAPS.depth,ledger.evaluationLimits.depth)};
  for(const k of ['nodes','edges','sourceBytes','work']as const)evaluatorBudget[k]=Math.min(EVALUATOR_CAPS[k],ledger.evaluationLimits[k]-ledger.evaluation[k]);
  const revisionPayloadHashes=new Map([...nodes].map(([id,n])=>[id,n.fullRevisionHash]));
  context.authorization?.assertLive();
  for(const node of nodes.values())context.authorization?.assertLive(node.id,node.source);
  const result=evaluateSqliteDependencySnapshot(db,{scope:context.scope,roots,authorization,sources,relations,revisionPayloadHashes,sqlBudget,evaluatorBudget});
  ledger.consumeSql(result.internalSql.consumed);if(result.internalEvaluation)ledger.consumeEvaluation(result.internalEvaluation.consumed);
  assertEnrollmentActive(state,epoch);
  context.authorization?.assertLive();
  if(result.internalSql.status!=='OBSERVED'||!result.internalEvaluation||result.publicResults.some(r=>r.visibility!=='CALLER_REPORTED_VISIBLE'||!['NO_REGISTERED_DEPENDENCIES','REGISTERED_DEPENDENCIES_CHECKED'].includes(r.dependencyStatus)))stop();
  // Include our independently read metadata and all edge sets, even empty sets.
  return metadataIdentity({enrollment:state.enrollmentId,epoch,scope:context.scope,policy:context.policyHash,
    discovery:[...nodes.values()],sql:result.internalSql.frontier,evaluation:result.internalEvaluation.observations});
}
