import { Ajv, type JSONSchemaType, type ErrorObject } from 'ajv';

export const SCHEMA_VERSION = '1' as const;
export type EvidenceResult = 'PASS' | 'FAIL' | 'ERROR' | 'NOT_RUN';
export type Applicability = 'EXACT' | 'STALE' | 'UNKNOWN';
export type EpistemicState = 'OBSERVED' | 'ASSERTED' | 'HYPOTHESIS' | 'CONFIRMED';
export type Lifecycle = 'ACTIVE' | 'SUPERSEDED' | 'RETRACTED';
export type ErrorCode = 'INVALID_INPUT' | 'UNSUPPORTED_VERSION' | 'IDENTITY_CONFLICT' | 'PROJECT_MISMATCH' | 'SOURCE_MISSING' | 'ARTIFACT_MISSING' | 'ARTIFACT_CORRUPT' | 'INPUT_INCOMPLETE' | 'UNTRUSTED_SOURCE' | 'PATH_OUTSIDE_PROJECT' | 'BUDGET_UNSATISFIABLE' | 'STORAGE_ERROR' | 'STORAGE_LOCATION_UNCONFIRMED' | 'STORAGE_MIGRATION_REQUIRED';
export interface SourceRef { source_id: string; kind: 'executor' | 'file' | 'user' | 'agent' | 'derived'; locator: string; version: string; content_hash: string }
export interface InputManifest {
  completeness: 'COMPLETE' | 'INCOMPLETE'; missing: string[];
  files_hash: string | null; test_definition_hash: string | null; command: string; args: string[];
  config_hash: string | null; toolchain_hash: string | null; dependencies_hash: string | null;
  fixtures_hash: string | null; environment_hash: string | null; external_state: 'CONTROLLED' | 'UNKNOWN';
}
export interface Snapshot { schema_version: '1'; snapshot_id: string; project_id: string; workspace_id: string; captured_at: string; manifest: InputManifest }
export interface Evidence { schema_version: '1'; evidence_id: string; project_id: string; workspace_id: string; run_id: string; snapshot_id: string; source: SourceRef; result: EvidenceResult; exit_code: number | null; artifact_hash: string | null; recorded_at: string }
export interface Event { schema_version: '1'; event_id: string; project_id: string; workspace_id: string; run_id: string; source: SourceRef; sequence: number; occurred_at: string; completeness: 'COMPLETE' | 'GAP' | 'TRUNCATED'; kind: 'execution' | 'observation' | 'correction'; content: string; evidence_id: string | null }
export interface MemoryRecord { schema_version: '1'; record_id: string; revision_id: string; project_id: string; kind: 'Observation' | 'DecisionRef' | 'ConstraintRef' | 'FailedAttempt' | 'RootCauseHypothesis'; source: SourceRef; epistemic_state: EpistemicState; lifecycle: Lifecycle; information_role: 'FACT' | 'NORMATIVE_REF' | 'EXPERIENCE' | 'SUGGESTION'; content: string; previous_revision_id: string | null }
export interface Relation { schema_version: '1'; relation_id: string; project_id: string; from_revision_id: string; to_revision_id: string; type: 'DERIVED_FROM' | 'SUPPORTED_BY' | 'APPLIES_UNDER' | 'SUPERSEDES' | 'CONFLICTS_WITH' | 'REFERENCES'; source: SourceRef; epistemic_state: EpistemicState }

const id = { type: 'string', minLength: 1 } as const;
const hash = { type: 'string', pattern: '^[a-f0-9]{64}$' } as const;
const nullableHash = { anyOf: [hash, { type:'null', nullable:true }] } as const;
const nullableId = { anyOf: [id, { type:'null', nullable:true }] } as const;
const timestamp = { type: 'string', format: 'utc-timestamp' } as const;
const version = { type: 'string', const: SCHEMA_VERSION } as const;
export const sourceSchema: JSONSchemaType<SourceRef> = { type: 'object', additionalProperties: false, required: ['source_id','kind','locator','version','content_hash'], properties: { source_id:id, kind:{type:'string',enum:['executor','file','user','agent','derived']},locator:id,version:id,content_hash:hash } };
export const inputManifestSchema: JSONSchemaType<InputManifest> = { type:'object',additionalProperties:false,required:['completeness','missing','files_hash','test_definition_hash','command','args','config_hash','toolchain_hash','dependencies_hash','fixtures_hash','environment_hash','external_state'],properties:{completeness:{type:'string',enum:['COMPLETE','INCOMPLETE']},missing:{type:'array',items:id,uniqueItems:true},files_hash:nullableHash,test_definition_hash:nullableHash,command:id,args:{type:'array',items:{type:'string'}},config_hash:nullableHash,toolchain_hash:nullableHash,dependencies_hash:nullableHash,fixtures_hash:nullableHash,environment_hash:nullableHash,external_state:{type:'string',enum:['CONTROLLED','UNKNOWN']}} };
export const snapshotSchema: JSONSchemaType<Snapshot> = { type:'object',additionalProperties:false,required:['schema_version','snapshot_id','project_id','workspace_id','captured_at','manifest'],properties:{schema_version:version,snapshot_id:id,project_id:id,workspace_id:id,captured_at:timestamp,manifest:inputManifestSchema} };
export const evidenceSchema: JSONSchemaType<Evidence> = { type:'object',additionalProperties:false,required:['schema_version','evidence_id','project_id','workspace_id','run_id','snapshot_id','source','result','exit_code','artifact_hash','recorded_at'],properties:{schema_version:version,evidence_id:id,project_id:id,workspace_id:id,run_id:id,snapshot_id:id,source:sourceSchema,result:{type:'string',enum:['PASS','FAIL','ERROR','NOT_RUN']},exit_code:{anyOf:[{type:'integer'},{type:'null',nullable:true}]},artifact_hash:nullableHash,recorded_at:timestamp} };
export const eventSchema: JSONSchemaType<Event> = { type:'object',additionalProperties:false,required:['schema_version','event_id','project_id','workspace_id','run_id','source','sequence','occurred_at','completeness','kind','content','evidence_id'],properties:{schema_version:version,event_id:id,project_id:id,workspace_id:id,run_id:id,source:sourceSchema,sequence:{type:'integer',minimum:0},occurred_at:timestamp,completeness:{type:'string',enum:['COMPLETE','GAP','TRUNCATED']},kind:{type:'string',enum:['execution','observation','correction']},content:id,evidence_id:nullableId} };
export const memoryRecordSchema: JSONSchemaType<MemoryRecord> = { type:'object',additionalProperties:false,required:['schema_version','record_id','revision_id','project_id','kind','source','epistemic_state','lifecycle','information_role','content','previous_revision_id'],properties:{schema_version:version,record_id:id,revision_id:id,project_id:id,kind:{type:'string',enum:['Observation','DecisionRef','ConstraintRef','FailedAttempt','RootCauseHypothesis']},source:sourceSchema,epistemic_state:{type:'string',enum:['OBSERVED','ASSERTED','HYPOTHESIS','CONFIRMED']},lifecycle:{type:'string',enum:['ACTIVE','SUPERSEDED','RETRACTED']},information_role:{type:'string',enum:['FACT','NORMATIVE_REF','EXPERIENCE','SUGGESTION']},content:id,previous_revision_id:nullableId} };
export const relationSchema: JSONSchemaType<Relation> = { type:'object',additionalProperties:false,required:['schema_version','relation_id','project_id','from_revision_id','to_revision_id','type','source','epistemic_state'],properties:{schema_version:version,relation_id:id,project_id:id,from_revision_id:id,to_revision_id:id,type:{type:'string',enum:['DERIVED_FROM','SUPPORTED_BY','APPLIES_UNDER','SUPERSEDES','CONFLICTS_WITH','REFERENCES']},source:sourceSchema,epistemic_state:{type:'string',enum:['OBSERVED','ASSERTED','HYPOTHESIS','CONFIRMED']}} };
const ajv = new Ajv({ allErrors:true, strict:true });
ajv.addFormat('utc-timestamp', { type:'string', validate:(value:string) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value });
export class ContractError extends Error { constructor(public readonly code:ErrorCode, message:string, public readonly details:readonly ErrorObject[] = []) { super(message); this.name='ContractError'; } }
function compile<T>(schema:JSONSchemaType<T>, semantic?:(value:T)=>void):(input:unknown)=>T {
 const validate=ajv.compile(schema);
 return (input:unknown):T => { if (!validate(input)) { const unsupported=typeof input==='object' && input!==null && 'schema_version' in input && input.schema_version!==SCHEMA_VERSION; throw new ContractError(unsupported?'UNSUPPORTED_VERSION':'INVALID_INPUT','Contract validation failed',structuredClone(validate.errors??[])); } semantic?.(input); return input; };
}
export const validateSource = compile(sourceSchema);
export const validateInputManifest = compile(inputManifestSchema, value => {
 const absent = Object.entries(value).filter(([key,v])=>key.endsWith('_hash') && v===null).map(([key])=>key);
 if(value.completeness==='COMPLETE' && (absent.length>0 || value.missing.length>0 || value.external_state==='UNKNOWN')) throw new ContractError('INVALID_INPUT','Complete manifest must enumerate controlled, present inputs');
 if(value.completeness==='INCOMPLETE' && value.missing.length===0) throw new ContractError('INVALID_INPUT','Incomplete manifest must explain missing inputs');
});
export const validateSnapshot = compile(snapshotSchema, value=>{validateInputManifest(value.manifest);});
export const validateEvidence = compile(evidenceSchema, value=>{
 if(value.result==='PASS' && value.exit_code!==0) throw new ContractError('INVALID_INPUT','PASS requires exit code zero');
 if(value.result==='FAIL' && (value.exit_code===null || value.exit_code===0)) throw new ContractError('INVALID_INPUT','FAIL requires nonzero exit code');
 if(value.result==='NOT_RUN' && value.exit_code!==null) throw new ContractError('INVALID_INPUT','NOT_RUN cannot contain an exit code');
});
export const validateEvent = compile(eventSchema, value=>{if(value.source.kind==='derived') throw new ContractError('INVALID_INPUT','Derived context cannot be an authoritative raw event');});
export const validateMemoryRecord = compile(memoryRecordSchema, value=>{
 if(value.source.kind==='derived') throw new ContractError('INVALID_INPUT','Derived context cannot be canonical memory provenance');
 if(['DecisionRef','ConstraintRef'].includes(value.kind) && value.information_role!=='NORMATIVE_REF') throw new ContractError('INVALID_INPUT','Normative records must retain normative role');
 if(value.previous_revision_id===value.revision_id) throw new ContractError('INVALID_INPUT','Revision cannot supersede itself');
});
export const validateRelation = compile(relationSchema, value=>{if(value.from_revision_id===value.to_revision_id) throw new ContractError('INVALID_INPUT','Self relations are not permitted');});
