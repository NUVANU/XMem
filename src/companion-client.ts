/** Transport-independent caller helpers. No retry, process launch, or authorization. */
import { createHash } from 'node:crypto';
import { canonicalContextJson } from './context.js';
import { validateCompanionCall } from './companion-contract.js';
import type { StandaloneCaptureInput } from './standalone.js';
const sha=(text:string)=>createHash('sha256').update(text,'utf8').digest('hex');
type ObjectValue=Record<string,any>;
const object=(x:unknown):x is ObjectValue=>!!x&&typeof x==='object'&&!Array.isArray(x);

export interface DecodedCompanionResult {
  ok:boolean; layer:'JSON_RPC'|'MCP'|'BUSINESS'|'PAYLOAD';
  status:'RETURNED'|'EMPTY'|'NOT_FOUND'|'INCOMPLETE'|'DENIED'|'UNAVAILABLE'|'VERSION_MISMATCH'|'ERROR'|'MALFORMED_SUCCESS';
  error_code:string|null; value?:ObjectValue;
  protocol_error_code?:number;
  diagnostic?:{raw_utf8_bytes:number;raw_sha256:string};
}
function classification(code:string):DecodedCompanionResult['status'] {
  if(['UNTRUSTED_SOURCE','PROJECT_MISMATCH','PATH_OUTSIDE_PROJECT','NOT_CONFIGURED','STORAGE_LOCATION_UNCONFIRMED'].includes(code))return'DENIED';
  if(['UNSUPPORTED_VERSION','MCP_CONTEXT_PROJECTION_INVALID'].includes(code))return'VERSION_MISMATCH';
  if(['BUDGET_UNSATISFIABLE','INPUT_INCOMPLETE'].includes(code))return'INCOMPLETE';
  if(['STORAGE_ERROR','SQLITE_CANTOPEN','UNAVAILABLE','TIMEOUT'].includes(code))return'UNAVAILABLE';
  return'ERROR';
}
const safeCode=(x:unknown,fallback:string)=>typeof x==='number'&&Number.isSafeInteger(x)?String(x):typeof x==='string'&&/^[A-Za-z0-9_:.-]{1,128}$/.test(x)?x:fallback;

/** Error layer is checked before JSON parsing. Caller retains its raw trace privately. */
export function decodeCompanionResult(envelope:unknown):DecodedCompanionResult {
  if(!object(envelope))return{ok:false,layer:'PAYLOAD',status:'MALFORMED_SUCCESS',error_code:'INVALID_ENVELOPE'};
  if(envelope.error!==undefined)return{ok:false,layer:'JSON_RPC',status:'ERROR',error_code:safeCode(envelope.error?.code,'JSON_RPC_ERROR')};
  const result=object(envelope.result)?envelope.result:envelope;
  const texts=Array.isArray(result.content)?result.content.filter((x:unknown)=>object(x)&&x.type==='text'&&typeof x.text==='string'):[];
  const text=texts.map((x:ObjectValue)=>x.text).join('\n');
  const diagnostic={raw_utf8_bytes:Buffer.byteLength(text,'utf8'),raw_sha256:sha(text)};
  if(result.isError===true){
    try{const errorBody=JSON.parse(text),code=safeCode(errorBody?.error?.code,'MCP_TOOL_ERROR');return{ok:false,layer:'MCP',status:classification(code),error_code:code,diagnostic};}
    catch{const notFound=/^MCP error (-?\d+): Tool [A-Za-z0-9_:-]{1,128} not found$/.exec(text);return{ok:false,layer:'MCP',status:'ERROR',error_code:notFound?'MCP_TOOL_NOT_FOUND':'MCP_TEXT_ERROR',...(notFound?{protocol_error_code:Number(notFound[1])}:{}),diagnostic};}
  }
  if(result.isError!==undefined&&typeof result.isError!=='boolean')return{ok:false,layer:'PAYLOAD',status:'MALFORMED_SUCCESS',error_code:'INVALID_MCP_ERROR_FLAG',diagnostic};
  let body:any;try{body=JSON.parse(text);}catch{return{ok:false,layer:'PAYLOAD',status:'MALFORMED_SUCCESS',error_code:'INVALID_SUCCESS_JSON',diagnostic};}
  if(body?.ok===false){const code=safeCode(body.error?.code,'BUSINESS_ERROR');return{ok:false,layer:'BUSINESS',status:classification(code),error_code:code,diagnostic};}
  if(body?.ok!==true||!object(body.value))return{ok:false,layer:'PAYLOAD',status:'MALFORMED_SUCCESS',error_code:'INVALID_SUCCESS_BODY',diagnostic};
  const value=body.value, state=value.status??value.context?.diagnostics?.status;
  const status:DecodedCompanionResult['status']=state==='EMPTY'?'EMPTY':state==='NOT_FOUND_WITHIN_SCOPE'?'NOT_FOUND':
    state==='BUDGET_UNSATISFIABLE'||state==='PARTIAL'||state==='INCOMPLETE'?'INCOMPLETE':'RETURNED';
  return{ok:true,layer:'BUSINESS',status,error_code:null,value};
}

/** An immutable public event uses its own key; never update it using a predecessor. */
export function eventCaptureArguments(project_root:string,task:{task_ref:string;task_version:string},event:{namespace:string;event_id:string;content:string;category:StandaloneCaptureInput['category'];roles?:string[]}) {
  if(!object(event)||typeof event.namespace!=='string'||!event.namespace.trim()||event.namespace.length>512||typeof event.event_id!=='string'||!event.event_id.trim()||event.event_id.length>512||event.namespace.includes('\0')||event.event_id.includes('\0'))throw new Error('INVALID_EVENT_IDENTITY');
  const args={project_root,input:{...task,memory_key:'bridge-event-'+sha(canonicalContextJson([event.namespace,event.event_id])),category:event.category,declared_actor:'agent',content:event.content,previous_revision_id:null,...(event.roles===undefined?{}:{roles:event.roles})}};
  return validateCompanionCall('xmem_session_capture',args) as {project_root:string;input:StandaloneCaptureInput};
}

export function verifyCaptureReadback(value:unknown,expected:{content:string;project_id:string;workspace_id:string;task_ref:string;task_version:string;role:string;revision_id:string}) {
  if(!object(value)||value.status!=='COMPLETE'||value.persisted!=='SAVED'||typeof value.payload!=='string')throw new Error('INCOMPLETE_READBACK');
  if(value.payload_bytes!==Buffer.byteLength(value.payload,'utf8')||value.content_hash!==sha(value.payload))throw new Error('PUBLIC_PAYLOAD_HASH_MISMATCH');
  const view=JSON.parse(value.payload);
  if(!object(view)||!object(view.scope)||!object(view.record)||!object(view.current))throw new Error('INVALID_READBACK_SCHEMA');
  for(const field of ['project_id','workspace_id','task_ref','task_version','role'] as const)if(view.scope[field]!==expected[field])throw new Error('READBACK_SCOPE_MISMATCH');
  if(view.record.revision_id!==expected.revision_id||view.record.content!==expected.content||view.source_content_hash!==sha(expected.content))throw new Error('BODY_OR_REVISION_MISMATCH');
  return {scope:view.scope,revision_id:view.record.revision_id,body_sha256:view.source_content_hash,body_bytes:Buffer.byteLength(view.record.content,'utf8'),public_payload_sha256:value.content_hash,
    current:view.current,epistemic_state:view.record.epistemic_state,applicability:value.applicability,
    execution_verified:value.execution_verified,actor_identity_verified:value.actor_identity_verified,owner_confirmation_verified:value.owner_confirmation_verified};
}
