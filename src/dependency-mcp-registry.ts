/** Server-owned ephemeral enrollment routes. Tokens never serialize SDK handles. */
import { randomUUID } from 'node:crypto';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { readProjectConfig } from './index.js';
import { readStandalonePolicy } from './standalone.js';
import { readStorageLocationAtProjectRoot } from './storage-location.js';
import { registerEngineeringDependencies } from './engineering-memory.js';
import { revokeEngineeringDependencies,type EngineeringDependencyHandle,type EngineeringDependencyOptions } from './engineering-dependencies.js';
import { PathsError,withPathValidationScope } from './paths.js';
import type { CodexResult } from './codex.js';
type Extra={sessionId?:string};
type Route={token:string;transport:string;session:string;root:string;project:string;workspace:string;policy:string;location:string;handle:EngineeringDependencyHandle};
function missing():never {throw new PathsError('DEPENDENCY_TOKEN_NOT_FOUND','Dependency enrollment unavailable in this server session');}

export function createDependencyMcpRegistry(server:McpServer) {
  const routes=new Map<string,Route>(),transports=new WeakMap<object,string>(),namespace=randomUUID();
  let registrationGuard:((x:{project_root:string;session_ref:string;binding_id?:string;input:any},extra:Extra)=>void)|undefined;
  const transport=(extra:Extra)=>{
    const actual=server.server.transport;let id=actual?transports.get(actual):namespace;
    if(actual&&!id){id=randomUUID();transports.set(actual,id);}return JSON.stringify([id,extra.sessionId??null]);
  };
  const verify=(r:Route,rootInput?:string)=>{
    const config=readProjectConfig(rootInput??r.root),policy=readStandalonePolicy(config.root),location=readStorageLocationAtProjectRoot(config.root,config.project_id);
    if(config.root!==r.root||config.project_id!==r.project||!policy?.policy.enabled||policy.policy.workspace_id!==r.workspace||policy.policy_hash!==r.policy||location.location_hash!==r.location)missing();
  };
  const lookup=(token:string,session:string,extra:Extra)=>{
    const route=routes.get(token);if(!route||route.session!==session||route.transport!==transport(extra))missing();verify(route);return route;
  };
  const run=(operation:()=>unknown):CodexResult=>{try{return{ok:true,value:withPathValidationScope(operation)};}catch(error){return{ok:false,error:{code:error instanceof PathsError?error.code:'INPUT_INCOMPLETE',message:'Dependency enrollment unavailable in this server session'}};}};
  return{
    setRegistrationGuard:(guard:NonNullable<typeof registrationGuard>)=>{registrationGuard=guard;},
    register:(x:{project_root:string;session_ref:string;binding_id?:string;input:any},extra:Extra):CodexResult=>{
      if(routes.size>=128)return{ok:false,error:{code:'DEPENDENCY_REGISTRY_CAPACITY',message:'Dependency enrollment capacity reached'}};
      const admitted=run(()=>{if(registrationGuard)registrationGuard(x,extra);else if(x.binding_id!==undefined)missing();});if(!admitted.ok)return admitted;
      const registered=registerEngineeringDependencies(x.project_root,x.input);if(!registered.ok)return registered;
      const value=registered.value as {handle:EngineeringDependencyHandle;registered_edges:number};
      const answer=run(()=>{
        const config=readProjectConfig(x.project_root),expected=x.input.expected_scope;
        const route:Route={token:randomUUID(),transport:transport(extra),session:x.session_ref,root:config.root,project:expected.project_id,workspace:expected.workspace_id,policy:expected.policy_hash,location:expected.storage_location_hash,handle:value.handle};
        verify(route);routes.set(route.token,route);
        return{contract:'xmem-dependency-registration/1',dependency_token:route.token,session_ref:route.session,registered_edges:value.registered_edges,ephemeral:true,authenticated_owner:false,read_permission_granted:false};
      });
      if(!answer.ok)revokeEngineeringDependencies(value.handle);return answer;
    },
    revoke:(x:{session_ref:string;dependency_token:string},extra:Extra):CodexResult=>run(()=>{
      const route=lookup(x.dependency_token,x.session_ref,extra);revokeEngineeringDependencies(route.handle);routes.delete(route.token);
      return{dependency_token:x.dependency_token,revoked:true,ephemeral:true,authenticated_owner:false,read_permission_granted:false};
    }),
    options:(root:string,token:string|undefined,session:string|undefined,extra:Extra):EngineeringDependencyOptions|undefined=>{
      if(token===undefined&&session===undefined)return undefined;if(!token||!session)missing();const route=lookup(token,session,extra);verify(route,root);return{dependencies:route.handle};
    },
    invalidateSession:(session:string,extra:Extra)=>{for(const [key,route]of routes)if(route.transport===transport(extra)&&route.session===session){revokeEngineeringDependencies(route.handle);routes.delete(key);}}
  };
}
export type DependencyMcpRegistry=ReturnType<typeof createDependencyMcpRegistry>;
