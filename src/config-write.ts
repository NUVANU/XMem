/** Cooperating owner-config writers only. No stale-lock takeover or new authority. */
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { PathsError } from './paths.js';

export function withConfigurationLock<T>(filename:string,operation:()=>T):T {
  const lock=filename+'.lock';let fd:number;
  try{fd=fs.openSync(lock,'wx',0o600);}catch(error){
    if((error as NodeJS.ErrnoException).code==='EEXIST')throw new PathsError('CONFIG_BUSY','Another configuration write is pending. Retry later; an interrupted writer lock requires explicit owner inspection, not automatic takeover.');
    throw error;
  }
  try{return operation();}finally{fs.closeSync(fd);fs.unlinkSync(lock);}
}

export function writeConfigurationAtomically(filename:string,value:unknown):void {
  const temporary=path.join(path.dirname(filename),'.'+path.basename(filename)+'.'+randomUUID()+'.tmp');
  let fd:number|undefined;
  try{
    fd=fs.openSync(temporary,'wx',0o600);fs.writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;
    fs.renameSync(temporary,filename);
    if(process.platform!=='win32'){const directory=fs.openSync(path.dirname(filename),'r');try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}}
  }finally{if(fd!==undefined)fs.closeSync(fd);if(fs.existsSync(temporary))fs.unlinkSync(temporary);}
}
