import { mkdir, open } from 'node:fs/promises';
import { randomBytes, createHash } from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { expand, loadPolicy } from './config.mjs';
import { initializeState } from './state.mjs';

export async function initialize(file) {
  const policy=await loadPolicy(file);
  const credentialFile=expand(policy.credentials_file);
  await mkdir(path.dirname(credentialFile),{recursive:true,mode:0o700});
  const creds={clients:[{id:'hermes',key:randomBytes(32).toString('base64url'),force_private:false},{id:'hermes-private',key:randomBytes(32).toString('base64url'),force_private:true}],session_hmac_key:randomBytes(32).toString('hex'),backend_key:'',openrouter_key:''};
  const f=await open(credentialFile,'wx',0o600);
  try{await f.writeFile(JSON.stringify(creds,null,2)+'\n');await f.sync();}finally{await f.close();}
  await initializeState(expand(policy.state_file),createHash('sha256').update(creds.session_hmac_key).digest('hex'));
  console.log('Initialized protected credentials and privacy state. No secret values printed.');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)initialize(process.argv[2]).catch(()=>{console.error('Initialization stopped; existing files are never overwritten.');process.exitCode=1;});
