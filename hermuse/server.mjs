import http from 'node:http';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { pathToFileURL } from 'node:url';
import { PolicyEngine } from './engine.mjs';
import { ALIASES, PolicyError, loadPolicy } from './config.mjs';

function send(res, status, data) {
  res.writeHead(status, {'Content-Type':'application/json','Cache-Control':'no-store','X-Should-Retry':'false'});
  res.end(JSON.stringify(data));
}
async function readBody(req, max) {
  let size=0;const chunks=[];
  for await (const chunk of req) { size+=chunk.length;if(size>max)throw new PolicyError('request_too_large',413);chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new PolicyError('invalid_json',400); }
}
export function createPolicyServer(engine, startupPolicy) {
  let active=0;
  return http.createServer({maxHeaderSize:16384,requestTimeout:30000},async(req,res)=>{
    const controller=new AbortController();
    res.on('close',()=>{if(!res.writableFinished)controller.abort();});
    let admitted=false;
    try {
      const p=new URL(req.url,'http://127.0.0.1').pathname;
      if(req.method==='GET'&&p==='/healthz')return send(res,200,{status:'ok',privacy:'fail-closed'});
      // No alternate inference paths, raw upstream models or admin proxy endpoints.
      if(req.method==='GET'&&p==='/v1/models')return send(res,200,{object:'list',data:ALIASES.map(id=>({id,object:'model',owned_by:'hermuse-router'}))});
      if(req.method!=='POST'||p!=='/v1/chat/completions')throw new PolicyError('unsupported_endpoint',404);
      const policy=await engine.load(engine.policyFile);
      if(policy.listen.host!==startupPolicy.listen.host||policy.listen.port!==startupPolicy.listen.port)throw new PolicyError('listen_change_requires_restart');
      if(active>=policy.limits.max_concurrency)throw new PolicyError('router_busy',429);
      active++;admitted=true;
      const body=await readBody(req,policy.limits.body_bytes);
      const result=await engine.handle(body,new Headers(req.headers),controller.signal);
      const headers={'Content-Type':result.response.headers.get('content-type')||'application/json','Cache-Control':'no-store',
        'X-Hermuse-Route':result.route,'X-Hermuse-Model':result.model,'X-Hermuse-Provider':result.provider,'X-Request-ID':result.requestId};
      if(body.stream)headers['X-Accel-Buffering']='no';
      res.writeHead(result.response.status,headers);
      if(result.response.body)await pipeline(Readable.fromWeb(result.response.body),res,{signal:controller.signal});else res.end();
    }catch(e){
      if(res.headersSent){res.destroy();return;}
      const error=e instanceof PolicyError?e:new PolicyError('router_error');
      send(res,error.status,{error:{message:error.code,type:'hermuse_policy_error',code:error.code}});
    }finally{if(admitted)active--;}
  });
}
export async function main(file) {
  if(!file)throw new Error('Usage: node hermuse/server.mjs /absolute/path/policy.json');
  const policy=await loadPolicy(file);const engine=new PolicyEngine({policyFile:file});
  const server=createPolicyServer(engine,policy);
  server.listen(policy.listen.port,policy.listen.host,()=>console.log(JSON.stringify({event:'listening',host:policy.listen.host,port:policy.listen.port})));
  const stop=()=>{server.close();setTimeout(()=>server.closeAllConnections(),15000).unref();};
  process.on('SIGTERM',stop);process.on('SIGINT',stop);
  return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main(process.argv[2]).catch(()=>{console.error('Router startup rejected: invalid or unreadable policy.');process.exitCode=1;});
