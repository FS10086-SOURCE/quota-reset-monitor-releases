// Authorization headers only to GitHub API hosts; CDN redirects never receive tokens.
import {REPOSITORY} from './contract.mjs';
const CDN=new Set(['release-assets.githubusercontent.com','objects.githubusercontent.com']);
export async function request(path,{token,method='GET',body,limit=1024*1024,accept='application/vnd.github+json',upload=false,fetchImpl=fetch}={}){
 let url=new URL(path,`https://${upload?'uploads':'api'}.github.com/repos/${REPOSITORY}/`);
 const origin=url.origin;
 if(!['https://api.github.com','https://uploads.github.com'].includes(origin)||!url.pathname.startsWith(`/repos/${REPOSITORY}/`))throw Error('Unapproved API destination');
 const timeout=AbortSignal.timeout(60000);
 for(let n=0;n<5;n++){
  if(url.protocol!=='https:'||url.username||url.password)throw Error('Unsafe redirect');
  const trusted=url.origin===origin;
  if(trusted&&!url.pathname.startsWith(`/repos/${REPOSITORY}/`))throw Error('Redirect escaped approved repository');
  if(!trusted&&(!CDN.has(url.hostname)||method!=='GET'))throw Error('Unapproved redirect');
  const headers={Accept:accept,'X-GitHub-Api-Version':'2022-11-28'};
  if(trusted){if(token)headers.Authorization=`Bearer ${token}`;if(body)headers['Content-Type']=upload?'application/octet-stream':'application/json';}
  const res=await fetchImpl(url,{method,headers,body,redirect:'manual',signal:timeout});
  if([301,302,303,307,308].includes(res.status)){const location=res.headers.get('location');await res.body?.cancel();if(!location)throw Error('Missing redirect');url=new URL(location,url);continue;}
  if(!res.ok){await res.body?.cancel();const error=Error(`GitHub request failed (${res.status}); inspect remote state before retry`);error.status=res.status;throw error;}
  const length=res.headers.get('content-length');if(length!==null&&(!/^\d+$/.test(length)||+length>limit)){await res.body?.cancel();throw Error('Response size exceeds bound');}
  const parts=[];let total=0;
  for await(const chunk of res.body){if(chunk.length>limit-total){await res.body?.cancel().catch(()=>{});throw Error('Response size exceeds bound');}parts.push(chunk);total+=chunk.length;}
  return Buffer.concat(parts,total);
 }
 throw Error('Too many redirects');
}
export async function json(path,opts){return JSON.parse((await request(path,opts)).toString('utf8'));}
