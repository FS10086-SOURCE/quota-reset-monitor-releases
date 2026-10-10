import {writeFileSync,mkdirSync,appendFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {receipt,draft,exactInstaller,manifest,hash,REPOSITORY,MAX_INSTALLER} from './contract.mjs';
import {json,request} from './github.mjs';
import {verifySignatureFile,readBoundedFile} from './verify-signature.mjs';
const mode=process.argv[2];
const e=process.env;
if(!['summary','prepare','publish'].includes(mode)||e.GITHUB_REPOSITORY!==REPOSITORY||e.GITHUB_REF!=='refs/heads/main'||e.GITHUB_EVENT_NAME!=='workflow_dispatch'||e.GITHUB_RUN_ATTEMPT!=='1')throw Error('Wrong invocation scope');
const r=receipt(e.APPROVED_RECEIPT,e.GITHUB_SHA);
for(const k of ['RELEASE_ID','INSTALLER_ASSET_ID'])if(!/^[1-9][0-9]{0,19}$/.test(e[k]||'')||/[\r\n]/.test(e[k]))throw Error('Exact numeric release/asset IDs required');
const token=e.GH_TOKEN,dir=resolve(e.RUNNER_TEMP,'qrm-release');
const opts={token};
const releasePath=`releases/${e.RELEASE_ID}`;
async function checkRemote(extras=[]){const release=await json(releasePath,opts);draft(release,r,e.RELEASE_ID,e.INSTALLER_ASSET_ID,extras);return release;}
async function remoteInstaller(){const bytes=await request(`releases/assets/${e.INSTALLER_ASSET_ID}`,{...opts,accept:'application/octet-stream',limit:MAX_INSTALLER});exactInstaller(bytes,r);return bytes;}
function local(name,limit){return readBoundedFile(resolve(dir,name),limit,name);}
function summary(){if(!e.GITHUB_STEP_SUMMARY)throw Error('GitHub summary required');appendFileSync(e.GITHUB_STEP_SUMMARY,'Owner approval required: compare this receipt with the reviewed private build before permitting draft access, signing and publication. No public upload is authorized by a receipt alone.\n\n<pre>'+JSON.stringify(r,null,2).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')+'</pre>\n');}
if(mode==='summary'){summary();}else{
await checkRemote();
// Never overwrite an existing published version, or let a draft target a different source tag.
async function absent(path){try{await json(path,opts);return false;}catch(error){if(error.status===404)return true;throw error;}}
async function checkVersion(){
if(!await absent(`git/ref/tags/v${r.version}`))throw Error('Version tag already exists; no replacement release');
try{const latest=await json('releases/latest',opts);const previous=/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(latest.tag_name);if(!previous)throw Error('Unexpected latest release version');const old=previous.slice(1).map(BigInt),next=r.version.split('.').map(BigInt);let newer=false;for(let i=0;i<3;i++){if(next[i]!==old[i]){newer=next[i]>old[i];break;}}if(!newer)throw Error('Release version must increase');}catch(error){if(error.status!==404)throw error;}
}
await checkVersion();
if(mode==='prepare'){
 const bytes=await remoteInstaller();mkdirSync(dir,{recursive:false});writeFileSync(resolve(dir,'installer.exe'),bytes,{flag:'wx'});writeFileSync(resolve(dir,'receipt.json'),JSON.stringify(r,null,2)+'\n',{flag:'wx'});
 if(!e.GITHUB_OUTPUT||!e.GITHUB_STEP_SUMMARY)throw Error('GitHub output channels required');
 for(const [k,v]of Object.entries({version:r.version,installer_sha256:r.installerSha256,installer_size:r.installerSize}))appendFileSync(e.GITHUB_OUTPUT,`${k}=${v}\n`);
 summary();
}else{
 const bytes=local('installer.exe',MAX_INSTALLER);exactInstaller(bytes,r);
 if(!local('receipt.json',16384).equals(Buffer.from(JSON.stringify(r,null,2)+'\n')))throw Error('Prepared receipt mismatch');
 local('installer.exe.sig',8192);
 const verified=verifySignatureFile({artifactPath:resolve(dir,'installer.exe'),signaturePath:resolve(dir,'installer.exe.sig'),expectedVersion:r.version});
 if(verified.artifactSha256!==r.installerSha256||verified.artifactSize!==r.installerSize)throw Error('Verified installer snapshot changed');
 const signature=verified.signature;
 await remoteInstaller(); // Remote bytes must still equal the signed, approved bytes.
 const outputs=new Map([[`${r.installerName}.sig`,Buffer.from(signature.trim())],['latest.json',Buffer.from(JSON.stringify(manifest(r,signature),null,2)+'\n')],['release-receipt.json',Buffer.from(JSON.stringify(r,null,2)+'\n')]]);
 const added=[];
 for(const [name,data]of outputs){
  await checkRemote(added);
  const result=await json(`${releasePath}/assets?name=${encodeURIComponent(name)}`,{...opts,method:'POST',upload:true,body:data});
  if(result.name!==name||result.size!==data.length||result.digest!==`sha256:${hash(data)}`||!Number.isSafeInteger(result.id))throw Error('Uploaded asset receipt mismatch');
  const saved=await request(`releases/assets/${result.id}`,{...opts,accept:'application/octet-stream',limit:16384});
  if(!saved.equals(data))throw Error('Uploaded asset readback mismatch');
  added.push({name,id:result.id,size:result.size,digest:result.digest});
 }
 await checkRemote(added);await remoteInstaller();
 for(const entry of added){const saved=await request(`releases/assets/${entry.id}`,{...opts,accept:'application/octet-stream',limit:16384});if(!saved.equals(outputs.get(entry.name)))throw Error('Publication output changed before publish');}
 await checkRemote(added);await checkVersion();
 const result=await json(releasePath,{...opts,method:'PATCH',body:JSON.stringify({draft:false,prerelease:false,make_latest:'true',tag_name:`v${r.version}`,target_commitish:r.workflowSha,name:`Quota Reset Monitor ${r.version}`,body:r.notes})});
 if(result.draft!==false||result.tag_name!==`v${r.version}`)throw Error('Publication outcome uncertain; inspect release, do not blindly retry');
 // Anonymous API/asset readback; installed Windows E2E remains a separate acceptance gate.
 const published=await json(`releases/tags/v${r.version}`,{});
 if(published.id!==result.id||published.draft)throw Error('Anonymous publication readback failed');
 const tag=await json(`git/ref/tags/v${r.version}`,{});if(tag.object?.type!=='commit'||tag.object.sha!==r.workflowSha)throw Error('Published tag commit mismatch');
 const latest=await json('releases/latest',{});if(latest.id!==result.id)throw Error('Latest release pointer mismatch');
 for(const [name,data]of outputs){const asset=published.assets.find(a=>a.name===name);if(!asset)throw Error('Missing public output');const publicBytes=await request(`releases/assets/${asset.id}`,{accept:'application/octet-stream',limit:16384});if(!publicBytes.equals(data))throw Error('Anonymous public output mismatch');}
 exactInstaller(await request(`releases/assets/${e.INSTALLER_ASSET_ID}`,{accept:'application/octet-stream',limit:MAX_INSTALLER}),r);
 console.log(`Published verified version ${r.version}; release ID ${result.id}`);
}

}
