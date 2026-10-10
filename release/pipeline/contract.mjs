// Public release-helper code only. No credential generation or private-source access.
import {createHash} from 'node:crypto';
export const REPOSITORY='FS10086-SOURCE/quota-reset-monitor-releases';
export const KEY_ID='3C03FD6ECC8CB0C6';
export const OVERLAY_SHA256='032fbe66c8a467b618ca88d28e63f11d137eb0b6fc854a116e6f8d28369b2d1e';
export const MAX_INSTALLER=256*1024*1024;
export const hash=b=>createHash('sha256').update(b).digest('hex');
const fail=()=>{throw Error('Release receipt or remote state does not match approved contract')};
export function receipt(input,workflowSha){
 if(typeof input!=='string'||Buffer.byteLength(input)>16384)fail();
 let r;try{r=JSON.parse(input)}catch{fail()}
 const keys=['schema','repository','version','sourceSha','sourceTree','buildRunId','privateArtifactId','workflowSha','installerName','installerSize','installerSha256','overlaySha256','publicKeyId','notes','builtAt'];
 if(!r||Array.isArray(r)||Object.keys(r).sort().join()!==keys.sort().join())fail();
 if(keys.some(k=>!['schema','installerSize'].includes(k)&&typeof r[k]!=='string'))fail();
 if(keys.some(k=>typeof r[k]==='string'&&k!=='notes'&&/[\r\n]/.test(r[k])))fail();
 if(r.schema!==1||r.repository!==REPOSITORY||!/^\d+\.\d+\.\d+$/.test(r.version)||r.version.split('.').some(n=>!Number.isSafeInteger(+n)||String(+n)!==n))fail();
 for(const k of ['sourceSha','sourceTree','workflowSha'])if(!/^[a-f0-9]{40}$/.test(r[k]))fail();
 if(r.workflowSha!==workflowSha||r.overlaySha256!==OVERLAY_SHA256||r.publicKeyId!==KEY_ID)fail();
 for(const k of ['buildRunId','privateArtifactId'])if(!/^[1-9][0-9]{0,19}$/.test(r[k]))fail();
 if(!/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}-setup\.exe$/.test(r.installerName)||!Number.isSafeInteger(r.installerSize)||r.installerSize<2||r.installerSize>MAX_INSTALLER||!/^[a-f0-9]{64}$/.test(r.installerSha256))fail();
 if(typeof r.notes!=='string'||Buffer.byteLength(r.notes)>4096||(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(r.notes)||/\r(?!\n)/.test(r.notes))||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(r.builtAt)||!Number.isFinite(Date.parse(r.builtAt)))fail();
 return Object.freeze(r);
}
export function exactInstaller(bytes,r){if(bytes.length!==r.installerSize||hash(bytes)!==r.installerSha256||bytes[0]!==0x4d||bytes[1]!==0x5a)fail();}
export function draft(release,r,releaseId,assetId,allowedExtra=[]){
 if(String(release.id)!==releaseId||release.draft!==true||release.prerelease!==false||release.tag_name!==`v${r.version}`||release.target_commitish!==r.workflowSha||release.name!==`Quota Reset Monitor ${r.version}`||release.body!==r.notes)fail();
 if(!Array.isArray(release.assets)||release.assets.length!==1+allowedExtra.length)fail();
 const asset=release.assets.find(a=>String(a.id)===assetId);
 if(!asset||asset.name!==r.installerName||asset.size!==r.installerSize||asset.state!=='uploaded'||asset.digest!==`sha256:${r.installerSha256}`)fail();
 if(release.assets.some(a=>a!==asset&&!allowedExtra.some(x=>x.name===a.name&&x.id===a.id&&x.size===a.size&&x.digest===a.digest&&a.state==='uploaded'))||new Set(release.assets.map(a=>a.name)).size!==release.assets.length)fail();
 return asset;
}
export function manifest(r,signature){return {version:r.version,notes:r.notes,pub_date:r.builtAt,platforms:{'windows-x86_64-nsis':{url:`https://github.com/${REPOSITORY}/releases/download/v${r.version}/${r.installerName}`,signature:signature.trim(),sha256:r.installerSha256}}};}
