import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createRegistrationHandler} from '../server/registration.mjs';
const origin='https://alepht08passkeyportfolio.vercel.app';
const token='a'.repeat(43), hash=createHash('sha256').update(token).digest('hex');
function fixture() {
 let active=true, generated, saved, rpc;
 const db={
  create:async row=>{saved=row}, list:async()=>[], findEnrollment:async()=>null,
  request:async(path,method,body)=>{
   if(path.startsWith('t08_sessions?')) return active?[{user_id:'11111111-1111-4111-8111-111111111111',expires_at:new Date(Date.now()+60000).toISOString()}]:[];
   if(path.startsWith('t08_users?')) return [{account_name:'수민 A',webauthn_user_id:'aGFuZGxl'}];
   if(path.startsWith('t08_passkeys?')) return [];
   assert.equal(path,'rpc/t08_set_account_name');rpc=body;
   return active?{name:body.p_account_name,userId:'aGFuZGxl'}:{error:'AUTH_REQUIRED'};
  }
 };
 const handle=createRegistrationHandler({database:()=>db,configuration:()=>({origin,rpID:new URL(origin).hostname}),library:async()=>({
  generateRegistrationOptions:async args=>{generated=args;return {challenge:'test-question',user:{id:Buffer.from(args.userID).toString('base64url')}}}
 })});
 const request=(action,body,login=true,site=origin)=>handle(new Request(origin+'/api/passkeys?action='+action,{
  method:body===undefined?'GET':'POST',headers:{origin:site,'content-type':'application/json',cookie:login?'__Host-t08_session='+token:''},body:body===undefined?undefined:JSON.stringify(body)
 }));
 return {request,get generated(){return generated},get saved(){return saved},get rpc(){return rpc},revoke(){active=false}};
}
test('new registration stores chosen account name and presents it to the authenticator',async()=>{
 const f=fixture();assert.equal((await f.request('options',{name:'laptop',storage:'device',accountName:' 테스트 B '},false)).status,200);
 assert.equal(f.generated.userName,'테스트 B');assert.equal(f.generated.userDisplayName,'테스트 B');assert.equal(f.saved.account_name,'테스트 B');
});
test('additional registration uses saved account name and unchanged user handle',async()=>{
 const f=fixture();await f.request('options',{name:'backup',storage:'phone',accountName:'forged'});
 assert.equal(f.generated.userName,'수민 A');assert.equal(Buffer.from(f.generated.userID).toString('base64url'),'aGFuZGxl');
 const data=await (await f.request('list')).json();assert.equal(data.account.name,'수민 A');
});
test('rename derives ownership solely from authenticated session and validates names',async()=>{
 const f=fixture();const result=await f.request('rename',{accountName:'수민 A 수정',userId:'other-user'});
 assert.equal(result.status,200);assert.deepEqual(f.rpc,{p_session_hash:hash,p_account_name:'수민 A 수정'});
 for(const accountName of ['', ' ', 'a'.repeat(61),'bad\nname',42]) assert.equal((await f.request('rename',{accountName})).status,400);
 assert.equal((await f.request('rename',{accountName:'x'},false)).status,401);
 assert.equal((await f.request('rename',{accountName:'x'},true,'https://other.example')).status,403);
 f.revoke();assert.equal((await f.request('rename',{accountName:'x'})).status,401);
});

import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
const clientSource=await readFile(new URL('../passkeys.js',import.meta.url),'utf8');
async function clientFixture(signalSupported=true) {
 const elements=new Map(),events={},signals=[];let resolveRename;
 function element(id){if(!elements.has(id))elements.set(id,{value:'',hidden:false,disabled:false,textContent:'',children:[],listeners:{},addEventListener(type,fn){this.listeners[type]=fn},replaceChildren(){this.children=[]},append(...x){this.children.push(...x)},reportValidity(){return true}});return elements.get(id)}
 const account={name:'수민 A',userId:'aGFuZGxl',rpId:new URL(origin).hostname};
 const credential=signalSupported?{signalCurrentUserDetails:async data=>{signals.push(data)}}:{};
 const window={location:{hostname:new URL(origin).hostname,origin},PublicKeyCredential:credential,addEventListener(type,fn){events[type]=fn}};
 vm.runInNewContext(clientSource,{
  window,document:{getElementById:element},PublicKeyCredential:credential,AbortSignal,
  fetch:async url=>url.includes('rename')?new Promise(resolve=>{resolveRename=()=>resolve({ok:true,json:async()=>({account:{...account,name:'변경됨'}})})}):{ok:true,json:async()=>({authenticated:true,account,passkeys:[]})},
  navigator:{},Set,Date,CustomEvent:class{},Uint8Array
 });
 await new Promise(resolve=>setImmediate(resolve));
 return {element,events,signals,resolve:()=>resolveRename()};
}
test('authenticated UI shows account name and signals exact saved user handle',async()=>{
 const f=await clientFixture();assert.equal(f.element('account-name').value,'수민 A');assert.equal(f.element('account-name-save').hidden,false);
 assert.equal(f.signals[0].userId,'aGFuZGxl');assert.equal(f.signals[0].displayName,'수민 A');
});
test('late rename cannot restore account UI or signal after logout; unsupported signal is safe',async()=>{
 const f=await clientFixture(false);
 const pending=f.element('account-name-form').listeners.submit({preventDefault(){}});
 f.events['t08-auth-state']({detail:{authenticated:false}});
 f.resolve();await pending;
 assert.equal(f.element('account-name').value,'');assert.equal(f.element('account-name-save').hidden,true);
 assert.equal(f.element('account-name-status').textContent,'');assert.equal(f.signals.length,0);
});
