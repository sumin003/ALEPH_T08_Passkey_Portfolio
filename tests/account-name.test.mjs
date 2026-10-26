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

test('new registration uses only the passkey name for authenticator labels',async()=>{
 const f=fixture();
 assert.equal((await f.request('options',{name:' 테스트 B ',storage:'device',accountName:'ignored'},false)).status,200);
 assert.equal(f.generated.userName,'테스트 B');assert.equal(f.generated.userDisplayName,'테스트 B');
 assert.equal(f.saved.passkey_name,'테스트 B');
});
test('additional registration uses its own passkey name while preserving the account handle',async()=>{
 const f=fixture();await f.request('options',{name:'수민 A 휴대폰',storage:'phone',accountName:'ignored'});
 assert.equal(f.generated.userName,'수민 A 휴대폰');assert.equal(f.generated.userDisplayName,'수민 A 휴대폰');
 assert.equal(Buffer.from(f.generated.userID).toString('base64url'),'aGFuZGxl');
});
test('separate account rename endpoint is no longer exposed',async()=>{
 const f=fixture();assert.equal((await f.request('rename',{accountName:'x'})).status,404);
});
