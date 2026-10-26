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

test('anonymous and expired sessions cannot start registration or create a challenge',async()=>{
 const f=fixture();
 assert.equal((await f.request('options',{name:'B',storage:'device',allowInitialRegistration:true},false)).status,401);
 assert.equal(f.saved,undefined);assert.equal(f.generated,undefined);
 f.revoke();
 assert.equal((await f.request('options',{name:'B',storage:'device'})).status,401);
 assert.equal(f.saved,undefined);
});
test('anonymous registration completion and enrollment listing are rejected',async()=>{
 const f=fixture();
 assert.equal((await f.request('verify',{challengeId:'11111111-1111-4111-8111-111111111111'},false)).status,401);
 assert.equal((await f.request('list',undefined,false)).status,401);
});
test('additional registration uses its own passkey name while preserving the account handle',async()=>{
 const f=fixture();await f.request('options',{name:'수민 A 휴대폰',storage:'phone',accountName:'ignored'});
 assert.equal(f.generated.userName,'수민 A 휴대폰');assert.equal(f.generated.userDisplayName,'수민 A 휴대폰');
 assert.equal(Buffer.from(f.generated.userID).toString('base64url'),'aGFuZGxl');
});
test('separate account rename endpoint is no longer exposed',async()=>{
 const f=fixture();assert.equal((await f.request('rename',{accountName:'x'})).status,404);
});

test('pre-closure initial challenge cannot complete even with a valid login session',async()=>{
 const db = {
  request:async()=>[{user_id:'11111111-1111-4111-8111-111111111111',expires_at:new Date(Date.now()+60000).toISOString()}],
  findChallenge:async()=>({kind:'registration',expires_at:new Date(Date.now()+60000).toISOString()}),
  finish:async()=>assert.fail('must not create a new account')
 };
 const handle=createRegistrationHandler({database:()=>db,library:async()=>assert.fail('must reject before verification'),configuration:()=>({origin,rpID:new URL(origin).hostname})});
 const response=await handle(new Request(origin+'/api/passkeys?action=verify',{
  method:'POST',headers:{origin,'content-type':'application/json',cookie:'__Host-t08_session='+token+'; __Host-t08_enrollment='+token},
  body:JSON.stringify({challengeId:'11111111-1111-4111-8111-111111111111',credential:{},allowInitialRegistration:true})
 }));
 assert.equal(response.status,403);assert.equal((await response.json()).error,'INITIAL_REGISTRATION_CLOSED');
});
test('production route refuses anonymous registration without touching the database',async()=>{
 const {default: route}=await import('../api/passkeys.js');
 for (const action of ['options','verify']) {
  const response=await route.fetch(new Request(origin+'/api/passkeys?action='+action,{
   method:'POST',headers:{origin,'content-type':'application/json'},
   body:JSON.stringify({name:'new',storage:'device',allowInitialRegistration:true})
  }));
  assert.equal(response.status,401);
 }
});
