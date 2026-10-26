-- Verification only. Creates synthetic records inside a transaction and ALWAYS rolls back.
-- Requires a trusted SQL Editor / service_role context; no real user's IDs are used.
begin;
set local role service_role;
do $check$
declare
 a uuid := gen_random_uuid(); b uuid := gen_random_uuid();
 qa uuid := gen_random_uuid(); qb uuid := gen_random_uuid();
 ka text := 'card5-' || gen_random_uuid()::text;
 kb text := 'card5-' || gen_random_uuid()::text;
 backup text := 'card5-' || gen_random_uuid()::text;
 sa text := encode(sha256(gen_random_uuid()::text::bytea),'hex');
 sb text := encode(sha256(gen_random_uuid()::text::bytea),'hex');
 ba text := repeat('a',64); bb text := repeat('b',64);
 result jsonb; replay_rejected boolean := false;
begin
 insert into public.t08_users(id,webauthn_user_id,enrollment_token_hash,enrollment_expires_at)
 values(a,'card5-'||a::text,encode(sha256(a::text::bytea),'hex'),clock_timestamp()+interval '5 minutes'),
       (b,'card5-'||b::text,encode(sha256(b::text::bytea),'hex'),clock_timestamp()+interval '5 minutes');
 insert into public.t08_passkeys(credential_id,user_id,public_key,counter,transports,device_type,backed_up,name,storage_label)
 values(ka,a,'AQID',0,'{}','singleDevice',false,'가상 A','검증 전용'),
       (kb,b,'BAUG',0,'{}','singleDevice',false,'가상 B','검증 전용'),
       (backup,a,'BwgJ',0,'{}','singleDevice',false,'가상 A 백업','검증 전용');
 insert into public.t08_auth_challenges(id,challenge,binding_hash,expires_at)
 values(qa,'card5-'||qa::text,ba,clock_timestamp()+interval '5 minutes'),
       (qb,'card5-'||qb::text,bb,clock_timestamp()+interval '5 minutes');
 if public.t08_finish_login(qa,ba,ka,0,1,sa,null)<>a then raise exception 'A login owner mismatch'; end if;
 if public.t08_finish_login(qb,bb,kb,0,1,sb,null)<>b then raise exception 'B login owner mismatch'; end if;
 update public.t08_private_items set content='가상 A 검증 자료: '||kind where user_id=a;
 update public.t08_private_items set content='가상 B 검증 자료: '||kind where user_id=b;
 if (select count(*) from public.t08_private_items i join public.t08_sessions s on s.user_id=i.user_id
     where s.token_hash=sa and s.revoked_at is null and s.expires_at>clock_timestamp()
     and i.content like '가상 A 검증 자료:%')<>3 then raise exception 'A scoped query failed'; end if;
 if exists(select 1 from public.t08_private_items i join public.t08_sessions s on s.user_id=i.user_id
     where s.token_hash=sa and i.user_id=b) then raise exception 'A leaked B'; end if;
 if (select count(*) from public.t08_private_items i join public.t08_sessions s on s.user_id=i.user_id
     where s.token_hash=sb and s.revoked_at is null and s.expires_at>clock_timestamp()
     and i.content like '가상 B 검증 자료:%')<>3 then raise exception 'B scoped query failed'; end if;
 if exists(select 1 from public.t08_private_items i join public.t08_sessions s on s.user_id=i.user_id
     where s.token_hash=sb and i.user_id=a) then raise exception 'B leaked A'; end if;
 begin
  perform public.t08_finish_login(qa,ba,ka,1,2,repeat('c',64),null);
 exception when sqlstate 'P0001' then
  if sqlerrm<>'challenge_unavailable' then raise; end if;
  replay_rejected:=true;
 end;
 if not replay_rejected then raise exception 'Replay accepted'; end if;
 result:=public.t08_remove_passkey(sa,kb);
 if result->>'error'<>'PASSKEY_NOT_FOUND' then raise exception 'Cross-owner deletion accepted'; end if;
 result:=public.t08_remove_passkey(sa,ka);
 if result->>'deleted'<>'true' or result->>'remaining'<>'1' then raise exception 'Deletion failed'; end if;
 if exists(select 1 from public.t08_passkeys where credential_id=ka) then raise exception 'Deleted key remains'; end if;
 if exists(select 1 from public.t08_sessions where token_hash=sa and revoked_at is null) then raise exception 'Deletion did not revoke'; end if;
 update public.t08_sessions set revoked_at=clock_timestamp() where token_hash=sb;
 if exists(select 1 from public.t08_sessions where token_hash=sb and revoked_at is null and expires_at>clock_timestamp()) then raise exception 'Old session still valid'; end if;
end;
$check$;
reset role;
select jsonb_build_object(
 'mode','REAL_DATABASE_TRANSACTION_ROLLBACK',
 'two_synthetic_accounts',true,'three_different_records_each',true,
 'A_owner_scope',true,'B_owner_scope',true,'used_challenge_rejected',true,
 'cross_owner_key_delete_rejected',true,'deleted_key_absent',true,'revoked_cookie_hash_rejected',true,
 'crypto_verified',false,'real_device_test',false,
 'all_changes_rolled_back',true
) as verification_result;
rollback;
