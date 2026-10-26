begin;
alter table public.t08_challenges
 add column existing_user_id uuid references public.t08_users(id),
 add column registration_session_hash text references public.t08_sessions(token_hash);
alter table public.t08_challenges add constraint t08_existing_registration_pair
 check ((existing_user_id is null and registration_session_hash is null)
   or (existing_user_id is not null and registration_session_hash is not null));

create function public.t08_finish_additional_registration(
 p_challenge_id uuid, p_binding_hash text, p_credential_id text, p_public_key text,
 p_counter bigint, p_transports text[], p_device_type text, p_backed_up boolean,
 p_session_hash text
) returns uuid language plpgsql security invoker set search_path=''
as $fn$
declare q public.t08_challenges%rowtype;
begin
 select * into q from public.t08_challenges where id=p_challenge_id and binding_hash=p_binding_hash for update;
 if not found or q.kind <> 'registration' or q.used_at is not null or q.expires_at<=clock_timestamp()
  or q.existing_user_id is null or q.registration_session_hash <> p_session_hash then
  raise exception 'registration_unavailable' using errcode='P0001';
 end if;
 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(q.existing_user_id::text,0));
 if not exists(select 1 from public.t08_sessions where token_hash=p_session_hash and user_id=q.existing_user_id
  and revoked_at is null and expires_at>clock_timestamp()) then
  raise exception 'session_unavailable' using errcode='P0001';
 end if;
 if q.candidate_user_id<>q.existing_user_id or not exists(select 1 from public.t08_users
  where id=q.existing_user_id and webauthn_user_id=q.webauthn_user_id) then
  raise exception 'owner_mismatch' using errcode='P0001';
 end if;
 if p_credential_id is null or length(p_credential_id)=0 or p_public_key is null or length(p_public_key)=0 then
  raise exception 'invalid_credential' using errcode='P0001';
 end if;
 insert into public.t08_passkeys(credential_id,user_id,public_key,counter,transports,device_type,backed_up,name,storage_label)
 values(p_credential_id,q.existing_user_id,p_public_key,p_counter,coalesce(p_transports,'{}'),
 p_device_type,p_backed_up,q.passkey_name,q.storage_label);
 update public.t08_challenges set used_at=clock_timestamp() where id=q.id;
 return q.existing_user_id;
end;
$fn$;
revoke all on function public.t08_finish_additional_registration(uuid,text,text,text,bigint,text[],text,boolean,text) from public,anon,authenticated;
grant execute on function public.t08_finish_additional_registration(uuid,text,text,text,bigint,text[],text,boolean,text) to service_role;

create function public.t08_remove_passkey(p_session_hash text,p_credential_id text)
 returns jsonb language plpgsql security invoker set search_path=''
as $fn$
declare owner uuid; remaining integer;
begin
 select user_id into owner from public.t08_sessions where token_hash=p_session_hash
  and revoked_at is null and expires_at>clock_timestamp();
 if not found then return jsonb_build_object('error','AUTH_REQUIRED'); end if;
 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(owner::text,0));
 if not exists(select 1 from public.t08_sessions where token_hash=p_session_hash and user_id=owner
  and revoked_at is null and expires_at>clock_timestamp()) then
  return jsonb_build_object('error','AUTH_REQUIRED');
 end if;
 perform 1 from public.t08_passkeys where credential_id=p_credential_id and user_id=owner for update;
 if not found then return jsonb_build_object('error','PASSKEY_NOT_FOUND'); end if;
 select count(*) into remaining from public.t08_passkeys where user_id=owner;
 if remaining<=1 then return jsonb_build_object('error','LAST_PASSKEY'); end if;
 delete from public.t08_passkeys where credential_id=p_credential_id and user_id=owner;
 update public.t08_sessions set revoked_at=clock_timestamp() where user_id=owner and revoked_at is null;
 return jsonb_build_object('deleted',true,'remaining',remaining-1,'loggedOut',true);
end;
$fn$;
revoke all on function public.t08_remove_passkey(text,text) from public,anon,authenticated;
grant execute on function public.t08_remove_passkey(text,text) to service_role;
commit;
