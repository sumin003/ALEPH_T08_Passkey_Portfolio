alter table public.t08_users add column account_name text
  check (account_name is null or (char_length(btrim(account_name)) between 1 and 60 and account_name !~ '[[:cntrl:]]'));
alter table public.t08_challenges add column account_name text
  check (account_name is null or (char_length(btrim(account_name)) between 1 and 60 and account_name !~ '[[:cntrl:]]'));
create or replace function public.t08_finish_registration(
  p_challenge_id uuid, p_binding_hash text, p_credential_id text,
  p_public_key text, p_counter bigint, p_transports text[],
  p_device_type text, p_backed_up boolean
) returns uuid
language plpgsql security invoker set search_path = ''
as $fn$
declare
  challenge_row public.t08_challenges%rowtype;
begin
  select * into challenge_row from public.t08_challenges
    where id = p_challenge_id and binding_hash = p_binding_hash
    for update;
  if not found or challenge_row.kind <> 'registration'
    or challenge_row.used_at is not null
    or challenge_row.expires_at <= clock_timestamp() then
    raise exception 'challenge_not_available' using errcode = 'P0001';
  end if;
  if p_credential_id is null or length(p_credential_id) = 0
    or p_public_key is null or length(p_public_key) = 0 then
    raise exception 'invalid_credential' using errcode = 'P0001';
  end if;

  insert into public.t08_users(id, webauthn_user_id, enrollment_token_hash, enrollment_expires_at, account_name)
    values (challenge_row.candidate_user_id, challenge_row.webauthn_user_id,
      p_binding_hash, clock_timestamp() + interval '15 minutes',
      coalesce(challenge_row.account_name, 'portfolio-' || right(challenge_row.candidate_user_id::text, 8)));
  insert into public.t08_passkeys(credential_id, user_id, public_key, counter,
    transports, device_type, backed_up, name, storage_label)
    values (p_credential_id, challenge_row.candidate_user_id, p_public_key,
      p_counter, coalesce(p_transports, '{}'), p_device_type, p_backed_up,
      challenge_row.passkey_name, challenge_row.storage_label);
  update public.t08_challenges set used_at = clock_timestamp() where id = p_challenge_id;
  return challenge_row.candidate_user_id;
end;
$fn$;
revoke all on function public.t08_finish_registration(uuid,text,text,text,bigint,text[],text,boolean) from public, anon, authenticated;
grant execute on function public.t08_finish_registration(uuid,text,text,text,bigint,text[],text,boolean) to service_role;

create or replace function public.t08_set_account_name(p_session_hash text, p_account_name text)
returns jsonb language plpgsql security invoker set search_path = ''
as $fn$
declare owner_id uuid; user_handle text;
begin
  select user_id into owner_id from public.t08_sessions
    where token_hash = p_session_hash and revoked_at is null and expires_at > clock_timestamp()
    for update;
  if not found then return jsonb_build_object('error','AUTH_REQUIRED'); end if;
  if p_account_name is null or char_length(btrim(p_account_name)) not between 1 and 60
    or p_account_name ~ '[[:cntrl:]]' then
    raise exception 'invalid_account_name' using errcode = '22023';
  end if;
  update public.t08_users set account_name = btrim(p_account_name)
    where id = owner_id returning webauthn_user_id into user_handle;
  return jsonb_build_object('name', btrim(p_account_name), 'userId', user_handle);
end;
$fn$;
revoke all on function public.t08_set_account_name(text,text) from public, anon, authenticated;
grant execute on function public.t08_set_account_name(text,text) to service_role;
