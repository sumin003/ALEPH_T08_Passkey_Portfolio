begin;
create table public.t08_users (
  id uuid primary key,
  webauthn_user_id text not null unique,
  enrollment_token_hash text not null unique check (enrollment_token_hash ~ '^[a-f0-9]{64}$'),
  enrollment_expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create table public.t08_challenges (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('registration','authentication')),
  challenge text not null unique,
  binding_hash text not null check (binding_hash ~ '^[a-f0-9]{64}$'),
  candidate_user_id uuid not null,
  webauthn_user_id text not null,
  passkey_name text not null check (char_length(passkey_name) between 1 and 60),
  storage_label text not null check (char_length(storage_label) between 1 and 100),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at timestamptz,
  check (expires_at > created_at)
);
create table public.t08_passkeys (
  credential_id text primary key,
  user_id uuid not null references public.t08_users(id) on delete cascade,
  public_key text not null,
  counter bigint not null check (counter >= 0),
  transports text[] not null default '{}',
  device_type text not null check (device_type in ('singleDevice','multiDevice')),
  backed_up boolean not null,
  name text not null check (char_length(name) between 1 and 60),
  storage_label text not null,
  created_at timestamptz not null default now()
);
create index t08_passkeys_user_idx on public.t08_passkeys(user_id);
create index t08_challenges_expiry_idx on public.t08_challenges(expires_at);

alter table public.t08_users enable row level security;
alter table public.t08_challenges enable row level security;
alter table public.t08_passkeys enable row level security;
revoke all on public.t08_users, public.t08_challenges, public.t08_passkeys from public, anon, authenticated;
grant select, insert, update, delete on public.t08_users, public.t08_challenges, public.t08_passkeys to service_role;

create function public.t08_finish_registration(
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

  insert into public.t08_users(id, webauthn_user_id, enrollment_token_hash, enrollment_expires_at)
    values (challenge_row.candidate_user_id, challenge_row.webauthn_user_id,
      p_binding_hash, clock_timestamp() + interval '15 minutes');
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
comment on table public.t08_passkeys is 'T08 passkey public credentials only. No private keys or passwords.';
comment on table public.t08_challenges is 'T08 server-issued registration/authentication questions; short expiry and one-time use.';
commit;
