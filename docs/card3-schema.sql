begin;
create table public.t08_auth_challenges (
 id uuid primary key default gen_random_uuid(),
 challenge text not null unique,
 binding_hash text not null check(binding_hash ~ '^[a-f0-9]{64}$'),
 created_at timestamptz not null default now(),
 expires_at timestamptz not null,
 used_at timestamptz,
 check(expires_at > created_at)
);
create index t08_auth_challenges_expiry_idx on public.t08_auth_challenges(expires_at);
create table public.t08_sessions (
 token_hash text primary key check(token_hash ~ '^[a-f0-9]{64}$'),
 user_id uuid not null references public.t08_users(id) on delete cascade,
 created_at timestamptz not null default now(),
 expires_at timestamptz not null,
 revoked_at timestamptz,
 check(expires_at > created_at)
);
create index t08_sessions_user_idx on public.t08_sessions(user_id);
create table public.t08_private_items (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references public.t08_users(id) on delete cascade,
 kind text not null check(kind in ('project-note','personal-goal','reflection')),
 title text not null,
 content text not null default '',
 created_at timestamptz not null default now(),
 unique(user_id, kind)
);
alter table public.t08_auth_challenges enable row level security;
alter table public.t08_sessions enable row level security;
alter table public.t08_private_items enable row level security;
revoke all on public.t08_auth_challenges, public.t08_sessions, public.t08_private_items from public, anon, authenticated;
grant select,insert,update,delete on public.t08_auth_challenges, public.t08_sessions, public.t08_private_items to service_role;

create function public.t08_finish_login(
 p_challenge_id uuid, p_binding_hash text, p_credential_id text,
 p_expected_counter bigint, p_new_counter bigint,
 p_session_hash text, p_previous_session_hash text
) returns uuid language plpgsql security invoker set search_path = ''
as $fn$
declare
 q public.t08_auth_challenges%rowtype;
 k public.t08_passkeys%rowtype;
begin
 select * into q from public.t08_auth_challenges
  where id=p_challenge_id and binding_hash=p_binding_hash for update;
 if not found or q.used_at is not null or q.expires_at <= clock_timestamp() then
  raise exception 'challenge_unavailable' using errcode='P0001';
 end if;
 select * into k from public.t08_passkeys where credential_id=p_credential_id for update;
 if not found or k.counter <> p_expected_counter then
  raise exception 'credential_changed' using errcode='P0001';
 end if;
 if p_new_counter < 0 or (k.counter > 0 and p_new_counter > 0 and p_new_counter <= k.counter) then
  raise exception 'counter_invalid' using errcode='P0001';
 end if;
 update public.t08_auth_challenges set used_at=clock_timestamp() where id=q.id;
 update public.t08_passkeys set counter=p_new_counter where credential_id=k.credential_id;
 if p_previous_session_hash is not null then
  update public.t08_sessions set revoked_at=clock_timestamp()
   where token_hash=p_previous_session_hash and revoked_at is null;
 end if;
 insert into public.t08_sessions(token_hash,user_id,expires_at)
  values(p_session_hash,k.user_id,clock_timestamp()+interval '1 hour');
 insert into public.t08_private_items(user_id,kind,title)
  values(k.user_id,'project-note','준비 중인 프로젝트 메모'),
        (k.user_id,'personal-goal','개인 목표와 진행 상황'),
        (k.user_id,'reflection','스스로 쓰는 회고')
  on conflict(user_id,kind) do nothing;
 return k.user_id;
end;
$fn$;
revoke all on function public.t08_finish_login(uuid,text,text,bigint,bigint,text,text) from public,anon,authenticated;
grant execute on function public.t08_finish_login(uuid,text,text,bigint,bigint,text,text) to service_role;
comment on table public.t08_sessions is 'T08 opaque session hashes only; raw cookie tokens are never stored.';
insert into public.t08_private_items(user_id,kind,title)
 select u.id,v.kind,v.title from public.t08_users u
 cross join (values ('project-note','준비 중인 프로젝트 메모'),('personal-goal','개인 목표와 진행 상황'),('reflection','스스로 쓰는 회고')) v(kind,title)
 on conflict(user_id,kind) do nothing;
commit;
