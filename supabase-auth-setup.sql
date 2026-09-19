-- Run this once in Supabase SQL Editor.
-- It makes every Auth account receive a durable public profile.

create unique index if not exists profiles_username_lower_unique
  on public.profiles (lower(username));

alter table public.profiles enable row level security;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'profiles'
      and policyname = 'Profiles are publicly readable'
  ) then
    create policy "Profiles are publicly readable"
      on public.profiles for select
      using (true);
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'profiles'
      and policyname = 'Users can insert their own profile'
  ) then
    create policy "Users can insert their own profile"
      on public.profiles for insert
      with check (auth.uid() = id);
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'profiles'
      and policyname = 'Users can update their own profile'
  ) then
    create policy "Users can update their own profile"
      on public.profiles for update
      using (auth.uid() = id)
      with check (auth.uid() = id);
  end if;
end
$$;

create or replace function public.create_gisthub_profile()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  requested_username text;
begin
  requested_username := lower(regexp_replace(
    coalesce(nullif(new.raw_user_meta_data ->> 'username', ''), split_part(new.email, '@', 1)),
    '[^a-z0-9_]', '', 'g'
  ));

  if length(requested_username) < 3 then
    requested_username := 'user_' || left(replace(new.id::text, '-', ''), 8);
  end if;

  insert into public.profiles (
    id, username, display_name, bio, country, city, gender, birthday,
    verified, suspended, is_admin, demo, created_at, last_seen
  )
  values (
    new.id,
    left(requested_username, 20),
    coalesce(nullif(new.raw_user_meta_data ->> 'display_name', ''), left(requested_username, 20)),
    coalesce(new.raw_user_meta_data ->> 'bio', ''),
    coalesce(new.raw_user_meta_data ->> 'country', ''),
    coalesce(new.raw_user_meta_data ->> 'city', ''),
    coalesce(new.raw_user_meta_data ->> 'gender', ''),
    nullif(new.raw_user_meta_data ->> 'birthday', '')::date,
    new.email_confirmed_at is not null,
    false,
    false,
    false,
    now(),
    now()
  )
  on conflict (id) do update set
    username = excluded.username,
    display_name = excluded.display_name,
    bio = excluded.bio,
    country = excluded.country,
    city = excluded.city,
    gender = excluded.gender,
    birthday = excluded.birthday,
    verified = excluded.verified,
    last_seen = excluded.last_seen;

  return new;
end;
$$;

drop trigger if exists create_gisthub_profile_after_signup on auth.users;

create trigger create_gisthub_profile_after_signup
after insert or update of email_confirmed_at on auth.users
for each row execute function public.create_gisthub_profile();

-- Repair profiles for Auth users who signed up before this trigger existed.
insert into public.profiles (
  id, username, display_name, bio, country, city, gender, birthday,
  verified, suspended, is_admin, demo, created_at, last_seen
)
select
  u.id,
  left(lower(regexp_replace(
    coalesce(nullif(u.raw_user_meta_data ->> 'username', ''), split_part(u.email, '@', 1)),
    '[^a-z0-9_]', '', 'g'
  )), 20),
  coalesce(nullif(u.raw_user_meta_data ->> 'display_name', ''), split_part(u.email, '@', 1)),
  coalesce(u.raw_user_meta_data ->> 'bio', ''),
  coalesce(u.raw_user_meta_data ->> 'country', ''),
  coalesce(u.raw_user_meta_data ->> 'city', ''),
  coalesce(u.raw_user_meta_data ->> 'gender', ''),
  nullif(u.raw_user_meta_data ->> 'birthday', '')::date,
  u.email_confirmed_at is not null,
  false,
  false,
  false,
  u.created_at,
  now()
from auth.users u
where not exists (select 1 from public.profiles p where p.id = u.id);
