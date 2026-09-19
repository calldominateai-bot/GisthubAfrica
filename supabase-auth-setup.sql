-- GistHubAfrica authentication and profile repair.
-- This matches the migration applied to the production Supabase project.

begin;

create unique index if not exists profiles_username_lower_unique
  on public.profiles (lower(username));

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  admin_flag boolean := false;
  clean_username text;
begin
  clean_username := left(
    lower(regexp_replace(
      coalesce(
        nullif(new.raw_user_meta_data->>'username',''),
        split_part(new.email,'@',1)
      ),
      '[^a-z0-9_]', '', 'g'
    )),
    20
  );

  if length(clean_username) < 3 then
    clean_username := 'user_' || substr(replace(new.id::text,'-',''),1,10);
  end if;

  if tg_op = 'INSERT'
     and not exists(select 1 from public.profiles where demo = false) then
    admin_flag := true;
  end if;

  insert into public.profiles (
    id, username, display_name, bio, country, city, gender, birthday,
    verified, is_admin
  )
  values (
    new.id,
    clean_username,
    coalesce(
      nullif(new.raw_user_meta_data->>'display_name',''),
      clean_username
    ),
    coalesce(new.raw_user_meta_data->>'bio',''),
    coalesce(new.raw_user_meta_data->>'country',''),
    coalesce(new.raw_user_meta_data->>'city',''),
    coalesce(new.raw_user_meta_data->>'gender',''),
    coalesce(new.raw_user_meta_data->>'birthday',''),
    new.email_confirmed_at is not null,
    admin_flag
  )
  on conflict (id) do update
    set verified = excluded.verified;

  return new;
end
$$;

drop trigger if exists on_auth_user_created on auth.users;

create trigger on_auth_user_created
after insert or update of email_confirmed_at on auth.users
for each row execute function public.handle_new_user();

update public.profiles p
set verified = true
from auth.users u
where u.id = p.id
  and u.email_confirmed_at is not null
  and coalesce(p.verified,false) = false;

drop policy if exists gm_read on public.group_members;

create policy gm_read
on public.group_members
for select
using (
  user_id = auth.uid()
  or exists (
    select 1
    from public.groups g
    where g.id = group_members.group_id
      and (g.privacy = 'pub' or g.owner = auth.uid())
  )
);

commit;
