-- =====================================================================
-- Hajeela admin portal · CMS: Photos and Website content
-- Run AFTER 1-setup.sql. Paste into Supabase > SQL Editor > New query > Run.
-- Safe to run again: it skips what already exists.
--
-- Rules it enforces (same as the portal):
--   * Owners and Editors upload photos and edit content. Viewers only look.
--   * Only an Owner approves a photo or publishes content.
--   * A photo can only be approved once it has a caption, a description,
--     an environment, a place, a credit, and permission from anyone in it.
--   * History rows can be added, never changed or deleted.
--   * The public website sees approved photos and published content only.
-- =====================================================================

-- ---------- Photos ---------------------------------------------------

create table if not exists public.media (
  id          uuid primary key default gen_random_uuid(),
  path        text not null unique,             -- file path in the "photos" storage bucket
  title       text not null default '',         -- caption; pages link to it
  alt         text not null default '',         -- description for screen readers
  env         text check (env in ('Sand','Sea','Summit','Snow')),
  place       text,                             -- destination id, e.g. 'white-desert'
  trip_id     text references public.trips(id) on delete set null,
  credit      text not null default '',
  taken       date,                             -- first day of the month it was taken
  people      text check (people in ('none','agreed','unknown')),
  status      text not null default 'wait' check (status in ('wait','ok','hid')),
  width       int,
  height      int,
  size_kb     int,
  uploaded_by uuid references auth.users(id) default auth.uid(),
  uploaded_at timestamptz not null default now(),
  approved_by uuid references auth.users(id),
  approved_at timestamptz
);

create table if not exists public.media_log (
  id         bigint generated always as identity primary key,
  media_id   uuid not null references public.media(id) on delete cascade,
  text       text not null,
  by_user    uuid references auth.users(id),
  by_name    text,
  created_at timestamptz not null default now()
);

-- Only owners approve, hide or show. Approval needs every detail filled in.
create or replace function public.guard_media() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'UPDATE' and new.status is distinct from old.status then
    if public.my_role() <> 'Owner' then
      raise exception 'Only an owner can approve or hide photos';
    end if;
    if new.status = 'ok' and (
         coalesce(trim(new.title),'') = '' or coalesce(trim(new.alt),'') = ''
      or new.env is null or new.place is null or coalesce(trim(new.credit),'') = ''
      or new.people is null or new.people = 'unknown') then
      raise exception 'Fill in every detail, and get permission from anyone in the photo, before approving';
    end if;
    if new.status = 'ok' then
      new.approved_by := auth.uid(); new.approved_at := now();
    end if;
  end if;
  if tg_op = 'UPDATE' and new.title is distinct from old.title and old.status = 'ok' then
    raise exception 'The caption is fixed once a photo is approved';
  end if;
  if tg_op = 'INSERT' then
    new.status := 'wait'; new.uploaded_by := auth.uid(); new.uploaded_at := now();
  end if;
  return new;
end $$;
drop trigger if exists trg_guard_media on public.media;
create trigger trg_guard_media before insert or update on public.media
  for each row execute function public.guard_media();

create or replace function public.stamp_media_log() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.by_user := auth.uid();
  new.by_name := (select name from public.team where user_id = auth.uid());
  new.created_at := now();
  return new;
end $$;
drop trigger if exists trg_stamp_media_log on public.media_log;
create trigger trg_stamp_media_log before insert on public.media_log
  for each row execute function public.stamp_media_log();

-- ---------- Website content ------------------------------------------
-- One row per editable thing: a page section, a destination, an
-- experience, a Hajeela fav or a question. Same draft / live / history
-- model as trip pages.

create table if not exists public.content_items (
  id         text primary key,                  -- e.g. 'dests-siwa', 'pages-home'
  collection text not null check (collection in ('pages','dests','exps','favs','faqs')),
  label      text,
  draft      jsonb not null,
  live       jsonb,
  approved   jsonb not null default '{}',       -- fields signed off word for word, e.g. {"h":true}
  sort       int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.content_versions (
  id         bigint generated always as identity primary key,
  item_id    text not null references public.content_items(id) on delete cascade,
  n          int not null,
  kind       text not null,
  note       text not null default '',
  changes    jsonb not null default '[]',
  snap       jsonb not null,
  by_user    uuid references auth.users(id),
  by_email   text,
  by_name    text,
  created_at timestamptz not null default now(),
  unique (item_id, n)
);

create or replace function public.guard_content() returns trigger
language plpgsql security definer set search_path = public as $$
declare k text;
begin
  if public.my_role() not in ('Owner','Editor') then
    raise exception 'Your access is view only';
  end if;
  if tg_op = 'UPDATE' then
    if new.live is distinct from old.live and public.my_role() <> 'Owner' then
      raise exception 'Only an owner can publish';
    end if;
    if new.approved is distinct from old.approved and public.my_role() <> 'Owner' then
      raise exception 'Only an owner can change which lines are approved';
    end if;
    -- approved lines: editors cannot change them, even in a draft
    if public.my_role() <> 'Owner' then
      for k in select jsonb_object_keys(old.approved) loop
        if new.draft -> k is distinct from old.draft -> k then
          raise exception 'This line is approved wording. Only an owner can change it';
        end if;
      end loop;
    end if;
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists trg_guard_content on public.content_items;
create trigger trg_guard_content before insert or update on public.content_items
  for each row execute function public.guard_content();

create or replace function public.stamp_content_version() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.by_user    := auth.uid();
  new.by_email   := (select email from public.team where user_id = auth.uid());
  new.by_name    := (select name  from public.team where user_id = auth.uid());
  new.created_at := now();
  new.n := coalesce((select max(n) from public.content_versions where item_id = new.item_id), 0) + 1;
  if new.kind = 'Published' and public.my_role() <> 'Owner' then
    raise exception 'Only an owner can publish';
  end if;
  return new;
end $$;
drop trigger if exists trg_stamp_content_version on public.content_versions;
create trigger trg_stamp_content_version before insert on public.content_versions
  for each row execute function public.stamp_content_version();

-- ---------- Security rules -------------------------------------------

alter table public.media            enable row level security;
alter table public.media_log        enable row level security;
alter table public.content_items    enable row level security;
alter table public.content_versions enable row level security;

drop policy if exists media_read   on public.media;
drop policy if exists media_insert on public.media;
drop policy if exists media_update on public.media;
drop policy if exists media_delete on public.media;
create policy media_read   on public.media for select to authenticated using (public.my_role() is not null);
create policy media_insert on public.media for insert to authenticated with check (public.my_role() in ('Owner','Editor'));
create policy media_update on public.media for update to authenticated using (public.my_role() in ('Owner','Editor'));
create policy media_delete on public.media for delete to authenticated using (public.is_owner());

drop policy if exists media_log_read   on public.media_log;
drop policy if exists media_log_insert on public.media_log;
create policy media_log_read   on public.media_log for select to authenticated using (public.my_role() is not null);
create policy media_log_insert on public.media_log for insert to authenticated with check (public.my_role() in ('Owner','Editor'));

drop policy if exists content_read  on public.content_items;
drop policy if exists content_write on public.content_items;
drop policy if exists content_edit  on public.content_items;
create policy content_read  on public.content_items for select to authenticated using (public.my_role() is not null);
create policy content_write on public.content_items for insert to authenticated with check (public.is_owner());
create policy content_edit  on public.content_items for update to authenticated using (public.my_role() in ('Owner','Editor'));

drop policy if exists cver_read   on public.content_versions;
drop policy if exists cver_insert on public.content_versions;
create policy cver_read   on public.content_versions for select to authenticated using (public.my_role() is not null);
create policy cver_insert on public.content_versions for insert to authenticated with check (public.my_role() in ('Owner','Editor'));
-- No update or delete policies on media_log or content_versions: history is permanent.

-- ---------- What the public website can read --------------------------
-- The website uses the public (anon) key. It only ever sees approved
-- photos and the live version of content, never drafts or history.

create or replace view public.website_photos with (security_invoker = false) as
  select id, path, title, alt, env, place, trip_id, credit, width, height
  from public.media where status = 'ok';

create or replace view public.website_content with (security_invoker = false) as
  select id, collection, sort, live as content
  from public.content_items where live is not null;

grant select on public.website_photos, public.website_content to anon;

-- ---------- Photo storage --------------------------------------------
-- A private bucket. The team uploads into it. The public can download a
-- file only once its photo is approved.

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('photos', 'photos', false, 5242880, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;

drop policy if exists photos_team_read   on storage.objects;
drop policy if exists photos_team_upload on storage.objects;
drop policy if exists photos_owner_del   on storage.objects;
drop policy if exists photos_public_read on storage.objects;
create policy photos_team_read on storage.objects for select to authenticated
  using (bucket_id = 'photos' and public.my_role() is not null);
create policy photos_team_upload on storage.objects for insert to authenticated
  with check (bucket_id = 'photos' and public.my_role() in ('Owner','Editor'));
create policy photos_owner_del on storage.objects for delete to authenticated
  using (bucket_id = 'photos' and public.is_owner());
create policy photos_public_read on storage.objects for select to anon
  using (bucket_id = 'photos'
         and exists (select 1 from public.media m where m.path = storage.objects.name and m.status = 'ok'));
