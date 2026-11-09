insert into storage.buckets (id, name, public)
values
  ('avatars', 'avatars', true),
  ('invoices', 'invoices', false);

create policy "Avatar images are public" on storage.objects
  for select using (bucket_id = 'avatars');

create policy "Anyone can upload invoices" on storage.objects
  for insert with check (bucket_id = 'invoices');

create policy "Users manage their own invoices" on storage.objects
  for all to authenticated
  using (bucket_id = 'invoices' and (storage.foldername(name))[1] = (select auth.uid())::text);

create view public.post_feed as
  select p.id, p.body, pr.display_name
  from public.posts p
  join public.profiles pr on pr.id = p.author_id;

create view public.my_notes with (security_invoker = true) as
  select id, body from public.notes;

create function public.delete_any_post(post_id bigint) returns void
language sql security definer as $$
  delete from public.posts where id = post_id;
$$;

create function public.is_note_owner(note_id bigint) returns boolean
language sql security definer set search_path = '' as $$
  select exists (
    select 1 from public.notes where id = note_id and user_id = (select auth.uid())
  );
$$;

create function public.list_profiles() returns setof public.profiles
language sql security definer as $$
  select * from public.profiles;
$$;

revoke execute on function public.list_profiles from public, anon, authenticated;
