create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id),
  title text not null,
  done boolean not null default false
);

create table public.profiles (
  id uuid primary key references auth.users (id),
  display_name text,
  email text
);

alter table public.profiles enable row level security;

create policy "Profiles are public" on public.profiles
  for select to anon, authenticated
  using (true);

create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id),
  body text
);

alter table public.notes enable row level security;

create policy "Users manage their own notes" on public.notes
  for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
