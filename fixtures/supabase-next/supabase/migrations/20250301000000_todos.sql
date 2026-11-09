create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id),
  title text not null
);

alter table public.todos enable row level security;

create policy "Owners read their todos" on public.todos
  for select to authenticated using ((select auth.uid()) = user_id);

create policy "Owners add their todos" on public.todos
  for insert to authenticated with check ((select auth.uid()) = user_id);
