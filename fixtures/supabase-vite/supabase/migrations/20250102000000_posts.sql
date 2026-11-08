create table public.posts (
  id bigint generated always as identity primary key,
  author_id uuid not null references auth.users (id),
  body text not null
);

alter table public.posts enable row level security;

create policy "Anyone can read posts" on public.posts
  for select using (true);

create policy "Signed in users can edit posts" on public.posts
  for update to authenticated
  using (true);

create or replace function public.touch_post() returns trigger
language plpgsql as $$
begin
  new.body := trim(new.body);
  return new;
end;
$$;
