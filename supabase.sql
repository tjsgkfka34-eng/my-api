-- Supabase Dashboard > SQL Editor 에서 한 번 실행하세요.
create table if not exists public.messages (
  id bigint generated always as identity primary key,
  content text not null,
  created_at timestamptz not null default now()
);

-- 백엔드는 secret(service_role) key로 접근하므로 RLS를 켜두어도 동작합니다.
-- 브라우저(anon key)에서 직접 접근하는 것을 막기 위해 RLS 활성화.
alter table public.messages enable row level security;
