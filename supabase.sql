-- Supabase Dashboard > SQL Editor 에서 전체를 한 번 실행하세요.
-- 장바구니용 테이블 4개 + 보안 설정 + 샘플 상품

-- (선택) 예전 테스트용 messages 테이블 삭제
drop table if exists public.messages;

-- 1) 상품 (가격의 "진짜 값"은 항상 여기서만 가져옵니다)
create table if not exists public.products (
  id          bigint generated always as identity primary key,
  name        text    not null unique,
  description text    not null default '',
  price       integer not null check (price >= 0),   -- 원(KRW)
  emoji       text    not null default '🛍️',
  active      boolean not null default true,
  created_at  timestamptz not null default now()
);

-- 2) 장바구니. 토큰 원문은 저장하지 않고 sha256 해시만 저장합니다.
create table if not exists public.carts (
  id          uuid primary key default gen_random_uuid(),
  token_hash  text not null unique,
  created_at  timestamptz not null default now()
);

-- 3) 장바구니 담긴 상품
create table if not exists public.cart_items (
  cart_id     uuid   not null references public.carts(id)    on delete cascade,
  product_id  bigint not null references public.products(id) on delete cascade,
  quantity    integer not null check (quantity between 1 and 99),
  updated_at  timestamptz not null default now(),
  primary key (cart_id, product_id)
);

-- ===== 보안 =====
-- RLS를 켜고 정책을 만들지 않으면, 공개(anon) 키로는 어떤 행도 읽고 쓸 수 없습니다.
-- 백엔드는 secret(service_role) 키를 쓰므로 RLS를 우회해서 정상 동작합니다.
alter table public.products   enable row level security;
alter table public.carts      enable row level security;
alter table public.cart_items enable row level security;

-- 공개 역할의 테이블 권한 자체도 제거 (이중 안전장치)
revoke all on public.products   from anon, authenticated;
revoke all on public.carts      from anon, authenticated;
revoke all on public.cart_items from anon, authenticated;

-- ===== 샘플 상품 =====
insert into public.products (name, description, price, emoji) values
  ('한라봉 선물세트',     '새콤달콤 제주 한라봉 3kg',         25000, '🍊'),
  ('감귤 초콜릿',         '제주 감귤 껍질로 만든 수제 초콜릿', 12000, '🍫'),
  ('흑돼지 오겹살',       '쫄깃한 제주 흑돼지 600g',          32000, '🐖'),
  ('제주 은갈치',         '두툼한 은갈치 한 마리',            28000, '🐟'),
  ('오설록 녹차 세트',    '제주 녹차 티백 세트',              18000, '🍵'),
  ('감귤 주스 6병',       '착즙 100% 감귤 주스',              15000, '🧃'),
  ('돌하르방 열쇠고리',   '제주의 수호신 돌하르방',            5000, '🗿'),
  ('우도 땅콩 과자',      '고소한 우도 땅콩 과자',             9000, '🥜')
on conflict (name) do nothing;

-- PostgREST 스키마 캐시 새로고침
notify pgrst, 'reload schema';
