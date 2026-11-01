-- =============================================================================
-- examples/bad-migration.sql
-- An intentionally BAD Supabase/Postgres billing migration. It is the smoke test
-- for the offline linter (no database, no Stripe key needed):
--
--   node src/cli.ts lint-sql examples/bad-migration.sql --no-fail-on-critical
--
-- Expected: 2 CRITICAL + 3 HIGH findings (each defect is marked below).
-- Table names match reconcile.config.json in this repository.
-- =============================================================================

create table public.users (
  id uuid primary key,
  email text not null,
  stripe_customer_id text unique
);
alter table public.users enable row level security;
create policy "Users can read their own row" on public.users
  for select to authenticated using (id = auth.uid());

create table public.subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users (id),
  stripe_subscription_id text unique,
  status text not null,
  updated_at timestamptz not null default now()
);
-- DEFECT (Check 3, HIGH): RLS is on but there is no policy at all.
alter table public.subscriptions enable row level security;

create table public.wallets (
  user_id uuid primary key references public.users (id),
  -- DEFECT (Check 1, CRITICAL): no CHECK (credits_balance >= 0), so two
  -- concurrent spends can drive the balance negative.
  credits_balance integer not null default 0
);
-- DEFECT (Check 3, HIGH): RLS is switched on and later off again.
alter table public.wallets enable row level security;
alter table public.wallets disable row level security;

create table public.credit_transactions (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.users (id),
  stripe_event_id text,
  stripe_invoice_id text,
  credits_delta integer not null,
  created_at timestamptz not null default now()
);
-- DEFECT (Check 2, CRITICAL): a plain (non-unique) index does not stop a
-- retried Stripe webhook from granting the same credits twice.
create index credit_transactions_stripe_event_id_idx
  on public.credit_transactions (stripe_event_id);
-- DEFECT (Check 3, HIGH): RLS is only "enabled" inside this comment:
-- alter table public.credit_transactions enable row level security;
