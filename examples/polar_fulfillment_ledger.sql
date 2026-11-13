-- ============================================================================
-- Billing Watchdog v2 — Persistent Polar.sh MoR Webhook & Ed25519 License Ledger
-- Safe for Vercel Serverless / Railway / Supabase Supavisor Transaction Pooler
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS public.polar_processed_webhooks (
  webhook_id text PRIMARY KEY,
  processed_at_utc timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.polar_entitlements (
  entitlement_key text PRIMARY KEY,
  customer_email text NOT NULL,
  customer_hash12 text NOT NULL,
  tier text NOT NULL CHECK (tier IN ('PRO_MONTHLY', 'LIFETIME_TEAM')),
  product_scope text NOT NULL CHECK (product_scope IN ('WATCHDOG_V2', 'BUNDLE_ALL')),
  status text NOT NULL CHECK (status IN ('NONE', 'ACTIVE', 'CANCELED_GRACE', 'REVOKED')),
  amount_minor_units integer NOT NULL CHECK (amount_minor_units >= 0),
  currency text NOT NULL,
  expires_at_utc timestamptz NOT NULL,
  last_event_created_unix bigint NOT NULL CHECK (last_event_created_unix >= 0),
  last_reverted_at_unix bigint CHECK (last_reverted_at_unix IS NULL OR last_reverted_at_unix >= 0),
  manual_override_locked boolean NOT NULL DEFAULT false,
  latest_license_key text,
  updated_at_utc timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_polar_entitlements_customer_email
  ON public.polar_entitlements (customer_email);

-- Row-Level Security (RLS) Lockdown:
-- Backend webhook workers connect via a dedicated server role; authenticated
-- end-users can only read their own verified email entitlement row.
ALTER TABLE public.polar_processed_webhooks ENABLE ROW LEVEL SECURITY;
CREATE POLICY polar_webhooks_admin_only
  ON public.polar_processed_webhooks
  FOR SELECT
  USING ((SELECT auth.uid()) IS NOT NULL AND (SELECT auth.jwt() ->> 'app_role') = 'billing_admin');

ALTER TABLE public.polar_entitlements ENABLE ROW LEVEL SECURITY;
CREATE POLICY polar_entitlements_owner_select
  ON public.polar_entitlements
  FOR SELECT
  USING (
    (SELECT auth.uid()) IS NOT NULL
    AND lower(customer_email) = lower(COALESCE((SELECT auth.jwt() ->> 'email'), ''))
  );

COMMIT;
