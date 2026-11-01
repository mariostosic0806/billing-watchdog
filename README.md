# Prime Tech Revenue Protection Suite (`Billing Watchdog v2` & `SafeRevert`)

Official 24/7 browser tools, deterministic state-machine simulators, and self-hosted CI/CD licensing portal:

1. **[Billing Watchdog v2 — Deterministic Stripe ↔ Postgres/Supabase State Machine, Chaos Webhook Simulator & Active Credit Circuit-Breaker](https://mariostosic0806.github.io/billing-watchdog/)**
   - **Live Stripe Webhook Chaos Test & Revenue Leak Calculator:** 1-click browser simulation of 50 parallel/out-of-order Stripe webhook storms (`invoice.paid`, `checkout.session.completed`, `customer.subscription.deleted`, `charge.dispute.created`) comparing a standard AI-generated webhook handler against the deterministic `Billing Watchdog v2` state machine.
   - **Zero-Credential Offline `.sql` Schema Linter:** 100% client-side verification of `CHECK (credits_balance >= 0)`, `UNIQUE (stripe_event_id)`, and Supabase Row-Level Security (`RLS`) policies.
   - **Self-Hosted CI/CD & Production Watchdog (`$49/mo` or `$149 Lifetime`):** Runs inside your own GitHub Actions or Kubernetes cronjob using a dedicated read-only PostgreSQL role (`BYPASSRLS`) inside one `BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY` transaction (`DATABASE_URL`, `STRIPE_RESTRICTED_KEY`, `SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL`), plus optional Dry-Run & Active Quarantine Circuit-Breaker (`is_billing_quarantined = true`).
2. **[SafeRevert — Shopify Bulk Price Scheduler & Free Recovery CSV Simulator (`/calculator`)](https://mariostosic0806.github.io/billing-watchdog/calculator/)**
   - Deterministic integer-cent discount preview, Unit-Cost (COGS) negative margin guard, EU Omnibus 30-day lowest price guard, and 1-Click Baseline Recovery CSV generator.

Contact: [mariostosic@prime-tech.rs](mailto:mariostosic@prime-tech.rs)
