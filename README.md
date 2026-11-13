# Billing Watchdog v2 & ProofTwin CI Gate (`Stripe ↔ Postgres/Supabase`)

[![CI](https://github.com/mariostosic0806/billing-watchdog/actions/workflows/ci.yml/badge.svg)](https://github.com/mariostosic0806/billing-watchdog/actions/workflows/ci.yml)

Deterministic Stripe ↔ PostgreSQL/Supabase billing integrity reconciler, zero-credential `ProofTwin` pull-request security gate, and self-hosted AI credit circuit-breaker.

- **Interactive Browser Simulator & Offline `.sql` / RLS Linter:** [https://mariostosic0806.github.io/billing-watchdog/](https://mariostosic0806.github.io/billing-watchdog/)
- **SafeRevert (Shopify Bulk Price & COGS Margin Calculator):** [https://mariostosic0806.github.io/billing-watchdog/calculator/](https://mariostosic0806.github.io/billing-watchdog/calculator/)

---

## 10-Second GitHub Action Quickstart (Zero Credentials Required)

Add `ProofTwin` (`command: verify-ci`) to `.github/workflows/billing-watchdog.yml` (see full template in `examples/billing-watchdog.yml`) to block vulnerable SQL migrations, broken multi-tenant Supabase RLS (`USING (true)`), unverified Stripe webhook `req.json()` routes, unreserved streaming LLM credit deductions (`onFinish` race conditions), and silent MCP tool description rug-pulls on every Pull Request:

```yaml
name: ProofTwin Billing & RLS PR Gate
on: [pull_request]

permissions:
  contents: read

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: mariostosic0806/billing-watchdog@v2.1.0
        with:
          command: verify-ci
          sql-path: supabase/migrations
          code-dir: app
```

---

## What It Catches

| Check / Guard | Free Diagnostic Action (`@v2.1.0`) | Self-Hosted Pro v2 (`$49/mo` or `$149` Lifetime) |
| :--- | :---: | :---: |
| Missing `CHECK (credits_balance >= 0)` & `UNIQUE (stripe_event_id)` (`examples/bad-migration.sql`) | ✅ Detects & blocks PR | ✅ Generates non-blocking `NOT VALID` + `VALIDATE CONSTRAINT` SQL patch |
| Permissive Multi-Tenant RLS (`USING (true)`) & `SECURITY DEFINER` RPC escalation | ✅ Detects & blocks PR | ✅ Live `READ ONLY` Cross-JWT RLS Isolation Prober (`src/prooftwin-ci-gate.ts`) |
| Unverified Stripe Webhooks & Denial-of-Wallet LLM Streaming Routes (`onFinish` race) | ✅ Detects & blocks PR | ✅ Drop-in `executeGuardedAiStream` Two-Phase Hold (`src/state-machine.ts`) & `examples/nextjs-stripe-webhook-route.ts` |
| MCP Tool Poisoning & Silent Description Rug-Pulls (`--mcp-manifest` / `--mcp-lock`) | ✅ Detects & blocks PR | ✅ Full canonical SHA-256 lockfile generator & Lethal Trifecta risk scorer |
| Live Nightly Stripe ↔ Postgres Drift (`ZOMBIE_SUBSCRIPTION`, `DUPLICATE_WEBHOOK_CREDIT_GRANT`, `CREDIT_CONSERVATION_VIOLATION`) | — | ✅ Single `BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY` snapshot + `SLACK_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` alerts |
| Active Runaway Credit Circuit-Breaker (`is_billing_quarantined = true`) & Asymmetric `Ed25519` Offline Key (`BWV2E-...`) | — | ✅ Deterministic Dry-Run Preview + Auto-Quarantine (`src/cli.ts`, `src/license.ts`, `src/polar-fulfillment.ts`) |

---

## Self-Hosted Live Reconciliation Role (`BYPASSRLS` + Strict `READ ONLY`)

For live `scan` and `alert` runs in Self-Hosted Pro v2, your `DATABASE_URL` and `STRIPE_RESTRICTED_KEY` (`rk_live_...` / `rk_test_...`) never leave your own GitHub Actions runner or cluster. Create a dedicated read-only PostgreSQL role with `BYPASSRLS` so RLS policies cannot silently hide rows during ledger reconciliation:

```sql
CREATE ROLE billing_watchdog_ro WITH LOGIN PASSWORD 'replace-with-strong-secret' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
GRANT CONNECT ON DATABASE postgres TO billing_watchdog_ro;
GRANT USAGE ON SCHEMA public TO billing_watchdog_ro;
GRANT SELECT ON public.users, public.subscriptions, public.wallets, public.credit_transactions TO billing_watchdog_ro;
```

Every live Pro run opens a single `BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY;` transaction, verifies `SHOW transaction_read_only;` equals `on`, sets `SET LOCAL row_security = off;`, snapshots mapped columns before querying Stripe, and dispatches alerts only to your configured `SLACK_WEBHOOK_URL` or `DISCORD_WEBHOOK_URL` (see `examples/watchdog_atomic_webhook.sql` and `scripts/macbook_auto_setup.sh`).

---

## Contact & Licensing

Unlock executable SQL remediation patches and the complete Self-Hosted Pro v2 TypeScript engine (`97` automated state-machine, pentest, and chaos tests) at [mariostosic0806.github.io/billing-watchdog](https://mariostosic0806.github.io/billing-watchdog/) or contact [mariostosic@prime-tech.rs](mailto:mariostosic@prime-tech.rs).
