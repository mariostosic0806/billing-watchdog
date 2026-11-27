# Billing Watchdog v2.4 & ProofTwin CI Gate (`Stripe ↔ Postgres/Supabase`)

[![CI](https://github.com/mariostosic0806/billing-watchdog/actions/workflows/ci.yml/badge.svg)](https://github.com/mariostosic0806/billing-watchdog/actions/workflows/ci.yml)
[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-v2.4.2-1F7A4D?logo=githubactions&logoColor=white)](https://github.com/marketplace/actions/stripe-supabase-billing-integrity-watchdog)

Deterministic Stripe ↔ PostgreSQL/Supabase billing integrity reconciler, zero-credential `ProofTwin` pull-request security gate (SQL, Drizzle ORM, Prisma, Next.js, Python FastAPI, Autumn, Stripe Billing Meters, and `.mcp.json` lockfiles), and self-hosted AI credit circuit-breaker.

- **GitHub Marketplace Action (`v2.4.2`, MIT):** [github.com/marketplace/actions/stripe-supabase-billing-integrity-watchdog](https://github.com/marketplace/actions/stripe-supabase-billing-integrity-watchdog)
- **Interactive Browser Simulator & Offline `.sql` / ORM / RLS Linter:** [https://mariostosic0806.github.io/billing-watchdog/](https://mariostosic0806.github.io/billing-watchdog/)
- **1-Page Technical & Agency Brief (PDF):** [billing-watchdog-cto-brief.pdf](https://mariostosic0806.github.io/billing-watchdog/billing-watchdog-cto-brief.pdf)
- **Claude Code Plugin (`/billing-watchdog:audit`, MIT):** [`plugins/billing-watchdog/`](plugins/billing-watchdog/) — install via `/plugin marketplace add mariostosic0806/billing-watchdog` then `/plugin install billing-watchdog@billing-watchdog`
- **Standalone MIT Agent Skill (`Claude Code`, `ECC`, `Cursor`, `Codex`, `Antigravity`):** [`skills/stripe-supabase-billing-guard/SKILL.md`](skills/stripe-supabase-billing-guard/SKILL.md) — install via `npx skills add mariostosic0806/billing-watchdog`

[![Billing Watchdog v2.4.2 Live Demo — 50-Event Storm, SQL/RLS Auditor & Drift Reconciler](docs/demo-watchdog.gif)](https://mariostosic0806.github.io/billing-watchdog/)

---

## 10-Second GitHub Action Quickstart (Zero Credentials Required)

Add `ProofTwin` (`command: verify-ci`) to `.github/workflows/billing-watchdog.yml` (see full template in `examples/billing-watchdog.yml`) to block vulnerable SQL migrations, Drizzle `pgTable` / Prisma `schema.prisma` constraint omissions, broken multi-tenant `org_id` Supabase RLS (`USING (true)` / uncorrelated `org_members`), unverified Stripe webhook `req.json()` / `request.json()` routes, unreserved streaming LLM credit deductions (`onFinish` race conditions), unidempotent `meterEvents.create` calls, and unpinned `.mcp.json` tool rug-pulls on every Pull Request:

```yaml
name: ProofTwin Billing & RLS PR Gate
on: [pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: mariostosic0806/billing-watchdog@v2.4.2
        # Optional SecOps immutable SHA pin for v2.4.2:
        # uses: mariostosic0806/billing-watchdog@278b57821d815db29062112fbadf5c7cb688a2e1
        with:
          command: verify-ci
          sql-path: supabase/migrations
          code-dir: app
          sarif-file: prooftwin.sarif
          agent-fix-file: prooftwin-agent-fix.md
      - if: always() && hashFiles('prooftwin.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: prooftwin.sarif
```

---

## What It Catches

| Check / Guard | Free Diagnostic Action (`@v2.4.2`) | Self-Hosted Pro v2 (`$149` Lifetime or `$299` Agency) |
| :--- | :---: | :---: |
| Missing `CHECK (credits_balance >= 0)` & `UNIQUE (stripe_event_id)` across SQL, Drizzle `pgTable`, & Prisma (`examples/bad-migration.sql`) | ✅ Detects & blocks PR | ✅ Generates non-blocking `NOT VALID` + `VALIDATE CONSTRAINT` & `CONCURRENTLY` SQL patches |
| Multi-Tenant `org_id` / `user_id` RLS & `SECURITY DEFINER` RPC escalation (`target_org_id`, uncorrelated `org_members`) | ✅ Detects & blocks PR | ✅ Live `READ ONLY` Cross-JWT Shadow DB RLS Isolation Prober (`--probe-rls-url` in `src/prooftwin-ci-gate.ts`) |
| Unverified Stripe Webhooks, Python FastAPI `.py`, Autumn, Stripe Meters & Streaming LLM Routes (`onFinish` race) | ✅ Detects & blocks PR | ✅ Serverless Postgres PL/pgSQL Two-Phase Hold (`src/webhook-firewall.ts`, `src/state-machine.ts`) & `examples/nextjs-stripe-webhook-route.ts` |
| Fail-Closed `.mcp.json` (`mcpServers`), Unpinned `ADDED` Tools, `SCHEMA_MUTATION` & `mcp-pin` CLI (`--mcp-manifest` / `--mcp-lock`) | ✅ Detects & pins SHA-256 lockfiles | ✅ Full canonical SHA-256 lockfile diffing & Lethal Trifecta risk scorer (`src/prooftwin-ci-gate.ts`) |
| OASIS SARIF 2.1.0 GitHub Code Scanning & PR Annotations (`sarif-file` / `--sarif-out`) | ✅ Exact file + 1-based line annotations | ✅ Full rule remediation metadata across `lint-sql`, `lint-code`, `verify-ci` & `scan` (`src/sarif.ts`) |
| Fact-Forcing Agent Remediation Packet (`agent-fix-file` / `--agent-fix-out`) + MIT Agent Skill | ✅ Prompt-injection-safe diagnostic checklist (`skills/stripe-supabase-billing-guard/SKILL.md`) | ✅ Schema/table-interpolated remediation contracts + runnable re-verify commands (`src/agent-fix.ts`) |
| Bi-Directional Stripe ↔ Postgres Drift (`ZOMBIE_SUBSCRIPTION`, `DROPPED_WEBHOOK_MISSING_CREDIT_GRANT`, `CREDIT_CONSERVATION_VIOLATION`) | — | ✅ Single `BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY` snapshot + `--redact-entities` `SLACK_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` alerts |
| Active Runaway Credit Circuit-Breaker (`is_billing_quarantined = true`) & Asymmetric `Ed25519` Offline Key (`BWV2E-...`) | — | ✅ Deterministic Dry-Run Preview + Auto-Quarantine (`src/cli.ts`, `src/license.ts`) |

---

## Self-Hosted Live Reconciliation Role (`BYPASSRLS` + Strict `READ ONLY`)

For live `scan` and `alert` runs in Self-Hosted Pro v2, your `DATABASE_URL` and `STRIPE_RESTRICTED_KEY` (`rk_live_...` / `rk_test_...`) never leave your own GitHub Actions runner or cluster. Create a dedicated read-only PostgreSQL role with `BYPASSRLS` so RLS policies cannot silently hide rows during ledger reconciliation:

```sql
CREATE ROLE billing_watchdog_ro WITH LOGIN PASSWORD 'replace-with-strong-secret' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
GRANT CONNECT ON DATABASE postgres TO billing_watchdog_ro;
GRANT USAGE ON SCHEMA public TO billing_watchdog_ro;
GRANT SELECT ON public.users, public.subscriptions, public.wallets, public.credit_transactions TO billing_watchdog_ro;
```

Every live Pro run opens a single `BEGIN ISOLATION LEVEL REPEATABLE READ, READ ONLY;` transaction, verifies `SHOW transaction_read_only;` equals `on`, sets `SET LOCAL row_security = off;`, snapshots mapped columns before querying Stripe, and dispatches alerts only to your configured `SLACK_WEBHOOK_URL` or `DISCORD_WEBHOOK_URL` (the full PL/pgSQL webhook & stream-hold RPC migration `examples/watchdog_atomic_webhook.sql` ships in Self-Hosted Pro v2).

---

## Contact & Licensing

Unlock executable SQL remediation patches, Agency Client-Handover rights (`BWV2E-AGENCY_TEAM`), and the complete Self-Hosted Pro v2.4.2 TypeScript engine at [mariostosic0806.github.io/billing-watchdog](https://mariostosic0806.github.io/billing-watchdog/) or contact [mariostosic@prime-tech.rs](mailto:mariostosic@prime-tech.rs).
