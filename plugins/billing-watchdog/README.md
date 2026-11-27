# Billing Watchdog for Claude Code

Billing Watchdog is an MIT-licensed static billing, Row-Level Security, and MCP integrity plugin for teams building Stripe, PostgreSQL, Supabase, Next.js, Drizzle, Prisma, and FastAPI applications. It catches silent credit leaks, webhook double-grants, permissive tenant read policies, and unpinned MCP tool definitions before code reaches production.

## Local Execution and Privacy Disclosure

Running `/billing-watchdog:audit` executes the bundled, zero-dependency local Node.js script `scripts/public-ci-gate.mjs` using your local `node` runtime (Node.js 22 or newer). All inspection runs strictly offline against files in your repository with zero database credentials, zero Stripe keys, and zero outbound network calls. The command performs read-only analysis and never modifies repository files or executes database migrations without explicit user confirmation.

## What Is Included

1. **`/billing-watchdog:audit` command (`commands/audit.md`):** Auto-detects SQL migrations, Drizzle or Prisma schemas, backend webhook/AI routes, and optional `.mcp.json` manifests, then runs 20 deterministic static checks across five categories:
   - Integer money columns, non-negative `CHECK (credits_balance >= 0)` guards, and unconditional `UNIQUE (stripe_event_id)` constraints (catching partial `WHERE` indexes that break `ON CONFLICT`).
   - Multi-tenant Supabase RLS (`FOR SELECT USING (true)` on billing tables skipped by Splinter rule `0024`, permissive OR-stacking) and `SECURITY DEFINER` RPCs missing `SET search_path` or `REVOKE EXECUTE ... FROM PUBLIC`.
   - Raw-body Stripe webhook signature verification, canonical invoice deduplication, and atomic SQL credit updates.
   - Streaming LLM credit reservation checks (`streamText` deducting inside `onFinish` without a two-phase hold) and idempotent Stripe Billing Meter events.
   - Static `.mcp.json` prompt-injection, unpinned launcher, and schema-drift checks.
2. **`stripe-supabase-billing-guard` skill (`skills/stripe-supabase-billing-guard/SKILL.md`):** Static production invariants for migrations, RLS, webhook handlers, and two-phase streaming credit holds.

## Usage

Install from the self-hosted marketplace inside Claude Code:

```text
/plugin marketplace add mariostosic0806/billing-watchdog
/plugin install billing-watchdog@billing-watchdog
```

Then audit the current project (or pass explicit paths):

```text
/billing-watchdog:audit
/billing-watchdog:audit supabase/migrations app
```

## License and Optional Pro Package

This plugin, static CLI (`scripts/public-ci-gate.mjs`), MIT GitHub Action, and offline browser simulator at https://mariostosic0806.github.io/billing-watchdog/ are free under the MIT License. An optional self-hosted Pro source package adds live read-only `REPEATABLE READ` Stripe-to-Postgres drift reconciliation, executable `NOT VALID` and `CONCURRENTLY` SQL patch generators, PL/pgSQL two-phase hold RPCs, and Cross-JWT shadow database RLS probing.
