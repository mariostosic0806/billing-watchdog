#!/usr/bin/env bash
# ==============================================================================
# Autonomous MacBook (macOS Apple Silicon) Setup & Verification
# Project: billing-watchdog (Stripe <-> Postgres/Supabase Billing Watchdog)
#
# Runs standalone or from ../macbook_master_auto_setup.sh. Works with the macOS
# /bin/bash 3.2 and is idempotent (dependencies are reinstalled only when
# package.json / package-lock.json / the Node version change).
#
# billing-watchdog is a CLI + GitHub Action: it has no local server and never
# opens Chrome, so MACBOOK_SETUP_NO_SERVERS, MACBOOK_SETUP_NO_CHROME,
# MACBOOK_SETUP_RESTART_SERVERS and MACBOOK_SETUP_LOG_DIR have nothing to do here.
# Nothing in this script talks to a real database, Stripe, Slack or Discord.
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

node_ok() {
  # Node >= 22.18 runs .ts files directly (type stripping on by default).
  command -v node >/dev/null 2>&1 &&
    node -e 'process.exit(process.features.typescript ? 0 : 1)' >/dev/null 2>&1
}

echo "=== [1/5] Node.js (>= 22.18 with native TypeScript type stripping) ==="
if ! command -v node >/dev/null 2>&1 && [ -x /opt/homebrew/bin/brew ]; then
  eval "$(/opt/homebrew/bin/brew shellenv)"
fi
if ! node_ok; then
  if command -v brew >/dev/null 2>&1; then
    echo "Node.js is missing or too old ($(node -v 2>/dev/null || echo none)); installing node@24 with Homebrew ..."
    brew install node@24
    # node@24 is keg-only: use it for this run instead of relying on `brew link`.
    PATH="$(brew --prefix node@24)/bin:$PATH"
    export PATH
  fi
fi
if ! node_ok; then
  echo "ERROR: Node.js >= 22.18 is required (found: $(node -v 2>/dev/null || echo none))." >&2
  echo "       Install it with: brew install node@24" >&2
  exit 1
fi
echo "Node version: $(node -v)"
echo "NPM version:  $(npm -v)"

echo "=== [2/5] Dependencies (npm ci from package-lock.json) ==="
stamp="node_modules/.billing-watchdog-setup-stamp"
want="$(cat package.json package-lock.json | shasum | cut -c1-16) node-$(node -v)"
have="$(cat "$stamp" 2>/dev/null || true)"
if [ "$want" != "$have" ] || [ ! -x node_modules/.bin/tsc ] || [ ! -d node_modules/pg ]; then
  npm ci --no-fund --no-audit
  printf '%s\n' "$want" > "$stamp"
else
  echo "node_modules already matches package-lock.json (npm ci skipped)."
fi

echo "=== [3/5] Strict TypeScript check + automated tests ==="
npm run typecheck
test_log="$(mktemp -t billing-watchdog-tests)"
trap 'rm -f "$test_log"' EXIT
npm test 2>&1 | tee "$test_log"
# Summary lines of node:test: "ℹ pass 64" (spec reporter) or "# pass 64" (TAP).
tests_total="$(grep -E '^(ℹ|#) tests [0-9]+' "$test_log" | tail -1 | awk '{print $3}' || true)"
tests_pass="$(grep -E '^(ℹ|#) pass [0-9]+' "$test_log" | tail -1 | awk '{print $3}' || true)"
tests_fail="$(grep -E '^(ℹ|#) fail [0-9]+' "$test_log" | tail -1 | awk '{print $3}' || true)"
if [ -z "$tests_total" ] || [ -z "$tests_pass" ] || [ "${tests_fail:-1}" != "0" ]; then
  echo "ERROR: could not confirm a green test run (tests=${tests_total:-?} pass=${tests_pass:-?} fail=${tests_fail:-?})." >&2
  exit 1
fi
echo "Test result: ${tests_pass}/${tests_total} passed, ${tests_fail} failed (node:test)"

echo "=== [4/5] Offline SQL linter smoke test (examples/bad-migration.sql) ==="
# --no-fail-on-critical: the example is intentionally bad, so CRITICAL findings are expected.
lint_out="$(node src/cli.ts lint-sql examples/bad-migration.sql --no-fail-on-critical)"
for code in MISSING_NON_NEGATIVE_CHECK MISSING_WEBHOOK_UNIQUE_CONSTRAINT MISSING_RLS_OR_POLICY; do
  case "$lint_out" in
    *"$code"*) ;;
    *)
      echo "ERROR: lint-sql did not report $code for examples/bad-migration.sql." >&2
      exit 1
      ;;
  esac
done
lint_findings="$(printf '%s\n' "$lint_out" | grep -c '^### \[Check #' || true)"
echo "SQL linter OK: ${lint_findings} expected findings in examples/bad-migration.sql"

echo "=== [5/5] Chaos Webhook Simulator & Active Circuit-Breaker Dry-Run smoke test ==="
chaos_out="$(node src/cli.ts chaos)"
case "$chaos_out" in
  *"SCENARIO_A_PARALLEL_BURST_20"* ) ;;
  *)
    echo "ERROR: chaos command did not output SCENARIO_A_PARALLEL_BURST_20." >&2
    exit 1
    ;;
esac
quarantine_out="$(node src/cli.ts quarantine --demo --dry-run --threshold-cents 2500 --no-fail-on-critical)"
case "$quarantine_out" in
  *"is_billing_quarantined"* ) ;;
  *)
    echo "ERROR: quarantine dry-run did not output is_billing_quarantined." >&2
    exit 1
    ;;
esac
echo "Chaos Simulator & Circuit-Breaker Dry-Run OK."

echo "=== SUCCESS: billing-watchdog v2 (${tests_pass}/${tests_total} tests green, typecheck OK, SQL linter OK, Chaos & Circuit-Breaker OK) ==="
