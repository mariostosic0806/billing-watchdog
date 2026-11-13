#!/usr/bin/env node
/**
 * Zero-dependency Public Diagnostic CI Gate (`lint-sql`, `lint-code`, `verify-ci`).
 *
 * Powers `uses: mariostosic0806/billing-watchdog@main` in Free Diagnostic Mode when
 * invoked from the public repository (where `src/cli.ts` Pro execution modules are
 * omitted). Executable PostgreSQL remediation patches and live `BYPASSRLS` + Stripe
 * reconciliation stay exclusive to self-hosted `Billing Watchdog Pro v2`.
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, resolve } from "node:path";

function collectFiles(targetPath, extensions) {
  const abs = resolve(targetPath);
  if (!existsSync(abs)) {
    throw new Error(`Input path does not exist: ${targetPath}`);
  }
  const st = statSync(abs);
  if (st.isFile()) return [abs];
  const out = [];
  const entries = readdirSync(abs, { withFileTypes: true }).sort((a, b) =>
    a.name.localeCompare(b.name)
  );
  for (const ent of entries) {
    if (ent.name === "node_modules" || ent.name === ".git" || ent.name === "dist") continue;
    const child = join(abs, ent.name);
    if (ent.isDirectory()) {
      out.push(...collectFiles(child, extensions));
    } else if (extensions.includes(extname(ent.name).toLowerCase())) {
      out.push(child);
    }
  }
  return out;
}

function stripSqlComments(sql) {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/--[^\r\n]*/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function lintPublicSqlText(rawSql) {
  const norm = stripSqlComments(rawSql);
  const findings = [];

  if (/\bCREATE\s+TABLE\b/i.test(norm)) {
    if (
      /\bwallets\b/i.test(norm) &&
      !/CHECK\s*\(\s*[a-zA-Z0-9_."]*balance[a-zA-Z0-9_."]*\s*>=\s*0\s*\)/i.test(norm)
    ) {
      findings.push({
        severity: "CRITICAL",
        code: "MISSING_NON_NEGATIVE_CHECK",
        target: "public.wallets.credits_balance",
        message: "Wallet balance column lacks CHECK (credits_balance >= 0).",
      });
    }
    if (
      /\bstripe_event_id\b/i.test(norm) &&
      !/stripe_event_id[^,)]*\bUNIQUE\b/i.test(norm) &&
      !/UNIQUE\s*\([^)]*stripe_event_id[^)]*\)/i.test(norm) &&
      !/CREATE\s+UNIQUE\s+INDEX\b(?![^;]*\bWHERE\b)[^;]*\bstripe_event_id\b/i.test(norm)
    ) {
      findings.push({
        severity: "CRITICAL",
        code: "MISSING_WEBHOOK_UNIQUE_CONSTRAINT",
        target: "public.credit_transactions.stripe_event_id",
        message: "Webhook ledger lacks an unconditional UNIQUE constraint on stripe_event_id.",
      });
    }
    for (const tbl of ["users", "subscriptions", "wallets", "credit_transactions"]) {
      const created = new RegExp(`CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?(?:public\\.)?${tbl}\\b`, "i").test(norm);
      if (!created) continue;
      const enabled = new RegExp(`ALTER\\s+TABLE\\s+(?:ONLY\\s+)?(?:public\\.)?${tbl}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`, "i").test(norm);
      const disabled = new RegExp(`ALTER\\s+TABLE\\s+(?:ONLY\\s+)?(?:public\\.)?${tbl}\\s+DISABLE\\s+ROW\\s+LEVEL\\s+SECURITY`, "i").test(norm);
      const hasPolicy = new RegExp(`CREATE\\s+POLICY\\s+[^;]+\\s+ON\\s+(?:public\\.)?${tbl}\\b`, "i").test(norm);
      if (!enabled || disabled || !hasPolicy) {
        findings.push({
          severity: "HIGH",
          code: "MISSING_RLS_OR_POLICY",
          target: `public.${tbl}`,
          message: `Table public.${tbl} lacks active ENABLE ROW LEVEL SECURITY + CREATE POLICY.`,
        });
      }
    }
  }

  const policyRegex =
    /CREATE\s+POLICY\s+([a-zA-Z0-9_"]+)\s+ON\s+([a-zA-Z0-9_."]+)[^;]*?\b(?:USING|WITH\s+CHECK)\s*\(([^;]+)\)/gi;
  let m;
  while ((m = policyRegex.exec(norm)) !== null) {
    const [, policyName, tableName, expr] = m;
    const isPermissiveTrue = /^\s*true\s*$/i.test(expr.trim());
    const isBroadRoleOnly =
      /auth\.role\s*\(\s*\)\s*=\s*'authenticated'/i.test(expr) &&
      !/auth\.(?:uid|jwt)\s*\(/i.test(expr);
    if (isPermissiveTrue || isBroadRoleOnly) {
      findings.push({
        severity: "CRITICAL",
        code: "RLS_PERMISSIVE_NO_TENANT_FILTER",
        target: `${tableName} (${policyName})`,
        message: `Permissive RLS policy ${policyName} on ${tableName} allows cross-tenant access without auth.uid() / auth.jwt().`,
      });
    }
  }

  if (/SECURITY\s+DEFINER/i.test(norm)) {
    if (!/SET\s+search_path\s*=/i.test(norm)) {
      findings.push({
        severity: "HIGH",
        code: "SECURITY_DEFINER_MISSING_SEARCH_PATH",
        target: "SECURITY DEFINER RPC",
        message: "SECURITY DEFINER function omits explicit SET search_path.",
      });
    }
    if (!/auth\.uid\s*\(/i.test(norm)) {
      findings.push({
        severity: "CRITICAL",
        code: "SECURITY_DEFINER_CALLER_ID_WITHOUT_AUTH_UID",
        target: "SECURITY DEFINER RPC",
        message: "SECURITY DEFINER function executes privileged SQL without auth.uid() caller verification.",
      });
    }
  }

  return findings;
}

function lintPublicCodeFiles(filePaths) {
  const findings = [];
  for (const fp of filePaths) {
    const src = readFileSync(fp, "utf8");
    const isWebhook = /stripe|webhook/i.test(fp) || /checkout\.session\.completed|invoice\.paid/.test(src);
    if (
      isWebhook &&
      /\b(?:req|request)\.json\s*\(\s*\)/.test(src) &&
      !/constructEvent|verifyStripeWebhookSignature/.test(src)
    ) {
      findings.push({
        severity: "CRITICAL",
        code: "MISSING_STRIPE_SIGNATURE_VERIFICATION",
        target: fp,
        message: "Webhook handler parses req.json() without raw-body Stripe-Signature HMAC verification.",
      });
    }
    if (
      /\bstreamText\s*\(/.test(src) &&
      /\bonFinish\b/.test(src) &&
      !/reserveCreditsForStream|reserveStreamCredits|executeGuardedAiStream/.test(src)
    ) {
      findings.push({
        severity: "CRITICAL",
        code: "UNRESERVED_STREAMING_LLM_DEDUCTION",
        target: fp,
        message: "Deducts LLM credits inside onFinish without a pre-flight HOLD reservation.",
      });
    }
    const invokesLlm =
      /\b(?:streamText|generateText|generateObject|streamObject)\s*\(/.test(src) ||
      /\b(?:openai|anthropic)\.[a-zA-Z0-9_.]*create\s*\(/.test(src);
    const hasAuth =
      /\b(?:getServerSession|auth\.getUser|currentUser|requireUser|verifySession)\b/.test(src);
    const hasHoldOrLimit =
      /\b(?:ratelimit|rateLimit|Ratelimit|reserveCreditsForStream|reserveStreamCredits|executeGuardedAiStream)\b/.test(
        src
      );
    if (invokesLlm && (!hasAuth || !hasHoldOrLimit)) {
      findings.push({
        severity: "CRITICAL",
        code: "DENIAL_OF_WALLET_UNGUARDED_AI_ROUTE",
        target: fp,
        message: "Paid LLM endpoint lacks caller session authentication or pre-flight rate/wallet hold.",
      });
    }
  }
  return findings;
}

function canonicalSha256(obj) {
  const norm = JSON.stringify(obj, Object.keys(obj).sort());
  return createHash("sha256").update(norm, "utf8").digest("hex");
}

function diffMcpManifest(manifestPath, lockPath) {
  const manifest = JSON.parse(readFileSync(resolve(manifestPath), "utf8"));
  const tools = Array.isArray(manifest.tools) ? manifest.tools : [];
  const findings = [];
  const lock = lockPath && existsSync(resolve(lockPath))
    ? JSON.parse(readFileSync(resolve(lockPath), "utf8"))
    : null;
  const lockMap = new Map(
    (lock?.tools ?? []).map((t) => [String(t.name), String(t.descriptionSha256 || t.toolSha256 || "")])
  );

  for (const t of tools) {
    const desc = String(t.description || "");
    const descHash = createHash("sha256").update(desc, "utf8").digest("hex");
    if (
      /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|<\s*system\b|[\u200b-\u200f\u202a-\u202e]/i.test(
        desc
      )
    ) {
      findings.push({
        severity: "CRITICAL",
        code: "MCP_TOOL_POISONING_DIRECTIVE",
        target: String(t.name),
        message: `MCP tool '${t.name}' description contains prompt-injection or hidden Unicode control markers.`,
      });
    }
    if (lockMap.has(String(t.name))) {
      const prev = lockMap.get(String(t.name));
      if (prev && prev !== descHash && prev !== canonicalSha256(t)) {
        findings.push({
          severity: "CRITICAL",
          code: "MCP_SILENT_DESCRIPTION_RUG_PULL",
          target: String(t.name),
          message: `MCP tool '${t.name}' mutated after lockfile pinning.`,
        });
      }
    }
  }
  return findings;
}

function parseArgs(argv) {
  const command = argv[0] || "";
  let sqlFile = "";
  let codeDir = "";
  let mcpManifest = "";
  let mcpLock = "";
  let failOnCritical = true;

  for (let i = 1; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--fail-on-critical") failOnCritical = true;
    else if (a === "--no-fail-on-critical") failOnCritical = false;
    else if (a === "--dry-run") continue;
    else if ((a === "--config" || a === "--sql-file" || a === "--file") && argv[i + 1]) {
      if (a !== "--config") sqlFile = argv[i + 1];
      i += 1;
    } else if (a === "--code-dir" && argv[i + 1]) {
      codeDir = argv[i + 1];
      i += 1;
    } else if (a === "--mcp-manifest" && argv[i + 1]) {
      mcpManifest = argv[i + 1];
      i += 1;
    } else if (a === "--mcp-lock" && argv[i + 1]) {
      mcpLock = argv[i + 1];
      i += 1;
    } else if (!a.startsWith("-")) {
      if (command === "lint-sql" && !sqlFile) sqlFile = a;
      if (command === "lint-code" && !codeDir) codeDir = a;
    }
  }
  return { command, sqlFile, codeDir, mcpManifest, mcpLock, failOnCritical };
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!["lint-sql", "lint-code", "verify-ci"].includes(opts.command)) {
    console.error(
      `[Billing Watchdog Public Diagnostic Action] Command '${opts.command}' requires the self-hosted Billing Watchdog Pro v2 engine (live REPEATABLE READ + Stripe reconciliation).`
    );
    console.error("Unlock Pro ($49/mo or $149 Lifetime): https://mariostosic0806.github.io/billing-watchdog/#self-hosted-license");
    process.exit(2);
  }

  const allFindings = [];
  try {
    if (opts.command === "lint-sql" || (opts.command === "verify-ci" && opts.sqlFile)) {
      if (!opts.sqlFile) {
        console.error("Usage error: --sql-file <path> is required for lint-sql.");
        process.exit(2);
      }
      const sqlFiles = collectFiles(opts.sqlFile, [".sql"]);
      const mergedSql = sqlFiles.map((f) => readFileSync(f, "utf8")).join("\n;\n");
      allFindings.push(...lintPublicSqlText(mergedSql));
    }

    if (opts.command === "lint-code" || (opts.command === "verify-ci" && opts.codeDir)) {
      if (!opts.codeDir) {
        console.error("Usage error: <code-dir> is required for lint-code.");
        process.exit(2);
      }
      const codeFiles = collectFiles(opts.codeDir, [".ts", ".tsx", ".js", ".mjs"]);
      allFindings.push(...lintPublicCodeFiles(codeFiles));
    }

    if (opts.command === "verify-ci" && opts.mcpManifest) {
      allFindings.push(...diffMcpManifest(opts.mcpManifest, opts.mcpLock));
    }
  } catch (err) {
    console.error(`[Billing Watchdog] ${err instanceof Error ? err.message : String(err)}`);
    process.exit(2);
  }

  console.log(`# Billing Watchdog Free Diagnostic CI Gate (${opts.command})`);
  console.log(`- Evaluated At (UTC): ${new Date().toISOString()}`);
  console.log(`- Findings Count: ${allFindings.length}`);
  for (const f of allFindings) {
    console.log(`- [${f.severity}] ${f.code} @ ${f.target}: ${f.message}`);
  }
  if (allFindings.length > 0) {
    console.log(
      "- Remediation SQL / Guard Blueprint: [REDACTED IN FREE DIAGNOSTIC MODE — Unlock Pro at https://mariostosic0806.github.io/billing-watchdog/]"
    );
  }

  const hasCritical = allFindings.some((f) => f.severity === "CRITICAL");
  if (opts.failOnCritical && hasCritical) {
    process.exit(1);
  }
  process.exit(0);
}

main();
