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
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, extname, join, posix, relative, resolve } from "node:path";

const SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json";

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

function escapeRegExp(literal) {
  return String(literal).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function stripSqlCommentsPreservingLines(sql) {
  return sql
    .replace(/--[^\r\n]*/g, (m) => " ".repeat(m.length))
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\r\n]/g, " "));
}

function stripSqlComments(sql) {
  return stripSqlCommentsPreservingLines(sql).replace(/\s+/g, " ").trim();
}

function toRepoRelativePosixUri(filePath, repoRoot = process.cwd()) {
  const trimmed = String(filePath || "").trim();
  if (!trimmed) return "workspace";
  const normalizedSlashes = trimmed.replace(/\\/g, "/");
  const isWinDrive = /^[a-zA-Z]:\//.test(normalizedSlashes);
  const isPosixAbs = normalizedSlashes.startsWith("/");
  if (!isWinDrive && !isPosixAbs) {
    const cleanRel = posix.normalize(normalizedSlashes).replace(/^(?:\.\/)+/, "");
    if (cleanRel && cleanRel !== "." && !cleanRel.startsWith("..")) {
      return cleanRel;
    }
  }
  const resolvedRoot = resolve(repoRoot);
  const resolvedTarget = resolve(resolvedRoot, trimmed);
  const rel = relative(resolvedRoot, resolvedTarget).replace(/\\/g, "/");
  if (
    rel &&
    rel !== "." &&
    !rel.startsWith("..") &&
    !/^[a-zA-Z]:/.test(rel) &&
    !rel.startsWith("/")
  ) {
    return rel;
  }
  return basename(normalizedSlashes) || "workspace";
}

function lineAndSnippetAtOffset(rawContent, offset) {
  const safeOffset = Math.max(0, Math.min(offset, rawContent.length));
  const startLine = Math.max(1, rawContent.slice(0, safeOffset).split(/\r?\n/).length);
  const rawLines = rawContent.split(/\r?\n/);
  const snippet = (rawLines[startLine - 1] ?? "").trim().slice(0, 160);
  return { startLine, snippet };
}

function locateTableOrColumnInSqlFiles(loadedSqlFiles, tableName, columnName) {
  const tableRe = new RegExp(
    `\\bCREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?(?:"?public"?\\.)?"?${escapeRegExp(tableName)}"?\\b`,
    "i"
  );
  for (const file of loadedSqlFiles) {
    const clean = stripSqlCommentsPreservingLines(file.content);
    const tm = tableRe.exec(clean);
    if (!tm || tm.index === undefined) continue;
    let offset = tm.index;
    if (columnName) {
      const semi = clean.indexOf(";", tm.index);
      const block = clean.slice(tm.index, semi > tm.index ? semi : clean.length);
      const colRe = new RegExp(`(?:^|[,(\\s])"?${escapeRegExp(columnName)}"?\\s+[a-zA-Z]`, "im");
      const cm = colRe.exec(block);
      if (cm && cm.index !== undefined) {
        const adjust =
          cm[0].startsWith(",") || cm[0].startsWith("(")
            ? cm[0].slice(1).search(/\S/) + 1
            : Math.max(0, cm[0].search(/\S/));
        offset = tm.index + cm.index + adjust;
      }
    }
    const { startLine, snippet } = lineAndSnippetAtOffset(file.content, offset);
    return { filePath: file.filePath, startLine, snippet };
  }
  return {
    filePath: loadedSqlFiles[0]?.filePath ?? "migrations.sql",
    startLine: 1,
    snippet: "",
  };
}

function lintPublicSqlFiles(sqlFilePaths) {
  const loadedSqlFiles = sqlFilePaths.map((filePath) => ({
    filePath,
    content: readFileSync(filePath, "utf8"),
  }));
  const mergedSql = loadedSqlFiles.map((f) => f.content).join("\n;\n");
  const norm = stripSqlComments(mergedSql);
  const findings = [];

  if (/\bCREATE\s+TABLE\b/i.test(norm)) {
    if (
      /\bwallets\b/i.test(norm) &&
      !/CHECK\s*\(\s*[a-zA-Z0-9_."]*balance[a-zA-Z0-9_."]*\s*>=\s*0\s*\)/i.test(norm)
    ) {
      const loc = locateTableOrColumnInSqlFiles(loadedSqlFiles, "wallets", "credits_balance");
      findings.push({
        severity: "CRITICAL",
        code: "MISSING_NON_NEGATIVE_CHECK",
        target: "public.wallets.credits_balance",
        message: "Wallet balance column lacks CHECK (credits_balance >= 0).",
        filePath: loc.filePath,
        startLine: loc.startLine,
        snippet: loc.snippet,
      });
    }
    if (
      /\bstripe_event_id\b/i.test(norm) &&
      !/stripe_event_id[^,)]*\bUNIQUE\b/i.test(norm) &&
      !/UNIQUE\s*\([^)]*stripe_event_id[^)]*\)/i.test(norm) &&
      !/CREATE\s+UNIQUE\s+INDEX\b(?![^;]*\bWHERE\b)[^;]*\bstripe_event_id\b/i.test(norm)
    ) {
      const loc = locateTableOrColumnInSqlFiles(
        loadedSqlFiles,
        "credit_transactions",
        "stripe_event_id"
      );
      findings.push({
        severity: "CRITICAL",
        code: "MISSING_WEBHOOK_UNIQUE_CONSTRAINT",
        target: "public.credit_transactions.stripe_event_id",
        message: "Webhook ledger lacks an unconditional UNIQUE constraint on stripe_event_id.",
        filePath: loc.filePath,
        startLine: loc.startLine,
        snippet: loc.snippet,
      });
    }
    for (const tbl of ["users", "subscriptions", "wallets", "credit_transactions"]) {
      const created = new RegExp(
        `CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?(?:public\\.)?${tbl}\\b`,
        "i"
      ).test(norm);
      if (!created) continue;
      const enabled = new RegExp(
        `ALTER\\s+TABLE\\s+(?:ONLY\\s+)?(?:public\\.)?${tbl}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`,
        "i"
      ).test(norm);
      const disabled = new RegExp(
        `ALTER\\s+TABLE\\s+(?:ONLY\\s+)?(?:public\\.)?${tbl}\\s+DISABLE\\s+ROW\\s+LEVEL\\s+SECURITY`,
        "i"
      ).test(norm);
      const hasPolicy = new RegExp(
        `CREATE\\s+POLICY\\s+[^;]+\\s+ON\\s+(?:public\\.)?${tbl}\\b`,
        "i"
      ).test(norm);
      if (!enabled || disabled || !hasPolicy) {
        const loc = locateTableOrColumnInSqlFiles(loadedSqlFiles, tbl, undefined);
        findings.push({
          severity: "HIGH",
          code: "MISSING_RLS_OR_POLICY",
          target: `public.${tbl}`,
          message: `Table public.${tbl} lacks active ENABLE ROW LEVEL SECURITY + CREATE POLICY.`,
          filePath: loc.filePath,
          startLine: loc.startLine,
          snippet: loc.snippet,
        });
      }
    }
  }

  for (const file of loadedSqlFiles) {
    const clean = stripSqlCommentsPreservingLines(file.content);
    const policyRegex =
      /CREATE\s+POLICY\s+([a-zA-Z0-9_"]+)\s+ON\s+([a-zA-Z0-9_."]+)[^;]*?\b(?:USING|WITH\s+CHECK)\s*\(([^;]+)\)/gi;
    let m;
    while ((m = policyRegex.exec(clean)) !== null) {
      const [, policyName, tableName, expr] = m;
      const isPermissiveTrue = /^\s*true\s*$/i.test(expr.trim());
      const isBroadRoleOnly =
        /auth\.role\s*\(\s*\)\s*=\s*'authenticated'/i.test(expr) &&
        !/auth\.(?:uid|jwt)\s*\(/i.test(expr);
      if (isPermissiveTrue || isBroadRoleOnly) {
        const loc = lineAndSnippetAtOffset(file.content, m.index);
        findings.push({
          severity: "CRITICAL",
          code: "RLS_PERMISSIVE_NO_TENANT_FILTER",
          target: `${tableName} (${policyName})`,
          message: `Permissive RLS policy ${policyName} on ${tableName} allows cross-tenant access without auth.uid() / auth.jwt().`,
          filePath: file.filePath,
          startLine: loc.startLine,
          snippet: loc.snippet,
        });
      }
    }

    const secDefMatch = /\bSECURITY\s+DEFINER\b/i.exec(clean);
    if (secDefMatch) {
      const loc = lineAndSnippetAtOffset(file.content, secDefMatch.index);
      if (!/SET\s+search_path\s*=/i.test(clean)) {
        findings.push({
          severity: "HIGH",
          code: "SECURITY_DEFINER_MISSING_SEARCH_PATH",
          target: "SECURITY DEFINER RPC",
          message: "SECURITY DEFINER function omits explicit SET search_path.",
          filePath: file.filePath,
          startLine: loc.startLine,
          snippet: loc.snippet,
        });
      }
      if (!/auth\.uid\s*\(/i.test(clean)) {
        findings.push({
          severity: "CRITICAL",
          code: "SECURITY_DEFINER_CALLER_ID_WITHOUT_AUTH_UID",
          target: "SECURITY DEFINER RPC",
          message:
            "SECURITY DEFINER function executes privileged SQL without auth.uid() caller verification.",
          filePath: file.filePath,
          startLine: loc.startLine,
          snippet: loc.snippet,
        });
      }
    }
  }

  return findings;
}

function lintPublicCodeFiles(filePaths) {
  const findings = [];
  for (const fp of filePaths) {
    const src = readFileSync(fp, "utf8");
    const isWebhook =
      /stripe|webhook/i.test(fp) || /checkout\.session\.completed|invoice\.paid/.test(src);
    const jsonCall = /\b(?:req|request)\.json\s*\(\s*\)/.exec(src);
    if (
      isWebhook &&
      jsonCall &&
      !/constructEvent|verifyStripeWebhookSignature/.test(src)
    ) {
      const loc = lineAndSnippetAtOffset(src, jsonCall.index);
      findings.push({
        severity: "CRITICAL",
        code: "MISSING_STRIPE_SIGNATURE_VERIFICATION",
        target: fp,
        message:
          "Webhook handler parses req.json() without raw-body Stripe-Signature HMAC verification.",
        filePath: fp,
        startLine: loc.startLine,
        snippet: loc.snippet,
      });
    }
    const streamCall = /\bstreamText\s*\(/.exec(src);
    if (
      streamCall &&
      /\bonFinish\b/.test(src) &&
      !/reserveCreditsForStream|reserveStreamCredits|executeGuardedAiStream/.test(src)
    ) {
      const loc = lineAndSnippetAtOffset(src, streamCall.index);
      findings.push({
        severity: "CRITICAL",
        code: "UNRESERVED_STREAMING_LLM_DEDUCTION",
        target: fp,
        message: "Deducts LLM credits inside onFinish without a pre-flight HOLD reservation.",
        filePath: fp,
        startLine: loc.startLine,
        snippet: loc.snippet,
      });
    }
    const llmMatch =
      /\b(?:streamText|generateText|generateObject|streamObject)\s*\(/.exec(src) ||
      /\b(?:openai|anthropic)\.[a-zA-Z0-9_.]*create\s*\(/.exec(src);
    const hasAuth =
      /\b(?:getServerSession|auth\.getUser|currentUser|requireUser|verifySession)\b/.test(src);
    const hasHoldOrLimit =
      /\b(?:ratelimit|rateLimit|Ratelimit|reserveCreditsForStream|reserveStreamCredits|executeGuardedAiStream)\b/.test(
        src
      );
    if (llmMatch && (!hasAuth || !hasHoldOrLimit)) {
      const loc = lineAndSnippetAtOffset(src, llmMatch.index);
      findings.push({
        severity: "CRITICAL",
        code: "DENIAL_OF_WALLET_UNGUARDED_AI_ROUTE",
        target: fp,
        message:
          "Paid LLM endpoint lacks caller session authentication or pre-flight rate/wallet hold.",
        filePath: fp,
        startLine: loc.startLine,
        snippet: loc.snippet,
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
  const resolvedManifest = resolve(manifestPath);
  const rawManifest = readFileSync(resolvedManifest, "utf8");
  const manifest = JSON.parse(rawManifest);
  const tools = Array.isArray(manifest.tools) ? manifest.tools : [];
  const findings = [];
  const lock =
    lockPath && existsSync(resolve(lockPath))
      ? JSON.parse(readFileSync(resolve(lockPath), "utf8"))
      : null;
  const lockMap = new Map(
    (lock?.tools ?? []).map((t) => [
      String(t.name),
      String(t.descriptionSha256 || t.toolSha256 || ""),
    ])
  );

  for (const t of tools) {
    const toolName = String(t.name || "");
    const desc = String(t.description || "");
    const descHash = createHash("sha256").update(desc, "utf8").digest("hex");
    const nameMatch = toolName
      ? new RegExp(`"${escapeRegExp(toolName)}"`).exec(rawManifest)
      : null;
    const loc = nameMatch
      ? lineAndSnippetAtOffset(rawManifest, nameMatch.index)
      : { startLine: 1, snippet: "" };

    if (
      /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|<\s*system\b|[\u200b-\u200f\u202a-\u202e]/i.test(
        desc
      )
    ) {
      findings.push({
        severity: "CRITICAL",
        code: "MCP_TOOL_POISONING_DIRECTIVE",
        target: toolName,
        message: `MCP tool '${toolName}' description contains prompt-injection or hidden Unicode control markers.`,
        filePath: resolvedManifest,
        startLine: loc.startLine,
        snippet: loc.snippet,
      });
    }
    if (lockMap.has(toolName)) {
      const prev = lockMap.get(toolName);
      if (prev && prev !== descHash && prev !== canonicalSha256(t)) {
        findings.push({
          severity: "CRITICAL",
          code: "MCP_SILENT_DESCRIPTION_RUG_PULL",
          target: toolName,
          message: `MCP tool '${toolName}' mutated after lockfile pinning.`,
          filePath: resolvedManifest,
          startLine: loc.startLine,
          snippet: loc.snippet,
        });
      }
    }
  }
  return findings;
}

function buildPublicSarifLog(findings, evaluatedAtUtc) {
  const ruleIndexById = new Map();
  const rules = [];
  for (const f of findings) {
    if (ruleIndexById.has(f.code)) continue;
    ruleIndexById.set(f.code, rules.length);
    const isCritical = f.severity === "CRITICAL";
    rules.push({
      id: f.code,
      shortDescription: { text: f.message },
      fullDescription: { text: f.message },
      help: {
        text: "[REDACTED IN FREE DIAGNOSTIC MODE — Unlock executable SQL/guard patches at https://mariostosic0806.github.io/billing-watchdog/]",
        markdown:
          "**Free Diagnostic Gate:** Remediation SQL & atomic guard blueprints are available in [Billing Watchdog Pro v2](https://mariostosic0806.github.io/billing-watchdog/).",
      },
      defaultConfiguration: { level: isCritical ? "error" : "warning" },
      properties: {
        tags: ["security", "billing"],
        "security-severity": isCritical ? "9.2" : "7.8",
      },
    });
  }

  const results = findings.map((f) => {
    const uri = toRepoRelativePosixUri(f.filePath || "workspace");
    const safeLine = Number.isSafeInteger(f.startLine) && f.startLine >= 1 ? f.startLine : 1;
    const fpHash = createHash("sha256")
      .update(`${f.code}:${uri}:${safeLine}:${f.target}`, "utf8")
      .digest("hex")
      .slice(0, 32);
    const region = { startLine: safeLine, startColumn: 1 };
    if (f.snippet) {
      region.snippet = { text: f.snippet };
    }
    return {
      ruleId: f.code,
      ruleIndex: ruleIndexById.get(f.code) ?? 0,
      level: f.severity === "CRITICAL" ? "error" : "warning",
      message: { text: `[${f.target}] ${f.message}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri, uriBaseId: "%SRCROOT%" },
            region,
          },
        },
      ],
      partialFingerprints: { primaryLocationLineHash: fpHash },
    };
  });

  return {
    $schema: SARIF_SCHEMA_URI,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Billing Watchdog & ProofTwin (Free Diagnostic Gate)",
            version: "2.1.0",
            informationUri: "https://github.com/mariostosic0806/billing-watchdog",
            rules,
          },
        },
        invocations: [{ executionSuccessful: true, endTimeUtc: evaluatedAtUtc }],
        results,
      },
    ],
  };
}

function parseArgs(argv) {
  const command = argv[0] || "";
  let sqlFile = "";
  let codeDir = "";
  let mcpManifest = "";
  let mcpLock = "";
  let sarifOut = "";
  let failOnCritical = true;

  for (let i = 1; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--fail-on-critical") failOnCritical = true;
    else if (a === "--no-fail-on-critical") failOnCritical = false;
    else if (a === "--dry-run") continue;
    else if (a.startsWith("--sarif-out=")) {
      sarifOut = a.slice("--sarif-out=".length);
    } else if (a === "--sarif-out") {
      if (!argv[i + 1] || argv[i + 1].startsWith("--")) {
        throw new Error("Option --sarif-out needs a value.");
      }
      sarifOut = argv[i + 1];
      i += 1;
    } else if ((a === "--config" || a === "--sql-file" || a === "--file") && argv[i + 1]) {
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
  return { command, sqlFile, codeDir, mcpManifest, mcpLock, sarifOut, failOnCritical };
}

function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(`[Billing Watchdog] ${err instanceof Error ? err.message : String(err)}`);
    process.exit(2);
  }

  if (!["lint-sql", "lint-code", "verify-ci"].includes(opts.command)) {
    console.error(
      `[Billing Watchdog Public Diagnostic Action] Command '${opts.command}' requires the self-hosted Billing Watchdog Pro v2 engine (live REPEATABLE READ + Stripe reconciliation).`
    );
    console.error(
      "Unlock Pro ($49/mo or $149 Lifetime): https://mariostosic0806.github.io/billing-watchdog/#self-hosted-license"
    );
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
      allFindings.push(...lintPublicSqlFiles(sqlFiles));
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

  const evaluatedAtUtc = new Date().toISOString();
  if (opts.sarifOut) {
    const outPath = resolve(opts.sarifOut);
    const sarifLog = buildPublicSarifLog(allFindings, evaluatedAtUtc);
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, JSON.stringify(sarifLog, null, 2) + "\n", "utf8");
  }

  console.log(`# Billing Watchdog Free Diagnostic CI Gate (${opts.command})`);
  console.log(`- Evaluated At (UTC): ${evaluatedAtUtc}`);
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
