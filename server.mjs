import Fastify from "fastify";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { spawn } from "node:child_process";

// =========================
// ENV / CONFIG
// =========================
const env = {
  PORT: Number(process.env.PORT || 8080),
  NODE_ENV: process.env.NODE_ENV || "development",

  // Auth
  RUNNER_JWT_SECRET: process.env.RUNNER_JWT_SECRET || "dev_secret_change_me_please",
  RUNNER_JWT_ISSUER: process.env.RUNNER_JWT_ISSUER || "studio-backend",
  RUNNER_JWT_AUDIENCE: process.env.RUNNER_JWT_AUDIENCE || "kestra-md-runner",

  // MotherDuck
  MOTHERDUCK_TOKEN: process.env.MOTHERDUCK_TOKEN || "",
  MOTHERDUCK_DATABASE: process.env.MOTHERDUCK_DATABASE || "ws_default",

  // Policy
  ALLOWED_PROJECT_SCHEMAS: (process.env.ALLOWED_PROJECT_SCHEMAS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
  TMP_SCHEMA: process.env.TMP_SCHEMA || "studio_tmp",

  // Limits
  NOTEBOOK_MAX_ROWS: Number(process.env.NOTEBOOK_MAX_ROWS || 200),
  PIPELINE_PREVIEW_ROWS: Number(process.env.PIPELINE_PREVIEW_ROWS || 50),
  QUERY_TIMEOUT_MS: Number(process.env.QUERY_TIMEOUT_MS || 600000)
};

const allowedProjectSchemas = new Set(env.ALLOWED_PROJECT_SCHEMAS);

// =========================
// APP
// =========================
const app = Fastify({ logger: true });

// =========================
// HELPERS: time
// =========================
const nowIso = () => new Date().toISOString();

// =========================
// AUTH (JWT)
// Expect claims:
// {
//   sub: "user/service",
//   ws: "ws_<workspace_db_name_or_id>",   (optional, else env.MOTHERDUCK_DATABASE)
//   scopes: ["notebook:run","pipeline:run"],
//   iss/aud/iat/exp...
// }
// =========================
function authErr(message) {
  const e = new Error(message);
  e.code = "AUTH";
  return e;
}
function verifyToken(req) {
  const h = req.headers.authorization;
  if (!h?.startsWith("Bearer ")) throw authErr("Missing Authorization: Bearer <token>");
  const token = h.slice("Bearer ".length).trim();

  const claims = jwt.verify(token, env.RUNNER_JWT_SECRET, {
    issuer: env.RUNNER_JWT_ISSUER,
    audience: env.RUNNER_JWT_AUDIENCE
  });

  if (!claims?.sub || !Array.isArray(claims?.scopes)) throw authErr("Invalid token claims");
  return claims;
}
function requireScope(claims, scope) {
  if (!claims.scopes.includes(scope)) throw authErr(`Missing scope: ${scope}`);
}

// =========================
// SAFETY (MVP)
// - Notebook: allow only SELECT-ish
// - Pipeline: block known dangerous extension/external patterns
// =========================
const BLOCKED_PATTERNS = [
  "drop database",
  "drop schema",
  "attach", // users must not attach arbitrary things
  "detach",
  "install", // only runner uses install/load motherduck
  "load",
  "pragma",
  "copy ", // exfil/import paths
  "export ",
  "import ",
  "call ",
  "create extension",
  "set motherduck_token",
  "httpfs",
  "s3",
  "azure",
  "gcs"
];
const NOTEBOOK_ALLOWED_PREFIXES = ["select", "with", "describe", "show", "explain"];

function normalizeSql(sql) {
  const withoutLineComments = String(sql).replace(/--.*$/gm, "");
  const withoutBlockComments = withoutLineComments.replace(/\/\*[\s\S]*?\*\//g, "");
  return withoutBlockComments.trim().replace(/\s+/g, " ");
}
function containsBlocked(sql) {
  const n = normalizeSql(sql).toLowerCase();
  for (const b of BLOCKED_PATTERNS) if (n.includes(b)) return b;
  return null;
}
function firstKeyword(sql) {
  const n = normalizeSql(sql).toLowerCase();
  const m = n.match(/^[a-z]+/);
  return m ? m[0] : "";
}
function safetyErr(message) {
  const e = new Error(message);
  e.code = "SAFETY";
  return e;
}
function assertSafeNotebookSql(sql) {
  const n = normalizeSql(sql);
  if (!n) throw safetyErr("Empty SQL");
  const blocked = containsBlocked(n);
  if (blocked) throw safetyErr(`Blocked SQL pattern: ${blocked}`);
  const kw = firstKeyword(n);
  if (!NOTEBOOK_ALLOWED_PREFIXES.includes(kw)) {
    throw safetyErr(`Notebook SQL must start with: ${NOTEBOOK_ALLOWED_PREFIXES.join(", ")}`);
  }
}
function assertSafePipelineSql(sql) {
  const n = normalizeSql(sql);
  if (!n) throw safetyErr("Empty SQL");
  const blocked = containsBlocked(n);
  if (blocked) throw safetyErr(`Blocked SQL pattern: ${blocked}`);
}
function assertIdentifier(name, label) {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) {
    throw safetyErr(`Invalid ${label}: ${name}`);
  }
}

// =========================
// DUCKDB CLI execution
// - requires duckdb binary in PATH (Dockerfile installs it)
// - uses motherduck extension internally
// =========================
function escapeSqlLiteral(s) {
  return String(s).replace(/'/g, "''");
}
function motherduckBootstrapSql(workspaceDb) {
  if (!env.MOTHERDUCK_TOKEN) throw new Error("MOTHERDUCK_TOKEN is not configured");
  return [
    "INSTALL motherduck;",
    "LOAD motherduck;",
    `SET motherduck_token='${escapeSqlLiteral(env.MOTHERDUCK_TOKEN)}';`,
    `ATTACH 'md:${escapeSqlLiteral(workspaceDb)}' AS md (READ_ONLY FALSE);`,
    "USE md;"
  ];
}
function execDuckDB(sqlStatements, timeoutMs) {
  const sql = sqlStatements.join("\n") + "\n";
  const t = timeoutMs ?? env.QUERY_TIMEOUT_MS;

  return new Promise((resolve, reject) => {
    const child = spawn("duckdb", ["-json"], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      const e = new Error(`Query timeout after ${t}ms`);
      e.code = "TIMEOUT";
      reject(e);
    }, t);

    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));

    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });

    child.stdin.write(sql);
    child.stdin.end();
  });
}
function safeParseJsonRows(stdout) {
  const s = (stdout || "").trim();
  if (!s) return [];
  // duckdb -json output can be one JSON array or multiple JSON lines (depends)
  try {
    const j = JSON.parse(s);
    return Array.isArray(j) ? j : [j];
  } catch {
    const rows = [];
    for (const line of s.split("\n").map((x) => x.trim()).filter(Boolean)) {
      try {
        rows.push(JSON.parse(line));
      } catch {}
    }
    return rows;
  }
}
function stripTrailingSemicolons(sql) {
  return String(sql).trim().replace(/;+\s*$/, "");
}

// =========================
// TEMP TABLE NAMING
// =========================
function tempTableName(tmpSchema, runId, stepSlug) {
  const r = String(runId).replace(/[^a-zA-Z0-9]/g, "").slice(0, 16);
  const s = String(stepSlug).replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 48);
  return `${tmpSchema}.r_${r}__${s}`.toLowerCase();
}

// =========================
// BEST-EFFORT IDEMPOTENCY (in-memory)
// NOTE: This does NOT survive restarts.
// For real idempotency, store in Supabase/Redis.
// =========================
const seen = new Map(); // key -> timestamp
function idemKey(runId, stepId, attempt) {
  return `${runId}:${stepId}:${attempt}`;
}
function rememberKey(key) {
  const now = Date.now();
  seen.set(key, now);
  if (seen.size > 10000) {
    for (const [k, ts] of seen) {
      if (now - ts > 60 * 60 * 1000) seen.delete(k);
    }
  }
}

// =========================
// RESPONSE helper
// =========================
function errorResponse(mode, startedAt, t0, err) {
  const type =
    err?.code === "SAFETY"
      ? "SAFETY"
      : err?.code === "TIMEOUT"
      ? "TIMEOUT"
      : err?.code === "AUTH"
      ? "AUTH"
      : "RUNTIME";

  return {
    ok: false,
    mode,
    startedAt,
    finishedAt: nowIso(),
    durationMs: Date.now() - t0,
    artifacts: [],
    outputRefs: [],
    warnings: [],
    error: { type, message: err?.message || "Unknown error" }
  };
}

// =========================
// SCHEMAS
// =========================
const ExecuteSchema = z.object({
  mode: z.literal("NOTEBOOK"),
  sql: z.string().min(1),
  maxRows: z.number().int().min(1).max(2000).optional(),
  timeoutMs: z.number().int().min(1000).max(3_600_000).optional()
});

const RunStepSchema = z.object({
  mode: z.literal("PIPELINE"),
  runId: z.string().min(6),
  stepId: z.string().min(1),
  stepSlug: z.string().min(1),
  stepType: z.enum(["SQL_TEMP", "MODEL", "CHECK"]),
  projectSchema: z.string().min(1),
  attempt: z.number().int().min(1).max(50),

  timeoutMs: z.number().int().min(1000).max(3_600_000).optional(),
  previewRows: z.number().int().min(1).max(500).optional(),

  // for SQL_TEMP / CHECK
  sql: z.string().optional(),

  output: z
    .object({
      kind: z.enum(["TEMP_TABLE", "NONE"]),
      alias: z.string().optional()
    })
    .optional(),

  // for MODEL
  model: z
    .object({
      name: z.string().min(1),
      materialization: z.enum(["VIEW", "TABLE"]),
      sql: z.string().min(1),
      outputName: z.string().min(1)
    })
    .optional()
});

// =========================
// ROUTES
// =========================
app.get("/health", async () => ({ ok: true }));

// NOTEBOOK: execute SELECT-ish with LIMIT
app.post("/execute_sql", async (req, reply) => {
  const startedAt = nowIso();
  const t0 = Date.now();

  try {
    const claims = verifyToken(req);
    requireScope(claims, "notebook:run");

    const body = ExecuteSchema.parse(req.body);

    assertSafeNotebookSql(body.sql);

    const limit = Math.min(body.maxRows ?? env.NOTEBOOK_MAX_ROWS, 2000);
    const sqlLimited = `${stripTrailingSemicolons(body.sql)} LIMIT ${limit};`;

    const workspaceDb = claims.ws || env.MOTHERDUCK_DATABASE;
    const bootstrap = motherduckBootstrapSql(workspaceDb);

    const result = await execDuckDB([...bootstrap, sqlLimited], body.timeoutMs ?? env.QUERY_TIMEOUT_MS);
    if (result.code !== 0) {
      const e = new Error((result.stderr || "").trim() || "DuckDB execution failed");
      e.code = "RUNTIME";
      throw e;
    }

    const rows = safeParseJsonRows(result.stdout);

    return reply.send({
      ok: true,
      mode: "NOTEBOOK",
      startedAt,
      finishedAt: nowIso(),
      durationMs: Date.now() - t0,
      artifacts: [
        { kind: "PREVIEW", rows },
        { kind: "LOGS", message: (result.stderr || "").trim() || "ok" }
      ],
      outputRefs: [],
      warnings: []
    });
  } catch (err) {
    return reply.status(err?.code === "AUTH" ? 401 : 400).send(errorResponse("NOTEBOOK", startedAt, t0, err));
  }
});

// PIPELINE: execute one step deterministically
app.post("/run_step", async (req, reply) => {
  const startedAt = nowIso();
  const t0 = Date.now();

  try {
    const claims = verifyToken(req);
    requireScope(claims, "pipeline:run");

    const body = RunStepSchema.parse(req.body);

    // schema policy
    assertIdentifier(body.projectSchema, "projectSchema");
    if (allowedProjectSchemas.size > 0 && !allowedProjectSchemas.has(body.projectSchema)) {
      throw safetyErr(`Project schema not allowed: ${body.projectSchema}`);
    }

    const key = idemKey(body.runId, body.stepId, body.attempt);
    if (seen.has(key)) {
      return reply.send({
        ok: true,
        mode: "PIPELINE",
        startedAt,
        finishedAt: nowIso(),
        durationMs: Date.now() - t0,
        artifacts: [{ kind: "LOGS", message: `idempotent replay accepted: ${key}` }],
        outputRefs: [],
        warnings: ["IDEMPOTENT_REPLAY"]
      });
    }
    rememberKey(key);

    const workspaceDb = claims.ws || env.MOTHERDUCK_DATABASE;
    const bootstrap = motherduckBootstrapSql(workspaceDb);

    const timeoutMs = body.timeoutMs ?? env.QUERY_TIMEOUT_MS;
    const previewRows = body.previewRows ?? env.PIPELINE_PREVIEW_ROWS;

    // Ensure schemas exist (idempotent)
    const statements = [
      `CREATE SCHEMA IF NOT EXISTS ${env.TMP_SCHEMA};`,
      `CREATE SCHEMA IF NOT EXISTS ${body.projectSchema};`
    ];

    const outputRefs = [];

    if (body.stepType === "MODEL") {
      if (!body.model) throw new Error("MODEL step missing model payload");
      assertIdentifier(body.model.outputName, "model.outputName");
      assertSafePipelineSql(body.model.sql);

      const fq = `${body.projectSchema}.${body.model.outputName}`;
      outputRefs.push(fq);

      const msql = stripTrailingSemicolons(body.model.sql);
      if (body.model.materialization === "VIEW") {
        statements.push(`CREATE OR REPLACE VIEW ${fq} AS ${msql};`);
      } else {
        statements.push(`CREATE OR REPLACE TABLE ${fq} AS ${msql};`);
      }
      statements.push(`SELECT * FROM ${fq} LIMIT ${previewRows};`);
    }

    if (body.stepType === "SQL_TEMP") {
      if (!body.sql) throw new Error("SQL_TEMP step missing sql");
      assertSafePipelineSql(body.sql);

      const s = stripTrailingSemicolons(body.sql);
      const outKind = body.output?.kind ?? "TEMP_TABLE";

      if (outKind === "TEMP_TABLE") {
        const tmpRef = tempTableName(env.TMP_SCHEMA, body.runId, body.stepSlug);
        outputRefs.push(tmpRef);

        statements.push(`CREATE OR REPLACE TABLE ${tmpRef} AS ${s};`);
        statements.push(`SELECT * FROM ${tmpRef} LIMIT ${previewRows};`);
      } else {
        statements.push(`${s};`);
      }
    }

    if (body.stepType === "CHECK") {
      if (!body.sql) throw new Error("CHECK step missing sql");
      assertSafePipelineSql(body.sql);

      const checkSql = stripTrailingSemicolons(body.sql);
      // Convention: check query returns failing rows; pass = 0 rows
      statements.push(`SELECT COUNT(*) AS failures FROM (${checkSql}) t;`);
    }

    const result = await execDuckDB([...bootstrap, ...statements], timeoutMs);
    if (result.code !== 0) {
      const e = new Error((result.stderr || "").trim() || "DuckDB execution failed");
      e.code = "RUNTIME";
      throw e;
    }

    const rows = safeParseJsonRows(result.stdout);

    return reply.send({
      ok: true,
      mode: "PIPELINE",
      startedAt,
      finishedAt: nowIso(),
      durationMs: Date.now() - t0,
      artifacts: [
        { kind: "PREVIEW", rows },
        { kind: "LOGS", message: (result.stderr || "").trim() || "ok" }
      ],
      outputRefs,
      warnings: []
    });
  } catch (err) {
    return reply.status(err?.code === "AUTH" ? 401 : 400).send(errorResponse("PIPELINE", startedAt, t0, err));
  }
});

// =========================
// START
// =========================
app.listen({ port: env.PORT, host: "0.0.0.0" }).catch((e) => {
  app.log.error(e);
  process.exit(1);
});
