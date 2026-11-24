/**
 * THE canonical description of every environment variable in this repo.
 *
 * Three things read this file:
 *   1. `pnpm generate:secrets`  (scripts/generate-secrets.ts)  — builds a
 *      ready-to-paste production env block, generating what it can and
 *      prompting for what it can't.
 *   2. `pnpm env:sync`          (scripts/sync-env-example.ts)  — regenerates
 *      `.env.example` and `apps/web/.env.example`.
 *      Those files are GENERATED. Do not hand-edit them; edit this
 *      manifest and re-run the script.
 *   3. `pnpm env:check`         (same script, `--check`)       — CI gate. Fails
 *      when a key declared in a `packages/env/src/vars/*.ts` Zod schema is
 *      missing here, or when a generated `.env.example` is stale.
 *
 * ---------------------------------------------------------------------------
 * ADDING A NEW ENVIRONMENT VARIABLE
 * ---------------------------------------------------------------------------
 *   1. Declare it in the right `packages/env/src/vars/*.ts` object (shared =
 *      server + worker, server = server-only, web = VITE_*) — never inline
 *      in the `createEnv({…})` call one
 *      directory up, which the scan cannot see.
 *   2. Add an entry to `ENV_VARS` below, in an existing group or a new one.
 *   3. Run `pnpm env:sync` and commit the regenerated `.env.example` files.
 *
 * Skipping step 2 fails CI — that is deliberate. A variable that the generator
 * doesn't know about is a variable that silently goes missing from a
 * production deploy and surfaces as a boot crash weeks later.
 *
 * REMOVING A FEATURE MODULE: delete that module's group and its vars from
 * this file, then run `pnpm env:sync`.
 */

// ---------------------------------------------------------------------------
// Deploy targets
// ---------------------------------------------------------------------------

/**
 * Deploy targets the generator knows about. Dokploy on a VPS is the repo's
 * deployment target is Dokploy on a VPS; the cross-platform
 * contract is `docs/infra.md`.
 */
export const DEPLOY_TARGETS = [
  {
    id: "vps",
    label: "VPS / Dokploy",
    doc: "docs/infra.md",
    injects: [],
    note: "You own the Postgres and Redis instances, so you supply both connection strings.",
  },
  {
    id: "other",
    label: "Other / not sure",
    doc: "docs/infra.md",
    injects: [],
    note: "Prompting for every non-defaulted variable. Delete anything your platform injects for you.",
  },
] as const;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Which .env file a variable belongs to. */
export type EnvFile = "root" | "web";

interface EnvGroup {
  id: string;
  /** Section heading in the generated .env.example. */
  title: string;
  file?: EnvFile;
  /** Always included; never prompted for. */
  always?: boolean;
  /**
   * Yes/no question gating the whole group in `pnpm generate:secrets`.
   * Omitted for `always` groups and for `tuning` groups.
   */
  prompt?: string;
  /** Default answer to `prompt`. */
  default?: boolean;
  /**
   * Tuning-only group: every var has a schema default, so the generator emits
   * the whole group commented out and never prompts.
   */
  tuning?: boolean;
  /**
   * Force this group on (skipping its yes/no) when an earlier answer makes it
   * mandatory — e.g. SMTP is not optional once SIGNUP_ENABLED is true, because
   * the server hard-throws at boot without it. Without this, the contradiction
   * only surfaces in the final validation pass, after every prompt has been
   * answered, and the whole run has to be redone.
   */
  requiredWhen?: { key: string; equals: string; because: string };
  /**
   * Offer to reuse this group's values from the shell environment the script
   * runs in, when they are already set there. Meant for credentials you hold
   * once and point several local apps at (SMTP, object storage, a translation
   * API key) — not for per-app values like BETTER_AUTH_URL or DATABASE_URL,
   * where silently inheriting another app's value is a footgun.
   */
  reuseFromEnv?: boolean;
  /** Comment block emitted above the section. */
  comment?: string[];
}

export interface EnvVar {
  key: string;
  group: string;
  /**
   * - `generate`: the script produces a value with `generator`.
   * - `prompt`:   only you know it — the script asks.
   * - `confirm`:  yes/no question; emits `"true"` only when the answer is yes
   *               (schema default covers the no case).
   * - `enable`:   when this var's group is selected, emit `"true"` automatically
   *               (feature flags that must flip on with their optional block).
   * - `default`:  a documented default value covers it, so the generator never
   *               asks and omits the key (shown commented out under `--all`).
   * - `manual`:   deliberate opt-in with no useful prompt; same emission as
   *               `default`, but documented in `.env.example` (rare — prefer
   *               `prompt`).
   */
  source: "generate" | "prompt" | "confirm" | "enable" | "default" | "manual";
  generator?: "secret32" | "vapid-public" | "vapid-private";
  /**
   * The effective default, for documentation only — setting this changes
   * nothing at runtime. Usually mirrors a Zod `.default()`; see `defaultFrom`
   * for the handful that come from application code instead.
   */
  default?: string;
  /**
   * Where `default` actually comes from. `"schema"` (the assumed case) means a
   * Zod `.default()`. `"app"` means the schema field is optional and the
   * fallback lives in application code — say so explicitly, because
   * `pnpm env:check` compares key sets, not defaults, and cannot catch this
   * drifting.
   */
  defaultFrom?: "schema" | "app";
  /**
   * Fixed set of valid values. Rendered as an `Allowed: …` line in
   * `.env.example`, and offered as a pick-list instead of a free-text prompt.
   */
  choices?: Array<{ value: string; label?: string; description?: string }>;
  /**
   * Shape-check applied at the prompt, mirroring the Zod refinement that would
   * otherwise only fire in the final validation pass — so a typo costs one
   * retry instead of the whole run.
   */
  format?: "origin" | "push-subject";
  /**
   * Set `false` to keep this var OUT of its group's reuse-from-environment
   * offer, even when the group has `reuseFromEnv`. For values that identify one
   * specific app rather than a shared provider account — inheriting those
   * silently points the new app at the previous one's resources.
   */
  reusable?: boolean;
  /**
   * Let the operator skip this otherwise-required var (empty answer = omit).
   * For values a platform may supply out of band — the generator records the
   * omission in the output header instead of blocking on it.
   */
  omittable?: boolean;
  /** Required once its group is enabled. Prompts are re-asked until answered. */
  required?: boolean;
  /** Question text for `source: "prompt"` / `source: "confirm"`. */
  prompt?: string;
  /** Default answer for `source: "confirm"` (false when omitted). */
  confirmDefault?: boolean;
  /** Extra guidance printed under the prompt. */
  hint?: string;
  /** Placeholder shown in the generated .env.example. */
  example?: string;
  /**
   * Emit this var UNCOMMENTED in the generated .env.example. Reserve it for
   * vars whose `example` is a working local-dev value — a live line with a
   * non-functional placeholder is worse than a commented one, because
   * `emptyStringAsUndefined` won't save you from a wrong value.
   * `source: "generate"` vars are always emitted live but empty.
   */
  exampleSet?: boolean;
  /** True for values that must never be echoed back or logged. */
  secret?: boolean;
  file?: EnvFile;
  /**
   * Set `false` for variables read outside the Zod schemas (e.g. by a shell
   * entrypoint). Excludes the key from the schema-coverage check's expectation
   * that every manifest key is also a schema key.
   */
  inSchema?: boolean;
  /** Comment lines emitted above the var. */
  comment?: string[];
  /**
   * Render into the trailing "Advanced tuning" section of the root
   * `.env.example` instead of the var's own feature section — for one-off
   * knobs a nontechnical operator should never touch (rate-limit budgets,
   * codec settings, cache TTLs). Always commented with the default shown.
   * The manifest and `generate:secrets --all` are unaffected; only the
   * `.env.example` placement moves.
   */
  advanced?: boolean;
  /**
   * Omit from the generated `.env.example` entirely. For deep one-shot knobs
   * (runtime identities and harness controls) whose audience
   * reads the operations docs, not the example file — the full catalog stays
   * here and in the Zod schema. Only valid on `source: "default"` /
   * `"manual"` vars (never on anything prompted, generated, or enabling).
   */
  hidden?: boolean;
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

export const ENV_GROUPS: EnvGroup[] = [
  {
    id: "core",
    title: "Datastores — [shared] (server + worker)",
    always: true,
  },
  {
    id: "runtime",
    title: "Runtime + schema sync — [shared]",
    always: true,
    comment: [
      "Committed Prisma migrations run at startup when MIGRATE_ON_START=true.",
      "Followers wait for matching history before admitting the application.",
      "See docs/schema-migrations.md.",
    ],
  },
  {
    id: "backups",
    title: "Database backups — [shared]",
    prompt: "Configure off-site database backups (S3/R2)?",
    default: false,
    comment: [
      "Logical pg_dump backups uploaded to a private bucket. Production",
      "requires a dedicated BACKUP_S3_ACCESS_KEY_ID,",
      "limited to GetObject, PutObject, and AbortMultipartUpload on the backup bucket. The freshness",
      "worker should use a distinct ListBucket-only monitor credential, not the",
      "dump-writer key.",
      "Use the regular image's backup-schedule command for opt-in UTC daily",
      "backups, and restore/restore-drill for explicit one-shot recovery.",
      "Set an explicit deployment-specific BACKUP_S3_PREFIX. See",
      "docs/operations/backup-and-restore.md.",
    ],
  },
  {
    id: "image-store",
    title: "Template image store — [shared] (server + worker)",
    tuning: true,
    comment: [
      "Template image distribution between hosts. With no bucket, images are",
      "copied between the owner's own hosts through the server (peer mode).",
      "Setting IMAGE_S3_BUCKET plus both keys turns on S3 mode (R2, MinIO, S3).",
      "Use a dedicated bucket-scoped key, never BACKUP_S3_*. Set the same values",
      "on server AND worker. See docs/operations/templates.md#image-store.",
    ],
  },
  {
    id: "auth",
    title: "Auth — [server-only]",
    always: true,
  },
  {
    id: "admin",
    title: "Admin + signup — [server-only]",
    always: true,
  },
  {
    id: "smtp",
    reuseFromEnv: true,
    title: "Email (SMTP) — [shared]",
    prompt: "Configure outgoing email (SMTP)?",
    default: true,
    requiredWhen: {
      key: "SIGNUP_ENABLED",
      equals: "true",
      because:
        "public signup is enabled, and Better-Auth enforces email verification — " +
        "the server refuses to boot in production without SMTP",
    },
    comment: [
      "REQUIRED if SIGNUP_ENABLED=true — Better-Auth enforces email verification",
      "on signup, and the server refuses to boot in production without it.",
      "Local dev: docker run -d -p 1025:1025 -p 8025:8025 axllent/mailpit",
      "  then set SMTP_HOST=localhost, SMTP_PORT=1025, open http://localhost:8025",
    ],
  },
  {
    id: "push",
    title: "Web Push (VAPID) — [server-only]",
    prompt: "Enable web push notifications?",
    default: false,
    comment: [
      "Optional — the app runs fine without these. Set ALL THREE or none.",
      "The keypair is generated for you by `pnpm generate:secrets`; you supply",
      "VAPID_SUBJECT, a real mailto: or https: URL push services use to reach",
      "YOU about delivery problems.",
    ],
  },
  {
    id: "translation",
    reuseFromEnv: true,
    title: "Translation provider — [shared]",
    prompt: "Enable i18n bundle translation?",
    default: false,
    comment: [
      "Used by `pnpm i18n:translate`.",
      "The app boots without these; the worker throws on the first job if the",
      "chosen provider's key is missing. Default provider is `openrouter` with",
      "`anthropic/claude-haiku-4-5` (~$0.05 for a full UI bundle).",
    ],
  },
  {
    id: "sandbox-relay",
    title: "Sandbox host relay — [server]",
    file: "root",
    tuning: true,
    comment: [
      "Outbound WebSocket relay for trusted sandbox node daemons",
      "(`apps/server/src/sandbox-relay`), always enabled with host-plane authentication.",
    ],
  },
  {
    id: "template-builds",
    title: "Template builds — [server]",
    file: "root",
    tuning: true,
    comment: [
      "Recipe/Dockerfile template builds in managed build VMs. On by default",
      "(TEMPLATE_BUILDS=auto) whenever image distribution is on; every knob is",
      "documented in docs/guide/template-builds.md.",
    ],
  },
  {
    id: "data-encryption",
    title: "Data encryption root key — [shared] (server + worker)",
    // Entropy like BETTER_AUTH_SECRET: always generated, so a standard deploy
    // has webhooks and CLI logins without an extra step.
    always: true,
    comment: [
      "DATA_ENCRYPTION_KEY is the one deployment-wide root key for data at rest.",
      "Each purpose (webhook endpoint secrets, the CLI-login vault) derives its own",
      "sub-key with HKDF-SHA256. The server and the worker MUST share the same value;",
      "unset turns webhooks and CLI logins off. Store it apart from database",
      "backups: losing it makes every value encrypted under it unrecoverable.",
      "Rotate via DATA_ENCRYPTION_KEY_PREVIOUS; see",
      "docs/operations/production-hardening.md.",
    ],
  },
  {
    id: "credential-vault",
    title: "CLI logins (credential vault) — [shared] (server + worker)",
    tuning: true,
    comment: [
      "Owners' CLI login values are encrypted in a write-only vault under sub-keys",
      "of DATA_ENCRYPTION_KEY. On by default: the feature is available whenever",
      "DATA_ENCRYPTION_KEY is set. Set CREDENTIALS_ENABLED=false to turn it off",
      "(existing values still settle). See docs/design/credential-vault.md.",
    ],
  },
  {
    id: "webhooks",
    title: "Outbound webhooks — [shared] (server + worker)",
    prompt: "Enable outbound webhooks (signed event deliveries to owner endpoints)?",
    default: true,
    comment: [
      "Endpoint signing secrets are encrypted under a sub-key of DATA_ENCRYPTION_KEY",
      "(data-encryption section above); without it webhooks are off.",
      "The worker needs outbound internet access. Private destinations are",
      "refused unless allowlisted below; see docs/guide/webhooks.md and",
      "docs/operations/production-hardening.md § Webhook egress.",
    ],
  },
  {
    id: "ratelimit",
    title: "Rate limiting — [server-only]",
    tuning: true,
    comment: [
      "Three named budgets (AUTH, RPC, EMAIL), two knobs",
      "each. Each budget describes its family's reference member; every other",
      "limiter in the family scales with it at its designed ratio, so setting",
      "a budget re-tunes the whole family coherently. Defaults are sensible;",
      "tighter is not safer — if a surface 429s legitimate users, split the",
      "surface instead of shrinking a budget. The native /v1 SDK API has three",
      "separate absolute budgets (RATE_LIMIT_SDK_*), one per dimension, that do",
      "not scale with any family. See docs/operations/production-hardening.md.",
    ],
  },
  {
    id: "limits",
    title: "Cache limits — [server-only]",
    tuning: true,
    comment: ["Optional tuning. Sensible defaults are built in."],
  },
  // --- apps/web/.env ---
  {
    id: "web",
    title: "Web app (build-time, public)",
    file: "web",
    always: true,
    comment: [
      "These are BUILD-TIME client vars — they are inlined into the browser",
      "bundle and are therefore public. Never put a secret here.",
    ],
  },
];

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------

export const ENV_VARS: EnvVar[] = [
  // --- core ----------------------------------------------------------------
  {
    key: "DATABASE_URL",
    group: "core",
    source: "prompt",
    required: true,
    omittable: true,
    secret: true,
    prompt: "PostgreSQL connection string",
    hint: "e.g. postgresql://user:password@host:5432/dbname — or leave blank to omit and set it on the platform",
    example: "postgresql://postgres:password@localhost:5432/wssp",
    exampleSet: true,
  },
  {
    key: "REDIS_URL",
    group: "core",
    source: "prompt",
    required: true,
    omittable: true,
    secret: true,
    prompt: "Redis connection string",
    hint: "e.g. redis://default:password@host:6379 (BullMQ + rate limiting) — or leave blank to omit and set it on the platform",
    example: "redis://localhost:6379",
    exampleSet: true,
  },
  {
    key: "DATABASE_POOL_MAX",
    group: "core",
    source: "default",
    default: "10",
    advanced: true,
    comment: [
      "Max connections in this process's Postgres pool (node-postgres `max`).",
      "Default 10 matches the driver default — raise it only against the",
      "database's connection budget, since every server/worker replica holds its own pool.",
      "Every server/worker replica holds its own pool against the same database.",
      "Each server process also opens at most 2 more, outside this pool, for the CLI connect audit.",
    ],
  },

  // --- runtime -------------------------------------------------------------
  {
    key: "WSSP_INSTANCE_ID",
    group: "runtime",
    source: "manual",
    hidden: true,
    comment: [
      "Fresh runtime-generated process UUID shared by admission and heartbeats; never operator-configure or reuse it.",
    ],
  },
  {
    key: "MIGRATE_ON_START",
    hidden: true,
    group: "runtime",
    source: "default",
    inSchema: false,
    default: "true",
    choices: [{ value: "true" }, { value: "false" }],
    comment: [
      "Apply committed migrations before startup; false waits for the leader. External workers use false.",
    ],
  },
  {
    key: "DEV_POSTGRES_PORT",
    group: "core",
    source: "default",
    inSchema: false,
    hidden: true,
    default: "5432",
    comment: ["Local Compose loopback port. Setup mirrors it into the local DATABASE_URL."],
  },
  {
    key: "DEV_REDIS_PORT",
    group: "core",
    source: "default",
    inSchema: false,
    hidden: true,
    default: "6379",
    comment: ["Local Compose loopback port. Setup mirrors it into the local REDIS_URL."],
  },
  {
    key: "BACKUP_SCHEDULE",
    group: "backups",
    source: "default",
    inSchema: false,
    hidden: true,
    default: "off",
    choices: [{ value: "off" }, { value: "daily" }],
    comment: ["Opt-in UTC daily writer schedule; requires BACKUP_ENABLED=true."],
  },
  {
    key: "BACKUP_HOUR_UTC",
    group: "backups",
    source: "default",
    inSchema: false,
    hidden: true,
    default: "3",
    comment: ["Daily snapshot hour in UTC (0-23)."],
  },
  {
    key: "BACKUP_KEEP",
    group: "backups",
    source: "default",
    inSchema: false,
    hidden: true,
    default: "14",
    comment: [
      "Daily local snapshot retention in days (1-365). Pre-migration snapshots default to five per label; --keep overrides.",
    ],
  },
  {
    key: "NODE_ENV",
    group: "runtime",
    source: "default",
    default: "development",
    choices: [{ value: "production" }, { value: "development" }, { value: "test" }],
    example: "production",
    comment: [
      "Set to `production` on every deployed environment. Several env guards",
      "escalate from a warning to a hard boot failure when this is `production`",
      "— that is intentional, do not weaken it to silence a startup error.",
    ],
  },
  {
    key: "BACKUP_ENABLED",
    group: "backups",
    source: "enable",
    default: "false",
    choices: [{ value: "true" }, { value: "false" }],
    example: "false",
    comment: [
      "Automatic backups default off: no migration snapshots, daily writer or",
      "freshness alerts. true (strict true|false): a migrating start FAILS when no",
      "destination (/backups volume or BACKUP_S3_BUCKET) is usable, and pending",
      "migrations get a dump first, a brand-new database included. Explicit",
      "backup commands and restore safety snapshots work either way.",
    ],
  },
  {
    key: "PORT",
    hidden: true,
    group: "runtime",
    source: "default",
    comment: [
      "[server-only] Injected by most platforms. Leave unset unless you are",
      "running the container by hand.",
    ],
  },
  {
    key: "SERVER_PORT",
    hidden: true,
    group: "runtime",
    source: "default",
    default: "3000",
    defaultFrom: "app",
    comment: [
      "[server-only] Raw local runs (`pnpm dev:raw`) and container overrides",
      "only. Leave unset for the default portless dev flow — portless injects",
      "PORT per app. The schema field is optional with no Zod default; 3000 is",
      "the fallback in apps/server/src/index.ts.",
    ],
  },

  {
    key: "WORKER_MODE",
    group: "runtime",
    source: "default",
    default: "embedded",
    comment: [
      "[server-only] embedded runs background jobs in the app (default).",
      "Set external only when deploying a dedicated worker with the same Redis/database.",
      "External mode never silently falls back; /ready fails if consumers disappear.",
    ],
  },

  // --- auth ----------------------------------------------------------------
  {
    key: "BETTER_AUTH_SECRET",
    group: "auth",
    source: "generate",
    generator: "secret32",
    required: true,
    secret: true,
    comment: [
      "REQUIRED, minimum 32 characters. The env validator rejects weak and",
      "placeholder values in production. Rotating this invalidates every",
      "existing session and all product credentials (host tokens, device",
      "credentials, SDK keys) — generate once per environment and keep it stable.",
      "",
      "For LOCAL dev this is filled in for you by `pnpm setup:app`; to mint one",
      "by hand use `pnpm generate:secret` and paste it below. For a PRODUCTION",
      "environment prefer `pnpm generate:secrets`, which generates this along",
      "with the rest of the block and validates the result.",
    ],
  },
  {
    key: "BETTER_AUTH_URL",
    format: "origin",
    group: "auth",
    source: "prompt",
    required: true,
    prompt: "Public app origin (used by auth callbacks and for SEO URLs)",
    hint: "Origin only — no path, query, hash, or credentials. e.g. https://app.example.com",
    example: "https://wssp.localhost",
    exampleSet: true,
  },
  {
    key: "CORS_ORIGIN",
    format: "origin",
    group: "auth",
    source: "manual",
    example: "https://app.example.com",
    comment: [
      "Optional. Set ONLY when the browser app runs on a different origin than",
      "the API (raw web dev, split-origin deploys). Leave unset for the default",
      "same-origin flow. No path, query, or hash.",
    ],
  },
  {
    key: "TRUST_PROXY_HOPS",
    advanced: true,
    group: "auth",
    source: "manual",
    example: "1",
    comment: [
      "Exact number of trusted reverse proxies in front of the server, for the",
      "client IP used as the anonymous rate-limit and audit key. Unset or 0 keys",
      "on the TCP socket peer and ignores X-Forwarded-For. Behind a proxy, 0",
      "puts every client in ONE shared bucket (the proxy's address); set the",
      "exact count (the generated Dokploy config sets 1 for Traefik, or N with",
      "--trust-proxy-hops N; 2 for a Cloudflare Tunnel into Traefik). N >= 1",
      "takes the entry N from the right of X-Forwarded-For plus the socket peer",
      "(an appended :port is stripped); a short or malformed chain falls back",
      "to the socket peer. Above 0, the",
      "app must be reachable only through that proxy chain.",
    ],
  },

  // --- admin ---------------------------------------------------------------
  {
    key: "ADMIN_EMAILS",
    group: "admin",
    source: "prompt",
    required: true,
    prompt: "Admin email addresses (comma-separated)",
    hint: "These accounts get admin privileges. Emails are trimmed and lowercased. Bootstrap-only: after provisioning, admins persist in the database and this list can be cleared. An empty list with SIGNUP_ENABLED=false (the default) only warns at boot — on a fresh install with no admin yet, nobody can become admin.",

    example: "admin@example.com,other@example.com",
  },
  {
    key: "SETUP_KEY",
    group: "admin",
    source: "manual",
    secret: true,
    example: "",
    comment: [
      "First-admin bootstrap without email (optional; unset by default). While",
      "set, `pnpm deploy:generate-admin` prints a one-time set-password link that",
      "creates the FIRST admin when it is opened; once an admin exists it is",
      "refused. 32 to 512 characters (`pnpm generate:secret` makes one). REMOVE",
      "IT after the first admin has signed in; the admin overview's deployment",
      "setup card says so until you do.",
    ],
  },
  {
    key: "MCP_ENABLED",
    hidden: true,
    group: "admin",
    source: "default",
    default: "true",
    example: "true",
    comment: ["Enable the built-in MCP endpoint and its OAuth provider."],
  },
  {
    key: "WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS",
    hidden: true,
    group: "admin",
    source: "default",
    default: "90",
    example: "90",
    comment: [
      "Maximum lifetime of newly minted agent tokens in days (1-3650). Existing tokens are unaffected.",
    ],
  },
  {
    key: "WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY",
    hidden: true,
    group: "admin",
    source: "default",
    default: "true",
    example: "true",
    comment: [
      "Allow no-expiry (unlimited-lifetime) agent tokens. The mint form preselects 90 days.",
      "Turn off to require an expiry within WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS on new tokens",
      "and to refuse existing no-expiry tokens (kept, shown as blocked) until turned back on.",
    ],
  },
  {
    key: "SIGNUP_ENABLED",
    group: "admin",
    source: "confirm",
    confirmDefault: false,
    prompt: "Enable public signup",
    hint: "Default when no signupEnabled app setting exists; admins can override it. On requires SMTP below — email verification is enforced and production refuses to boot without it.",
    default: "false",
    example: "false",
    comment: [
      "Public signup defaults to disabled. The signupEnabled app setting, when",
      "present, overrides this deployment default for signup and the form.",
      "Setting this default to true REQUIRES SMTP below: email verification is",
      "enforced and the server refuses to boot without SMTP.",
    ],
  },

  // --- smtp ----------------------------------------------------------------
  {
    key: "SMTP_HOST",
    group: "smtp",
    source: "prompt",
    required: true,
    prompt: "SMTP host",
    hint: "e.g. smtp.resend.com, smtp.postmarkapp.com, email-smtp.us-east-1.amazonaws.com",
    example: "localhost",
  },
  {
    key: "SMTP_PORT",
    group: "smtp",
    source: "prompt",
    required: true,
    prompt: "SMTP port",
    hint: "587 for STARTTLS (most providers), 465 for implicit TLS, 1025 for a local mailpit sink",
    example: "1025",
  },
  {
    key: "SMTP_USER",
    group: "smtp",
    source: "prompt",
    prompt: "SMTP username (blank if your provider doesn't require auth)",
    example: "",
  },
  {
    key: "SMTP_PASS",
    group: "smtp",
    source: "prompt",
    secret: true,
    prompt: "SMTP password / API key (blank if not required)",
    example: "",
  },
  {
    key: "SMTP_FROM",
    group: "smtp",
    source: "prompt",
    required: true,
    // Excluded from the group's reuse offer: this is the app's own From:
    // identity, so inheriting it sends the new app's mail branded as the old.
    reusable: false,
    prompt: "From: address for outgoing mail",
    hint: 'e.g. "App Name <no-reply@yourdomain.com>". Required whenever SMTP_HOST is set.',
    example: "noreply@example.com",
  },

  // --- data-encryption -------------------------------------------------------
  {
    key: "DATA_ENCRYPTION_KEY",
    group: "data-encryption",
    source: "generate",
    generator: "secret32",
    required: true,
    secret: true,
    comment: [
      "Root key for data at rest: exactly 64 lowercase hex characters (32 random bytes).",
      "Generate with: openssl rand -hex 32. Same value on server and worker. Never derived",
      "from BETTER_AUTH_SECRET; keep it out of database backups.",
    ],
  },
  {
    key: "DATA_ENCRYPTION_KEY_PREVIOUS",
    hidden: true,
    group: "data-encryption",
    source: "manual",
    secret: true,
    hint: "Second root during a rotation (incoming before data-key:promote, outgoing after); remove once data-key:status reports safeToRemove.",
  },

  // --- credential-vault ------------------------------------------------------
  {
    key: "CREDENTIALS_ENABLED",
    group: "credential-vault",
    hidden: true,
    source: "default",
    default: "true",
    choices: [{ value: "true" }, { value: "false" }],
    example: "true",
    comment: [
      "Turn-off switch for CLI logins. Effective only with DATA_ENCRYPTION_KEY set; a",
      "missing key makes logins unavailable but never fails boot. false with the key",
      "present = drain mode (new use refused; captures, deletes and rewraps continue).",
    ],
  },

  {
    key: "CREDENTIAL_MAX_INSTANCES_PER_OWNER",
    group: "credential-vault",
    hidden: true,
    source: "default",
    default: "1000",
    hint: 'Maximum CLI-login account instances one account may have (1-100000), or "unlimited". Checked under the owner lock at every instance create.',
  },

  // --- webhooks --------------------------------------------------------------
  {
    key: "WEBHOOK_ALLOWED_PRIVATE_CIDRS",
    group: "webhooks",
    source: "default",
    default: "",
    hint: "CSV of private CIDRs webhook deliveries may reach (e.g. a tailnet /32). Hard-denied ranges fail at boot.",
  },
  {
    key: "WEBHOOK_ALLOWED_PRIVATE_HOSTS",
    group: "webhooks",
    source: "default",
    default: "",
    hint: "CSV of exact hostnames that may resolve to private addresses (used only when no CIDRs are set).",
  },
  {
    key: "WEBHOOK_TRANSLATION_PREFIXES",
    hidden: true,
    group: "webhooks",
    source: "default",
    default: "",
    hint: "CSV of network-specific NAT64/DNS64 IPv6 prefixes (RFC 6052 lengths /32-/96) on the worker's network; hard-denied for webhook delivery.",
  },
  {
    key: "WEBHOOK_PRIVATE_ALLOWLIST_SCOPE",
    group: "webhooks",
    source: "default",
    default: "admins",
    choices: [{ value: "admins" }, { value: "all" }],
    hint: "Which accounts may use the private allowlist. Keep `admins` unless every account is trusted.",
  },
  {
    key: "WEBHOOK_ALLOW_PLAINTEXT_PRIVATE",
    group: "webhooks",
    source: "default",
    default: "false",
    hint: "Allow http:// to allowlisted private destinations only. Public destinations always need https.",
  },
  {
    key: "WEBHOOK_DELIVERY_CONCURRENCY",
    hidden: true,
    group: "webhooks",
    source: "default",
    default: "8",
    hint: "Concurrent delivery attempts per worker process (1-64).",
  },

  // --- push ----------------------------------------------------------------
  {
    key: "VAPID_PUBLIC_KEY",
    group: "push",
    source: "generate",
    generator: "vapid-public",
    required: true,
  },
  {
    key: "VAPID_PRIVATE_KEY",
    group: "push",
    source: "generate",
    generator: "vapid-private",
    required: true,
    secret: true,
  },
  {
    key: "VAPID_SUBJECT",
    format: "push-subject",
    group: "push",
    source: "prompt",
    required: true,
    prompt: "VAPID contact URI",
    hint: "A mailto: or https: URL push services use to contact YOU about delivery problems. Use a real, monitored address.",
    example: "mailto:you@yourdomain.com",
  },

  // --- image-store (tuning) -----------------------------------------------
  {
    key: "IMAGE_DISTRIBUTION",
    group: "image-store",
    source: "default",
    default: "auto",
    hint: "auto (S3 when a bucket and keys are set, else peer) or off (no image distribution, capture or lease-from-READY).",
  },
  {
    key: "IMAGE_S3_ENDPOINT",
    group: "image-store",
    source: "manual",
    example: "https://ACCOUNT_ID.r2.cloudflarestorage.com",
    hint: "S3 API endpoint (https; http only on loopback). R2: https://<ACCOUNT_ID>.r2.cloudflarestorage.com",
  },
  {
    key: "IMAGE_S3_REGION",
    hidden: true,
    group: "image-store",
    source: "default",
    default: "auto",
    hint: "Bucket region; auto for R2.",
  },
  {
    key: "IMAGE_S3_BUCKET",
    group: "image-store",
    source: "manual",
    example: "",
    hint: "Private bucket for template images. Setting it (plus both keys) turns on S3 mode.",
  },
  {
    key: "IMAGE_S3_ACCESS_KEY_ID",
    group: "image-store",
    source: "manual",
    example: "",
    secret: true,
    hint: "Dedicated key scoped to the image bucket (Object Read and Write).",
  },
  {
    key: "IMAGE_S3_SECRET_ACCESS_KEY",
    group: "image-store",
    source: "manual",
    example: "",
    secret: true,
    hint: "Secret for IMAGE_S3_ACCESS_KEY_ID.",
  },
  {
    key: "IMAGE_S3_FORCE_PATH_STYLE",
    group: "image-store",
    source: "default",
    default: "false",
    hint: "true for MinIO; recommended for R2.",
  },
  {
    key: "IMAGE_S3_PUBLIC_ENDPOINT",
    hidden: true,
    group: "image-store",
    source: "manual",
    example: "",
    hint: "Endpoint host signed into node download/upload URLs (https; http only on loopback). Defaults to IMAGE_S3_ENDPOINT.",
  },
  {
    key: "IMAGE_S3_PREFIX",
    group: "image-store",
    source: "default",
    default: "images",
    hidden: true,
    hint: "Object key prefix inside the bucket.",
  },
  {
    key: "IMAGE_S3_PRESIGN_TTL_SECONDS",
    hidden: true,
    group: "image-store",
    source: "default",
    default: "600",
    hint: "Lifetime of presigned node URLs: 60-3600 seconds.",
  },
  {
    key: "IMAGE_STORE_ENCRYPTION",
    group: "image-store",
    source: "default",
    default: "off",
    hint: "on encrypts stored images with per-image data keys (AES-256-GCM).",
  },
  {
    key: "IMAGE_STORE_ENCRYPTION_KEY",
    group: "image-store",
    source: "manual",
    example: "",
    secret: true,
    hint: "base64 of 32 random bytes (openssl rand -base64 32). Required when IMAGE_STORE_ENCRYPTION=on.",
  },
  {
    key: "IMAGE_GC_GRACE_DAYS",
    hidden: true,
    group: "image-store",
    source: "default",
    default: "7",
    hint: "Days an unreferenced stored image is kept before deletion: 0-90.",
  },
  {
    key: "IMAGE_STORE_MAX_GIB_PER_ACCOUNT",
    hidden: true,
    group: "image-store",
    source: "default",
    default: "50",
    hint: "Stored image GiB per account (0-1048576) or unlimited. Admins may lower it per account.",
  },
  {
    key: "IMAGE_DOWNLOADS_PER_HOUR_MAX",
    hidden: true,
    group: "image-store",
    source: "default",
    default: "120",
    hint: "Image downloads per account per hour (0-100000) or unlimited.",
  },
  {
    key: "SANDBOX_OFFLOAD",
    hidden: true,
    group: "image-store",
    source: "default",
    default: "auto",
    hint: "auto (offload stopped sandbox disks to S3 when the image store is in S3 mode and DATA_ENCRYPTION_KEY is set) or off (no new offloads; offloaded sandboxes stay restorable).",
  },
  {
    key: "SANDBOX_OFFLOAD_MAX_GIB_PER_ACCOUNT",
    hidden: true,
    group: "image-store",
    source: "default",
    default: "200",
    hint: "Stored offloaded-disk GiB per account: 1-1048576. Admins may lower it per account.",
  },
  {
    key: "SANDBOX_OFFLOAD_GIB_PER_DAY",
    hidden: true,
    group: "image-store",
    source: "default",
    default: "500",
    hint: "Offload upload GiB per account per rolling day: 1-1048576. Restores are never refused.",
  },
  {
    key: "SANDBOX_OFFLOAD_SHRED_GRACE_HOURS",
    hidden: true,
    group: "image-store",
    source: "default",
    default: "24",
    hint: "Hours a destroyed sandbox's offloaded disk key is kept before shredding: 1-720.",
  },

  // --- backups -------------------------------------------------------------
  {
    key: "BACKUP_S3_BUCKET",
    group: "backups",
    source: "prompt",
    required: true,
    reusable: false,
    prompt: "Backup bucket name",
    hint: "Private bucket for pg_dump custom-format dumps. Use a dedicated bucket.",
    example: "",
  },
  {
    key: "BACKUP_S3_ACCESS_KEY_ID",
    group: "backups",
    source: "prompt",
    required: true,
    secret: true,
    prompt: "Backup S3 access key ID",
    hint: "Required for dump writers. Must be a distinct GetObject/PutObject/AbortMultipartUpload key.",
    example: "",
  },
  {
    key: "BACKUP_S3_SECRET_ACCESS_KEY",
    group: "backups",
    source: "prompt",
    required: true,
    secret: true,
    prompt: "Backup S3 secret access key",
    example: "",
  },
  {
    key: "BACKUP_MONITOR_S3_ACCESS_KEY_ID",
    group: "backups",
    source: "prompt",
    required: true,
    secret: true,
    prompt: "Backup-monitor S3 access key ID",
    hint: "ListBucket-only key for the worker freshness check; never reuse the dump read/write key.",
    example: "",
  },
  {
    key: "BACKUP_MONITOR_S3_SECRET_ACCESS_KEY",
    group: "backups",
    source: "prompt",
    required: true,
    secret: true,
    prompt: "Backup-monitor S3 secret access key",
    example: "",
  },
  {
    key: "BACKUP_S3_REGION",
    group: "backups",
    source: "prompt",
    default: "auto",
    prompt: "Backup S3 region",
    hint: '"auto" for Cloudflare R2; a real region for AWS S3',
    example: "auto",
  },
  {
    key: "BACKUP_S3_ENDPOINT",
    group: "backups",
    source: "prompt",
    prompt: "Backup S3 endpoint URL (blank for AWS S3; required for R2/MinIO/B2/Spaces)",
    example: "",
  },
  {
    key: "BACKUP_S3_PREFIX",
    group: "backups",
    source: "prompt",
    required: true,
    prompt: "Deployment-specific backup object prefix",
    hint: "Explicit nonempty prefix unique to this deployment; use the identical prefix for writer and monitor.",
    example: "",
  },
  {
    key: "BACKUP_S3_FORCE_PATH_STYLE",
    hidden: true,
    group: "backups",
    source: "default",
    default: "false",
    example: "false",
  },
  {
    key: "BACKUP_S3_SSE",
    hidden: true,
    group: "backups",
    source: "default",
    inSchema: false,
    example: "",
    comment: [
      "Leave empty for R2 and most S3-compatible providers. Set to AES256 only",
      "for AWS S3 when you want SSE-S3 on backup objects.",
    ],
  },
  {
    key: "BACKUP_MAX_AGE_HOURS",
    hidden: true,
    group: "backups",
    source: "default",
    default: "36",
    example: "36",
    comment: [
      "Backup freshness check (worker, every 6h): alert admins and flag the",
      "admin dashboard when the newest dump in BACKUP_S3_BUCKET is older than",
      "this many hours by its embedded UTC snapshot time. 36 tolerates one missed run.",
    ],
  },
  {
    key: "BACKUP_HEARTBEAT_URL",
    hidden: true,
    group: "backups",
    source: "default",
    inSchema: false,
    example: "",
    comment: [
      "Optional dead-man's-switch ping. After a dump uploads successfully,",
      "the canonical S3 CLI sends an HTTP GET to this URL (including upload-only retries; healthchecks.io,",
      "Cronitor, Uptime Kuma push, or any self-hosted endpoint). Leave empty to",
      "skip. The service you point it at alerts when the ping stops arriving.",
    ],
  },

  // --- translation ---------------------------------------------------------
  {
    key: "PUBLIC_APP_URL",
    hidden: true,
    format: "origin",
    group: "translation",
    source: "manual",
    example: "https://app.example.com",
    comment: [
      "Optional origin metadata sent to translation providers such as",
      "OpenRouter. Not used for auth — it is declared in the shared schema, so",
      "a worker-only deploy can set it.",
    ],
  },
  {
    key: "TRANSLATION_PROVIDER",
    group: "translation",
    source: "prompt",
    default: "openrouter",
    prompt: "Translation provider",
    choices: [
      {
        value: "openrouter",
        label: "OpenRouter (default)",
        description: "Cheapest path to claude-haiku-4-5, plus multi-model access from one account",
      },
      {
        value: "anthropic",
        label: "Anthropic direct",
        description: "Calls the Anthropic API directly with ANTHROPIC_API_KEY",
      },
    ],
    example: "openrouter",
  },
  {
    key: "OPENROUTER_API_KEY",
    group: "translation",
    source: "prompt",
    secret: true,
    prompt: "OpenRouter API key (blank if using anthropic)",
    hint: "Required when TRANSLATION_PROVIDER=openrouter",
    example: "",
  },
  {
    key: "ANTHROPIC_API_KEY",
    group: "translation",
    source: "prompt",
    secret: true,
    prompt: "Anthropic API key (blank if using openrouter)",
    hint: "Required when TRANSLATION_PROVIDER=anthropic",
    example: "",
  },
  {
    key: "TRANSLATION_MODEL",
    hidden: true,
    group: "translation",
    source: "manual",
    example: "anthropic/claude-haiku-4-5",
    comment: [
      "Per-call model override. Defaults to `anthropic/claude-haiku-4-5`",
      "(OpenRouter) or `claude-haiku-4-5` (Anthropic direct) when unset.",
    ],
  },

  // --- sandbox-relay (tuning) ----------------------------------------------
  {
    key: "SANDBOX_MAX_HOSTS_PER_OWNER",
    group: "sandbox-relay",
    source: "default",
    default: "20",
    hint: 'Maximum hosts one account may have (1-100000, including hosts pending deletion), or "unlimited". Enforced at host creation and device-login enrollment.',
  },
  {
    key: "SANDBOX_MAX_SOCKETS_PER_HOST",
    group: "sandbox-relay",
    source: "default",
    default: "2",
    hint: "Maximum concurrent node-daemon WebSockets per host on one server process (1-64). Extra connections are refused with a protocol error naming this limit.",
  },
  {
    key: "SANDBOX_EGRESS_BLOCKLIST",
    hidden: true,
    group: "sandbox-relay",
    source: "manual",
    example: "203.0.113.0/24,bad.example",
    hint: "Deployment-wide egress blocklist pushed to every host's egress guard: IPv4 CIDRs and domains, comma or space separated. An invalid list is logged at boot and never sent (hosts keep their last list).",
  },
  {
    key: "WSSP_CLI_RELEASE_BASE_URL",
    hidden: true,
    group: "sandbox-relay",
    source: "manual",
    example: "https://downloads.example.com/wssp/v1.0.0",
    hint: "Where /install.sh downloads the wssp release archives and sha256.sum from (a mirror of this version's release). Unset: this version's GitHub Release. Plain https URL only.",
  },

  {
    key: "WSSP_CA_FILE",
    hidden: true,
    group: "sandbox-relay",
    source: "default",
    example: "",
    comment: [
      "Optional PEM CA file read by the Rust CLI, not Node processes.",
      "Adds to webpki roots for host run, enroll, drain and undrain.",
      "See docs/guide/hosts.md for private CA and local Caddy setup.",
    ],
  },
  {
    key: "WSSP_INCUS_DAEMON_LOCK_DIR",
    hidden: true,
    group: "sandbox-relay",
    source: "default",
    example: "",
    comment: [
      "Dev/test-only seam read by the Rust node daemon",
      "(crates/sandbox-runtime), not by the Zod schemas: relocates the",
      "administrator-provisioned shared daemon lock directory from",
      "/var/lib/wssp/incus-daemon-locks for shim-driven harnesses. The",
      "relocated directory faces the identical ownership/mode validation.",
      "Never set in production. See docs/design/native-http-contract.md.",
    ],
  },
  {
    key: "WSSP_TEST_SHARED_INCUS",
    hidden: true,
    group: "sandbox-relay",
    source: "default",
    example: "",
    comment: [
      "Test-only override read by DEBUG builds of the Rust node daemon",
      "(wssp host run), not by the Zod schemas: 1 skips the",
      "one-daemon-per-Incus-server check so the local chaos stack can run",
      "two daemons on one Incus server. Release builds compile it out; the",
      "daemon refuses it unless the control plane is loopback and logs a",
      "warning. Never set in production. See docs/guide/hosts.md.",
    ],
  },
  {
    key: "WSSP_SURFACE_ROOT",
    hidden: true,
    group: "sandbox-relay",
    source: "default",
    example: "",
    comment: [
      "Dev/test-only seam read by the Rust surface harness",
      "(crates/sandbox-runtime/src/bin/incus-surface.rs), not by the Zod",
      "schemas: relocates the owner-validated, mode-0700 surface state",
      "root (run locks and per-run state dirs) for shim-driven",
      "integration tests. The relocated root faces the identical",
      "ownership/mode validation. Never set in production. See",
      "docs/design/native-http-contract.md.",
    ],
  },
  {
    key: "TRANSFER_SPOOL_DIR",
    group: "sandbox-relay",
    source: "default",
    default: ".data/transfers",
    hint: "Private persistent server spool directory; Compose mounts the server-data volume at /app/.data. One server process only.",
  },
  {
    key: "TRANSFER_MAX_BYTES",
    group: "sandbox-relay",
    source: "default",
    default: "1073741824",
    hint: "Maximum transfer length in bytes (default and hard ceiling 1 GiB, the node daemon's limit; lower values allowed, higher ones fail startup).",
  },
  {
    key: "TRANSFER_DISK_BYTES",
    group: "sandbox-relay",
    source: "default",
    default: "10737418240",
    hint: "Aggregate reserved transfer bytes (default 10 GiB); provision disk plus filesystem overhead.",
  },
  {
    key: "TRANSFER_OWNER_ACTIVE",
    group: "sandbox-relay",
    source: "default",
    default: "4",
    hint: "Maximum open transfers per owner; a settled upload or a fully delivered download frees its slot at once.",
  },
  {
    key: "TRANSFER_GLOBAL_ACTIVE",
    group: "sandbox-relay",
    source: "default",
    default: "16",
    hint: "Maximum open transfers and in-flight spool operations per server.",
  },
  {
    key: "TRANSFER_IDLE_SECONDS",
    group: "sandbox-relay",
    source: "default",
    default: "900",
    hint: "Idle expiry in seconds; successful chunks and reads refresh it.",
  },
  {
    key: "TRANSFER_ABSOLUTE_SECONDS",
    group: "sandbox-relay",
    source: "default",
    default: "3600",
    hint: "Absolute transfer expiry in seconds; never extended by activity.",
  },

  {
    key: "SANDBOX_REQUEST_HMAC_SECRET",
    group: "sandbox-relay",
    source: "generate",
    generator: "secret32",
    required: true,
    secret: true,
    comment: [
      "REQUIRED server-only master for future keyed sandbox request/config digests.",
      "Generate with secret32 via pnpm generate:secrets (32 random bytes, lowercase hex).",
      "At least 64 even hex characters; weak/placeholder values fail in every environment.",
      "Share one stable key across server replicas; store/backup externally in production.",
      "Dev: `vite dev` runs SSR server functions, so web#dev gets it too (apps/web/turbo.json).",
      "Never expose it to hosts, guests or logs. Rotation requires quiescence and retirement",
      "of retained configs under the old key; restoring the original key is recovery.",
    ],
  },
  {
    key: "SANDBOX_CONNECT_MAX_BYTES_PER_SECOND",
    hidden: true,
    group: "sandbox-relay",
    source: "default",
    default: "8388608",
    hint: "CLI connect data rate per connection and direction: 65536..1073741824 bytes/s (default 8 MiB/s).",
  },
  {
    key: "SANDBOX_CREATE_CONNECT_BUDGET_POINTS",
    group: "sandbox-relay",
    source: "default",
    default: "300",
    hint: "Owner create/connect procedure budget: 1..10000 points.",
  },
  {
    key: "SANDBOX_CREATE_CONNECT_BUDGET_WINDOW_SECONDS",
    group: "sandbox-relay",
    source: "default",
    default: "60",
    hint: "Owner create/connect budget window: 60..3600 seconds.",
  },
  {
    key: "IMAGE_RELAY_SPOOL_DIR",
    hidden: true,
    group: "sandbox-relay",
    source: "default",
    default: ".data/image-relay",
    hint: "Transient spool for relayed peer image parts; keep it outside TRANSFER_SPOOL_DIR (transfer recovery refuses foreign entries).",
  },
  {
    key: "IMAGE_RELAY_SPOOL_BYTES",
    hidden: true,
    group: "sandbox-relay",
    source: "default",
    default: "2147483648",
    hint: "Total bytes of relayed image parts held at once on this server.",
  },
  {
    key: "IMAGE_RELAY_MAX_ACTIVE",
    hidden: true,
    group: "sandbox-relay",
    source: "default",
    default: "4",
    hint: "Concurrent relayed peer image copies on this server (1-256).",
  },
  {
    key: "SANDBOX_CREATE_PROVISION_MAX_MS",
    hidden: true,
    group: "sandbox-relay",
    source: "default",
    default: "7200000",
    hint: "Longest a create may take to reach READY (image download included) before the server reclaims it: 600000-86400000 ms.",
  },
  {
    key: "SANDBOX_MAX_TIMEOUT_MS",
    group: "sandbox-relay",
    source: "default",
    default: "86400000",
    hint: "Deployment maximum sandbox lease: 300000..2073600000 ms, or unlimited (allows timeoutMs 0).",
  },
  {
    key: "SANDBOX_CAPACITY_WAIT_MAX_MS",
    group: "sandbox-relay",
    source: "default",
    default: "3600000",
    hint: 'Longest a pool create may wait for capacity (waitForCapacityMs): 0..2073600000 ms (0 disables waits), or "unlimited". Pools may set a lower limit.',
  },
  {
    key: "SANDBOX_CAPACITY_QUEUE_MAX_PER_KEY",
    group: "sandbox-relay",
    source: "default",
    default: "16",
    hint: 'Waiting pool creates one SDK key may hold across all pools (0-100000), or "unlimited". Pools may set a lower limit.',
  },
  {
    key: "SANDBOX_CAPACITY_QUEUE_MAX_PER_OWNER",
    group: "sandbox-relay",
    source: "default",
    default: "64",
    hint: 'Waiting pool creates one account may hold across all pools (0-100000), or "unlimited". Pools may set a lower per-pool limit.',
  },
  {
    key: "CAPACITY_RETRY_AFTER_SECONDS",
    hidden: true,
    group: "sandbox-relay",
    source: "default",
    default: "30",
    hint: "Retry-After (1-86400 s) on /v1 capacity, quota and pool 409s with retryable: true. Never sent when retryable is false. Advisory backoff only.",
  },

  // --- template-builds (tuning; hidden from .env.example) ----------------
  {
    key: "TEMPLATE_BUILDS",
    hidden: true,
    group: "template-builds",
    source: "default",
    default: "auto",
    choices: [{ value: "auto" }, { value: "off" }],
    hint: "`auto` runs template builds when image distribution is on and the lease ceiling leaves room; `off` disables them. Never fails boot.",
  },
  {
    key: "TEMPLATE_BUILD_MAX_MINUTES",
    hidden: true,
    group: "template-builds",
    source: "default",
    default: "60",
    hint: "Longest build (1-1440 min). Clamped so build + capture window + 60 min storage + 15 min fits SANDBOX_MAX_TIMEOUT_MS.",
  },
  {
    key: "TEMPLATE_BUILD_MAX_CONCURRENT_PER_ACCOUNT",
    hidden: true,
    group: "template-builds",
    source: "default",
    default: "2",
    hint: 'Builds one account may run at once, AWAITING_CONTEXT included (0-100000), or "unlimited". Admins may set a lower per-account limit.',
  },
  {
    key: "TEMPLATE_BUILD_MINUTES_PER_MONTH",
    hidden: true,
    group: "template-builds",
    source: "default",
    default: "1000",
    hint: 'Build minutes per account per UTC month (0-100000000), or "unlimited". Admins may set a lower per-account limit.',
  },
  {
    key: "TEMPLATE_BUILD_CAPTURE_WINDOW_MINUTES",
    hidden: true,
    group: "template-builds",
    source: "default",
    default: "60",
    hint: "Time allowed to capture a finished build VM (5-720 min); not charged. The build lease adds it, a 60 min storage window and 15 min to the build timeout.",
  },
  {
    key: "TEMPLATE_BUILD_CONTEXT_MAX_BYTES",
    hidden: true,
    group: "template-builds",
    source: "default",
    default: "1073741824",
    hint: "Largest COPY context of one build; clamped to TRANSFER_MAX_BYTES and the staged budgets.",
  },
  {
    key: "TEMPLATE_BUILD_CONTEXT_STAGED_BYTES_PER_ACCOUNT",
    hidden: true,
    group: "template-builds",
    source: "default",
    default: "2147483648",
    hint: "Staged (not yet adopted) context bytes one account may hold on this server; clamped to the global budget.",
  },
  {
    key: "TEMPLATE_BUILD_CONTEXT_STAGED_BYTES",
    hidden: true,
    group: "template-builds",
    source: "default",
    default: "8589934592",
    hint: "Staged context bytes all accounts may hold on this server, beside the transfer spool.",
  },

  // --- ratelimit (tuning) --------------------------------------------------
  // Three named budgets replace the 34 per-surface knobs this group used to
  // carry. Family-scaling semantics: a budget describes its family's
  // REFERENCE member; every other member keeps its ratio to that reference,
  // so POINTS multiplies every member's points by (provided/reference) and
  // WINDOW_SECONDS multiplies every member's window AND block duration by the
  // same factor. Burst/sustained ratios, bucket keying, and fail-open vs
  // fail-closed stay fixed in code (packages/api/src/lib/rate-limit-families.ts
  // + apps/server/src/rate-limit.ts). Tighter is not safer — if one surface
  // 429s legitimate users, split the surface instead of shrinking a budget.
  // Native /v1 is the exception: RATE_LIMIT_SDK_{IP,KEY,OWNER}_POINTS are
  // absolute per-dimension budgets over a fixed 60 s window (owner ruling
  // 2026-09-26), not family members.
  // Family tables live in packages/api/src/lib/rate-limit-families.ts.
  {
    key: "RATE_LIMIT_AUTH_POINTS",
    group: "ratelimit",
    advanced: true,
    source: "default",
    default: "30",
    hint: "Auth family reference: requests per IP per window on the general /api/auth/* surface (password reset, verification, session ops). Setting it rescales the whole fail-closed auth family at each member's designed ratio: credential 10, credential-burst 3/10s, signup 10/h, 2FA-OTP 3/15min.",
  },
  {
    key: "RATE_LIMIT_AUTH_WINDOW_SECONDS",
    group: "ratelimit",
    advanced: true,
    source: "default",
    default: "60",
    hint: "Window (seconds) for the auth family reference. Scales every auth-family window AND block duration by the same factor.",
  },
  {
    key: "RATE_LIMIT_RPC_POINTS",
    group: "ratelimit",
    advanced: true,
    source: "default",
    default: "100",
    hint: "RPC family reference: requests per user (per IP signed out) per window on /rpc/*. /ready (60) and SSR (300) scale with it. Native /v1 does not; it has its own RATE_LIMIT_SDK_* budgets. One batched request can carry up to ORPC_BATCH_MAX_SIZE procedures.",
  },
  {
    key: "RATE_LIMIT_RPC_WINDOW_SECONDS",
    group: "ratelimit",
    advanced: true,
    source: "default",
    default: "60",
    hint: "Window (seconds) for the RPC family reference; scales the /ready and SSR windows with it.",
  },
  {
    key: "RATE_LIMIT_SDK_IP_POINTS",
    group: "ratelimit",
    advanced: true,
    source: "default",
    default: "300",
    hint: "Native /v1 SDK API: requests per client IP per 60 s, charged before authentication (covers /v1/openapi.json). Absolute value, positive integer; does not scale with RATE_LIMIT_RPC_*. Fails closed.",
  },
  {
    key: "RATE_LIMIT_SDK_KEY_POINTS",
    group: "ratelimit",
    advanced: true,
    source: "default",
    default: "100",
    hint: "Native /v1 SDK API: requests per SDK key per 60 s, charged after authentication. Absolute value, positive integer; does not scale with RATE_LIMIT_RPC_*. Fails closed.",
  },
  {
    key: "RATE_LIMIT_SDK_OWNER_POINTS",
    group: "ratelimit",
    advanced: true,
    source: "default",
    default: "300",
    hint: "Native /v1 SDK API: requests per owner (all of one user's SDK keys together) per 60 s, charged after the key budget. Absolute value, positive integer; does not scale with RATE_LIMIT_RPC_*. Fails closed.",
  },
  {
    key: "RATE_LIMIT_EMAIL_POINTS",
    group: "ratelimit",
    advanced: true,
    source: "default",
    default: "3",
    hint: "Email family reference: mails per RECIPIENT per window on the anonymous send-mail endpoints (verification resend, password reset). Signup (6) and sign-in-triggered mails (10) scale with it. Keyed on the mailbox, so rotating IPs cannot flood one inbox. 0 disables the whole recipient family.",
  },
  {
    key: "RATE_LIMIT_EMAIL_WINDOW_SECONDS",
    group: "ratelimit",
    advanced: true,
    source: "default",
    default: "3600",
    hint: "Window (seconds) for the email family reference; scales all three recipient buckets with it.",
  },

  // --- images (tuning) -----------------------------------------------------

  // --- limits (tuning) -----------------------------------------------------
  {
    key: "SSR_CACHE_TTL_SECONDS",
    advanced: true,
    group: "limits",
    source: "default",
    default: "60",
    comment: [
      "In-memory SSR HTML cache for anonymous GETs of public routes. 0 disables",
      "it. Public content edits can take up to this long to appear live.",
      "Public content edits can take up to this long to appear live.",
    ],
  },

  // --- apps/web/.env -------------------------------------------------------
  {
    key: "VITE_APP_NAME",
    group: "web",
    file: "web",
    source: "default",
    default: "WS Sandbox Proxy",
    // Not a Zod default: web.ts declares this `.optional()` and applies "WS Sandbox Proxy"
    // through a getter on the exported env object.
    defaultFrom: "app",
    example: "WS Sandbox Proxy",
    comment: ["Display name used in the app shell title/header; defaults to WS Sandbox Proxy."],
  },
  {
    key: "VITE_SERVER_URL",
    group: "web",
    file: "web",
    source: "manual",
    example: "http://localhost:3000",
    comment: [
      "API origin. Defaults to window.location.origin at runtime — leave unset",
      "for the portless/Vite proxy flow. No path, query string, or hash.",
    ],
  },
  {
    key: "VITE_DEV_PORT",
    group: "web",
    file: "web",
    source: "manual",
    example: "3001",
    comment: [
      "Raw dev-server knobs. Leave unset with portless, which assigns ports and",
      "proxies /api, /rpc, /sw, /ws. Without portless, Vite listens on",
      "3001 and proxies to 3000.",
    ],
  },
  {
    key: "VITE_DEV_SERVER_URL",
    group: "web",
    file: "web",
    source: "manual",
    example: "http://localhost:3000",
  },
  {
    key: "VITE_DOCS_URL",
    group: "web",
    file: "web",
    source: "manual",
    example: "https://docs.example.com/wssp",
    comment: [
      "Base URL of the product docs: where the repository's docs/ directory is",
      "published (a docs site, or a repository browser URL ending in /docs).",
      "The dashboard links pages below it, e.g. <base>/operations/templates.md.",
      "Leave unset to show doc paths as plain text instead of links.",
    ],
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function groupsForFile(file: EnvFile): EnvGroup[] {
  return ENV_GROUPS.filter((g) => (g.file ?? "root") === file);
}

export function varsInGroup(groupId: string): EnvVar[] {
  return ENV_VARS.filter((v) => v.group === groupId);
}
