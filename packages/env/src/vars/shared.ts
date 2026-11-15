import { z } from "zod";
import { isWeakSecret } from "../secret-strength.js";
import { httpUrl, originUrl, secureServiceUrl } from "../url.js";

// ---------------------------------------------------------------------------
// Worker-safe variable DECLARATIONS.
//
// Split out of ../shared.ts so that tooling can read the key set without
// importing that module — which runs validation that throws when the variables
// are unset (exactly the situation in CI). Nothing in this directory may have
// import side effects. Dotenv loading lives in ../load-dotenv.ts / ../root-env.ts
// and is imported only from process entrypoints.
//
// `pnpm env:check` (scripts/lib/env-schema.ts) enumerates every module in this
// directory and takes `Object.keys()` of each exported declaration object, so a
// new variable is visible to the manifest check the moment it is added here.
// Declaring one inline in ../shared.ts instead would hide it — the check fails
// on that too.
// ---------------------------------------------------------------------------

export const strictBooleanFlag = (defaultValue: boolean = false) =>
  z
    .enum(["true", "false"])
    .default(defaultValue ? "true" : "false")
    .transform((value) => value === "true");

export const sharedVars = {
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),
  // Fresh per-process identity from entrypoint admission; absent in local dev/tests.
  WSSP_INSTANCE_ID: z.uuid().optional(),
  // Max connections in this process's Postgres pool (node-postgres `max`).
  // Default 10 matches the driver default — raise it only against the
  // database's connection budget, since every server/worker replica holds its
  // own pool. Transaction-mode poolers need a pool size that fits the budget.
  DATABASE_POOL_MAX: z.coerce.number().int().positive().default(10),
  NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
  // ---- Automatic database backups are opt-in: migration snapshots, the daily
  // writer and freshness monitoring. Explicit backup/restore commands still work.
  // The monitor lists snapshots with its own ListBucket-only credentials.
  BACKUP_ENABLED: strictBooleanFlag(),
  BACKUP_S3_BUCKET: z.string().optional(),
  BACKUP_S3_ACCESS_KEY_ID: z.string().optional(),
  BACKUP_S3_SECRET_ACCESS_KEY: z.string().optional(),
  // The worker only lists objects for freshness; it never reads or writes a
  // dump. Keep that ListBucket-only identity separate from the dump key.
  BACKUP_MONITOR_S3_ACCESS_KEY_ID: z.string().optional(),
  BACKUP_MONITOR_S3_SECRET_ACCESS_KEY: z.string().optional(),
  BACKUP_S3_REGION: z.string().default("auto"),
  BACKUP_S3_ENDPOINT: httpUrl("BACKUP_S3_ENDPOINT").optional(),
  BACKUP_S3_PREFIX: z.string().default(""),
  BACKUP_S3_FORCE_PATH_STYLE: strictBooleanFlag(),
  // Newest dump older than this = stale. 36h tolerates one missed nightly
  // run plus clock skew without paging anyone; two misses always alert.
  BACKUP_MAX_AGE_HOURS: z.coerce
    .number()
    .int()
    .min(1)
    .max(24 * 30)
    .default(36),
  // ---- Template image distribution (docs/operations/templates.md#image-store).
  // `off` keeps today's behaviour exactly: no fetch, serve, capture, image
  // store or lease-from-READY. `auto` is S3 mode when IMAGE_S3_BUCKET and both
  // keys are set, otherwise peer mode (relayed copies between the owner's hosts).
  IMAGE_DISTRIBUTION: z.enum(["auto", "off"]).default("auto"),
  IMAGE_S3_ENDPOINT: secureServiceUrl("IMAGE_S3_ENDPOINT").optional(),
  IMAGE_S3_REGION: z.string().min(1).default("auto"),
  IMAGE_S3_BUCKET: z.string().min(1).optional(),
  // Dedicated, bucket-scoped key. Never reuse BACKUP_S3_*.
  IMAGE_S3_ACCESS_KEY_ID: z.string().min(1).optional(),
  IMAGE_S3_SECRET_ACCESS_KEY: z.string().min(1).optional(),
  IMAGE_S3_FORCE_PATH_STYLE: strictBooleanFlag(),
  // Host that presigned node URLs are signed for; defaults to IMAGE_S3_ENDPOINT.
  IMAGE_S3_PUBLIC_ENDPOINT: secureServiceUrl("IMAGE_S3_PUBLIC_ENDPOINT").optional(),
  IMAGE_S3_PREFIX: z
    .string()
    .regex(/^[a-z0-9][a-z0-9-]{0,62}$/, "IMAGE_S3_PREFIX must be a lowercase path segment.")
    .default("images"),
  IMAGE_S3_PRESIGN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(600),
  IMAGE_STORE_ENCRYPTION: z.enum(["on", "off"]).default("off"),
  // base64 of exactly 32 random bytes (`openssl rand -base64 32`).
  IMAGE_STORE_ENCRYPTION_KEY: z
    .string()
    .refine(
      (value) => Buffer.from(value, "base64").length === 32 && /^[A-Za-z0-9+/]+=*$/.test(value),
      {
        message: "IMAGE_STORE_ENCRYPTION_KEY must be base64 of exactly 32 bytes.",
      },
    )
    .optional(),
  IMAGE_GC_GRACE_DAYS: z.coerce.number().int().min(0).max(90).default(7),
  IMAGE_STORE_MAX_GIB_PER_ACCOUNT: z
    .union([
      z.literal("unlimited").transform(() => null),
      z.coerce.number().int().min(0).max(1_048_576),
    ])
    .default(50),
  IMAGE_DOWNLOADS_PER_HOUR_MAX: z
    .union([
      z.literal("unlimited").transform(() => null),
      z.coerce.number().int().min(0).max(100_000),
    ])
    .default(120),
  // ---- Stopped-sandbox disk offload to the image store's S3 bucket
  // (docs/operations/templates.md#image-store). Needs S3 mode and
  // DATA_ENCRYPTION_KEY. `off` stops new offloads and evictions only:
  // sandboxes already offloaded stay restorable and destroyable.
  SANDBOX_OFFLOAD: z.enum(["auto", "off"]).default("auto"),
  // Stored offload GiB per account. Admins may lower it per account.
  SANDBOX_OFFLOAD_MAX_GIB_PER_ACCOUNT: z.coerce.number().int().min(1).max(1_048_576).default(200),
  // Offload upload GiB per account per rolling day (restores are never refused).
  SANDBOX_OFFLOAD_GIB_PER_DAY: z.coerce.number().int().min(1).max(1_048_576).default(500),
  // Hours a destroyed sandbox's offloaded disk key is kept before it is
  // shredded (salvage window against a mis-mapped destroy): 1 h to 30 days.
  SANDBOX_OFFLOAD_SHRED_GRACE_HOURS: z.coerce
    .number()
    .int()
    .min(1)
    .max(24 * 30)
    .default(24),
  // Optional extra PEM CA trust, read only by the Rust CLI.
  WSSP_CA_FILE: z.string().min(1).optional(),
  // Dev/test-only seam read by the Rust node daemon (crates/sandbox-runtime),
  // not by any Node process: relocates the administrator-provisioned shared
  // Incus daemon lock directory from /var/lib/wssp/incus-daemon-locks for
  // shim-driven harnesses. Never set in production.
  WSSP_INCUS_DAEMON_LOCK_DIR: z.string().min(1).optional(),
  // Test-only override read by DEBUG builds of the Rust node daemon
  // (`wssp connect`), not by any Node process: `1` lets a daemon share its
  // Incus server with another wssp daemon (local chaos stack). Release builds
  // compile it out; accepted only with a loopback control plane. Never set in
  // production.
  WSSP_TEST_SHARED_INCUS: z.literal("1").optional(),
  // Dev/test-only seam read by the Rust surface harness
  // (crates/sandbox-runtime/src/bin/incus-surface.rs), not by any Node
  // process: relocates the owner-validated, mode-0700 surface state root
  // (run locks and state dirs) for shim-driven integration tests. Never set
  // in production.
  WSSP_SURFACE_ROOT: z.string().min(1).optional(),
  // ---- Translation provider (optional). Used by `pnpm i18n:translate` to
  // fill non-default locale bundles. The validator keeps both API keys optional so the rest of the
  // app boots without them; the provider factory throws at first use if the
  // key for the chosen provider is missing.
  //
  // Default provider is `openrouter` because it's the cheapest path to
  // claude-haiku-4-5 + gives a single account multi-model access for A/B
  // experiments. Set TRANSLATION_PROVIDER=anthropic to call the Anthropic
  // API directly with ANTHROPIC_API_KEY.
  OPENROUTER_API_KEY: z.string().min(1).optional(),
  ANTHROPIC_API_KEY: z.string().min(1).optional(),
  TRANSLATION_PROVIDER: z.enum(["openrouter", "anthropic"]).default("openrouter"),
  // Optional public origin metadata for translation providers such as
  // OpenRouter. This is not used for auth and is safe for worker-only env.
  PUBLIC_APP_URL: originUrl("PUBLIC_APP_URL").optional(),
  // ---- Email transport (optional). Shared because both the server and the
  // worker use @wssp/mailer. Keeping SMTP here lets worker-only deploys
  // opt into failure-alert emails without setting Better-Auth server vars.
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().int().positive().optional(),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_FROM: z.string().optional(),
  // Per-call model override. Falls through to the provider's default
  // (`anthropic/claude-haiku-4-5` for OpenRouter, `claude-haiku-4-5` for
  // direct Anthropic) when unset.
  TRANSLATION_MODEL: z.string().min(1).optional(),
  // ---- Data encryption root key (optional). Shared: the server encrypts and
  // the worker decrypts data at rest, so both need the same value. One
  // deployment-wide root; each purpose (webhook endpoint secrets, the
  // credential vault's DEK and return-key wraps) derives its own sub-key with HKDF-SHA256
  // (packages/api/src/crypto/data-key.ts). Exactly 32 bytes as 64 lowercase
  // hex. Unset = features that need it are off (webhooks: no capability,
  // UNSUPPORTED_CAPABILITY). Store it apart from database backups: losing it
  // makes every value encrypted under it unrecoverable.
  DATA_ENCRYPTION_KEY: z
    .string()
    .regex(/^[0-9a-f]{64}$/, "DATA_ENCRYPTION_KEY must be 64 lowercase hex characters.")
    .refine((value) => isWeakSecret(value) === null, { message: "DATA_ENCRYPTION_KEY is weak." })
    .optional(),
  // Decrypt-only previous root during a rotation; the worker re-encrypts rows
  // under DATA_ENCRYPTION_KEY, after which this can be removed.
  DATA_ENCRYPTION_KEY_PREVIOUS: z
    .string()
    .regex(/^[0-9a-f]{64}$/, "DATA_ENCRYPTION_KEY_PREVIOUS must be 64 lowercase hex characters.")
    .refine((value) => isWeakSecret(value) === null, {
      message: "DATA_ENCRYPTION_KEY_PREVIOUS is weak.",
    })
    .optional(),
  // ---- CLI logins (credential vault). On by default; set false to turn the
  // feature off. Effective only with DATA_ENCRYPTION_KEY: without the key the
  // feature is unavailable (never a boot failure). Explicitly false with the
  // key present = drain mode: new use is refused, existing values settle
  // (docs/design/credential-vault.md § Feature gate).
  CREDENTIALS_ENABLED: strictBooleanFlag(true),
  // ---- Outbound webhooks (optional). Endpoint signing secrets are encrypted
  // under a sub-key of DATA_ENCRYPTION_KEY; unset root = webhooks are off.
  // Operator allowlist for private webhook destinations (CSV). CIDRs that
  // intersect hard-denied ranges (metadata, link-local, multicast, mapped,
  // loopback in production) fail at boot. Hosts are exact DNS names.
  WEBHOOK_ALLOWED_PRIVATE_CIDRS: z.string().default(""),
  WEBHOOK_ALLOWED_PRIVATE_HOSTS: z.string().default(""),
  // CSV of network-specific IPv6 translation prefixes (RFC 6052 NAT64/DNS64,
  // e.g. `fd12:3456:789a:bcde::/64`) on the worker's network. Their ranges are
  // hard-denied like the well-known 64:ff9b::/96 and may not be allowlisted.
  WEBHOOK_TRANSLATION_PREFIXES: z.string().default(""),
  // Who may use that allowlist: `admins` (default) or `all` accounts.
  WEBHOOK_PRIVATE_ALLOWLIST_SCOPE: z.enum(["admins", "all"]).default("admins"),
  // Permit http:// only to allowlisted private destinations. Off by default.
  WEBHOOK_ALLOW_PLAINTEXT_PRIVATE: strictBooleanFlag(false),
  // Concurrent webhook delivery attempts per worker process.
  WEBHOOK_DELIVERY_CONCURRENCY: z.coerce.number().int().min(1).max(64).default(8),
};
