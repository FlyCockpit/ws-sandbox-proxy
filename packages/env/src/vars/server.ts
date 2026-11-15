import { z } from "zod";
import { isWeakSecret } from "../secret-strength.js";
import { originUrl } from "../url.js";
import { strictBooleanFlag } from "./shared.js";

// ---------------------------------------------------------------------------
// Server-only variable DECLARATIONS. See ./shared.ts for why these live in a
// side-effect-free module of their own.
//
// Disjointness contract: no key declared here may also appear in ./shared.ts —
// `extends` merges, it does not allow overriding.
// ---------------------------------------------------------------------------

export const serverVars = {
  WORKER_MODE: z.enum(["embedded", "external"]).default("embedded"),
  // Optional process port override. Portless and production platforms inject
  // `PORT`; `SERVER_PORT` is only for raw local runs or container overrides.
  PORT: z.coerce.number().int().min(1).max(65_535).optional(),
  SERVER_PORT: z.coerce.number().int().min(1).max(65_535).optional(),
  BETTER_AUTH_SECRET: z.string().min(32),
  BETTER_AUTH_URL: originUrl("BETTER_AUTH_URL"),
  CORS_ORIGIN: originUrl("CORS_ORIGIN").optional(),
  SIGNUP_ENABLED: strictBooleanFlag(),
  MCP_ENABLED: strictBooleanFlag(true),
  WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY: strictBooleanFlag(true),
  WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS: z.coerce.number().int().min(1).max(3650).default(90),
  VAPID_PUBLIC_KEY: z.string().optional(),
  VAPID_PRIVATE_KEY: z.string().optional(),
  // Web Push contact URI sent to push services (RFC 8292 requires a mailto:
  // or https: URL the service can use to reach you about problems).
  VAPID_SUBJECT: z
    .string()
    .regex(/^(mailto:|https:)/, "VAPID_SUBJECT must be a mailto: or https: URL")
    .optional(),
  // ---- Rate limiting: three named budgets, two knobs each. ----------------
  // Each budget describes its family's REFERENCE member (the number below);
  // every other limiter in the family keeps its ratio to that reference, so
  // setting a budget re-tunes the whole family coherently:
  //
  //   • POINTS multiplies every family member's points by provided/reference.
  //   • WINDOW_SECONDS multiplies every member's window AND block duration by
  //     the same factor (the window:block ratio is part of each member's
  //     design and moves as a unit).
  //
  // Why not one knob per limiter (the old scheme, 34 keys): a per-surface
  // knob invites squeezing one budget to "be safe" — which locks out a
  // shared office behind one NAT IP — instead of SPLITTING the surface that
  // needs its own bucket. Tighter is not safer; if one surface 429s
  // legitimate users, split the surface instead of shrinking a budget.
  // Burst/sustained ratios, bucket keying, and fail-open/fail-closed stay
  // fixed in code (apps/server/src/rate-limit.ts +
  // packages/api/src/lib/rate-limit-families.ts). Defaults reproduce the
  // shipped numbers exactly.
  //
  // AUTH family — the fail-closed /api/auth/* limiters: general auth surface
  // (this reference, 30/60 s + 5-min block), credential (10/60 s),
  // credential burst (3/10 s), signup (10/h), and 2FA-OTP resend
  // (3/15 min). IP-keyed, so shared-NAT
  // offices share these budgets — size for several concurrent humans.
  RATE_LIMIT_AUTH_POINTS: z.coerce.number().int().positive().default(30),
  RATE_LIMIT_AUTH_WINDOW_SECONDS: z.coerce.number().int().positive().default(60),
  // RPC family — ordinary request volume: /rpc/* (this reference, 100/60 s),
  // /ready (60), and the SSR catch-all (300). Native /v1 has its own
  // per-dimension budgets below.
  RATE_LIMIT_RPC_POINTS: z.coerce.number().int().positive().default(100),
  RATE_LIMIT_RPC_WINDOW_SECONDS: z.coerce.number().int().positive().default(60),
  // Native SDK API (/v1) — one absolute budget per dimension, each over a
  // fixed 60 s window, independent of the RPC family (these do NOT scale with
  // RATE_LIMIT_RPC_*). The IP budget is charged before authentication (it
  // also covers the anonymous /v1/openapi.json); key and owner are charged
  // after a valid SDK key. All three fail closed.
  RATE_LIMIT_SDK_IP_POINTS: z.coerce.number().int().positive().default(300),
  RATE_LIMIT_SDK_KEY_POINTS: z.coerce.number().int().positive().default(100),
  RATE_LIMIT_SDK_OWNER_POINTS: z.coerce.number().int().positive().default(300),
  // EMAIL family — per-RECIPIENT caps on the anonymous endpoints that mail a
  // caller-supplied address: verification resend / password reset (this
  // reference, 3 per hour), signup (6), and sign-in-triggered mails (10).
  // The 0-second block stays code-fixed: a block on a caller-supplied key is
  // an unauthenticated lockout lever against that user's password reset.
  RATE_LIMIT_EMAIL_POINTS: z.coerce.number().int().min(0).default(3),
  RATE_LIMIT_EMAIL_WINDOW_SECONDS: z.coerce.number().int().positive().default(3600),
  // Exact number of trusted reverse proxies in front of the app, for deriving
  // the client IP used as the anonymous rate-limit and audit key
  // (apps/server/src/client-ip.ts). Unset means 0: key on the TCP socket peer
  // and ignore X-Forwarded-For. N >= 1 takes the entry N from the right of
  // [...X-Forwarded-For, socket] (an appended `:port` is stripped), falling
  // back to the socket peer on a short or malformed chain. The generated Dokploy config sets 1 (Traefik). Behind
  // a proxy with 0, every client shares the proxy's single bucket.
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).optional(),
  ADMIN_EMAILS: z.string().optional(),
  // TTL (seconds) for the in-memory SSR HTML cache of public pages
  // (apps/server/src/ssr-cache.ts). 0 disables the cache entirely; the
  // default keeps a cached public render for up to a minute. Edits to a live
  // URL can take up to this long to appear.
  SSR_CACHE_TTL_SECONDS: z.coerce.number().int().min(0).default(60),
  // Transfer spool for the always-enabled outbound sandbox host relay.
  TRANSFER_SPOOL_DIR: z.string().min(1).default(".data/transfers"),
  // One transfer cap end to end (C30): the node daemon's staging ceiling is
  // 1 GiB (`sandbox_runtime::FILE_MAX_BYTES`), equal to the contracts'
  // `TRANSFER_MAX_BYTES`. Lower values are allowed; higher ones fail startup.
  TRANSFER_MAX_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .max(1024 ** 3)
    .default(1024 ** 3),
  TRANSFER_DISK_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .max(Number.MAX_SAFE_INTEGER)
    .default(10 * 1024 ** 3),
  TRANSFER_OWNER_ACTIVE: z.coerce.number().int().min(1).max(1024).default(4),
  TRANSFER_GLOBAL_ACTIVE: z.coerce.number().int().min(1).max(1024).default(16),
  TRANSFER_IDLE_SECONDS: z.coerce.number().int().min(1).max(3600).default(900),
  TRANSFER_ABSOLUTE_SECONDS: z.coerce.number().int().min(1).max(86400).default(3600),
  // Staged for pools/create: declaration only; no active budget/lease changes.
  SANDBOX_CREATE_CONNECT_BUDGET_POINTS: z.coerce.number().int().min(1).max(10_000).default(300),
  SANDBOX_CREATE_CONNECT_BUDGET_WINDOW_SECONDS: z.coerce
    .number()
    .int()
    .min(60)
    .max(3600)
    .default(60),
  // Deployment layer of the sandbox lease policy. `unlimited` (the literal word)
  // lets hosts, pools and memberships that also allow it accept timeoutMs 0;
  // finite values above 24 days must be expressed as `unlimited`.
  SANDBOX_MAX_TIMEOUT_MS: z
    .union([
      z.literal("unlimited").transform(() => null),
      z.coerce.number().int().min(300_000).max(2_073_600_000),
    ])
    .default(86_400_000),
  // Capacity queue (pool creates that wait for capacity). Each accepts the
  // literal "unlimited" (no deployment limit). Wait 0 disables waits; queue
  // limits count WAITING entries per SDK key and per creator across pools.
  SANDBOX_CAPACITY_WAIT_MAX_MS: z
    .union([
      z.literal("unlimited").transform(() => null),
      z.coerce.number().int().min(0).max(2_073_600_000),
    ])
    .default(3_600_000),
  SANDBOX_CAPACITY_QUEUE_MAX_PER_KEY: z
    .union([
      z.literal("unlimited").transform(() => null),
      z.coerce.number().int().min(0).max(100_000),
    ])
    .default(16),
  SANDBOX_CAPACITY_QUEUE_MAX_PER_OWNER: z
    .union([
      z.literal("unlimited").transform(() => null),
      z.coerce.number().int().min(0).max(100_000),
    ])
    .default(64),
  // Retry-After (seconds) on /v1 capacity, quota and pool refusals that carry
  // `retryable: true` (current usage, queue depth or online state blocks the
  // request). Never sent on `retryable: false`. Advisory backoff, not a
  // promise that capacity frees by then (apps/server/src/sandbox-api/errors.ts).
  CAPACITY_RETRY_AFTER_SECONDS: z.coerce.number().int().min(1).max(86_400).default(30),
  // Decode canonical hex to master bytes only when keyed dispatch lands.
  // Required even in development; never substitute an auth secret or default.
  SANDBOX_REQUEST_HMAC_SECRET: z
    .string()
    .min(64)
    .regex(/^[0-9a-f]+$/, "Invalid sandbox HMAC secret.")
    .refine((value) => value.length % 2 === 0 && isWeakSecret(value) === null, {
      message: "Invalid sandbox HMAC secret.",
    }),
  // C52-R2-3 resource caps. Hosts per owner counts every host row the owner
  // has, including hosts pending deletion; `unlimited` (the literal word) lifts
  // it for a single-owner deployment. Sockets per host bounds concurrent
  // node-daemon WebSockets (registered or awaiting hello) for one host on one
  // server process; each can hold an 8 MiB receive queue, so it has a hard
  // ceiling instead of an unlimited form. Normal operation needs 1, plus 1
  // while a reconnect overlaps a dying socket.
  SANDBOX_MAX_HOSTS_PER_OWNER: z
    .union([
      z.literal("unlimited").transform(() => null),
      z.coerce.number().int().min(1).max(100_000),
    ])
    .default(20),
  /** CLI logins: maximum account instances (token sets) per owner, or "unlimited". */
  CREDENTIAL_MAX_INSTANCES_PER_OWNER: z
    .union([
      z.literal("unlimited").transform(() => null),
      z.coerce.number().int().min(1).max(100_000),
    ])
    .default(1000),
  SANDBOX_MAX_SOCKETS_PER_HOST: z.coerce.number().int().min(1).max(64).default(2),
  // Deployment-wide egress blocklist (IPv4 CIDRs and domains, comma or space
  // separated) relayed to every node daemon's egress guard. Validated by the
  // relay at boot WITHOUT failing boot: an invalid list is logged and never
  // sent, so hosts keep their last list (or refuse new sandboxes).
  SANDBOX_EGRESS_BLOCKLIST: z.string().optional(),
  // Relayed peer image copies: transient part spool (never durable storage).
  // Defaults inside the node-owned server-data volume (`.data`), beside but
  // never inside TRANSFER_SPOOL_DIR: transfer recovery refuses any foreign entry.
  IMAGE_RELAY_SPOOL_DIR: z.string().min(1).default(".data/image-relay"),
  IMAGE_RELAY_SPOOL_BYTES: z.coerce
    .number()
    .int()
    .min(64 * 1024 * 1024)
    .max(1024 * 1024 * 1024 * 1024)
    .default(2_147_483_648),
  IMAGE_RELAY_MAX_ACTIVE: z.coerce.number().int().min(1).max(256).default(4),
  // Template builds (docs/guide/template-builds.md). `auto` runs builds whenever
  // their prerequisites hold (image distribution on, a lease ceiling with room
  // for a build); otherwise builds report unavailable with a reason. A missing
  // prerequisite never fails boot. Cross-variable bounds (context bytes within
  // TRANSFER_MAX_BYTES and the staged budgets) are clamped, not refused.
  TEMPLATE_BUILDS: z.enum(["auto", "off"]).default("auto"),
  TEMPLATE_BUILD_MAX_MINUTES: z.coerce.number().int().min(1).max(1440).default(60),
  TEMPLATE_BUILD_MAX_CONCURRENT_PER_ACCOUNT: z
    .union([
      z.literal("unlimited").transform(() => null),
      z.coerce.number().int().min(0).max(100_000),
    ])
    .default(2),
  TEMPLATE_BUILD_MINUTES_PER_MONTH: z
    .union([
      z.literal("unlimited").transform(() => null),
      z.coerce.number().int().min(0).max(100_000_000),
    ])
    .default(1000),
  TEMPLATE_BUILD_CAPTURE_WINDOW_MINUTES: z.coerce.number().int().min(5).max(720).default(60),
  TEMPLATE_BUILD_CONTEXT_MAX_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .max(1024 ** 3)
    .default(1024 ** 3),
  TEMPLATE_BUILD_CONTEXT_STAGED_BYTES_PER_ACCOUNT: z.coerce
    .number()
    .int()
    .positive()
    .max(Number.MAX_SAFE_INTEGER)
    .default(2 * 1024 ** 3),
  TEMPLATE_BUILD_CONTEXT_STAGED_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .max(Number.MAX_SAFE_INTEGER)
    .default(8 * 1024 ** 3),
  // Longest a create may take from acceptance to READY (image fetch included)
  // when the lease clock starts at READY; the server's reclaim backstop.
  SANDBOX_CREATE_PROVISION_MAX_MS: z.coerce
    .number()
    .int()
    .min(600_000)
    .max(86_400_000)
    .default(7_200_000),
};
