/** Generate a reviewable native-Git setup. No network, credentials, or writes. */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { relative } from "node:path";
import { fileURLToPath } from "node:url";
import { serverVars } from "../packages/env/src/vars/server.js";
import { sharedVars } from "../packages/env/src/vars/shared.js";
import { ENV_VARS } from "./lib/env-manifest.js";

type Topology = "app" | "app-worker";
type Options = {
  environment: "development" | "production";
  gitRef: string;
  topology: Topology;
  url: string;
  project?: string;
  proxyNetwork?: string;
  backups?: boolean;
  /**
   * The repository Dokploy builds from. Set: every build context is the pinned
   * Git context `<gitUrl>#<gitRef>`, so the pasted (raw) Compose builds
   * without a source tree. Unset: `context: .` (plain `docker compose` from a
   * checkout; the CLI's `--git-url local`).
   */
  gitUrl?: string;
  /**
   * `--env KEY[,KEY…]`: optional runtime variables the generator does not
   * forward by itself (request budgets, the image store, offload tuning …),
   * each forwarded as `${KEY:-}` to every runtime role its declaration
   * allows (`assertPassthroughKeys`). Empty or unset keeps the app default.
   */
  env?: readonly string[];
  /**
   * `--trust-proxy-hops N` (default 1): the server's `TRUST_PROXY_HOPS`, the
   * exact number of reverse proxies in front of it (client-ip.ts). 1 is
   * client -> Traefik -> server; 2 adds one proxy Traefik trusts, such as
   * `cloudflared` in front of Traefik on a home server.
   */
  trustProxyHops?: number;
};
/** Highest `--trust-proxy-hops`; a longer chain is a mistake, not a topology. */
const MAX_TRUST_PROXY_HOPS = 8;
const trustProxyHops = (options: Options) => String(options.trustProxyHops ?? 1);
const keys = new Set(ENV_VARS.map((variable) => variable.key));
const sharedKeys = new Set(Object.keys(sharedVars));
const serverKeys = new Set([...sharedKeys, ...Object.keys(serverVars)]);
// Keys the generator owns (lifecycle, backup, instance identity): never
// optional inventory, never `--env`.
// The proxy targets port 3000 (`loadbalancer.server.port`), so the listen
// port is the generator's too.
const GENERATOR_OWNED =
  /^(RESTORE_|WORKER_MODE$|MIGRATE_ON_START$|WSSP_INSTANCE_ID$|BACKUP_|PORT$|SERVER_PORT$)/;

/**
 * `--env` validation: every key is a declared server or shared runtime
 * variable (packages/env/src/vars/{server,shared}.ts, listed in the
 * manifest), not one the generator owns or already forwards, and named once.
 * Values never pass through the generator: the Compose only references the
 * key, and the operator sets it in Dokploy's environment.
 */
export function assertPassthroughKeys(env: readonly string[], mapped: ReadonlySet<string>) {
  const seen = new Set<string>();
  for (const key of env) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(key)) throw new Error(`--env ${key} is not a variable name.`);
    if (seen.has(key)) throw new Error(`--env names ${key} twice.`);
    seen.add(key);
    if (GENERATOR_OWNED.test(key))
      throw new Error(`--env ${key} is set by the generator itself; it cannot be passed through.`);
    if (!keys.has(key) || !serverKeys.has(key))
      throw new Error(
        `--env ${key} is not a server or worker variable of this repository (packages/env/src/vars).`,
      );
    if (mapped.has(key)) throw new Error(`--env ${key} is already forwarded; drop it from --env.`);
  }
}

/** The note the checklists show for one `--env` key. */
const PASSTHROUGH_NOTE =
  "Forwarded by --env. Define it (an empty value keeps the app default; Dokploy rejects a reference to an undefined variable). See docs/operations/environment-variables.md.";

/** Optional keys of one configuration: the fixed ones plus its `--env` keys. */
function optionalForwarded(options: Options): Record<string, string> {
  return {
    ...OPTIONAL_FORWARDED,
    ...Object.fromEntries((options.env ?? []).map((key) => [key, PASSTHROUGH_NOTE])),
  };
}

/** `--env` keys a role receives: every key for the server, shared keys for the worker. */
const passthroughFor = (options: Options, role: "server" | "worker") =>
  (options.env ?? []).filter((key) => role === "server" || sharedKeys.has(key));

/**
 * A repository URL Docker can use as a Git build context: https://, ssh:// or
 * scp-like `user@host:path`. Never credentials (the file is pasted into
 * Dokploy and kept in its database), never a `#` (the ref is appended).
 */
export function assertGitUrl(gitUrl: string) {
  const fail = (why: string): never => {
    throw new Error(`--git-url ${why}`);
  };
  if (!gitUrl || /[\s#"'`$\\]/.test(gitUrl))
    fail(
      "must be a repository URL without spaces, quotes, `$`, `\\` or `#` (the ref is appended).",
    );
  if (/^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^/]/.test(gitUrl)) return;
  let parsed: URL;
  try {
    parsed = new URL(gitUrl);
  } catch {
    return fail("must be https://…, ssh://… or git@host:owner/repo.git.");
  }
  if (
    !["https:", "ssh:"].includes(parsed.protocol) ||
    !parsed.hostname ||
    parsed.pathname.length < 2
  )
    fail("must be https://…, ssh://… or git@host:owner/repo.git.");
  if (parsed.password || (parsed.protocol === "https:" && parsed.username))
    fail(
      "must not contain credentials: the generated file is pasted into Dokploy. Use a public URL, or an SSH URL the Dokploy server's Docker can fetch.",
    );
  if (parsed.search || parsed.hash) fail("must not have a query or fragment.");
}

/** The build context of every service: the pinned Git context, or `.`. */
const buildContext = (options: Options) =>
  options.gitUrl === undefined ? "." : JSON.stringify(`${options.gitUrl}#${options.gitRef}`);

/**
 * `--git-url`: the repository each image builds from (`<url>#<git-ref>`).
 * Absent: the checkout's `origin` remote. `local`: `context: .` (plain
 * `docker compose` from a checkout, never a pasted Dokploy Compose).
 */
export function resolveGitUrl(
  flag: string | undefined,
  origin: () => string | undefined,
): string | undefined {
  if (flag === "local") return undefined;
  if (flag !== undefined) return flag;
  const remote = origin()?.trim();
  if (!remote)
    throw new Error(
      "No --git-url and no `origin` remote: pass --git-url <repository URL> (what Dokploy builds from), or --git-url local for plain docker compose in a checkout.",
    );
  return remote;
}

export function generateDokployConfig(options: Options) {
  if (!["development", "production"].includes(options.environment))
    throw new Error("Choose development or production.");
  if (!["app", "app-worker"].includes(options.topology))
    throw new Error("Choose app or app-worker.");
  if (options.environment === "development" && options.gitRef !== "main")
    throw new Error("Development automatic deployment follows main.");
  if (options.environment === "production" && !/^release\/[a-f0-9]{40}$/.test(options.gitRef))
    throw new Error("Production requires an immutable release/<full-commit-sha> Git tag.");
  const url = new URL(options.url);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/" ||
    url.port ||
    url.hostname.length > 253 ||
    !url.hostname.split(".").every((part) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part))
  )
    throw new Error(
      "URL must be an HTTPS origin with a DNS hostname, without credentials, port, query, or path.",
    );
  validateNames(options);
  if (
    options.trustProxyHops !== undefined &&
    (!Number.isInteger(options.trustProxyHops) ||
      options.trustProxyHops < 1 ||
      options.trustProxyHops > MAX_TRUST_PROXY_HOPS)
  )
    throw new Error(
      `--trust-proxy-hops must be a whole number from 1 to ${MAX_TRUST_PROXY_HOPS} (Traefik counts as 1).`,
    );
  if (options.gitUrl !== undefined) assertGitUrl(options.gitUrl);
  if (options.env?.length) {
    const base = composeEnvironments({ ...options, env: [] });
    assertPassthroughKeys(
      options.env,
      new Set([...Object.keys(base.server ?? {}), ...Object.keys(base.worker ?? {})]),
    );
  }
  const worker = options.topology === "app-worker";
  const prefix = backupPrefix(options);
  const optional = optionalForwarded(options);
  const reference = (key: string) => {
    if (!keys.has(key)) throw new Error(`Environment manifest is missing ${key}.`);
    return `\${{environment.${key}}}`;
  };
  const refs = (names: string[]) =>
    Object.fromEntries(names.map((name) => [name, reference(name)]));
  const runtime = refs(["DATABASE_URL", "REDIS_URL"]);
  const serverEnvironment = {
    ...runtime,
    ...refs([
      "BETTER_AUTH_SECRET",
      "SANDBOX_REQUEST_HMAC_SECRET",
      ...WEBHOOK_KEYS,
      "BETTER_AUTH_URL",
      "ADMIN_EMAILS",
      "SETUP_KEY",
      "SMTP_HOST",
      "SMTP_PORT",
      "SMTP_USER",
      "SMTP_PASS",
      "SMTP_FROM",
      "MCP_ENABLED",
    ]),
    NODE_ENV: "production",
    // Client -> Traefik -> server: one trusted proxy unless --trust-proxy-hops
    // counts more (client-ip.ts).
    TRUST_PROXY_HOPS: trustProxyHops(options),
    WORKER_MODE: worker ? "external" : "embedded",
    MIGRATE_ON_START: "true",
    BACKUP_S3_PREFIX: prefix,
    ...refs(writerKeys),
    ...refs(["BACKUP_ENABLED", "BACKUP_HEARTBEAT_URL"]),
    // With an external worker the server never runs the freshness check, but
    // it is the one container that holds the writer key: it gets the monitor
    // key ID alone (never the secret), so its entrypoint can refuse a reused
    // key, then drops it before the server starts.
    ...(!worker ? refs(monitorKeys) : refs([MONITOR_KEY_ID])),
    ...refs(passthroughFor(options, "server")),
  };
  const workerEnvironment = {
    ...runtime,
    ...refs(WEBHOOK_KEYS),
    ...refs(smtpKeys),
    NODE_ENV: "production",
    MIGRATE_ON_START: "false",
    BACKUP_S3_PREFIX: prefix,
    ...refs(monitorKeys),
    ...refs(passthroughFor(options, "worker")),
  };
  const application = (role: string, dockerfile: string, environment: Record<string, string>) => ({
    name: `${projectName(options)}-${role}`,
    sourceType: "git",
    customGitUrl:
      options.gitUrl ?? "<your repository URL; configure its Git credentials in Dokploy>",
    customGitBranch: options.gitRef,
    autoDeploy: options.environment === "development",
    buildType: "dockerfile",
    dockerfile,
    dockerContextPath: ".",
    createEnvFile: false,
    modeSwarm: { Replicated: { Replicas: 1 } },
    restartPolicySwarm: { Condition: "on-failure" },
    // Dokploy defaults to these when unset. A partial saved object replaces
    // those defaults, so the checklist spells out the complete runtime policy.
    updateConfigSwarm: {
      Parallelism: 1,
      Order: role === "server" ? "stop-first" : "start-first",
      FailureAction: "rollback",
    },
    rollbackConfigSwarm: {
      Parallelism: 1,
      Order: role === "server" ? "stop-first" : "start-first",
    },
    stopGracePeriodSwarm: 30_000_000_000,
    environment,
    persistentStorage:
      role === "server"
        ? [
            {
              volume: `${projectName(options)}-server-data`,
              mountPath: "/app/.data",
              ownerUid: 1000,
              directoryMode: "0700",
            },
            ...(options.backups
              ? [
                  {
                    volume: `${projectName(options)}-backups`,
                    mountPath: "/backups",
                    ownerUid: 1000,
                    directoryMode: "0700",
                  },
                ]
              : []),
          ]
        : [],
    buildArgs: {
      BUILD_VERSION:
        options.environment === "production"
          ? options.gitRef.slice("release/".length)
          : "<full SHA of selected Git ref>",
    },
    domain: role === "server" ? { host: url.hostname, port: 3000, https: true } : null,
  });
  const applications = [application("server", "Dockerfile", serverEnvironment)];
  if (worker) applications.push(application("worker", "Dockerfile.worker", workerEnvironment));
  const required = [
    ...new Set(
      applications.flatMap((app) =>
        Object.values(app.environment).flatMap((value) => {
          const match = /^\$\{\{environment\.([A-Z0-9_]+)\}\}$/.exec(value);
          return match ? [match[1]!] : [];
        }),
      ),
    ),
  ];
  // Derive optional runtime inventory from the declarations + manifest. An
  // optional credential is never granted to every role just because it exists.
  const excluded = GENERATOR_OWNED;
  const optionalFor = (allowed: Set<string>, mapped: Record<string, string>) =>
    ENV_VARS.filter(
      (variable) =>
        !variable.hidden &&
        allowed.has(variable.key) &&
        !Object.hasOwn(mapped, variable.key) &&
        !excluded.test(variable.key),
    ).map((variable) => variable.key);
  return {
    format: "Dokploy settings checklist; not an import or API payload",
    environment: options.environment,
    topology: options.topology,
    project: projectName(options),
    projectStem: projectStem(options),
    proxyNetwork: options.proxyNetwork ?? "dokploy-network",
    compose: composeChecklist(options),
    database: { name: `${projectName(options)}-postgres`, sharedWithOtherEnvironments: false },
    redis: {
      name: `${projectName(options)}-redis`,
      sharedWithOtherEnvironments: false,
      maxmemoryPolicy: "noeviction",
    },
    environmentVariablesToSetOnce: Object.fromEntries(
      required
        .filter((key) => !Object.hasOwn(optional, key))
        .map((key) => [
          key,
          key === "BETTER_AUTH_URL"
            ? url.origin
            : key.startsWith("BACKUP_")
              ? (backupDefaults[key] ?? "")
              : `<set ${key} for ${options.environment}; complete literal value, no nested references>`,
        ]),
    ),
    environmentVariablesOptional: Object.fromEntries(
      required.filter((key) => Object.hasOwn(optional, key)).map((key) => [key, optional[key]!]),
    ),
    applications,
    optionalEnvironmentKeys: {
      server: optionalFor(serverKeys, serverEnvironment),
      ...(worker ? { worker: optionalFor(sharedKeys, workerEnvironment) } : {}),
    },
    backupSetupRequired: false,
    backupSetup:
      (options.backups
        ? "The generated Compose defaults BACKUP_ENABLED=true and BACKUP_SCHEDULE=daily. Enable the backup profile for daily backups. "
        : "Backups default off; migrations and readiness work without backup settings. To opt in, regenerate with --backups true and enable the generated backup profile. ") +
      "Writer keys belong to startup and backup operations; monitor keys belong to the selected worker runtime. See docs/operations/backup-and-restore.md.",
    rolloutContract:
      "The server applies committed migrations before HTTP startup; external workers wait up to 300s and register their instance. Server updates and rollbacks use stop-first so only one process owns the private transfer spool. Keep 30s grace for relay and transfer drain. Accept the expected full commit and repeated readiness with pnpm dokploy:verify --server <service> --url <https-origin> --commit <full-sha> (Swarm-deployed services; for a plain Compose deployment check GET /ready reports the commit); preserve adjacent-release queue compatibility.",
    releaseContract:
      options.environment === "development"
        ? "Git builds may finish in any order. Migration history, checksums and contract admission guard startup."
        : "Disable automatic deployment. Select the same immutable Git tag for every role, deploy the server leader first, then external workers, and run the deployment verifier.",
  };
}

// Stable logical service names keep scripts/backup/host.sh discovery working.
// Physical resources and proxy labels include the project stem and origin hash.
const projectStem = (options: Options) => options.project ?? `wssp-${options.environment}`;
function validateNames(options: Options) {
  if (!/^[a-z0-9][a-z0-9-]{0,31}$/.test(projectStem(options)))
    throw new Error(
      "Project must contain 1..32 lowercase letters, digits or hyphens, starting with a letter or digit.",
    );
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(options.proxyNetwork ?? "dokploy-network"))
    throw new Error(
      "Proxy network must contain 1..128 letters, digits, dots, underscores or hyphens.",
    );
}
function originHash(options: Options) {
  return createHash("sha256").update(new URL(options.url).origin).digest("hex").slice(0, 10);
}
function projectName(options: Options): string {
  const scoped = options.project
    ? `${options.project}-${options.environment}`
    : projectStem(options);
  // Leave seven characters for the server's DNS suffix (63 total).
  const host = new URL(options.url).hostname
    .replace(/[^a-z0-9-]/g, "-")
    .slice(0, Math.max(0, 44 - scoped.length));
  return [scoped, host.replace(/-+$/, ""), originHash(options)].filter(Boolean).join("-");
}
function backupPrefix(options: Options): string {
  return `wssp/${options.environment}/${projectStem(options)}/${new URL(options.url).hostname}-${originHash(options)}/database`;
}
const smtpKeys = ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_FROM"];
// Identical encryption, CLI-login and webhook policy on server/external worker.
const WEBHOOK_KEYS = [
  "DATA_ENCRYPTION_KEY",
  "DATA_ENCRYPTION_KEY_PREVIOUS",
  "CREDENTIALS_ENABLED",
  "WEBHOOK_ALLOWED_PRIVATE_CIDRS",
  "WEBHOOK_ALLOWED_PRIVATE_HOSTS",
  "WEBHOOK_TRANSLATION_PREFIXES",
  "WEBHOOK_PRIVATE_ALLOWLIST_SCOPE",
  "WEBHOOK_ALLOW_PLAINTEXT_PRIVATE",
];
const OPTIONAL_FORWARDED: Record<string, string> = {
  ...Object.fromEntries(
    ENV_VARS.filter((variable) => variable.key.startsWith("BACKUP_")).map((variable) => [
      variable.key,
      "Optional backup configuration; define it with an empty value when backups are off (Dokploy rejects a reference to an undefined variable). See docs/operations/backup-and-restore.md.",
    ]),
  ),
  DATA_ENCRYPTION_KEY_PREVIOUS:
    "Define it with an empty value outside an encryption-root rotation (Dokploy rejects a reference to an undefined variable); use the same previous root on server and worker during rotation.",
  CREDENTIALS_ENABLED:
    "Define it with an empty value for the existing CLI-login default (Dokploy rejects a reference to an undefined variable); set false on both server and worker to disable.",
  SETUP_KEY:
    "Server only. Define it with an empty value (Dokploy rejects a reference to an undefined variable); the first-admin setup route then does not exist. To create the first admin without email, set a key (pnpm generate:secret), redeploy, run pnpm deploy:generate-admin, then empty it again and redeploy. See docs/operations/deployment.md#first-admin-without-email.",
  MCP_ENABLED:
    "Server only. Define it with an empty value for the default (true: the built-in MCP endpoint and its OAuth provider are on; Dokploy rejects a reference to an undefined variable); set false to turn MCP off (its routes then return 404).",
};
const writerKeys = [
  "BACKUP_S3_BUCKET",
  "BACKUP_S3_ACCESS_KEY_ID",
  "BACKUP_S3_SECRET_ACCESS_KEY",
  "BACKUP_S3_REGION",
  "BACKUP_S3_ENDPOINT",
  "BACKUP_S3_FORCE_PATH_STYLE",
  "BACKUP_S3_SSE",
];
const MONITOR_KEY_ID = "BACKUP_MONITOR_S3_ACCESS_KEY_ID";
const monitorKeys = [
  "BACKUP_ENABLED",
  "BACKUP_MAX_AGE_HOURS",
  "BACKUP_S3_BUCKET",
  "BACKUP_S3_REGION",
  "BACKUP_S3_ENDPOINT",
  "BACKUP_S3_FORCE_PATH_STYLE",
  "BACKUP_MONITOR_S3_ACCESS_KEY_ID",
  "BACKUP_MONITOR_S3_SECRET_ACCESS_KEY",
];
const backupDefaults: Record<string, string> = {
  BACKUP_ENABLED: "false",
  BACKUP_MAX_AGE_HOURS: "36",
  BACKUP_S3_REGION: "auto",
  BACKUP_S3_FORCE_PATH_STYLE: "false",
  WEBHOOK_PRIVATE_ALLOWLIST_SCOPE: "admins",
  WEBHOOK_ALLOW_PLAINTEXT_PRIVATE: "false",
};
const composeVar = (name: string, fallback = "") => `\${${name}:-${fallback}}`;
const databaseUrl = `postgresql://\${POSTGRES_USER:-wssp}:\${POSTGRES_PASSWORD:-}@postgres:5432/\${POSTGRES_DB:-wssp}`;
const redisUrl = `redis://:\${REDIS_PASSWORD:-}@redis:6379`;
const refsForCompose = (names: string[]) =>
  Object.fromEntries(names.map((key) => [key, composeVar(key, backupDefaults[key] ?? "")]));

function composeEnvironments(options: Options): Record<string, Record<string, string>> {
  const worker = options.topology === "app-worker";
  const common = { DATABASE_URL: databaseUrl, REDIS_URL: redisUrl, NODE_ENV: "production" };
  const prefix = backupPrefix(options);
  return {
    postgres: {
      POSTGRES_USER: composeVar("POSTGRES_USER", "wssp"),
      POSTGRES_PASSWORD: composeVar("POSTGRES_PASSWORD"),
      POSTGRES_DB: composeVar("POSTGRES_DB", "wssp"),
    },
    redis: { REDIS_PASSWORD: composeVar("REDIS_PASSWORD") },
    server: {
      ...common,
      ...refsForCompose([
        "BETTER_AUTH_SECRET",
        "SANDBOX_REQUEST_HMAC_SECRET",
        ...WEBHOOK_KEYS,
        "ADMIN_EMAILS",
        "SETUP_KEY",
        "SMTP_HOST",
        "SMTP_USER",
        "SMTP_PASS",
        "SMTP_FROM",
        "MCP_ENABLED",
      ]),
      SMTP_PORT: composeVar("SMTP_PORT", "587"),
      BETTER_AUTH_URL: new URL(options.url).origin,
      TRUST_PROXY_HOPS: trustProxyHops(options),
      WORKER_MODE: worker ? "external" : "embedded",
      MIGRATE_ON_START: "true",
      ...refsForCompose(writerKeys),
      BACKUP_HEARTBEAT_URL: composeVar("BACKUP_HEARTBEAT_URL"),
      ...(!worker ? refsForCompose(monitorKeys) : refsForCompose([MONITOR_KEY_ID])),
      BACKUP_S3_PREFIX: prefix,
      BACKUP_ENABLED: composeVar("BACKUP_ENABLED", options.backups ? "true" : "false"),
      ...refsForCompose(passthroughFor(options, "server")),
    },
    ...(worker
      ? {
          worker: {
            ...common,
            ...refsForCompose(WEBHOOK_KEYS),
            ...refsForCompose(["SMTP_HOST", "SMTP_USER", "SMTP_PASS", "SMTP_FROM"]),
            SMTP_PORT: composeVar("SMTP_PORT", "587"),
            MIGRATE_ON_START: "false",
            ...refsForCompose(monitorKeys),
            BACKUP_S3_PREFIX: prefix,
            BACKUP_ENABLED: composeVar("BACKUP_ENABLED", options.backups ? "true" : "false"),
            ...refsForCompose(passthroughFor(options, "worker")),
          },
        }
      : {}),
    ...(options.backups
      ? {
          backup: {
            DATABASE_URL: databaseUrl,
            ...refsForCompose(writerKeys),
            BACKUP_HEARTBEAT_URL: composeVar("BACKUP_HEARTBEAT_URL"),
            BACKUP_S3_PREFIX: prefix,
            BACKUP_ENABLED: composeVar("BACKUP_ENABLED", "true"),
            BACKUP_SCHEDULE: composeVar("BACKUP_SCHEDULE", "daily"),
            BACKUP_HOUR_UTC: composeVar("BACKUP_HOUR_UTC", "3"),
            BACKUP_KEEP: composeVar("BACKUP_KEEP", "14"),
          },
        }
      : {}),
  };
}

function composeChecklist(options: Options) {
  const optional = optionalForwarded(options);
  return {
    file: "docker-compose.dokploy.yml",
    topology: options.topology,
    buildContext:
      options.gitUrl === undefined
        ? "local (`context: .`): only for plain `docker compose` in a checkout. A pasted Dokploy Compose has no source tree; regenerate with --git-url <repository URL> for Dokploy."
        : `${options.gitUrl}#${options.gitRef}: every role builds that Git ref from the repository, so the pasted Compose needs no source tree. The Dokploy server's Docker fetches the URL itself.`,
    import:
      "Paste the generated Compose into Dokploy (Compose); every role builds the selected Git ref from the build context above.",
    environmentVariables: Object.fromEntries(
      Object.entries(composeEnvironments(options)).map(([role, entries]) => [
        role,
        [
          ...new Set(
            Object.values(entries).flatMap((value) =>
              [...value.matchAll(/\$\{([A-Z0-9_]+):-\}/g)].map((match) => match[1]!),
            ),
          ),
        ]
          .filter((key) => !Object.hasOwn(optional, key))
          .sort(),
      ]),
    ),
    optionalEnvironmentVariables: Object.fromEntries(
      Object.entries(composeEnvironments(options)).map(([role, entries]) => [
        role,
        Object.fromEntries(
          Object.keys(optional)
            .filter((key) => Object.hasOwn(entries, key))
            .map((key) => [key, optional[key]!]),
        ),
      ]),
    ),
    manualMigration: "docker compose run --rm server migrate",
    backups:
      (options.backups
        ? "The generated Compose includes the shared /backups volume and defaults BACKUP_ENABLED=true and BACKUP_SCHEDULE=daily. Migration snapshots and freshness monitoring are enabled; enable the backup profile for daily backups. "
        : "Backups default off. Regenerate with --backups true to add the backup profile and shared /backups volume with backups enabled; enable the profile for daily backups. ") +
      "Exactly one schedule per database.",
  };
}

/** Above the main router's default priority (its rule length). */
const CONTENT_ROUTER_PRIORITY = 1000;

/**
 * The Traefik v3 rule of the uncompressed download router: `GET`/`HEAD`
 * `/v1/operations/{id}/content` and `/api/dashboard/operations/{id}/content`
 * on the deployment's host. `$$` is Compose's escape for a literal `$`.
 */
export function contentDownloadRule(hostname: string): string {
  return `Host(\`${hostname}\`) && PathRegexp(\`^/(v1|api/dashboard)/operations/[^/]+/content$$\`)`;
}

/** Generate a project-isolated server-led deployment with an optional backup profile. */
export function generateDokployCompose(options: Options): string {
  generateDokployConfig(options); // Validate both public entry points identically.
  const project = projectName(options);
  const router = `${project}-server`;
  const envs = composeEnvironments(options);
  const buildVersion = composeVar(
    "BUILD_VERSION",
    options.environment === "production" ? options.gitRef.slice("release/".length) : "",
  );
  const envLines = (role: string) =>
    Object.entries(envs[role] ?? {})
      .map(([key, value]) => `      ${key}: ${JSON.stringify(value)}`)
      .join("\n");
  const runtime = (role: "server" | "worker") => `  ${role}:
    build:
      context: ${buildContext(options)}
      dockerfile: ${role === "server" ? "Dockerfile" : "Dockerfile.worker"}
      args:
        BUILD_VERSION: ${buildVersion}
    restart: unless-stopped
    stop_grace_period: 30s
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
${envLines(role)}
${
  role === "server"
    ? `    volumes:
${options.backups ? "      - backups:/backups\n" : ""}      - server-data:/app/.data
    labels:
${[
  "traefik.enable=true",
  `traefik.docker.network=${options.proxyNetwork ?? "dokploy-network"}`,
  `traefik.http.routers.${router}.service=${router}`,
  `traefik.http.routers.${router}.rule=Host(\`${new URL(options.url).hostname}\`)`,
  `traefik.http.routers.${router}.entrypoints=websecure`,
  `traefik.http.routers.${router}.tls.certresolver=letsencrypt`,
  `traefik.http.services.${router}.loadbalancer.server.port=3000`,
  `traefik.http.middlewares.${router}-compress.compress=true`,
  `traefik.http.middlewares.${router}-compress.compress.encodings=zstd,br,gzip`,
  `traefik.http.routers.${router}.middlewares=${router}-compress`,
  // Operation content downloads are never compressed (docs/operations/
  // deployment.md "Reverse proxy transfer bodies"): their own router, same
  // service, no middleware, above the main router.
  `traefik.http.routers.${router}-content.service=${router}`,
  `traefik.http.routers.${router}-content.rule=${contentDownloadRule(new URL(options.url).hostname)}`,
  `traefik.http.routers.${router}-content.priority=${CONTENT_ROUTER_PRIORITY}`,
  `traefik.http.routers.${router}-content.entrypoints=websecure`,
  `traefik.http.routers.${router}-content.tls.certresolver=letsencrypt`,
]
  .map((value) => `      - ${JSON.stringify(value)}`)
  .join("\n")}
    networks:
      - default
      - dokploy
`
    : ""
}    deploy:
      replicas: 1
      update_config:
        parallelism: 1
        order: ${role === "server" ? "stop-first" : "start-first"}
        failure_action: rollback
      rollback_config:
        parallelism: 1
        order: ${role === "server" ? "stop-first" : "start-first"}
      restart_policy:
        condition: on-failure
`;
  return `# Generated for Git ref ${options.gitRef}; do not commit this artifact.
# Build context: ${options.gitUrl === undefined ? ". (--git-url local: plain docker compose in a checkout only)" : `${options.gitUrl}#${options.gitRef} (fetched by the Dokploy server's Docker)`}.
# PostgreSQL 18 + Valkey 9 (noeviction); server-led committed migrations.
# External workers wait before starting consumers. No database/cache host ports.
# Server stop-first protects its private spool; keep the 30s drain grace.
# Backups default off. Regenerate with --backups true for the backup profile
# and shared volume, then enable the profile. Exactly one schedule per DB.
# Writer keys are stripped after server startup; monitor uses its own read-only keys.
name: ${project}

services:
  postgres:
    image: docker.io/library/postgres:18.6-trixie@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42
    restart: unless-stopped
    environment:
${envLines("postgres")}
    volumes:
      - postgres-data:/var/lib/postgresql
    healthcheck:
      test: pg_isready -h 127.0.0.1 -U $\${POSTGRES_USER} -d $\${POSTGRES_DB}
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
  redis:
    image: docker.io/valkey/valkey:9.1.3-alpine@sha256:bf09d58e96d6b4524a15396b65b242bbe18beebbcc15a04d8ee75ddac62fae0b
    restart: unless-stopped
    command: ["valkey-server", "--appendonly", "yes", "--maxmemory-policy", "noeviction", "--requirepass", "\${REDIS_PASSWORD:-}"]
    environment:
${envLines("redis")}
    volumes:
      - redis-data:/data
    healthcheck:
      test: valkey-cli --no-auth-warning -a "$\${REDIS_PASSWORD}" ping
      interval: 10s
      timeout: 5s
      retries: 5
${runtime("server")}${options.topology === "app-worker" ? runtime("worker") : ""}
${
  options.backups
    ? `  backup:
    profiles: [backup]
    build:
      context: ${buildContext(options)}
      dockerfile: Dockerfile
      args:
        BUILD_VERSION: ${buildVersion}
    command: backup-schedule
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    environment:
${envLines("backup")}
    volumes:
      - backups:/backups
    # A scheduler has no HTTP listener, so it does not inherit the server probe:
    # it is unhealthy when the last scheduled run failed or the last success is stale.
    healthcheck:
      test: ["CMD", "node", "/app/scripts/backup/schedule.mjs", "health"]
      interval: 5m
      timeout: 30s
      retries: 1
      start_period: 10m
`
    : ""
}
volumes:
  postgres-data:
  redis-data:
${options.backups ? "  backups:\n" : ""}  server-data:
networks:
  default:
    driver: bridge
  dokploy:
    name: ${options.proxyNetwork ?? "dokploy-network"}
    external: true
`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    const fields: Record<string, string> = {};
    for (let index = 0; index < args.length; index += 2) {
      const key = args[index];
      const value = args[index + 1];
      if (
        !key ||
        ![
          "--environment",
          "--git-ref",
          "--topology",
          "--url",
          "--project",
          "--proxy-network",
          "--backups",
          "--git-url",
          "--env",
          "--trust-proxy-hops",
        ].includes(key) ||
        fields[key] ||
        !value ||
        value.startsWith("--")
      )
        throw new Error(
          "Use --environment development|production --git-ref <ref> --topology app|app-worker --url <https-origin> [--git-url <repository URL, default the origin remote>|local] [--project <stem>] [--proxy-network <name>] [--backups true|false] [--env KEY,KEY…] [--trust-proxy-hops N, default 1].",
        );
      fields[key] = value;
    }
    if (fields["--backups"] && !["true", "false"].includes(fields["--backups"]))
      throw new Error("--backups must be true or false.");
    const hops = fields["--trust-proxy-hops"];
    if (hops !== undefined && !/^[0-9]+$/.test(hops))
      throw new Error("--trust-proxy-hops must be a whole number.");
    const options = {
      environment: fields["--environment"],
      gitRef: fields["--git-ref"],
      topology: fields["--topology"] || "app",
      url: fields["--url"],
      project: fields["--project"],
      proxyNetwork: fields["--proxy-network"],
      backups: fields["--backups"] === "true",
      env: fields["--env"]?.split(",").map((key) => key.trim()),
      trustProxyHops: hops === undefined ? undefined : Number(hops),
      gitUrl: resolveGitUrl(fields["--git-url"], () => {
        const remote = spawnSync("git", ["remote", "get-url", "origin"], {
          cwd: fileURLToPath(new URL("..", import.meta.url)),
          encoding: "utf8",
        });
        return remote.status === 0 ? remote.stdout : undefined;
      }),
    };
    if (!options.environment || !options.gitRef || !options.url)
      throw new Error("--environment, --git-ref, and --url are required.");
    const composePath = fileURLToPath(new URL("../docker-compose.dokploy.yml", import.meta.url));
    writeFileSync(composePath, generateDokployCompose(options as Options));
    console.error(
      `[dokploy] wrote ${relative(process.cwd(), composePath)} — a gitignored artifact. Import it in Dokploy (Compose) and fill the variables the checklist lists under "compose".`,
    );
    console.log(JSON.stringify(generateDokployConfig(options as Options), null, 2));
  } catch (error) {
    console.error(
      error instanceof TypeError
        ? "Invalid configuration URL."
        : error instanceof Error
          ? error.message
          : "Invalid configuration.",
    );
    process.exitCode = 1;
  }
}
