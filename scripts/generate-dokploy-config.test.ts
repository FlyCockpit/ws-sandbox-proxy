import assert from "node:assert/strict";
import { test } from "node:test";
import {
  generateDokployCompose,
  generateDokployConfig,
  resolveGitUrl,
} from "./generate-dokploy-config.js";

const defaults = {
  environment: "development" as const,
  gitRef: "main",
  topology: "app" as const,
  url: "https://dev.example.com",
};
const block = (compose: string, role: string) =>
  compose.split(`\n  ${role}:\n`)[1]?.split(/\n {2}[a-z][a-z-]*:\n/)[0] ?? "";

test("server leads, external worker waits, and all Applications build the selected ref", () => {
  for (const topology of ["app", "app-worker"] as const) {
    const config = generateDokployConfig({ ...defaults, topology });
    assert.equal(config.applications.length, topology === "app" ? 1 : 2);
    const server = config.applications[0]!;
    assert.equal(server.environment.MIGRATE_ON_START, "true");
    assert.equal(server.environment.WORKER_MODE, topology === "app" ? "embedded" : "external");
    assert.ok(server.environment.SANDBOX_REQUEST_HMAC_SECRET);
    assert.deepEqual(
      server.persistentStorage.map((entry) => entry.mountPath),
      ["/app/.data"],
    );
    for (const app of config.applications) {
      const order = app === server ? "stop-first" : "start-first";
      assert.equal(app.customGitBranch, "main");
      assert.equal(app.autoDeploy, true);
      assert.equal(app.updateConfigSwarm.Order, order);
      assert.equal(app.rollbackConfigSwarm.Order, order);
      assert.equal(app.updateConfigSwarm.FailureAction, "rollback");
      assert.equal(app.stopGracePeriodSwarm, 30_000_000_000);
    }
    assert.doesNotMatch(
      JSON.stringify(config),
      /APPLY_SCHEMA|WAIT_FOR_SCHEMA|schema-apply|db-applier/,
    );
    if (topology === "app-worker") {
      const worker = config.applications[1]!;
      assert.equal(worker.environment.MIGRATE_ON_START, "false");
      for (const key of [
        "DATA_ENCRYPTION_KEY",
        "DATA_ENCRYPTION_KEY_PREVIOUS",
        "CREDENTIALS_ENABLED",
        "WEBHOOK_ALLOWED_PRIVATE_CIDRS",
        "WEBHOOK_ALLOWED_PRIVATE_HOSTS",
        "WEBHOOK_TRANSLATION_PREFIXES",
        "WEBHOOK_PRIVATE_ALLOWLIST_SCOPE",
        "WEBHOOK_ALLOW_PLAINTEXT_PRIVATE",
      ])
        assert.equal(worker.environment[key], server.environment[key], key);
    }
  }
});

test("production requires an immutable release and development follows main", () => {
  for (const gitRef of ["master", "feature/test", "refs/heads/main"])
    assert.throws(() => generateDokployConfig({ ...defaults, gitRef }), /follows main/);
  assert.throws(
    () => generateDokployConfig({ ...defaults, environment: "production" }),
    /immutable/,
  );
  const commit = "a".repeat(40);
  const config = generateDokployConfig({
    ...defaults,
    environment: "production",
    gitRef: `release/${commit}`,
    topology: "app-worker",
  });
  for (const app of config.applications) {
    assert.equal(app.autoDeploy, false);
    assert.equal(app.buildArgs.BUILD_VERSION, commit);
  }
  assert.match(config.database.name, /^wssp-production-/);
  const compose = generateDokployCompose({
    ...defaults,
    environment: "production",
    gitRef: `release/${commit}`,
  });
  assert.ok(compose.includes(`BUILD_VERSION: \${BUILD_VERSION:-${commit}}`));
});

test("both entry points validate origins, project stems, proxy networks and topology", () => {
  for (const url of [
    "http://example.com",
    "https://u:p@example.com",
    "https://example.com/path",
    "https://example.com?x=1",
    "https://example.com/#frag",
    "https://example.com:8443",
    "https://bad_host.example.com",
  ])
    for (const generate of [generateDokployConfig, generateDokployCompose])
      assert.throws(() => generate({ ...defaults, url }));
  for (const project of ["", "UPPER", "-leading", "bad_name", "a".repeat(33), "bad\ninjected"])
    for (const generate of [generateDokployConfig, generateDokployCompose])
      assert.throws(() => generate({ ...defaults, project }), /Project/);
  for (const proxyNetwork of ["", "bad network", "bad\ninjected", "-leading", "a".repeat(129)])
    assert.throws(() => generateDokployCompose({ ...defaults, proxyNetwork }), /Proxy network/);
  for (const topology of ["app-applier", "full"])
    assert.throws(
      () => generateDokployCompose({ ...defaults, topology: topology as "app" }),
      /Choose app/,
    );
});

test("writer keys reach startup/backup, monitor keys reach only the selected runtime", () => {
  for (const topology of ["app", "app-worker"] as const) {
    const config = generateDokployConfig({ ...defaults, topology });
    const server = config.applications[0]!;
    const monitor = config.applications[topology === "app" ? 0 : 1]!;
    assert.equal(
      server.environment.BACKUP_S3_ACCESS_KEY_ID,
      `\${{environment.BACKUP_S3_ACCESS_KEY_ID}}`,
    );
    assert.ok(server.environment.BACKUP_HEARTBEAT_URL);
    assert.match(
      server.environment.BACKUP_S3_PREFIX!,
      /^wssp\/development\/wssp-development\/dev.example.com-[a-f0-9]{10}\/database$/,
    );
    assert.equal(monitor.environment.BACKUP_S3_PREFIX, server.environment.BACKUP_S3_PREFIX);
    assert.ok(monitor.environment.BACKUP_MONITOR_S3_ACCESS_KEY_ID);
    if (topology === "app-worker") {
      // The ID alone, for the entrypoint's reuse check; never the secret.
      assert.equal(
        server.environment.BACKUP_MONITOR_S3_ACCESS_KEY_ID,
        `\${{environment.BACKUP_MONITOR_S3_ACCESS_KEY_ID}}`,
      );
      assert.equal(server.environment.BACKUP_MONITOR_S3_SECRET_ACCESS_KEY, undefined);
      assert.deepEqual(
        Object.keys(server.environment).filter((key) => key.startsWith("BACKUP_MONITOR_")),
        ["BACKUP_MONITOR_S3_ACCESS_KEY_ID"],
      );
      assert.equal(monitor.environment.BACKUP_S3_ACCESS_KEY_ID, undefined);
      assert.equal(monitor.environment.BETTER_AUTH_SECRET, undefined);
    }
    assert.equal(config.environmentVariablesToSetOnce.BACKUP_ENABLED, undefined);
    assert.ok(config.environmentVariablesOptional.BACKUP_ENABLED);
    assert.equal(config.backupSetupRequired, false);
    assert.match(config.backupSetup, /Backups default off/);
    assert.equal(
      Object.keys(config.environmentVariablesToSetOnce).some((key) => key.startsWith("BACKUP_")),
      false,
    );
    for (const optional of Object.values(config.optionalEnvironmentKeys))
      assert.equal(
        optional.some((key) => /^(BACKUP_|RESTORE_|MIGRATE_|WSSP_INSTANCE_ID)/.test(key)),
        false,
      );
  }
});

test("Compose preserves spool/drain, pins PG18/Valkey9, and wires the opt-in scheduler", () => {
  for (const topology of ["app", "app-worker"] as const) {
    const compose = generateDokployCompose({ ...defaults, topology, backups: true });
    assert.doesNotMatch(
      compose,
      /schema-apply|db-applier|APPLY_SCHEMA|WAIT_FOR_SCHEMA|service_completed_successfully/,
    );
    assert.doesNotMatch(compose, /^\s+(ports|container_name):/m);
    assert.match(compose, /image: docker.io\/library\/postgres:18.6-trixie@sha256:/);
    assert.match(compose, /image: docker.io\/valkey\/valkey:9.1.3-alpine@sha256:/);
    assert.match(compose, /postgres-data:\/var\/lib\/postgresql/);
    assert.match(compose, /--maxmemory-policy", "noeviction"/);
    const server = block(compose, "server");
    assert.equal(server.match(/^ {6}BACKUP_ENABLED:/gm)?.length, 1);
    assert.match(server, /BACKUP_ENABLED: "\$\{BACKUP_ENABLED:-true\}"/);
    assert.match(server, /MIGRATE_ON_START: "true"/);
    assert.match(server, /stop_grace_period: 30s/);
    assert.match(server, /order: stop-first/);
    assert.match(server, /server-data:\/app\/\.data/);
    assert.match(server, /backups:\/backups/);
    assert.match(server, /compress\.encodings=zstd,br,gzip/);
    assert.match(server, /rule=Host\(`dev.example.com`\)/);
    assert.doesNotMatch(server, /healthcheck:/);
    const backup = block(compose, "backup");
    assert.match(backup, /BACKUP_ENABLED: "\$\{BACKUP_ENABLED:-true\}"/);
    assert.match(backup, /profiles: \[backup\]/);
    assert.match(backup, /dockerfile: Dockerfile\n/);
    assert.match(backup, /command: backup-schedule/);
    assert.match(backup, /BACKUP_SCHEDULE: "\$\{BACKUP_SCHEDULE:-daily\}"/);
    assert.match(backup, /backups:\/backups/);
    assert.match(
      backup,
      /test: \["CMD", "node", "\/app\/scripts\/backup\/schedule\.mjs", "health"\]/,
    );
    assert.doesNotMatch(backup, /disable: true/);
    assert.doesNotMatch(backup, /BETTER_AUTH_SECRET|REDIS_URL|BACKUP_MONITOR_/);
    const prefix = (value: string) => value.match(/BACKUP_S3_PREFIX: "([^"]+)"/)?.[1];
    assert.equal(prefix(backup), prefix(server));
    if (topology === "app-worker") {
      const worker = block(compose, "worker");
      assert.match(worker, /MIGRATE_ON_START: "false"/);
      assert.match(worker, /order: start-first/);
      assert.doesNotMatch(worker, /BACKUP_S3_ACCESS_KEY_ID|BACKUP_S3_SECRET_ACCESS_KEY|networks:/);
      assert.deepEqual(
        [...server.matchAll(/^\s+(BACKUP_MONITOR_[A-Z0-9_]+):/gm)].map((match) => match[1]),
        ["BACKUP_MONITOR_S3_ACCESS_KEY_ID"],
      );
      assert.equal(prefix(worker), prefix(server));
    } else assert.equal(block(compose, "worker"), "");
    for (const match of compose.matchAll(
      /\$\{([A-Z0-9_]*(?:SECRET|PASSWORD|PASS)[A-Z0-9_]*):-([^}]*)\}/g,
    ))
      assert.equal(match[2], "", `${match[1]} has a secret default`);
  }
});

test("two project stems, origins and environments have disjoint physical identities", () => {
  for (const environment of ["development", "production"] as const)
    for (const topology of ["app", "app-worker"] as const) {
      const options = {
        ...defaults,
        environment,
        topology,
        gitRef: environment === "development" ? "main" : `release/${"b".repeat(40)}`,
      };
      const first = generateDokployConfig({ ...options, project: "wssp-one" });
      const second = generateDokployConfig({ ...options, project: "wssp-two" });
      assert.notEqual(first.project, second.project);
      assert.notEqual(first.database.name, second.database.name);
      assert.notEqual(first.redis.name, second.redis.name);
      for (let i = 0; i < first.applications.length; i++) {
        assert.notEqual(first.applications[i]?.name, second.applications[i]?.name);
        assert.notEqual(
          first.applications[i]?.environment.BACKUP_S3_PREFIX,
          second.applications[i]?.environment.BACKUP_S3_PREFIX,
        );
      }
      assert.notDeepEqual(
        first.applications[0]?.persistentStorage,
        second.applications[0]?.persistentStorage,
      );
      for (const [config, project] of [
        [first, "wssp-one"],
        [second, "wssp-two"],
      ] as const) {
        const compose = generateDokployCompose({ ...options, project });
        assert.match(compose, new RegExp(`^name: ${config.project}$`, "m"));
        assert.match(
          compose,
          new RegExp(`routers\\.${config.project}-server\\.service=${config.project}-server`),
        );
      }
    }
  const development = generateDokployConfig({ ...defaults, project: "wssp-shared" });
  const production = generateDokployConfig({
    ...defaults,
    project: "wssp-shared",
    environment: "production",
    gitRef: `release/${"c".repeat(40)}`,
  });
  assert.notEqual(development.project, production.project);
  assert.ok(
    generateDokployConfig({ ...defaults, project: "a".repeat(32) }).applications[0]!.name.length <=
      63,
  );
  const a = generateDokployConfig({ ...defaults, url: "https://a-b.example.com" });
  const b = generateDokployConfig({ ...defaults, url: "https://a.b.example.com" });
  assert.notEqual(a.project, b.project);
  assert.notEqual(
    a.applications[0]?.environment.BACKUP_S3_PREFIX,
    b.applications[0]?.environment.BACKUP_S3_PREFIX,
  );
});

test("only the server joins the configurable shared ingress, with explicit Traefik selection", () => {
  const compose = generateDokployCompose({
    ...defaults,
    topology: "app-worker",
    proxyNetwork: "custom_ingress",
  });
  assert.match(compose, /name: custom_ingress\n\s+external: true/);
  assert.match(block(compose, "server"), /traefik.docker.network=custom_ingress/);
  assert.match(block(compose, "server"), /- default\n\s+- dokploy/);
  for (const role of ["postgres", "redis", "worker", "backup"])
    assert.doesNotMatch(block(compose, role), /networks:|traefik\./);
});

test("only the server trusts exactly one proxy hop (Traefik) for client IPs", () => {
  const config = generateDokployConfig({ ...defaults, topology: "app-worker" });
  assert.equal(config.applications[0]!.environment.TRUST_PROXY_HOPS, "1");
  assert.equal(config.applications[1]!.environment.TRUST_PROXY_HOPS, undefined);
  assert.ok(!config.optionalEnvironmentKeys.server.includes("TRUST_PROXY_HOPS"));
  const compose = generateDokployCompose({ ...defaults, topology: "app-worker" });
  assert.match(block(compose, "server"), /\n\s+TRUST_PROXY_HOPS: "1"\n/);
  for (const role of ["postgres", "redis", "worker", "backup"])
    assert.doesNotMatch(block(compose, role), /TRUST_PROXY_HOPS/);
});

test("checklist reflects the actual roles and explicit backup configuration", () => {
  const config = generateDokployConfig(defaults);
  assert.equal(config.compose.file, "docker-compose.dokploy.yml");
  assert.deepEqual(config.compose.environmentVariables.postgres, ["POSTGRES_PASSWORD"]);
  assert.ok(config.compose.environmentVariables.server?.includes("BETTER_AUTH_SECRET"));
  assert.ok(config.compose.optionalEnvironmentVariables.server?.BACKUP_S3_ACCESS_KEY_ID);
  assert.match(config.compose.manualMigration, /server migrate/);
  assert.equal(config.environmentVariablesToSetOnce.DATA_ENCRYPTION_KEY_PREVIOUS, undefined);
  assert.equal(config.environmentVariablesToSetOnce.CREDENTIALS_ENABLED, undefined);
  assert.ok(config.environmentVariablesOptional.CREDENTIALS_ENABLED);
  assert.ok(config.compose.optionalEnvironmentVariables.server?.DATA_ENCRYPTION_KEY_PREVIOUS);
  assert.ok(!config.compose.environmentVariables.server?.includes("DATA_ENCRYPTION_KEY_PREVIOUS"));
});

test("default Compose needs no backup settings, service or volume", () => {
  for (const topology of ["app", "app-worker"] as const) {
    const config = generateDokployConfig({ ...defaults, topology });
    const compose = generateDokployCompose({ ...defaults, topology });
    assert.equal(block(compose, "backup"), "");
    assert.doesNotMatch(compose, /backups:|backups:\/backups|BACKUP_SCHEDULE:/);
    assert.match(block(compose, "server"), /BACKUP_ENABLED: "\$\{BACKUP_ENABLED:-false\}"/);
    for (const required of Object.values(config.compose.environmentVariables))
      assert.equal(
        required.some((key) => key.startsWith("BACKUP_")),
        false,
      );
    assert.equal(config.compose.environmentVariables.backup, undefined);
    const optedIn = generateDokployConfig({ ...defaults, topology, backups: true });
    for (const checklist of [optedIn.backupSetup, optedIn.compose.backups]) {
      assert.match(checklist, /defaults BACKUP_ENABLED=true and BACKUP_SCHEDULE=daily/);
      assert.match(checklist, /[Ee]nable the backup profile/);
      assert.doesNotMatch(checklist, /regenerate|[Ss]et BACKUP_ENABLED/);
    }
    assert.ok(
      optedIn.applications[0]!.persistentStorage.some((entry) => entry.mountPath === "/backups"),
    );
  }
});

const release = `release/${"a".repeat(40)}`;

test("--git-url pins every build context to <url>#<git-ref>, so a pasted Compose builds without a source tree", () => {
  for (const [options, contexts] of [
    [{ ...defaults }, 1],
    [
      {
        ...defaults,
        environment: "production" as const,
        gitRef: release,
        topology: "app-worker" as const,
        backups: true,
      },
      3,
    ],
  ] as const) {
    const withUrl = { ...options, gitUrl: "https://github.com/example/app.git" };
    const compose = generateDokployCompose(withUrl);
    const found = [...compose.matchAll(/^ {6}context: (.+)$/gm)].map((match) => match[1]);
    assert.equal(found.length, contexts, compose);
    for (const context of found)
      assert.equal(context, JSON.stringify(`https://github.com/example/app.git#${withUrl.gitRef}`));
    assert.doesNotMatch(compose, /context: \.$/m);
    const config = generateDokployConfig(withUrl);
    assert.ok(
      config.compose.buildContext.startsWith(
        `https://github.com/example/app.git#${withUrl.gitRef}: `,
      ),
    );
    for (const app of config.applications)
      assert.equal(app.customGitUrl, "https://github.com/example/app.git");
  }
  // --project, --proxy-network and the backup profile keep working with it.
  const compose = generateDokployCompose({
    ...defaults,
    gitUrl: "git@github.com:example/app.git",
    project: "wssp",
    proxyNetwork: "edge-net",
    backups: true,
  });
  assert.match(compose, /context: "git@github\.com:example\/app\.git#main"/);
  assert.match(compose, /name: edge-net/);
  assert.match(compose, /profiles: \[backup\]/);
});

test("without a Git URL the context stays local and the checklist says it is not for Dokploy", () => {
  const compose = generateDokployCompose(defaults);
  assert.match(compose, /^ {6}context: \.$/m);
  assert.match(compose, /--git-url local/);
  assert.match(generateDokployConfig(defaults).compose.buildContext, /^local/);
});

test("--git-url refuses credentials, fragments and characters that could break the YAML", () => {
  for (const gitUrl of [
    "https://user:token@github.com/example/app.git",
    "https://token@github.com/example/app.git",
    "ssh://git:secret@example.com/app.git",
    "https://github.com/example/app.git#main",
    "https://github.com/example/app.git?x=1",
    "http://github.com/example/app.git",
    "file:///srv/app.git",
    'https://github.com/example/"app',
    "https://github.com/example/app.git $(id)",
    "",
  ])
    assert.throws(() => generateDokployConfig({ ...defaults, gitUrl }), /--git-url/, gitUrl);
});

test("resolveGitUrl: the flag, else the origin remote; local means context .; neither is an error", () => {
  assert.equal(
    resolveGitUrl("https://x.example/a.git", () => "ignored"),
    "https://x.example/a.git",
  );
  assert.equal(
    resolveGitUrl(undefined, () => "git@github.com:o/r.git\n"),
    "git@github.com:o/r.git",
  );
  assert.equal(
    resolveGitUrl("local", () => "ignored"),
    undefined,
  );
  assert.throws(() => resolveGitUrl(undefined, () => undefined), /--git-url/);
  assert.throws(() => resolveGitUrl(undefined, () => "  "), /--git-url/);
});

test("MCP_ENABLED is an optional server-only key: empty keeps the app default (on), false turns MCP off", () => {
  for (const topology of ["app", "app-worker"] as const) {
    const config = generateDokployConfig({ ...defaults, topology });
    assert.equal(config.applications[0]!.environment.MCP_ENABLED, `\${{environment.MCP_ENABLED}}`);
    if (topology === "app-worker")
      assert.equal(config.applications[1]!.environment.MCP_ENABLED, undefined);
    assert.equal(config.environmentVariablesToSetOnce.MCP_ENABLED, undefined);
    assert.match(
      config.environmentVariablesOptional.MCP_ENABLED ?? "",
      /set false to turn MCP off/,
    );
    assert.ok(config.compose.optionalEnvironmentVariables.server?.MCP_ENABLED);
    assert.ok(!config.compose.environmentVariables.server?.includes("MCP_ENABLED"));
    const compose = generateDokployCompose({ ...defaults, topology });
    // Empty is unset for the app's env parser (emptyStringAsUndefined): default true.
    assert.match(block(compose, "server"), /MCP_ENABLED: "\$\{MCP_ENABLED:-\}"/);
    if (topology === "app-worker") assert.doesNotMatch(block(compose, "worker"), /MCP_ENABLED/);
  }
});
