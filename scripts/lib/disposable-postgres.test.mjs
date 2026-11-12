/**
 * `pnpm policy:pg-image-ci`: every CI job that runs the real-PostgreSQL layer
 * (`pnpm test:pg`, or `pnpm verify`, which includes it) pulls the pinned image
 * first via `pnpm test:pg:pull-image`, because the harness never pulls
 * implicitly. No workflow may pull a postgres image by literal tag (the pin
 * lives only in scripts/lib/disposable-postgres.mjs).
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import {
  canonicalApplyFixture,
  execRedacted,
  missingImageReason,
  POSTGRES_IMAGE,
  redactDockerArgs,
} from "./disposable-postgres.mjs";

const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const workflows = join(root, ".github/workflows");

/**
 * Consumers of the real-PostgreSQL layer, in any runner shape: the bare
 * `test:pg` script token (pnpm with any global flags, turbo, npm, node --run),
 * the harness entry itself, or a package-manager run of `verify` (which
 * includes test:pg). `verify:fast`, `verify:tooling` and `test:pg:pull-image`
 * are not consumers.
 */
const CONSUMERS = [
  /(?<![\w:-])test:pg(?![:\w-])/,
  /\btest-pg\.mjs\b/,
  /\b(?:pnpm|npm|yarn|bun)\b(?:\s+[^\s;&|]+)*?\s+(?:run\s+)?verify(?![:\w-])/,
  /\bnode\s+--run\s+verify(?![:\w-])/,
];
/** The pinned pull: the pnpm script, or the module entry it wraps. */
const PULL = /(?<![\w:-])test:pg:pull-image\b|\bdisposable-postgres\.mjs\s+pull\b/;
/** A postgres image referenced by literal tag: a docker pull or a job/service image. */
const LITERAL_POSTGRES = [
  /\bdocker\s+(?:image\s+)?pull\b.*\bpostgres\b/,
  /^\s*(?:-\s*)?image:\s*["']?(?:[\w.-]+(?::\d+)?\/)*postgres(?:[:@"'\s]|$)/,
];
const isConsumer = (line) => CONSUMERS.some((pattern) => pattern.test(line));
/** Docker Hub's implicit `docker.io/library/` prefix, so both spellings of the pin match. */
const normalizeImage = (reference) => reference.replace(/^(?:docker\.io\/)?(?:library\/)?/, "");
/** A job/service `image:` naming exactly the pinned digest is the reviewed server, not a literal tag. */
const isPinnedServiceImage = (line) => {
  const match = /^\s*(?:-\s*)?image:\s*["']?([^"'\s#]+)["']?\s*(?:#.*)?$/.exec(line);
  return match !== null && normalizeImage(match[1]) === normalizeImage(POSTGRES_IMAGE);
};

/**
 * `{ workflow, job, lines }` per job; comment lines dropped, backslash line
 * continuations joined. Strict: a workflow whose `jobs:` block it cannot
 * attribute line by line (no `jobs:` key, flow style, a line at an unexpected
 * indentation, no jobs) THROWS, so no workflow is ever silently unscanned.
 */
export function workflowJobs(files) {
  const jobs = [];
  for (const [workflow, text] of files) {
    const lines = [];
    text.split(/\r?\n/).forEach((line, index) => {
      const previous = lines.at(-1);
      if (previous && /\\\s*$/.test(previous.line))
        previous.line = `${previous.line.replace(/\s*\\\s*$/, "")} ${line.trim()}`;
      else lines.push({ line, number: index + 1 });
    });
    const content = ({ line }) => line.trim() !== "" && !/^\s*#/.test(line);
    const header = lines.findIndex(({ line }) => /^jobs\s*:/.test(line));
    if (header === -1)
      throw new Error(`${workflow}: no top-level jobs: key; the policy cannot scan it`);
    if (!/^jobs:\s*(?:#.*)?$/.test(lines[header].line))
      throw new Error(
        `${workflow}:${lines[header].number}: unsupported jobs: layout (use block style)`,
      );
    let indent;
    let current;
    for (const entry of lines.slice(header + 1)) {
      if (!content(entry)) continue;
      const depth = /^ */.exec(entry.line)[0].length;
      if (depth === 0) break;
      indent ??= depth;
      if (depth < indent)
        throw new Error(`${workflow}:${entry.number}: unexpected indentation inside jobs:`);
      if (depth === indent) {
        const job = /^ *([A-Za-z0-9_-]+|"[^"]+"|'[^']+'):\s*(?:#.*)?$/.exec(entry.line);
        if (!job) throw new Error(`${workflow}:${entry.number}: unsupported job layout`);
        current = { workflow, job: job[1].replace(/^["']|["']$/g, ""), lines: [] };
        jobs.push(current);
      } else current.lines.push(entry.line);
    }
    if (!jobs.some((job) => job.workflow === workflow))
      throw new Error(`${workflow}: jobs: has no jobs; the policy cannot scan it`);
  }
  return jobs;
}

export function violations(jobs) {
  const found = [];
  for (const { workflow, job, lines } of jobs) {
    const consumer = lines.findIndex(isConsumer);
    const pull = lines.findIndex((line) => PULL.test(line));
    if (consumer !== -1 && (pull === -1 || pull > consumer))
      found.push(
        `${workflow}#${job}: runs "${lines[consumer].trim()}" without a prior pnpm test:pg:pull-image`,
      );
    for (const line of lines)
      if (!isPinnedServiceImage(line) && LITERAL_POSTGRES.some((pattern) => pattern.test(line)))
        found.push(
          `${workflow}#${job}: references postgres by literal tag ("${line.trim()}"); use pnpm test:pg:pull-image`,
        );
  }
  return found;
}

const read = () =>
  readdirSync(workflows)
    .filter((name) => /\.ya?ml$/.test(name))
    .map((name) => [name, readFileSync(join(workflows, name), "utf8")]);

test("every workflow job that runs pnpm verify or pnpm test:pg pulls the pinned image first", () => {
  const jobs = workflowJobs(read());
  // Guard against a silently empty scan: the known consumers are present.
  const consumers = jobs.filter((job) => job.lines.some(isConsumer));
  assert.ok(consumers.some((job) => job.workflow === "pr-checks.yml"));
  assert.ok(consumers.some((job) => job.workflow === "release.yml" && job.job === "node-checks"));
  assert.deepEqual(violations(jobs), []);
});

test("the checker flags a consumer with no pull, a pull after the consumer, and a literal pull", () => {
  const jobs = workflowJobs([
    [
      "fixture.yml",
      [
        "jobs:",
        "  missing:",
        "    steps:",
        "      - run: pnpm verify && pnpm verify:tooling",
        "  late:",
        "    steps:",
        "      - run: pnpm test:pg",
        "      - run: pnpm test:pg:pull-image",
        "  literal:",
        "    steps:",
        "      - run: docker pull postgres:18-alpine",
        "  fine:",
        "    steps:",
        "      - run: pnpm test:pg:pull-image",
        "      - run: pnpm test:pg",
        "  unrelated:",
        "    steps:",
        "      - run: pnpm verify:fast && pnpm verify:tooling",
        "      # pnpm verify in a comment is not a step",
      ].join("\n"),
    ],
  ]);
  assert.deepEqual(violations(jobs), [
    'fixture.yml#missing: runs "- run: pnpm verify && pnpm verify:tooling" without a prior pnpm test:pg:pull-image',
    'fixture.yml#late: runs "- run: pnpm test:pg" without a prior pnpm test:pg:pull-image',
    'fixture.yml#literal: references postgres by literal tag ("- run: docker pull postgres:18-alpine"); use pnpm test:pg:pull-image',
  ]);
});

const fixture = (...lines) => [["fixture.yml", ["jobs:", ...lines].join("\n")]];

test("every consumer shape is caught: pnpm global flags, turbo, the harness entry, npm/node --run verify, line continuations", () => {
  const shapes = [
    "pnpm -w run test:pg",
    "pnpm --workspace-root run test:pg",
    "pnpm --filter @wssp/db test:pg",
    "pnpm turbo run test:pg --concurrency=1",
    "node scripts/test-pg.mjs",
    "pnpm run verify",
    "pnpm -w verify && pnpm verify:tooling",
    "npm run verify",
    "node --run verify",
  ];
  for (const shape of shapes)
    assert.deepEqual(
      violations(workflowJobs(fixture("  j:", "    steps:", `      - run: ${shape}`))),
      [`fixture.yml#j: runs "- run: ${shape}" without a prior pnpm test:pg:pull-image`],
      shape,
    );
  assert.deepEqual(
    violations(
      workflowJobs(fixture("  j:", "    steps:", "      - run: pnpm \\", "          test:pg")),
    ),
    ['fixture.yml#j: runs "- run: pnpm test:pg" without a prior pnpm test:pg:pull-image'],
  );
  // Not consumers.
  for (const shape of [
    "pnpm verify:fast",
    "pnpm verify:tooling",
    "pnpm dokploy:verify",
    "cosign verify-blob x",
  ])
    assert.deepEqual(
      violations(workflowJobs(fixture("  j:", "    steps:", `      - run: ${shape}`))),
      [],
      shape,
    );
});

test("a 4-space-indented or commented jobs: block is scanned, and an unscannable layout throws", () => {
  assert.deepEqual(
    violations(
      workflowJobs([
        [
          "four.yml",
          ["jobs:  # all jobs", "    a:", "        steps:", "            - run: pnpm test:pg"].join(
            "\n",
          ),
        ],
      ]),
    ),
    ['four.yml#a: runs "- run: pnpm test:pg" without a prior pnpm test:pg:pull-image'],
  );
  assert.throws(
    () => workflowJobs([["flow.yml", "jobs: {a: {runs-on: x}}\n"]]),
    /flow\.yml:1: unsupported jobs: layout/,
  );
  assert.throws(
    () => workflowJobs([["none.yml", "on: push\n"]]),
    /none\.yml: no top-level jobs: key/,
  );
  assert.throws(
    () => workflowJobs([["empty.yml", "jobs:\n# nothing\non: push\n"]]),
    /empty\.yml: jobs: has no jobs/,
  );
  assert.throws(
    () => workflowJobs([["odd.yml", "jobs:\n    a:\n      steps: []\n  b:\n"]]),
    /odd\.yml:4: unexpected indentation inside jobs:/,
  );
  assert.throws(
    () => workflowJobs([["list.yml", "jobs:\n  - a\n"]]),
    /list\.yml:2: unsupported job layout/,
  );
});

test("every literal postgres reference is flagged: docker image pull, a registry path, a job/service image", () => {
  const found = violations(
    workflowJobs(
      fixture(
        "  a:",
        "    steps:",
        "      - run: docker image pull postgres:18-alpine",
        "      - run: docker pull -q docker.io/library/postgres:18",
        "  b:",
        "    services:",
        "      db:",
        "        image: postgres:18",
        "  c:",
        "    container:",
        '      image: "ghcr.io/x/postgres@sha256:abc"',
      ),
    ),
  );
  assert.deepEqual(found, [
    'fixture.yml#a: references postgres by literal tag ("- run: docker image pull postgres:18-alpine"); use pnpm test:pg:pull-image',
    'fixture.yml#a: references postgres by literal tag ("- run: docker pull -q docker.io/library/postgres:18"); use pnpm test:pg:pull-image',
    'fixture.yml#b: references postgres by literal tag ("image: postgres:18"); use pnpm test:pg:pull-image',
    'fixture.yml#c: references postgres by literal tag ("image: "ghcr.io/x/postgres@sha256:abc""); use pnpm test:pg:pull-image',
  ]);
});

test("a service image is allowed only when it is exactly the pinned digest", () => {
  const pinned = POSTGRES_IMAGE.replace(/^docker\.io\/library\//, "");
  const [tag, digest] = pinned.split("@");
  const nearMiss = `${tag}@${digest.slice(0, -1)}${digest.endsWith("0") ? "1" : "0"}`;
  const found = violations(
    workflowJobs(
      fixture(
        "  exact:",
        "    services:",
        "      postgres:",
        `        image: ${pinned}`,
        "  exact-full:",
        "    services:",
        "      postgres:",
        `        image: "${POSTGRES_IMAGE}"`,
        "  near:",
        "    services:",
        "      postgres:",
        `        image: ${nearMiss}`,
        "  mutable:",
        "    services:",
        "      postgres:",
        `        image: ${tag}`,
      ),
    ),
  );
  assert.deepEqual(found, [
    `fixture.yml#near: references postgres by literal tag ("image: ${nearMiss}"); use pnpm test:pg:pull-image`,
    `fixture.yml#mutable: references postgres by literal tag ("image: ${tag}"); use pnpm test:pg:pull-image`,
  ]);
});

test("the module-entry pull counts as the pinned pull (no false positive)", () => {
  assert.deepEqual(
    violations(
      workflowJobs(
        fixture(
          "  j:",
          "    steps:",
          "      - run: node scripts/lib/disposable-postgres.mjs pull",
          "      - run: pnpm -w run test:pg",
        ),
      ),
    ),
    [],
  );
});

test("a failing docker command never echoes an --env value (argv or stderr)", () => {
  const secret = `pw-${process.pid}-s3cr3t`;
  assert.throws(
    () =>
      execRedacted(process.execPath, [
        "-e",
        "console.error('boom ' + process.argv.at(-1)); process.exit(3)",
        "--",
        "--env",
        `POSTGRES_PASSWORD=${secret}`,
      ]),
    (error) => {
      assert.doesNotMatch(error.message, new RegExp(secret));
      assert.doesNotMatch(JSON.stringify(Object.entries(error)), new RegExp(secret));
      assert.match(error.message, /--env POSTGRES_PASSWORD=<redacted> failed \(exit 3\)/);
      assert.match(error.message, /: boom POSTGRES_PASSWORD=<redacted>$/);
      return true;
    },
  );
  assert.deepEqual(redactDockerArgs(["run", "-e", "A=1", "--env=B=2", "-e=C=3", "img"]), {
    redacted: ["run", "-e", "A=<redacted>", "--env=B=<redacted>", "-e=C=<redacted>", "img"],
    secrets: ["1", "2", "3"],
  });
});

test("the missing-image reason names pnpm test:pg:pull-image, never a literal pull", () => {
  const reason = missingImageReason("postgres:0-wssp-nonexistent-probe");
  assert.equal(
    reason,
    "image postgres:0-wssp-nonexistent-probe is not present; run: pnpm test:pg:pull-image",
  );
});

/**
 * A process that owns a disposable directory and an owned process group (a
 * leader that, like Turbo, waits for its child; a grandchild that, like a
 * Vitest worker, takes a moment to exit on SIGINT and records whether the
 * directory still existed when it exited).
 */
async function ownedTreeFixture(t) {
  const dir = await mkdtemp(join(tmpdir(), "owned-group-test-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const grandchild = `
const fs = require('node:fs');
const done = () => { fs.writeFileSync(process.env.REPORT, JSON.stringify({ dirExisted: fs.existsSync(process.env.OWNED_DIR) })); process.exit(0); };
process.on('SIGINT', () => setTimeout(done, 300));
process.on('SIGTERM', () => setTimeout(done, 300));
fs.writeFileSync(process.env.GRAND_READY, String(process.pid));
setInterval(() => {}, 1000);`;
  const leader = `
const cp = require('node:child_process');
const fs = require('node:fs');
// GRAND_OWN_GROUP: like Turbo's tasks, the grandchild leads a process group of
// its own, and the leader forwards nothing; only the owner can reach it.
const g = cp.spawn(process.execPath, ['-e', ${JSON.stringify(grandchild)}], { stdio: 'ignore', env: process.env, detached: process.env.GRAND_OWN_GROUP === '1' });
process.on('SIGINT', () => {});
process.on('SIGTERM', () => {});
g.on('exit', () => process.exit(process.env.LEADER_EXIT === 'early' ? 0 : 0));
fs.writeFileSync(process.env.GRAND_PID, String(g.pid));
fs.writeFileSync(process.env.LEADER_READY, String(process.pid));
// Early exit orphans the grandchild the instant it is spawned.
if (process.env.LEADER_EXIT === 'early') process.exit(0);
setInterval(() => {}, 1000);`;
  const owner = join(dir, "owner.mjs");
  await writeFile(
    owner,
    `import { disposableDirectory, spawnOwnedProcessGroup } from ${JSON.stringify(join(root, "scripts/lib/disposable-postgres.mjs"))};
import { writeFileSync } from "node:fs";
const owned = disposableDirectory("wssp-owned-group-test-");
writeFileSync(process.env.OWNED_DIR_FILE, owned.path);
const { exited } = spawnOwnedProcessGroup(process.execPath, ["-e", ${JSON.stringify(leader)}], {
  stdio: "ignore",
  env: { ...process.env, OWNED_DIR: owned.path },
});
const code = await exited;
writeFileSync(process.env.EXITED, String(code));
owned.remove();
`,
  );
  const files = {
    REPORT: join(dir, "report.json"),
    GRAND_READY: join(dir, "grand.pid"),
    GRAND_PID: join(dir, "grand-spawned.pid"),
    LEADER_READY: join(dir, "leader.pid"),
    OWNED_DIR_FILE: join(dir, "owned-dir"),
    EXITED: join(dir, "exited"),
  };
  const waitFor = async (path) => {
    for (let attempt = 0; attempt < 200; attempt++) {
      try {
        return await readFile(path, "utf8");
      } catch {
        await delay(25);
      }
    }
    throw new Error(`fixture never wrote ${path}`);
  };
  return { owner, files, waitFor };
}

const reap = (...pids) => {
  for (const pid of pids)
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      /* already gone */
    }
};

const alive = (pid) => {
  try {
    process.kill(pid, 0);
    // An orphan may remain as a zombie until the host reaper runs. It has
    // exited and holds no database sockets or files; kill(pid, 0) alone
    // incorrectly reports it as an executing child on a busy Linux host.
    if (process.platform === "linux") {
      const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
      const state = stat.slice(stat.lastIndexOf(")") + 2).split(" ")[0];
      if (state === "Z" || state === "X") return false;
    }
    return true;
  } catch {
    return false;
  }
};

for (const [shape, extra] of [
  ["one process group", {}],
  ["a grandchild in its own process group, like Turbo's tasks", { GRAND_OWN_GROUP: "1" }],
])
  test(`a SIGINT to the owner alone terminates its whole child tree (${shape}) BEFORE removing what the tree uses, then exits`, async (t) => {
    const { owner, files, waitFor } = await ownedTreeFixture(t);
    const child = spawn(process.execPath, [owner], {
      stdio: "ignore",
      env: { ...process.env, ...files, ...extra },
    });
    const exit = new Promise((resolveExit) =>
      child.once("exit", (code, signal) => resolveExit({ code, signal })),
    );
    const grand = Number(await waitFor(files.GRAND_READY));
    const leader = Number(await waitFor(files.LEADER_READY));
    // A regression must not leak the fixture tree past this test.
    t.after(() => reap(leader, grand));
    const ownedDir = await waitFor(files.OWNED_DIR_FILE);
    process.kill(child.pid, "SIGINT"); // the owner only, as `kill -INT <pid>` does
    assert.deepEqual(await exit, { code: 130, signal: null });
    // Nothing in the tree outlived the owner, and the grandchild exited while
    // the owned directory still existed (children first, then the resources).
    assert.deepEqual(
      { leader: alive(leader), grand: alive(grand) },
      { leader: false, grand: false },
    );
    assert.deepEqual(JSON.parse(await readFile(files.REPORT, "utf8")), { dirExisted: true });
    assert.equal(existsSync(ownedDir), false);
  });

for (const [shape, extra] of [
  ["one process group", {}],
  // Orphaned and reparented once the leader exits, so no longer below it in `ps`.
  ["a grandchild in its own process group, like Turbo's tasks", { GRAND_OWN_GROUP: "1" }],
])
  test(`exited resolves only after a descendant that outlived the leader is gone (${shape})`, async (t) => {
    const { owner, files, waitFor } = await ownedTreeFixture(t);
    const child = spawn(process.execPath, [owner], {
      stdio: "ignore",
      env: { ...process.env, ...files, ...extra, LEADER_EXIT: "early" },
    });
    const exit = new Promise((resolveExit) => child.once("exit", (code) => resolveExit(code)));
    const grand = Number(await waitFor(files.GRAND_PID));
    t.after(() => reap(grand));
    assert.equal(await exit, 0);
    assert.equal(await readFile(files.EXITED, "utf8"), "0");
    assert.equal(alive(grand), false);
    // Terminated so early it may die before handling the signal; if it did
    // handle it, the owned directory still existed then.
    if (existsSync(files.REPORT))
      assert.deepEqual(JSON.parse(await readFile(files.REPORT, "utf8")), { dirExisted: true });
  });

test("a group created by an orphaned worker while it handles SIGTERM is terminated too", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "owned-respawn-test-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const files = {
    WORKER_READY: join(dir, "worker.pid"),
    CHILD_PID: join(dir, "child.pid"),
    EXITED: join(dir, "exited"),
  };
  const child = `setInterval(() => {}, 1000);`;
  // Orphaned in its own group; on SIGTERM it starts a new detached group, then exits.
  const worker = `
const cp = require('node:child_process');
const fs = require('node:fs');
process.on('SIGTERM', () => {
  const c = cp.spawn(process.execPath, ['-e', ${JSON.stringify(child)}], { stdio: 'ignore', env: process.env, detached: true });
  fs.writeFileSync(process.env.CHILD_PID, String(c.pid));
  setTimeout(() => process.exit(0), 100);
});
fs.writeFileSync(process.env.WORKER_READY, String(process.pid));
setInterval(() => {}, 1000);`;
  const leader = `
const cp = require('node:child_process');
const fs = require('node:fs');
cp.spawn(process.execPath, ['-e', ${JSON.stringify(worker)}], { stdio: 'ignore', env: process.env, detached: true });
const ready = setInterval(() => { if (fs.existsSync(process.env.WORKER_READY)) process.exit(0); }, 10);`;
  const owner = join(dir, "owner.mjs");
  await writeFile(
    owner,
    `import { spawnOwnedProcessGroup } from ${JSON.stringify(join(root, "scripts/lib/disposable-postgres.mjs"))};
import { writeFileSync } from "node:fs";
const { exited } = spawnOwnedProcessGroup(process.execPath, ["-e", ${JSON.stringify(leader)}], { stdio: "ignore" });
writeFileSync(process.env.EXITED, String(await exited));
`,
  );
  const run = spawn(process.execPath, [owner], {
    stdio: "ignore",
    env: { ...process.env, ...files },
  });
  const code = await new Promise((resolveExit) => run.once("exit", resolveExit));
  const workerPid = Number(await readFile(files.WORKER_READY, "utf8"));
  const childPid = Number(await readFile(files.CHILD_PID, "utf8"));
  t.after(() => reap(workerPid, childPid));
  assert.equal(code, 0);
  assert.equal(await readFile(files.EXITED, "utf8"), "0");
  assert.deepEqual(
    { worker: alive(workerPid), child: alive(childPid) },
    { worker: false, child: false },
  );
});

/**
 * A fake `docker` on PATH: records every call (and, for `run`, the env file's
 * mode and content) to $FAKE_DOCKER_LOG. With FAKE_CONTAINER_EXISTS=1 the
 * container never goes away (`rm` fails, `inspect` succeeds).
 */
async function fakeDockerFixture(t) {
  const dir = await mkdtemp(join(tmpdir(), "fake-docker-test-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const bin = join(dir, "bin");
  await mkdir(bin);
  const script = `#!${process.execPath}
const fs = require("node:fs");
const args = process.argv.slice(2);
const entry = { args };
if (args[0] === "run") {
  const file = args[args.indexOf("--env-file") + 1];
  if (args.includes("--env-file")) entry.envFile = { path: file, mode: fs.statSync(file).mode & 0o777, content: fs.readFileSync(file, "utf8") };
}
fs.appendFileSync(process.env.FAKE_DOCKER_LOG, JSON.stringify(entry) + "\\n");
const exists = process.env.FAKE_CONTAINER_EXISTS === "1";
const down = process.env.FAKE_DOCKER_DOWN;
if (down && (args[0] === "container" || args[0] === "rm")) {
  // A timed-out inspection is killed by SIGTERM, just as execFileSync's timeout does.
  if (down === "timeout") process.kill(process.pid, "SIGTERM");
  console.error("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?");
  process.exit(1);
}
if (args[0] === "image") { console.log("sha256:fake"); process.exit(0); }
if (args[0] === "run") { console.log("fakecontainer"); process.exit(0); }
if (args[0] === "port") { console.log("127.0.0.1:55432"); process.exit(0); }
if (args[0] === "exec") process.exit(0);
if (args[0] === "container" && args[1] === "inspect") {
  if (exists) { console.log("fakeid0123"); process.exit(0); }
  console.error("Error: No such container: " + args.at(-1));
  process.exit(1);
}
if (args[0] === "rm" || args[0] === "stop") process.exit(exists ? 1 : 0);
process.exit(2);
`;
  await writeFile(join(bin, "docker"), script, { mode: 0o755 });
  const log = join(dir, "docker.log");
  const run = async (body, env = {}) => {
    const file = join(dir, `probe-${Math.random().toString(36).slice(2)}.mjs`);
    await writeFile(
      file,
      `import * as harness from ${JSON.stringify(join(root, "scripts/lib/disposable-postgres.mjs"))};\n${body}\n`,
    );
    const child = spawn(process.execPath, [file], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, FAKE_DOCKER_LOG: log, ...env },
    });
    let stderr = "";
    let stdout = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    const code = await new Promise((resolveExit) => child.once("exit", resolveExit));
    return { code, stderr, stdout };
  };
  const calls = async () =>
    (await readFile(log, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
  return { run, calls };
}

test("the container password reaches docker only through a 0600 env file removed after docker run, never argv", async (t) => {
  const { run, calls } = await fakeDockerFixture(t);
  const result = await run(
    `const pg = await harness.startDisposablePostgres({ owner: "probe" });
console.log(JSON.stringify({ password: pg.password }));
pg.stop();`,
  );
  assert.equal(result.code, 0, result.stderr);
  const { password } = JSON.parse(result.stdout.trim().split("\n").at(-1));
  const all = await calls();
  const started = all.find((call) => call.args[0] === "run");
  assert.ok(started, "docker run was called");
  for (const call of all) {
    assert.ok(!call.args.some((arg) => arg.includes(password)), call.args.join(" "));
    assert.ok(!call.args.some((arg) => arg.includes("POSTGRES_PASSWORD")), call.args.join(" "));
  }
  assert.equal(started.envFile.mode, 0o600);
  assert.equal(started.envFile.content, `POSTGRES_PASSWORD=${password}\n`);
  assert.equal(existsSync(started.envFile.path), false, "env file removed");
});

test("a container that survives every removal attempt is named with its id on stderr and the process exits non-zero", async (t) => {
  const { run } = await fakeDockerFixture(t);
  const result = await run(
    `const removed = harness.forceRemove("wssp-probe-left", { attempts: 2 });
console.log(String(removed));
process.exitCode = 0;`,
    { FAKE_CONTAINER_EXISTS: "1" },
  );
  assert.equal(result.stdout.trim(), "false");
  assert.match(
    result.stderr,
    /FAILED \(disposable-postgres teardown\): container wssp-probe-left \(id fakeid0123\) still exists after 2 removal attempts; remove it by hand: docker rm --force wssp-probe-left/,
  );
  assert.equal(result.code, 1);
});

for (const [shape, down, reason] of [
  ["the daemon is unreachable", "1", /exit 1: Cannot connect to the Docker daemon/],
  ["the inspection times out", "timeout", /signal SIGTERM/],
])
  test(`a container is never reported removed when ${shape}, and stays owned for a later retry`, async (t) => {
    const { run, calls } = await fakeDockerFixture(t);
    const result = await run(
      `const pg = await harness.startDisposablePostgres({ owner: "probe" });
process.env.FAKE_DOCKER_DOWN = ${JSON.stringify(down)};
let stopped = "stopped";
try { pg.stop(); } catch (error) { stopped = error.message; }
console.log(stopped);
process.exitCode = 0;`,
    );
    assert.match(result.stdout, /Disposable PostgreSQL container \S+ could not be removed/);
    assert.match(
      result.stderr,
      /FAILED \(disposable-postgres teardown\): could not confirm container \S+ was removed: docker container inspect failed/,
    );
    assert.match(result.stderr, reason);
    assert.equal(result.code, 1);
    // Still owned: the exit handler tried the removal again and reported it again.
    assert.equal(result.stderr.match(/could not confirm container/g)?.length, 2, result.stderr);
    const removals = (await calls()).filter((call) => call.args[0] === "rm");
    assert.equal(removals.length, 2 * 2);
  });

test("spawnOwnedProcessGroup refuses to start without POSIX ps, naming it", async (t) => {
  const { run } = await fakeDockerFixture(t);
  const result = await run(
    `try {
  harness.spawnOwnedProcessGroup(process.execPath, ["-e", ""], { stdio: "ignore" });
  console.log("spawned");
} catch (error) {
  console.log(error.message);
}`,
    { PATH: "/nonexistent-wssp-no-ps" },
  );
  assert.doesNotMatch(result.stdout, /spawned/);
  assert.match(result.stdout, /spawnOwnedProcessGroup needs the POSIX ps command/);
});

test("a ps failure at teardown is reported on stderr and the process exits non-zero", async (t) => {
  const { run } = await fakeDockerFixture(t);
  const result = await run(
    `const { exited } = harness.spawnOwnedProcessGroup(process.execPath, ["-e", "setTimeout(() => {}, 200)"], { stdio: "ignore" });
process.env.PATH = "/nonexistent-wssp-no-ps";
console.log(String(await exited));
process.exitCode = 0;`,
  );
  assert.equal(result.stdout.trim(), "0");
  assert.match(
    result.stderr,
    /FAILED \(disposable-postgres teardown\): could not list the descendants of process group \d+ \(ps -A -o pid=,ppid=,pgid= failed/,
  );
  assert.equal(result.code, 1);
});

test("a /proc scan failure at teardown is reported once on stderr and the process exits non-zero", async (t) => {
  const { run } = await fakeDockerFixture(t);
  const result = await run(
    `import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
const { exited } = harness.spawnOwnedProcessGroup(process.execPath, ["-e", "setTimeout(() => {}, 200)"], { stdio: "ignore" });
const readdir = fs.readdirSync;
fs.readdirSync = (path, ...rest) => {
  if (path === "/proc") throw Object.assign(new Error("EACCES: permission denied, scandir '/proc'"), { code: "EACCES" });
  return readdir(path, ...rest);
};
syncBuiltinESMExports();
console.log(String(await exited));
process.exitCode = 0;`,
  );
  assert.equal(result.stdout.trim(), "0");
  assert.equal(
    result.stderr.match(
      /FAILED \(disposable-postgres teardown\): could not scan \/proc for the processes of tree \d+ \(EACCES/g,
    )?.length,
    1,
    result.stderr,
  );
  assert.equal(result.code, 1);
});

test("migration fixture relocates the complete production closure and excludes checkout environment and seed", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "wssp-migration-isolation-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const source = join(directory, "checkout");
  const target = join(directory, "isolated");
  mkdirSync(join(source, "scripts/lib"), { recursive: true });
  mkdirSync(join(source, "packages/db/prisma"), { recursive: true });
  cpSync(join(root, "scripts/db"), join(source, "scripts/db"), { recursive: true });
  cpSync(
    join(root, "scripts/lib/bounded-child.mjs"),
    join(source, "scripts/lib/bounded-child.mjs"),
  );
  for (const name of ["package.json", "prisma.config.ts"])
    cpSync(join(root, "packages/db", name), join(source, "packages/db", name));
  for (const name of ["schema", "migrations"])
    cpSync(join(root, "packages/db/prisma", name), join(source, "packages/db/prisma", name), {
      recursive: true,
    });
  // The source's only dependencies are the same installed package closure.
  symlinkSync(
    join(root, "packages/db/node_modules"),
    join(source, "packages/db/node_modules"),
    "dir",
  );
  writeFileSync(
    join(source, ".env"),
    "DATABASE_URL=postgresql://checkout-sentinel.invalid/never_use\nBACKUP_S3_BUCKET=checkout-sentinel\n",
  );
  writeFileSync(
    join(source, "packages/db/prisma/seed.cli.ts"),
    'throw new Error("seed must never load");',
  );
  writeFileSync(
    join(source, "scripts/db/migrate-runtime.mjs"),
    `
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";
import { ROOT, SCHEMA_DIR, MIGRATIONS_DIR, prisma } from "./lib/prisma.mjs";
import config from "../../packages/db/prisma.config.ts";
assert.equal(process.argv[2], "apply");
assert.equal(ROOT, process.cwd());
assert.equal(SCHEMA_DIR, path.join(ROOT, "packages/db/prisma/schema"));
assert.equal(MIGRATIONS_DIR, path.join(ROOT, "packages/db/prisma/migrations"));
assert.equal(existsSync(path.join(ROOT, ".env")), false);
assert.equal(existsSync(path.join(ROOT, "packages/db/prisma/seed.cli.ts")), false);
assert.equal(config.datasource.url, "postgresql://fixture:fixture@127.0.0.1:1/disposable");
assert.equal(config.migrations.seed, "tsx prisma/seed.cli.ts");
assert.equal(process.env.NODE_ENV, "production");
// Node may set FORCE_COLOR automatically; no unrelated parent input may survive.
assert.deepEqual(Object.keys(process.env).filter((key) => key !== "FORCE_COLOR").sort(), ["DATABASE_URL", "NODE_ENV", "PATH"]);
const validated = await prisma(["validate"], { capture: true });
assert.equal(validated.code, 0, validated.stderr);
// Exercise the copied owner module through a real pinned native-engine diff.
const diff = await prisma(["migrate", "diff", "--from-empty", "--to-schema=" + SCHEMA_DIR, "--script"], { capture: true });
assert.equal(diff.code, 0, diff.stderr);
assert.ok(diff.stdout.includes('CREATE TABLE "user"'));
console.log("isolated closure and pinned Prisma passed");
`,
  );
  const fixture = canonicalApplyFixture(
    source,
    target,
    "postgresql://fixture:fixture@127.0.0.1:1/disposable",
  );
  assert.deepEqual(Object.keys(fixture.env).sort(), ["DATABASE_URL", "NODE_ENV", "PATH"]);
  assert.equal(fixture.runner, join(target, "scripts/db/migrate-runtime.mjs"));
  assert.equal(fixture.prismaCwd, join(target, "packages/db"));
  assert.equal(
    realpathSync(join(fixture.prismaCwd, "node_modules")),
    realpathSync(join(root, "packages/db/node_modules")),
  );
  for (const name of [
    "scripts/db/lib/prisma.mjs",
    "scripts/db/lib/prisma-owner.mjs",
    "scripts/lib/bounded-child.mjs",
    "packages/db/package.json",
    "packages/db/prisma.config.ts",
    "packages/db/prisma/migrations/0_init/migration.sql",
  ]) {
    assert.equal(lstatSync(join(target, name)).isSymbolicLink(), false, name);
    assert.equal(
      readFileSync(join(target, name), "utf8"),
      readFileSync(join(source, name), "utf8"),
    );
  }
  assert.equal(existsSync(join(target, ".env")), false);
  assert.equal(existsSync(join(target, "packages/db/prisma/seed.cli.ts")), false);
  assert.match(fixture.apply().toString(), /isolated closure and pinned Prisma passed/);
});
