// Subprocess sources and shared setup for the local transport double that
// drives the REAL `wssp` daemon (the cancel-wire suite and the WP1 reconnect
// chaos suite, `relay-chaos.contract.test.ts`). These run only in temporary
// test directories, without Incus or live VMs.
import { type ChildProcess, execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { chmod, mkdir, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { requestDigestMetadata } from "@wssp/api/sandbox/idempotency";
import type prismaClient from "@wssp/db";
import { canonicalEgressPolicyJson, vmSizeSchema } from "@wssp/sandbox-contracts";
import { expect, vi } from "vitest";
import {
  initialProcessFields,
  initialResultFields,
} from "../../../../packages/api/src/sandbox/operation-results";
import {
  type FenceStore,
  installFenceTransaction,
  matches,
  type OperationRow,
  prismaPromise,
  relayStore,
} from "./fenced-prisma-harness.js";

/** The fixture VM's image: its template, placement and dispatches agree. */
/**
 * Read a file a directory listing just returned. The daemon retires receipts
 * (and other journal files) concurrently, so one may vanish between the
 * listing and the read: that ENOENT means "absent now" and yields undefined.
 * Every other error is real and throws.
 */
export async function readListedFile(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException | null)?.code === "ENOENT") return undefined;
    throw error;
  }
}

export const WIRE_FINGERPRINT = `sha256:${"abcdef0123456789".repeat(4)}`;

/** The pinned size and allocation of the fixture's seeded boot placement. */
export function pinnedSize(store: FenceStore) {
  const placement = store.placements.get("placement:sbx-1")!;
  const size = vmSizeSchema.parse({
    diskGiB: placement.diskGiB,
    cpuCount: placement.cpuCount,
    memoryMiB: placement.memoryMiB,
  });
  return {
    cpuCount: size.cpuCount,
    memoryMiB: size.memoryMiB,
    allocation: {
      ...size,
      storagePoolName: placement.storagePoolName,
      storageMarker: placement.storageMarker,
      chargedMemoryMiB: placement.chargedMemoryMiB,
      chargedVcpu: placement.chargedVcpu,
      rootChargeGiB: placement.rootChargeGiB,
    },
  };
}

/**
 * The relay store for one wire case: `op-1` of `kind` QUEUED, seeded as
 * acceptance writes it for its kind (result version and process identity
 * included), never as a legacy row; the fixture VM's template and image.
 */
export function wireStore(kind: string): FenceStore {
  const store = relayStore(kind, "QUEUED");
  store.templates.set("tpl-1", {
    id: "tpl-1",
    userId: "user-1",
    sandboxHostId: "host-1",
    incusFingerprint: WIRE_FINGERPRINT,
    architecture: "x86_64",
    guestUid: 1000,
    guestGid: 1000,
    guestHome: "/home/user",
    guestShell: "/bin/bash",
    retiredAt: null,
  });
  // This fixture's recorded boot uses the wire image above. Updating a
  // revision row cannot change the immutable placement snapshot.
  Object.assign(store.placements.get("placement:sbx-1")!, { artifact: WIRE_FINGERPRINT });
  store.hosts.get("host-1")!.connectionEpoch = 0;
  store.hosts.get("host-1")!.hostTerminalVetoedAt = null;
  Object.assign(store.operations.get("op-1")!, {
    dispatchAttempt: 0,
    acceptedAttempt: null,
    dispatchedHostId: null,
    dispatchedConnectionEpoch: null,
    idempotencyKey: "key-1",
    ...requestDigestMetadata(),
    // The created row (nullable columns read NULL), then the acceptance
    // writers (sandboxes.ts): a scalar result kind is versioned at creation
    // and a command is born with its process identity.
    resultVersion: null,
    processId: null,
    ...initialResultFields(String(store.operations.get("op-1")!.kind), true),
    ...initialProcessFields(String(store.operations.get("op-1")!.kind)),
  });
  return store;
}

/** The incus shim and its scenario mode, in a fresh case directory. */
export async function writeWireShim(dir: string, mode: string) {
  await writeFile(join(dir, "incus"), cancelIncusFixture);
  await chmod(join(dir, "incus"), 0o700);
  await writeFile(join(dir, "mode"), mode);
}

/**
 * The pre-existing fixture VM models one an earlier "lease-bootstrap" create
 * provisioned: it carries that attempt's create idempotency key, so the
 * bootstrap (`bootstrapHostLease`) is that create's retry — the C37
 * existing-instance path — which binds only because this immutable metadata
 * matches. The durable lease config is written by the fixture only once the
 * bootstrap commits it (host admission refuses a listed managed VM the
 * journal does not hold a lease for).
 */
export async function writeBootstrapVm(dir: string) {
  await writeFile(
    join(dir, "lease-config.json"),
    JSON.stringify({ "user.flycockpit.create_idempotency_key": "lease-bootstrap" }),
  );
}

/**
 * Store-backed reads and writes outside the fenced transaction, on the mocked
 * `@wssp/db` client. `operation` answers `sandboxOperation.findFirst` (the
 * cancel-wire suite's single operation by default).
 */
export function installWireDelegates(
  prisma: typeof prismaClient,
  store: FenceStore,
  operation: (where: Record<string, unknown> | undefined) => OperationRow | null = () =>
    store.operations.get("op-1")!,
) {
  const db = vi.mocked(prisma, true);
  installFenceTransaction(db, store);
  db.outboxEvent.findMany.mockImplementation((args) =>
    prismaPromise(
      Promise.resolve(
        [...store.outbox.values()]
          .filter((row) => matches(row, args?.where as Record<string, unknown>))
          .slice(0, args?.take ?? 32) as never,
      ),
    ),
  );
  db.outboxEvent.updateMany.mockImplementation((args) =>
    prismaPromise(prisma.$transaction((tx) => tx.outboxEvent.updateMany(args))),
  );
  db.sandboxTemplate.findMany.mockImplementation((args) =>
    // pagination:audited — test double forwarding the caller's own (bounded) args
    prismaPromise(prisma.$transaction((tx) => tx.sandboxTemplate.findMany(args))),
  );
  db.sandboxTemplateAvailability.findMany.mockImplementation((args) =>
    // pagination:audited — test double forwarding the caller's own (bounded) args
    prismaPromise(prisma.$transaction((tx) => tx.sandboxTemplateAvailability.findMany(args))),
  );
  db.sandboxHost.updateMany.mockImplementation((args) =>
    prismaPromise(prisma.$transaction((tx) => tx.sandboxHost.updateMany(args))),
  );
  // Terminal binding revalidation checks the durable veto outside the mint
  // transaction too. Evaluate the same host predicates on that read.
  db.sandboxHost.findFirst.mockImplementation((args) =>
    Object.assign(
      prismaPromise(
        Promise.resolve(
          ([...store.hosts.values()].find((row) =>
            matches(row, args?.where as Record<string, unknown>),
          ) ?? null) as never,
        ),
      ),
      {
        HostQueuedCommands: vi.fn(),
        HostFileReceipts: vi.fn(),
        HostTerminalTickets: vi.fn(),
        ImageCache: vi.fn(),
        User: vi.fn(),
        HostTokens: vi.fn(),
        HostDeviceCredentials: vi.fn(),
        Sandboxes: vi.fn(),
        TemplateAvailability: vi.fn(),
        PoolMemberships: vi.fn(),
        SdkKeyHostAllowlist: vi.fn(),
        StoragePools: vi.fn(),
        CredentialPendingCaptures: vi.fn(),
        CredentialCensus: vi.fn(),
        CredentialTombstones: vi.fn(),
        CredentialReturnKeys: vi.fn(),
        DiskCopies: vi.fn(),
      },
    ),
  );
  db.$queryRaw.mockResolvedValue([]);
  db.sandboxOperation.findFirst.mockImplementation((args) =>
    Object.assign(
      prismaPromise(
        Promise.resolve(operation(args?.where as Record<string, unknown> | undefined) as never),
      ),
      {
        User: vi.fn(),
        Sandbox: vi.fn(),
        TypedResult: vi.fn(),
        CommandOutput: vi.fn(),
        Placement: vi.fn(),
        Capture: vi.fn(),
        CapacityWait: vi.fn(),
        CredentialSpec: vi.fn(),
        RestoreWait: vi.fn(),
      },
    ),
  );
}

export type WireHostOptions = {
  /** The case directory: shim, data dir and config live under it. */
  dir: string;
  /** The relay base URL the daemon dials (`ws://127.0.0.1:<port>`). */
  serverUrl: string;
  /** Extra `wssp connect` arguments. */
  args?: readonly string[];
  /** Extra (debug-build-only) environment for this daemon. */
  env?: Readonly<Record<string, string>>;
};

/**
 * Spawn the real debug `target/debug/wssp connect` against the case's incus
 * shim, guard double and data dir. Build it first with
 * `cargo build -p wssp --bin wssp --locked`; no compiler runs here.
 */
export async function spawnWireHost({
  dir,
  serverUrl,
  args = [],
  env = {},
}: WireHostOptions): Promise<ChildProcess> {
  const configDir = join(dir, "config");
  await mkdir(configDir, { recursive: true });
  // Model the administrator-provisioned shared daemon lock directory
  // (mode 2770, group-only; the runtime validates this exact shape).
  const lockDir = join(dir, "daemon-locks");
  await mkdir(lockDir, { recursive: true, mode: 0o2770 });
  await chmod(lockDir, 0o2770);
  await writeFile(
    join(configDir, "config.toml"),
    `host_token_env = "WSSP_CANCEL_WIRE_HOST_TOKEN"\nserver_url = "${serverUrl}"\n`,
  );
  return spawn(
    resolve("target/debug/wssp"),
    [
      "connect",
      "--server",
      serverUrl,
      "--host-id",
      "host-1",
      "--runtime",
      "incus",
      "--incus-project",
      "default",
      ...args,
    ],
    {
      env: {
        ...process.env,
        WSSP_CONFIG_DIR: configDir,
        WSSP_CANCEL_WIRE_HOST_TOKEN: `wssp_host_${"B".repeat(43)}`,
        WSSP_INCUS_BINARY: join(dir, "incus"),
        // Test-only (loopback server): the transport double models no
        // one-daemon-per-Incus-server lease, so this daemon claims none.
        WSSP_TEST_SHARED_INCUS: "1",
        WSSP_DATA_DIR: join(dir, "data"),
        // Debug-build-only: the daemon asks the guard double, never the
        // machine's `/run/wssp-guard/guard.sock` (the gates build the
        // debug `target/debug/wssp`).
        WSSP_TEST_GUARD_ROOT: join(dir, "guard-root"),
        // The shared daemon lock needs an administrator-provisioned dir;
        // the harness provisions an equivalent one per run.
        WSSP_INCUS_DAEMON_LOCK_DIR: lockDir,
        // Debug-build-only ordering control (apps/cli expiry.rs): while this
        // file exists the periodic sweep skips policy inspection and
        // acknowledges with `<path>.held`. Inert unless a case creates it.
        WSSP_TEST_HOLD_POLICY_RECONCILER: join(dir, "hold-policy-reconciler"),
        ...env,
      },
      detached: true, // Own the entire daemon -> shim process group.
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
}

/** Graceful stop of the daemon's whole process group (SIGTERM, then SIGKILL). */
export async function stopWireHost(child: ChildProcess | undefined) {
  if (!child?.pid) return;
  const stopped =
    child.exitCode !== null || child.signalCode !== null ? Promise.resolve() : once(child, "exit");
  const signal = (value: NodeJS.Signals) => {
    try {
      process.kill(-child.pid!, value);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
    }
  };
  signal("SIGTERM");
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      stopped,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, 2_000);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
    // Even an exited leader can leave a descendant holding pipes open.
    signal("SIGKILL");
  }
  await stopped;
}

/** SIGKILL the daemon's process group; false when it had already exited. */
export async function crashWireHost(child: ChildProcess | undefined): Promise<boolean> {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return false;
  const stopped = once(child, "exit");
  process.kill(-child.pid, "SIGKILL");
  await stopped;
  return true;
}

/** `/proc/<pid>/stat` fields after the command name: ppid, pgid, sid. */
function statIds(stat: string) {
  const [, ppid, pgid, sid] = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
  return { ppid: Number(ppid), pgid: Number(pgid), sid: Number(sid) };
}
/**
 * Live fixture processes: every process whose argv names a path under `root`
 * (zombies have an empty cmdline), plus (G10R-3) every process sharing a
 * process group or session with one of them or descending from one, so a
 * child that does not name the dir is caught too. The test runner's own
 * group and session are never included.
 */
async function fixtureProcesses(root: string): Promise<number[]> {
  const own = statIds(await readFile("/proc/self/stat", "utf8"));
  const rows: { pid: number; ppid: number; pgid: number; sid: number; named: boolean }[] = [];
  for (const entry of await readdir("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    const [cmdline, stat] = await Promise.all([
      readFile(`/proc/${entry}/cmdline`, "utf8").catch(() => ""),
      readFile(`/proc/${entry}/stat`, "utf8").catch(() => ""),
    ]);
    if (!cmdline || !stat) continue;
    rows.push({ pid: Number(entry), ...statIds(stat), named: cmdline.includes(`${root}/`) });
  }
  const live = new Set(rows.filter((row) => row.named).map((row) => row.pid));
  for (let grown = true; grown; ) {
    grown = false;
    const groups = new Set(rows.filter((row) => live.has(row.pid)).map((row) => row.pgid));
    const sessions = new Set(rows.filter((row) => live.has(row.pid)).map((row) => row.sid));
    groups.delete(own.pgid);
    sessions.delete(own.sid);
    for (const row of rows)
      if (
        !live.has(row.pid) &&
        row.pgid !== own.pgid &&
        row.sid !== own.sid &&
        (live.has(row.ppid) || groups.has(row.pgid) || sessions.has(row.sid))
      ) {
        live.add(row.pid);
        grown = true;
      }
  }
  return [...live];
}
/**
 * Teardown barrier: every fixture process (shim, wrapper, writer, holder) has
 * exited before its directory is removed. Host exit alone did not imply this:
 * before G10R-1 the daemon detached its loss sweep at shutdown, and the sweep's
 * in-flight `incus` child (its own process group) outlived the host; its
 * prologue recreated `device-eth0` after `rm` unlinked it, failing `rmdir`
 * with ENOTEMPTY. The daemon now joins that sweep; this barrier stays as
 * defence against any other lingering fixture process. Coverage: argv naming
 * a path under `root` (shim and writer paths, holder code, the wrapper's ops
 * dir), plus their groups, sessions and children. Limitation: a reparented
 * process in a new session that names no path under `root` is not seen.
 */
async function settleFixtureProcesses(root: string) {
  // Both bounds fit the 10 s hook timeout; shims normally exit within ms.
  const graceUntil = Date.now() + 2_000;
  const killUntil = graceUntil + 2_000;
  for (;;) {
    const live = await fixtureProcesses(root);
    if (live.length === 0) return;
    if (Date.now() > killUntil) throw new Error(`fixture processes survived SIGKILL: ${live}`);
    if (Date.now() > graceUntil)
      for (const pid of live) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          /* already exited */
        }
      }
    await delay(10);
  }
}

/** The daemon's durable runtime journal dir: <data>/relay/<sha256(hostId)>/runtime. */
function wireRuntimeDir(dir: string) {
  return join(dir, "data", "relay", createHash("sha256").update("host-1").digest("hex"), "runtime");
}

/**
 * Before the daemon's graceful exit: release every fixture barrier, model
 * the sandbox's destruction out of band and repair any faulted journal.
 */
export async function releaseWireFixture(dir: string) {
  for (const name of [
    "release-cleanup",
    "release-natural",
    "release-pipe",
    "release-stop",
    "release-wrapper",
    "release-acl-read",
  ])
    await writeFile(join(dir, name), "");
  // Settle the bootstrap lease before host exit: the honest census (C35)
  // keeps a lease for a live instance/network unsettled, and `wait_idle`
  // only retires it once the inventory proves absence. Model the sandbox's
  // destruction out of band: instance gone, egress resources gone, no
  // pending cleanup obligations.
  await writeFile(join(dir, "deleted"), "");
  // Restore faulted journals before waiting for graceful host shutdown.
  // A file substituted for a journal directory intentionally prevents the
  // runtime from proving cleanup until the storage fault is repaired.
  const runtimeDir = wireRuntimeDir(dir);
  for (const name of ["enforcement-losses", "network-cleanups"]) {
    const path = join(runtimeDir, name);
    if (
      await readFile(path).then(
        () => true,
        () => false,
      )
    ) {
      await rm(path);
      await rename(`${path}-held`, path);
    }
  }
  for (const sub of [
    "networks",
    "acls",
    // The runtime's durable network journal lives under the host state dir
    // the relay resolved and passed in.
    join(
      "data",
      "relay",
      createHash("sha256").update("host-1").digest("hex"),
      "runtime",
      "network-cleanups",
    ),
  ]) {
    const subdir = join(dir, sub);
    for (const entry of await readdir(subdir).catch(() => [] as string[]))
      await rm(join(subdir, entry), { force: true });
  }
}

/** After the daemon exited: kill recorded guest groups, settle, remove the dir. */
export async function removeWireDir(dir: string) {
  for (const name of ["guest-pgid", "holder-pid"]) {
    try {
      process.kill(-Number(await readFile(join(dir, name), "utf8")), "SIGKILL");
    } catch {
      /* already reaped */
    }
  }
  await settleFixtureProcesses(dir);
  await rm(dir, { recursive: true, force: true });
}

const execFileAsync = promisify(execFile);

export type WireLeaseContext = {
  dir: string;
  store: FenceStore;
  /** Send a server frame to the daemon on its current relay socket. */
  send(frame: string): void;
  /** Resolves with the daemon's `operation.result` for `operationId`. */
  result(operationId: string): Promise<Record<string, unknown>>;
  until(check: () => boolean | Promise<boolean>, label: string): Promise<void>;
};

/**
 * Commands require a previously accepted host lease. Establish it through
 * the real relay/journal/runtime path before the scenario. C37 R1: the
 * bootstrap is a CREATE, not a reconnect — reconnect now verifies the
 * recorded enforcement and refuses when it is missing, so only a create
 * provisions it. The fixture's pre-existing VM (`writeBootstrapVm`) carries
 * this attempt's create idempotency key, so the bootstrap takes the
 * existing-instance retry path.
 */
export async function bootstrapHostLease(
  context: WireLeaseContext,
  egress?: { policy: { domains: string[]; cidrs: string[] }; hash: string },
  guestRoot = false,
) {
  const { dir, store } = context;
  const binding = {
    sandboxOwnerId: "user-1",
    operationId: "lease-bootstrap",
    sandboxId: "sbx-1",
    generation: 1,
    attempt: 1,
    bodyHash: "b".repeat(64),
    idempotencyKey: "lease-bootstrap",
    kind: "sandbox.create",
  };
  // Subscribe before dispatch so even an immediate result satisfies the barrier.
  const resultReceived = context.result(binding.operationId);
  // send can throw before the await; keep the barrier's later rejection handled.
  resultReceived.catch(() => undefined);
  context.send(
    JSON.stringify({
      type: "operation.dispatch",
      ...binding,
      digestScheme: requestDigestMetadata().requestDigestScheme,
      digestKeyId: requestDigestMetadata().requestDigestKeyId,
      ...pinnedSize(store),
      lease: store.outbox.get("evt-1")!.payload.lease,
      incusFingerprint: WIRE_FINGERPRINT,
      templateDigest: WIRE_FINGERPRINT,
      architecture: "x86_64",
      guestUid: 1000,
      guestGid: 1000,
      guestHome: "/home/user",
      guestShell: "/bin/bash",
      ...(guestRoot ? { guestRoot: true } : {}),
      egressPolicy: egress?.policy ?? { domains: [], cidrs: [] },
      egressPolicyHash:
        egress?.hash ??
        createHash("sha256")
          .update(canonicalEgressPolicyJson({ domains: [], cidrs: [] }))
          .digest("hex"),
    }),
  );
  const result = await resultReceived;
  expect(result, JSON.stringify(result)).toMatchObject({ state: "succeeded" });
  context.send(JSON.stringify({ type: "receipt.confirmed", ...binding }));
  await context.until(
    async () =>
      !(await readdir(join(dir, "data"), { recursive: true })).some((path) =>
        path.endsWith("receipts/lease-bootstrap.json"),
      ),
    "bootstrap receipt confirmation",
  );
  // The committed create stamps the durable lease config on the VM exactly
  // as a fresh init would (the existing-instance retry path does not rewrite
  // it); only now may the census list the VM as managed, since the journal
  // holds the lease.
  await execFileAsync(join(dir, "incus"), [
    "config",
    "set",
    "wssp-sbx-sbx-1",
    "user.flycockpit.lease",
    JSON.stringify(store.outbox.get("evt-1")!.payload.lease),
  ]);
}

/**
 * A healthy egress guard double speaking the G1 socket protocol
 * (`crates/sandbox-runtime/src/guard/protocol.rs`): one 4-byte big-endian
 * length-prefixed JSON request per connection, one reply, then close.
 * Modelled on `FakeGuardServer` in `apps/cli/src/sandbox_relay/test_support.rs`.
 * It listens at `<root>/run/wssp-guard/guard.sock`; a debug daemon started with
 * `WSSP_TEST_GUARD_ROOT=<root>` asks it instead of the machine's guard. Every
 * `wsn-*` bridge the incus shim recorded under `networksDir` is reported as
 * covered with its `.1` gateway, so the start fence attests it. Like a guard
 * that just started, its deployment source is `unknown` until the daemon's
 * first `push_deployment`; the daemon admits no create before that push.
 */
export type FakeGuard = { server: Server; pushes: () => number };

export async function startFakeGuard(root: string, networksDir: string): Promise<FakeGuard> {
  const socketPath = join(root, "run", "wssp-guard", "guard.sock");
  await mkdir(dirname(socketPath), { recursive: true });
  await rm(socketPath, { force: true });
  const bootId = (await readFile("/proc/sys/kernel/random/boot_id", "utf8")).trim();
  const instanceId = "c".repeat(32);
  let generation = 0;
  // `undefined`: nothing pushed since start (`unknown`), as the real guard.
  let deployment: boolean | undefined;
  let pushes = 0;
  const digest = "sha256:deployment";

  /** CLOCK_BOOTTIME in ns, as a decimal string (`/proc/uptime` is boottime). */
  async function boottimeNs(): Promise<bigint> {
    const [seconds = "0"] = (await readFile("/proc/uptime", "utf8")).split(" ");
    const [whole = "0", fraction = ""] = seconds.split(".");
    return BigInt(whole) * 1_000_000_000n + BigInt(fraction.padEnd(9, "0").slice(0, 9));
  }
  async function gateways(): Promise<Array<{ bridge: string; gateway: string }>> {
    const names = await readdir(networksDir).catch(() => [] as string[]);
    const pairs: Array<{ bridge: string; gateway: string }> = [];
    for (const name of names.sort()) {
      if (!name.startsWith("wsn-") || !name.endsWith(".json")) continue;
      const text = await readListedFile(join(networksDir, name));
      if (text === undefined) continue;
      const config = JSON.parse(text);
      const address = String(config["ipv4.address"] ?? "");
      const gateway = address.split("/")[0];
      if (gateway) pairs.push({ bridge: name.slice(0, -".json".length), gateway });
    }
    return pairs;
  }
  async function reply(request: Record<string, unknown>): Promise<string> {
    switch (request.op) {
      case "status": {
        generation += 1;
        const now = await boottimeNs();
        const covered = await gateways();
        const status = {
          guard_version: 1,
          instance_id: instanceId,
          boot_id: bootId,
          generation,
          ok: true,
          reasons: [],
          sources: {
            root: { state: "not_configured" },
            deployment:
              deployment === undefined
                ? { state: "unknown" }
                : { state: deployment ? "valid" : "not_configured", digest },
          },
          live_bridges: covered.map((pair) => pair.bridge),
          gateways: covered,
          uplinks: ["eth0"],
          counts: {},
          verified_boottime_ns: "@VERIFIED@",
          lease_until_boottime_ns: "@LEASE@",
        };
        // u64 nanoseconds exceed JSON-safe integers on long-running hosts.
        return JSON.stringify({ result: "status", status })
          .replace('"@VERIFIED@"', now.toString())
          .replace('"@LEASE@"', (now + 15_000_000_000n).toString());
      }
      case "push_deployment": {
        deployment = request.configured === true;
        pushes += 1;
        const state = deployment
          ? { state: "valid", digest, cidrs: 0, domains: 0 }
          : { state: "not_configured", digest };
        return JSON.stringify({ result: "pushed", digest, state });
      }
      case "policy": {
        const empty = (source: string) => ({
          state: { state: "not_configured", digest: source },
          digest: source,
          domains: [],
          cidrs: 0,
        });
        return JSON.stringify({
          result: "policy",
          policy: { root: empty("sha256:root"), deployment: empty(digest) },
        });
      }
      default:
        return JSON.stringify({
          result: "error",
          code: "invalid_request",
          message: "unknown request",
        });
    }
  }
  function serve(socket: Socket) {
    let buffered = Buffer.alloc(0);
    socket.on("error", () => socket.destroy());
    socket.on("data", (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);
      if (buffered.length < 4) return;
      const length = buffered.readUInt32BE(0);
      if (buffered.length < 4 + length) return;
      socket.pause();
      const body = buffered.subarray(4, 4 + length).toString("utf8");
      void reply(JSON.parse(body) as Record<string, unknown>).then((text) => {
        const payload = Buffer.from(text, "utf8");
        const header = Buffer.alloc(4);
        header.writeUInt32BE(payload.length, 0);
        socket.end(Buffer.concat([header, payload]));
      });
    });
  }
  const server = createServer(serve);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve());
  });
  return { server, pushes: () => pushes };
}

const cancelIncusFixture = String.raw`#!/usr/bin/env python3
"""Incus transport double: real wrapper/helper processes, no Incus or VM calls.
All ordering is file-barrier driven; polling intervals are not test assertions.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

root = Path(__file__).resolve().parent
UNIT_RE = r"wssp-cmd-([A-Za-z0-9_-]{1,128})-([0-9]{1,20})-([0-9]{1,20})\.scope"

def metadata_mkdir(argv):
    # Model only the readiness directory in the VM. Never execute this helper
    # against the host's /home/user path. The real helper is tested in Rust
    # temp-dir suites; this transport double must speak the same READY/result.
    if len(argv) != 9 or argv[0] != "python3" or argv[1:3] != ["-I", "-c"] or argv[4] != "ensure-dir":
        return False
    assert argv[5] == "/home/user/repo", argv[5]
    token = argv[6]
    assert len(token) == 64 and all(c in "0123456789abcdef" for c in token)
    print("WSSP_COMMIT_READY " + token, flush=True)
    if sys.stdin.buffer.read(1) != b"C":
        print("WSSP_STATUS " + token + " cancelled none", file=sys.stderr, flush=True)
        sys.exit(1)
    print(json.dumps({"result":{"type":"file.mkdir","created":False},"continuation":None}), flush=True)
    print("WSSP_STATUS " + token + " ok", file=sys.stderr, flush=True)
    return True

def metadata_stat(argv):
    # B2-K-1: run the REAL metadata helper for a read-only stat, confined to
    # this temporary directory, so its precise missing-path record reaches
    # the real host binary unchanged.
    if len(argv) != 9 or argv[0] != "python3" or argv[1:3] != ["-I", "-c"] or argv[4] != "stat":
        return False
    assert argv[5].startswith(str(root) + "/"), argv[5]
    os.execvp("python3", argv)

# The pre-existing VM models a healthy C35 VM: it carries the local eth0
# override its init recorded (root disk stays profile-inherited).
_device = root / "device-eth0"
if not _device.exists():
    _bridge = "wsn-" + hashlib.sha256(b"sbx-1").hexdigest()[:10]
    _device.write_text("eth0,network=" + _bridge + ",security.mac_filtering=true,security.ipv4_filtering=true,security.ipv6_filtering=true,security.port_isolation=true")

def instance_devices(sandbox_id):
    """(local, expanded) devices with real Incus semantics: devices holds
    local devices only (the recorded init/override eth0); expanded_devices
    merges the default profile (root disk + plain incusbr0 NIC) with local
    overrides -- the effective set the runtime verifies."""
    profile = {"root": {"type": "disk", "path": "/", "pool": "default"}, "eth0": {"type": "nic", "network": "incusbr0"}}
    local = {"root": {"type":"disk","path":"/","pool":"default","size":"32GiB"}}
    dev = root / "device-eth0"
    if dev.exists():
        nic = dict(t.split("=", 1) for t in dev.read_text().strip().split(",")[1:] if "=" in t)
        nic["type"] = "nic"
        local["eth0"] = nic
    expanded = dict(profile)
    expanded.update(local)
    return local, expanded
args = sys.argv[1:]
if args[:1] == ["--project"]:
    args = args[2:]
if args[:1] == ["--quiet"]:
    args = args[1:]
cmd = args[0]
if cmd == "version":
    sys.exit(0)
if cmd == "profile":
    print('[{"name":"default","devices":{"root":{"type":"disk","path":"/","pool":"default"},"eth0":{"type":"nic","network":"test"}}}]')
    sys.exit(0)
if cmd == "list":
    # Accurate census: a VM the query endpoint reports is also listed — once
    # it is managed, i.e. carries the durable lease a real launch writes.
    rows = []
    mode_now = (root / "mode").read_text()
    if mode_now.startswith("readiness-"):
        cp = root / "config.json"
        if cp.exists() and not (root / "deleted").exists():
            cfg = json.loads(cp.read_text())
            if "user.flycockpit.lease" in cfg:
                stopped = mode_now == "readiness-reconnect" and not (root / "started").exists()
                rows = [{"name": "wssp-sbx-sbx-1", "type": "virtual-machine", "status": "Stopped" if stopped else "Running", "config": cfg}]
    elif (root / "created").exists() and not (root / "deleted").exists():
        fp0 = "abcdef0123456789" * 4
        lc = {}
        lcp = root / "lease-config.json"
        if lcp.exists():
            lc = json.loads(lcp.read_text())
        cfg = {**lc, "user.flycockpit.sandbox_id": "sbx-1", "user.flycockpit.template_digest": "sha256:" + fp0, "volatile.base_image": fp0}
        if "user.flycockpit.lease" in cfg:
            stopped = (root / "stopped").exists()
            rows = [{"name": "wssp-sbx-sbx-1", "type": "virtual-machine", "status": "Stopped" if stopped else "Running", "config": cfg}]
    print(json.dumps(rows))
    sys.exit(0)
if cmd == "delete" and not (root / "mode").read_text().startswith("readiness-"):
    (root / "deleted").touch()
    sys.exit(0)
# Read-only daemon totals for optional host capacity detection (no new argv).
if cmd == "query" and args[-1] == "/1.0/resources":
    print(json.dumps({"type":"sync","status_code":200,"error_code":0,"metadata":{"memory":{"total":16*1024*1024*1024},"cpu":{"total":8}}}))
    sys.exit(0)
# Runtime bootstrap verifies project-owned custom marker volumes read-only.
if cmd == "query" and "/1.0/projects/" in args[-1]:
    print(json.dumps({"type":"sync","status_code":200,"error_code":0,"metadata":{"config":{"features.storage.volumes":"true"}}}))
    sys.exit(0)
# Strict 1.0 fixture pool/root evidence. All paths remain in this temp double.
if cmd == "query" and "/1.0/storage-pools/" in args[-1]:
    path = args[-1].split("?")[0]
    tail = "/".join(path.split("/")[4:])
    metadata = {}
    if tail == "": metadata = {"driver":"dir","status":"Created","config":{}}
    elif tail == "resources": metadata = {"space":{"total":1024*(1<<30),"used":64*(1<<30)}}
    elif tail == "volumes/custom/wssp-pool-marker": metadata = {"name":"wssp-pool-marker","type":"custom","content_type":"filesystem","config":{"size":"1GiB","user.wssp.storage-id":"a"*32}}
    elif tail == "volumes":
        present = not (root/"deleted").exists() and ((root/"created").exists() or (root/"config.json").exists())
        metadata = [{"name":"wssp-sbx-sbx-1","type":"virtual-machine","config":{"size":"32GiB"}}] if present else []
    elif tail.endswith("/state"): metadata = {"usage":{"total":32*(1<<30),"used":1<<30}}
    elif tail.startswith("volumes/virtual-machine/"):
        if (root/"deleted").exists():
            print(json.dumps({"type":"error","error_code":404,"error":"Not Found"})); sys.exit(0)
        metadata = {"name":"wssp-sbx-sbx-1","type":"virtual-machine","content_type":"block","config":{"size":"32GiB"}}
    print(json.dumps({"type":"sync","status_code":200,"error_code":0,"metadata":metadata})); sys.exit(0)
if args[:4] == ["storage","volume","file","pull"]:
    sys.stdout.write("wssp-storage-v1\n"+"a"*32+"\n"); sys.exit(0)
# The startup offload sweep lists aliases separately from image metadata.
if cmd == "query" and args[-1].split("?")[0] == "/1.0/images/aliases":
    print(json.dumps({"type":"sync","metadata":[]}))
    sys.exit(0)
# Template preflight and image inventory use the native image metadata API.
if cmd == "query" and "/1.0/images/" in args[-1]:
    fingerprint = args[-1].split("?")[0].rsplit("/", 1)[-1]
    print(json.dumps({"type":"sync","metadata":{"fingerprint":fingerprint,"architecture":"x86_64","type":"virtual-machine","properties":{}}}))
    sys.exit(0)
# C35 per-sandbox bridge/ACL surface (file-backed, keyed by object name).
if cmd == "network":
    sub = args[1]
    if sub == "list":
        rows = [{"name": "incusbr0", "managed": True, "type": "bridge"}]
        netdir = root / "networks"
        if netdir.exists():
            rows += [{"name": p.stem, "managed": True, "type": "bridge"} for p in sorted(netdir.glob("*.json"))]
        print(json.dumps(rows))
        sys.exit(0)
    if sub == "create":
        name = args[2]
        if len(name) > 15:
            # Linux IFNAMSIZ: bridge names are interface names.
            print("Error: interface name too long: " + name, file=sys.stderr)
            sys.exit(1)
        kv = {}
        rest = args[3:]
        i = 0
        while i < len(rest):
            if rest[i] == "--type":
                i += 2
            else:
                k, v = rest[i].split("=", 1)
                kv[k] = v
                i += 1
        (root / "networks").mkdir(exist_ok=True)
        (root / "networks" / (name + ".json")).write_text(json.dumps(kv))
        sys.exit(0)
    if sub == "set":
        # network set <name> <key> <value>
        p = root / "networks" / (args[2] + ".json")
        if not p.exists():
            print("Error: network not found", file=sys.stderr)
            sys.exit(1)
        kv = json.loads(p.read_text())
        kv[args[3]] = args[4]
        p.write_text(json.dumps(kv))
        sys.exit(0)
    if sub == "delete":
        p = root / "networks" / (args[2] + ".json")
        if not p.exists():
            print("Error: network not found", file=sys.stderr)
            sys.exit(1)
        p.unlink()
        sys.exit(0)
    if sub == "acl":
        if args[2] == "list":
            acldir = root / "acls"
            rows = [{"name": p.stem} for p in sorted(acldir.glob("*.json"))] if acldir.exists() else []
            print(json.dumps(rows))
            sys.exit(0)
        if args[2] == "set":
            # network acl set <name> <key> <value>
            p = root / "acls" / (args[3] + ".json")
            if not p.exists():
                print("Error: acl not found", file=sys.stderr)
                sys.exit(1)
            state = json.loads(p.read_text())
            state["config"][args[4]] = args[5]
            p.write_text(json.dumps(state))
            sys.exit(0)
        if args[2] == "create":
            name = args[3]
            kv = dict(a.split("=", 1) for a in args[4:])
            (root / "acls").mkdir(exist_ok=True)
            (root / "acls" / (name + ".json")).write_text(json.dumps({"config": kv, "ingress": [], "egress": []}))
            sys.exit(0)
        if args[2] == "rule" and args[3] == "add":
            name, direction = args[4], args[5]
            p = root / "acls" / (name + ".json")
            state = json.loads(p.read_text())
            rule = dict(a.split("=", 1) for a in args[6:])
            # Incus reports every rule with an explicit effective state.
            rule.setdefault("state", "enabled")
            state[direction].append(rule)
            p.write_text(json.dumps(state))
            sys.exit(0)
        if args[2] == "delete":
            p = root / "acls" / (args[3] + ".json")
            if not p.exists():
                print("Error: acl not found", file=sys.stderr)
                sys.exit(1)
            p.unlink()
            sys.exit(0)
    raise RuntimeError("unsupported network shim call: " + str(args))
if cmd == "query" and (args[-1].startswith("/1.0?") or "/1.0/networks/" in args[-1] or "/1.0/network-acls/" in args[-1]):
    path = args[-1]
    name = path.split("?")[0].rsplit("/", 1)[-1]
    if path.startswith("/1.0?"):
        print(json.dumps({"type":"sync","metadata":{"api_extensions":["network_acl"],"environment":{"server_version":"6.14"}}}))
        sys.exit(0)
    if "/1.0/networks/" in path:
        p = root / "networks" / (name + ".json")
        if p.exists():
            print(json.dumps({"type":"sync","metadata":{"name":name,"type":"bridge","managed":True,"config":json.loads(p.read_text())}}))
        else:
            print(json.dumps({"type":"error","error_code":404,"error":"Not Found"}))
        sys.exit(0)
    p = root / "acls" / (name + ".json")
    if "-X" in args and args[args.index("-X") + 1] == "PUT":
        if not p.exists():
            print(json.dumps({"type":"error","error_code":404,"error":"Not Found"}))
            sys.exit(1)
        state = json.loads(p.read_text())
        fields = ("action","source","destination","protocol","source_port","destination_port","icmp_type","icmp_code","description","state")
        def etag_rules(direction):
            rules = state.get(direction)
            if rules is None: return None
            return [{key:rule.get(key, "") for key in fields if rule.get(key, "") or key in ("action", "state")} for rule in rules]
        values = [name, state.get("description", ""), etag_rules("ingress"), etag_rules("egress"), dict(sorted(state["config"].items()))]
        encoded = json.dumps(values, separators=(",",":"), ensure_ascii=False).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029") + "\n"
        expected = hashlib.sha256(encoded.encode()).hexdigest()
        header = args[args.index("--header") + 1].removeprefix("If-Match: ").strip('"')
        if header != expected:
            print(json.dumps({"type":"error","error_code":412,"error":"ETag mismatch"}))
            sys.exit(1)
        body = sys.stdin.read() if "--data-file" in args else args[args.index("-d") + 1]
        p.write_text(json.dumps(json.loads(body)))
        print(json.dumps({"type":"sync","status_code":200,"metadata":None}))
        sys.exit(0)
    barrier = root / "barrier-acl-read"
    if barrier.exists():
        barrier.unlink()
        (root / "acl-read-entered").touch()
        while not (root / "release-acl-read").exists():
            time.sleep(.005)
    if p.exists():
        print(json.dumps({"type":"sync","metadata":{"name":name,**json.loads(p.read_text())}}))
    else:
        print(json.dumps({"type":"error","error_code":404,"error":"Not Found"}))
    sys.exit(0)
# C14 lifecycle scenarios use the same production CLI/relay/journal transport.
mode = (root / "mode").read_text()
if mode.startswith("readiness-"):
    fp = "abcdef0123456789" * 4
    config_path = root / "config.json"
    if cmd == "query":
        if not config_path.exists() or (root / "deleted").exists():
            print(json.dumps({"type":"error","error_code":404,"error":"Not Found"}))
        elif "/state?" in args[-1]:
            print(json.dumps({"type":"sync","metadata":{"status":"Running","status_code":103,"processes":1}}))
        else:
            stopped = mode == "readiness-reconnect" and not (root / "started").exists()
            local_dev, expanded_dev = instance_devices("sbx-1")
            # expanded_config: a real daemon merges local + profile + image
            # config; the profile/image carry none here (C37).
            cfg = json.loads(config_path.read_text())
            print(json.dumps({"type":"sync","metadata":{"name":"wssp-sbx-sbx-1","status":"Stopped" if stopped else "Running","status_code":102 if stopped else 103,"architecture":"x86_64","type":"virtual-machine","config":cfg,"expanded_config":dict(cfg),"devices":local_dev,"expanded_devices":expanded_dev}}))
        sys.exit(0)
    if cmd == "init":
        # Prove effect intent was durable before the external allocation.
        # Prove an effect intent was durable before the external allocation.
        # Any op's effect-phase receipt counts: C37 R1 readiness scenarios
        # bootstrap enforcement with a separate provisioning op first.
        effect_receipts = [p for p in (root / "data").rglob("receipts/*.json") if json.loads(p.read_text())["receipt"]["phase"] == "effect"]
        assert effect_receipts, "no durable effect-phase receipt"
        config = dict(args[i+1].split("=",1) for i,a in enumerate(args) if a == "-c")
        config["volatile.base_image"] = args[args.index("--")+1]
        device = next((args[i+1] for i,a in enumerate(args) if a == "--device"), None)
        if device:
            (root / "device-eth0").write_text(device)
        config_path.write_text(json.dumps(config))
        (root / "created").touch()
        sys.exit(0)
    if cmd == "config" and args[1] == "get":
        print(json.loads(config_path.read_text()).get(args[-1], ""))
        sys.exit(0)
    if cmd == "config" and args[1] == "set":
        config = json.loads(config_path.read_text())
        config[args[-2]] = args[-1]
        config_path.write_text(json.dumps(config))
        sys.exit(0)
    if cmd == "start":
        effect_receipts = [p for p in (root / "data").rglob("receipts/*.json") if json.loads(p.read_text())["receipt"]["phase"] == "effect"]
        assert effect_receipts, "no durable effect-phase receipt"
        (root / "started").touch()
        sys.exit(0)
    if cmd == "stop":
        # Out-of-band stop: the sandbox is STOPPED when the reconnect under
        # test arrives, so the resume exercises the cold-start path.
        started = root / "started"
        if started.exists():
            started.unlink()
        sys.exit(0)
    if cmd == "exec":
        # The daemon transport always works; the nonce-bound identity
        # readiness fails once the test arms the failure marker. A C37 R1
        # reconnect never re-applies enforcement, so the scenario bootstraps
        # it with a successful create BEFORE the marker is armed — until
        # then the guest answers the readiness protocol like a healthy VM.
        argv_exec = args[args.index("--")+1:]
        # The guest kernel boot id (readiness compares it across each pass):
        # the host's own, which is also every fixture command's birth boot.
        if len(argv_exec) > 4 and argv_exec[3] == "wssp-boot":
            with open("/proc/sys/kernel/random/boot_id") as boot:
                print("WSSP_BOOT " + argv_exec[4] + " " + boot.read().strip(), file=sys.stderr)
            sys.exit(0)
        if argv_exec != ["true"] and (root / "fail-readiness").exists():
            # The readiness script names its failed check (a fixed label).
            if len(argv_exec) > 4 and argv_exec[3] == "wssp-readiness":
                print("WSSP_NOT_READY " + argv_exec[4] + " user")
            sys.exit(1)
        if argv_exec == ["true"]:
            sys.exit(0)
        # The guest-sudo-helper (guest root): grant / revoke / revoke-audit. The
        # planted "sudo-verdict-<mode>" file forces a verdict.
        if argv_exec[:5] == ["python3", "-I", "-S", "-B", "-c"] and "wssp guest-sudo-helper" in argv_exec[5]:
            assert "--user" in args and args[args.index("--user") + 1] == "0", args
            sudo_mode, sudo_nonce, sudo_uid, sudo_gid = argv_exec[6:]
            assert sudo_mode in ["grant", "revoke", "revoke-audit"] and sudo_uid == "1000", argv_exec[6:]
            with open(root / "sudo-execs", "a") as log:
                log.write(sudo_mode + "\n")
            planted = root / ("sudo-verdict-" + sudo_mode)
            verdict = planted.read_text().strip() if planted.exists() else {"grant": "granted", "revoke": "revoked"}.get(sudo_mode, "clean") + " sudo_ws"
            print("WSSP_SUDO " + sudo_nonce + " " + verdict, file=sys.stderr, flush=True)
            sys.exit(0)
        # The root-grow-helper (guest root, create only): a grown root unless
        # the test plants "root-verdict" (the record body after the nonce).
        if argv_exec[:5] == ["python3", "-I", "-S", "-B", "-c"] and "wssp root-grow-helper" in argv_exec[5]:
            assert "--user" in args and args[args.index("--user") + 1] == "0", args
            root_mode, root_nonce, root_disk, root_budget = argv_exec[6:]
            assert root_mode == "grow" and root_disk.isdigit() and root_budget.isdigit(), argv_exec[6:]
            with open(root / "root-execs", "a") as log:
                log.write(root_disk + "\n")
            part = str(int(root_disk) - 1048576)
            planted = root / "root-verdict"
            body = planted.read_text().strip() if planted.exists() else " ".join([root_disk, root_disk, part, "ext4", part, "partition", part])
            if body == "ungrown":
                # An 8 GiB image root that never grew on this disk.
                body = " ".join([root_disk, "8589934592", "8588886016", "ext4", "8588886016", "partition", "8300000000"])
            print("WSSP_ROOT " + root_nonce + " " + body, file=sys.stderr, flush=True)
            sys.exit(0)
        if metadata_mkdir(argv_exec):
            sys.exit(0)
        if len(argv_exec) > 3 and argv_exec[3] == "wssp-readiness":
            print("WSSP_READY " + argv_exec[4])
            sys.exit(0)
        # The guest network probe (E1-A-01): the fake guest has its lease.
        if len(argv_exec) > 3 and argv_exec[3] == "wssp-network":
            print("WSSP_NET " + argv_exec[4])
            sys.exit(0)
        sys.exit(1)
    if cmd == "delete":
        (root / "deleted").touch()
        sys.exit(0)
    if cmd == "config" and args[1:3] == ["device", "add"]:
        # config device add <inst> <dev> <type> k=v... — a complete LOCAL
        # device shadow (R22-F2: init --device merging is not used anymore).
        dev = args[4]
        (root / ("device-" + dev)).write_text(dev + "," + ",".join(args[6:]))
        sys.exit(0)
    if cmd == "config" and args[1:3] == ["device", "remove"]:
        dev_path = root / ("device-" + args[4])
        if not dev_path.exists():
            print("Error: The device doesn't exist", file=sys.stderr)
            sys.exit(1)
        dev_path.unlink()
        sys.exit(0)
    raise RuntimeError("unsupported readiness shim call: " + str(args))
if cmd == "init":
    config = dict(args[i+1].split("=",1) for i,a in enumerate(args) if a == "-c")
    (root/"created").touch()
    (root/"lease-config.json").write_text(json.dumps(config))
    sys.exit(0)
if cmd == "start":
    sys.exit(0)
config_path = root / "lease-config.json"
lease_config = json.loads(config_path.read_text()) if config_path.exists() else {}
if cmd == "config":
    if args[1] == "set":
        lease_config[args[-2]] = args[-1]
        config_path.write_text(json.dumps(lease_config))
    else:
        print(lease_config.get(args[-1], ""))
    sys.exit(0)
if cmd == "query":
    fp = "abcdef0123456789" * 4
    if (root / "deleted").exists() or not (root/"created").exists():
        print(json.dumps({"type":"error","error_code":404,"error":"Not Found"}))
        sys.exit(0)
    stopped = (root / "stopped").exists()
    local_dev, expanded_dev = instance_devices("sbx-1")
    inst_config = {
        **lease_config,
        "user.flycockpit.sandbox_id":"sbx-1",
        "user.flycockpit.template_digest":"sha256:" + fp,
        "volatile.base_image":fp
    }
    print(json.dumps({"type":"sync","metadata":{
        "status":"Stopped" if stopped else "Running","status_code":102 if stopped else 103,
        "type":"virtual-machine","architecture":"x86_64","config":inst_config,
        # A real daemon merges local + profile + image config; the
        # profile/image carry none here (C37).
        "expanded_config":dict(inst_config),
        "devices":local_dev,
        "expanded_devices":expanded_dev
    }}))
    sys.exit(0)
if cmd == "stop":
    (root / "stop-entered").touch()
    while not (root / "release-stop").exists():
        time.sleep(.005)
    try:
        os.killpg(int((root / "guest-pgid").read_text()), signal.SIGKILL)
    except (ProcessLookupError, FileNotFoundError):
        pass
    (root / "stopped").touch()
    sys.exit(0)
if cmd != "exec":
    raise RuntimeError("unsupported shim call: " + cmd)
options = args[:args.index("--")]
argv = args[args.index("--") + 1:]
# The guest-sudo-helper (guest root) after readiness: grant / revoke /
# revoke-audit, as in the readiness branch above.
if argv[:5] == ["python3", "-I", "-S", "-B", "-c"] and "wssp guest-sudo-helper" in argv[5]:
    assert options[3:9] == ["--user", "0", "--group", "0", "--cwd", "/"], options
    sudo_mode, sudo_nonce, sudo_uid, sudo_gid = argv[6:]
    assert sudo_mode in ["grant", "revoke", "revoke-audit"] and sudo_uid == "1000", argv[6:]
    with open(root / "sudo-execs", "a") as log:
        log.write(sudo_mode + "\n")
    planted = root / ("sudo-verdict-" + sudo_mode)
    verdict = planted.read_text().strip() if planted.exists() else {"grant": "granted", "revoke": "revoked"}.get(sudo_mode, "clean") + " sudo_ws"
    print("WSSP_SUDO " + sudo_nonce + " " + verdict, file=sys.stderr, flush=True)
    sys.exit(0)
# The root-grow-helper (guest root, create only), as in the readiness branch.
if argv[:5] == ["python3", "-I", "-S", "-B", "-c"] and "wssp root-grow-helper" in argv[5]:
    assert options[3:9] == ["--user", "0", "--group", "0", "--cwd", "/"], options
    root_mode, root_nonce, root_disk, root_budget = argv[6:]
    assert root_mode == "grow" and root_disk.isdigit() and root_budget.isdigit(), argv[6:]
    part = str(int(root_disk) - 1048576)
    planted = root / "root-verdict"
    body = planted.read_text().strip() if planted.exists() else " ".join([root_disk, root_disk, part, "ext4", part, "partition", part])
    if body == "ungrown":
        body = " ".join([root_disk, "8589934592", "8588886016", "ext4", "8588886016", "partition", "8300000000"])
    print("WSSP_ROOT " + root_nonce + " " + body, file=sys.stderr, flush=True)
    sys.exit(0)
# Plan §10: the root retire helper (guest root, cwd /, no guest env). The
# attempt's scope is modelled by its guest process group (the pid file the
# real wrapper wrote): populated while the group lives; a kill mode kills
# the whole group. Planted files force not_due / unscoped.
if argv[:5] == ["python3", "-I", "-S", "-B", "-c"] and "Plan §10 retire helper" in argv[5]:
    assert options == ["exec", "wssp-sbx-sbx-1", "-T", "--user", "0", "--group", "0", "--cwd", "/"], options
    assert len(argv) == 11, argv
    mode, nonce, uid, unit, budget = argv[6:]
    assert mode in ["observe", "kill-cancel", "kill-deadline"], mode
    assert re.fullmatch("[0-9a-f]{32}", nonce) and uid == "1000" and re.fullmatch("0|[1-9][0-9]*", budget)
    matched = re.fullmatch(UNIT_RE, unit)
    assert matched, unit
    with open(root / "retire-execs", "a") as log:
        log.write(" ".join([mode, unit, budget]) + "\n")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    def record(verdict):
        print("WSSP_RETIRE " + nonce + " " + boot + " " + verdict, file=sys.stderr, flush=True)
        sys.exit(0)
    if (root / "retire-unscoped").exists():
        record("unscoped")
    try:
        pgid = int((root / "ops" / (matched.group(1) + ".pid")).read_text().split()[0])
        os.killpg(pgid, 0)
    except (OSError, ValueError, IndexError):
        record("absent")
    if mode == "observe":
        record("populated")
    if (root / "retire-not-due").exists():
        record("not_due 1000")
    os.killpg(pgid, signal.SIGKILL)
    (root / "retire-killed").write_text(mode)
    record("killed")
# Model the guest's scope without invoking the host service manager.
scope = ["/usr/bin/systemd-run", "--scope", "--quiet", "--collect", "--no-ask-password", "--description=wssp-command", "--property=OOMPolicy=continue", "--expand-environment=no"]
if argv[:1] == ["/usr/bin/systemd-run"]:
    assert argv[:len(scope)] == scope, "unexpected command scope"
    assert re.fullmatch("--unit=" + UNIT_RE, argv[len(scope)]), argv
    assert argv[len(scope) + 1:len(scope) + 3] == ["--slice=wssp.slice", "--"], argv
    argv = argv[len(scope) + 3:]
identity_setup = argv[:4] == ["python3", "-I", "-S", "-c"]
expected_id = "0" if identity_setup else "1000"
assert options[options.index("--user") + 1] == expected_id, options
assert options[options.index("--group") + 1] == expected_id, options
if identity_setup:
    # The launcher forwards the attempt's derived scope unit, then uid gid.
    assert re.fullmatch(UNIT_RE, argv[5]), argv[5]
    assert argv[6:8] == ["1000", "1000"]
    # Never initialize guest groups against the test host's account database.
    argv = argv[8:]
guest_env = dict(options[i + 1].split("=", 1) for i, value in enumerate(options) if value == "--env")
assert guest_env["HOME"] == "/home/user", guest_env
if metadata_mkdir(argv):
    sys.exit(0)
metadata_stat(argv)
if "-t" in options:
    # C52 PTY stand-in for the declared guest shell, attached to the real
    # host PTY that the daemon allocated for this "incus exec -t" child.
    (root / "pty-argv").write_text(json.dumps(args))
    if (root / "mode").read_text() == "terminal-flood":
        chunk = b"y" * 16384
        while True:
            os.write(1, chunk)
    while True:
        data = os.read(0, 4096)
        if not data:
            sys.exit(0)
        if b"bye" in data:
            sys.exit(7)
        os.write(1, b"got:" + data.strip() + b"\n")
if argv == ["true"]:
    sys.exit(0)
if len(argv) > 3 and argv[3] == "wssp-env-tools":
    print("WSSP_ENV_TOOLS " + argv[4] + "\n/usr/bin/python3\n/usr/bin/setsid")
    sys.exit(0)
if argv[:3] == ["/usr/bin/python3", "-I", "-c"]:
    # The real stdin-frame helper consumes env values; the shim only models
    # the guest's fixed identity and its private operation directory.
    start = argv.index("--") + 1
    wrapper = argv[start:]
    offset = 2 if wrapper[1:2] == ["-w"] else 1
    script_index = start + offset + 2
    argv[script_index] = argv[script_index].replace(guest_env["HOME"] + "/.wssp/ops", str(root / "ops"))
    base = dict(os.environ, **guest_env)
    base.setdefault("SHELL", "/bin/bash")
    os.execve(argv[0], argv, base)
if len(argv) > 3 and argv[3] == "wssp-readiness":
    print("WSSP_READY " + argv[4])
    sys.exit(0)
if len(argv) > 4 and argv[3] == "wssp-boot":
    # The guest kernel boot id readiness compares across each pass.
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    print("WSSP_BOOT " + argv[4] + " " + boot, file=sys.stderr)
    sys.exit(0)
if len(argv) > 3 and argv[3] == "wssp-network":
    print("WSSP_NET " + argv[4])
    sys.exit(0)
offset = (2 if argv[1:2] == ["-w"] else 1) if argv[0] == "setsid" else 0
helper = argv[offset + 3]
mode = (root / "mode").read_text()
if helper == "wssp-terminate":
    # No guest mutation may precede durable intent.
    receipts = list((root / "data").rglob("receipts/op-1.json"))
    assert len(receipts) == 1, receipts
    receipt = json.loads(receipts[0].read_text())["receipt"]
    # A command timeout stops the group with no cancel intent; only a case
    # that arms this marker expects that.
    if not (root / "terminate-on-timeout").exists():
        assert receipt["cancelRequested"], receipt
    (root / "cleanup-entered").touch()
    if mode in ["blocked", "natural-during-cleanup", "natural-after-retry", "natural-cleanup-release", "natural-late-output", "natural-late-reframed"]:
        while not (root / "release-cleanup").exists():
            time.sleep(0.005)
    if mode == "failed" and not (root / "release-cleanup").exists():
        # Fail once, then hold the same owner's retry until the server has
        # observed UNKNOWN and explicitly permits recovery. Fast retries must
        # not exhaust the bounded helper attempts before that wire round trip.
        if not (root / "cleanup-failed-once").exists():
            (root / "cleanup-failed-once").touch()
            sys.exit(1)
        while not (root / "release-cleanup").exists():
            time.sleep(0.005)
    # The production helper performs TERM, grace, KILL and group_gone observation.
    os.execvp(argv[0], argv)
if helper != "wssp-run":
    raise RuntimeError("unsupported guest helper: " + helper)
# Reap the guest descendants too, as a VM's init would. No host PID1 assumptions.
ctypes.CDLL(None).prctl(36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER
script = argv[offset + 2].replace(guest_env["HOME"] + "/.wssp/ops", str(root / "ops"))
nonce = script.split("WSSP_PID ")[1].split(" ")[0]
argv[offset + 2] = script
if mode in ["natural", "natural-no-ready"]:
    # The real wrapper's head: PID banner, then the fixed-position start
    # record (wssp_ready: boot id and /proc stat field 22). That record is
    # mandatory; "natural-no-ready" models a head that lost it anyway.
    head = f"WSSP_PID {nonce} {os.getpid()}\n"
    if mode == "natural":
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        start_ticks = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]
        head += f"WSSP_READY {nonce} {os.getpid()} {boot_id} {start_ticks}\n"
    sys.stderr.write(f"{head}\nWSSP_EXIT {nonce} 0\n")
    sys.stderr.flush()
    (root / "natural-exit").touch()
    while not (root / "release-natural").exists():
        time.sleep(0.005)
    sys.exit(0)
if mode in ["natural-late-output", "natural-late-reframed"]:
    # The transport cannot exit while waiting for this independent descriptor
    # holder. Parent disappearance proves finish_cancel observed the first EXIT
    # and killed/reaped the transport before these additional bytes are emitted.
    tail = f"\nWSSP_EXIT {nonce} 7\n" if mode == "natural-late-reframed" else ""
    holder_code = "import os,sys,time,pathlib; parent=os.getppid();\nwhile os.getppid()==parent: time.sleep(.005)\nsys.stdout.write('late-stdout');sys.stdout.flush();sys.stderr.write('late-stderr' + " + repr(tail) + ");sys.stderr.flush();pathlib.Path(" + repr(str(root / "late-done")) + ").touch()"
    holder = subprocess.Popen([sys.executable, "-c", holder_code], start_new_session=True)
    (root / "holder-pid").write_text(str(holder.pid))
entry_mode = mode in ["natural-entry-exit", "natural-entry-setup"]
if entry_mode:
    # Unlike the cleanup-time tails above, these bytes arrive while the local
    # transport is still alive, after cancellation has reached the host.
    holder_code = "import sys,time,pathlib;\nwhile not pathlib.Path(" + repr(str(root / "release-pipe")) + ").exists(): time.sleep(.005)\nsys.stdout.write('late-stdout');sys.stdout.flush();sys.stderr.write('late-stderr');sys.stderr.flush();pathlib.Path(" + repr(str(root / "late-done")) + ").touch()"
    holder = subprocess.Popen([sys.executable, "-c", holder_code], start_new_session=True)
    (root / "holder-pid").write_text(str(holder.pid))
    if mode == "natural-entry-setup":
        # Exercise the real wrapper's failed mkdir branch, before argv starts.
        (root / "ops").write_text("not a directory")
if (root / "hold-wrapper").exists():
    (root / "before-wrapper").touch()
    while not (root / "release-wrapper").exists():
        time.sleep(.005)
p = subprocess.Popen(argv, stderr=subprocess.PIPE if entry_mode else None)
(root / "guest-pgid").write_text(str(p.pid))
if entry_mode:
    initial_stderr = p.stderr.read()
    (root / "initial-stderr").write_bytes(initial_stderr)
    sys.stderr.buffer.write(initial_stderr)
    sys.stderr.buffer.flush()
if mode == "held-pipe":
    holder = subprocess.Popen([sys.executable, "-c", "import pathlib,time; p=pathlib.Path(" + repr(str(root / "release-pipe")) + ");\nwhile not p.exists(): time.sleep(.005)"], start_new_session=True)
    (root / "holder-pid").write_text(str(holder.pid))
status = p.wait()
if mode.startswith("natural-"):
    (root / "natural-finished").touch()
if entry_mode:
    while not (root / "release-stop").exists():
        time.sleep(.005)
if status == -signal.SIGKILL:
    (root / "kill-observed").write_text(str(time.monotonic_ns()))
while True:
    try:
        _, status = os.waitpid(-1, 0)
        if os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL:
            (root / "kill-observed").write_text(str(time.monotonic_ns()))
    except ChildProcessError:
        break
`;

export const cancelWriterFixture = String.raw`import os
from pathlib import Path
import signal
import sys
import time
root = Path(sys.argv[1])
def term(_signal, _frame):
    (root / 'term-observed').write_text(str(time.monotonic_ns()))
signal.signal(signal.SIGTERM, term)
(root / 'armed').touch()
while True:
    if (root / 'release-natural').exists():
        sys.exit(0)
    for name in ['write-before', 'write-after']:
        request = root / name
        if request.exists() and not (root / (name + '-done')).exists():
            with (root / 'bytes').open('ab') as output:
                output.write(b'X')
                output.flush()
            (root / (name + '-done')).touch()
    time.sleep(.005)
`;
