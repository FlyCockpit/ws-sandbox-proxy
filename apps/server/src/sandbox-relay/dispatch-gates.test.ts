import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { Prisma } from "@wssp/db";
import { describe, expect, it, vi } from "vitest";

// The gates under test read only their arguments (and one host row); every
// other import is IO-bound.
vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/api/lib/sdk-key-access", () => ({ checkAcceptedDispatchAuthority: vi.fn() }));
vi.mock("@wssp/api/sandbox/host-admission", () => ({ requireRetainedStorage: vi.fn() }));
vi.mock("@wssp/api/sandbox/outbox", () => ({
  decodeOutboxPrincipal: vi.fn(),
  systemDispatchAllowed: vi.fn(),
}));
vi.mock("@wssp/api/sandbox/principal-kinds", () => ({
  dispatchClassOf: vi.fn(),
  recordedKeyIdOf: vi.fn(),
}));
vi.mock("@wssp/api/sandbox/contracts", () => ({ KEY_FREE_CLEANUP_KINDS: new Set<string>() }));

const {
  buildDispatchFieldsMatch,
  createEgressAdmissible,
  diskOffloadHostUnsupported,
  launchStartup,
  retainedStorageAdmits,
  templateStartupHostUnsupported,
  tunnelPortsHostUnsupported,
} = await import("./dispatch-gates");
const { requireRetainedStorage } = await import("@wssp/api/sandbox/host-admission");

const BUILD = "b1";
const buildVm = { purpose: "TEMPLATE_BUILD", buildId: BUILD, revisionSourceKind: "MANUAL" };
const workload = { purpose: "WORKLOAD", buildId: null, revisionSourceKind: "MANUAL" };
/** A community build VM booting its UPSTREAM pin, and the same pin elsewhere. */
const upstreamBuildVm = { ...buildVm, revisionSourceKind: "UPSTREAM" };
const upstreamWorkload = { ...workload, revisionSourceKind: "UPSTREAM" };
const verifyVm = { purpose: "TEMPLATE_VERIFY", buildId: null, revisionSourceKind: "BUILD" };
const copy = {
  contextPath: `/var/tmp/wssp-build/${BUILD}/context.tar`,
  sha256: "a".repeat(64),
  src: ["."],
  dest: "/app/",
  owner: "user",
};

// Defence in depth for D1 (plan template-builds §3.1): build frame fields go
// only to the build VM they name; anything else settles as protocol_error.
describe("buildDispatchFieldsMatch", () => {
  it.each([
    ["plain create on a workload", "sandbox.create", {}, workload, true],
    ["plain command on a workload", "command.run", { script: "id" }, workload, true],
    [
      "build create with its binding",
      "sandbox.create",
      { build: { buildId: BUILD } },
      buildVm,
      true,
    ],
    ["build VM create WITHOUT its binding", "sandbox.create", {}, buildVm, false],
    [
      "binding naming another build",
      "sandbox.create",
      { build: { buildId: "b2" } },
      buildVm,
      false,
    ],
    ["binding on a workload", "sandbox.create", { build: { buildId: BUILD } }, workload, false],
    ["binding on a command", "command.run", { build: { buildId: BUILD } }, buildVm, false],
    ["plain command on a build VM", "command.run", { script: "id" }, buildVm, true],
    ["root step on its build VM", "command.run", { script: "id", runAs: "root" }, buildVm, true],
    ["root step on a workload", "command.run", { script: "id", runAs: "root" }, workload, false],
    ["root on a non-command kind", "file.get", { runAs: "root" }, buildVm, false],
    ["unknown runAs value", "command.run", { runAs: "admin" }, buildVm, false],
    ["copy on its build VM", "command.run", { buildCopy: copy }, buildVm, true],
    ["copy on a workload", "command.run", { buildCopy: copy }, workload, false],
    [
      "copy from another build's context",
      "command.run",
      { buildCopy: { ...copy, contextPath: "/var/tmp/wssp-build/b2/context.tar" } },
      buildVm,
      false,
    ],
    ["copy with runAs", "command.run", { buildCopy: copy, runAs: "root" }, buildVm, false],
    ["kill of a build VM", "sandbox.kill", {}, buildVm, true],
    // I12 (community-base): bootstrap ⇔ UPSTREAM ∧ create ∧ build VM.
    [
      "bootstrap create of its UPSTREAM pin",
      "sandbox.create",
      { build: { buildId: BUILD, bootstrap: true } },
      upstreamBuildVm,
      true,
    ],
    [
      "UPSTREAM build VM create without bootstrap",
      "sandbox.create",
      { build: { buildId: BUILD } },
      upstreamBuildVm,
      false,
    ],
    [
      "bootstrap on a non-UPSTREAM build VM",
      "sandbox.create",
      { build: { buildId: BUILD, bootstrap: true } },
      buildVm,
      false,
    ],
    ["workload create of an UPSTREAM pin", "sandbox.create", {}, upstreamWorkload, false],
    ["reconnect of an UPSTREAM pin (build VM)", "sandbox.reconnect", {}, upstreamBuildVm, false],
    ["reconnect of an UPSTREAM pin (workload)", "sandbox.reconnect", {}, upstreamWorkload, false],
    [
      "bootstrap on a reconnect frame",
      "sandbox.reconnect",
      { build: { buildId: BUILD, bootstrap: true } },
      buildVm,
      false,
    ],
    [
      "UPSTREAM build VM command",
      "command.run",
      { script: "id", runAs: "root" },
      upstreamBuildVm,
      true,
    ],
    ["verify VM create (no binding)", "sandbox.create", {}, verifyVm, true],
    ["verify VM command (no root)", "command.run", { script: "id" }, verifyVm, true],
    ["root on a verify VM", "command.run", { script: "id", runAs: "root" }, verifyVm, false],
    ["a binding on a verify VM", "sandbox.create", { build: { buildId: BUILD } }, verifyVm, false],
    ["malformed binding never throws", "sandbox.create", { build: 7 }, buildVm, false],
  ] as const)("%s → %s", (_name, kind, payload, sandbox, expected) => {
    expect(buildDispatchFieldsMatch(kind, payload, sandbox)).toBe(expected);
  });
});

// B9: a launch whose revision has a start command is refused on an admitted
// daemon without `templateStartup` (never booted without its start command).
describe("template startup capability", () => {
  const host = (daemonFeatures: unknown, over: Record<string, unknown> = {}) => ({
    status: "CONNECTED",
    connectionEpoch: 4,
    admissionEpoch: 4,
    daemonFeatures: daemonFeatures as never,
    ...over,
  });

  it("refuses only on positive current-epoch evidence", () => {
    expect(templateStartupHostUnsupported(host({ egressPolicy: true }))).toBe(true);
    expect(templateStartupHostUnsupported(host({ templateStartup: false }))).toBe(true);
    expect(templateStartupHostUnsupported(host({ templateStartup: true }))).toBe(false);
    // The hello-time flag alone is not admitted yet.
    expect(templateStartupHostUnsupported(host({ helloTemplateStartup: true }))).toBe(true);
    // A host that is not admitted on this epoch, or offline, proves nothing.
    expect(templateStartupHostUnsupported(host({}, { admissionEpoch: 3 }))).toBe(false);
    expect(templateStartupHostUnsupported(host({}, { admissionEpoch: null }))).toBe(false);
    expect(templateStartupHostUnsupported(host({}, { status: "DISCONNECTED" }))).toBe(false);
    expect(templateStartupHostUnsupported(null)).toBe(false);
  });

  it("carries the revision's start/ready on launches of ordinary sandboxes only", async () => {
    const findFirst = vi.fn().mockResolvedValue({
      startCmd: "npm start",
      readyCmd: "curl -sf localhost:3000",
      readyTimeoutMs: 5000,
      defaultCwd: "/home/user/app",
    });
    const tx = { sandboxTemplateRevision: { findFirst } } as never;
    const sandbox = { userId: "u1", templateRevisionId: "rev1", buildId: null };
    const expected = {
      command: "npm start",
      ready: "curl -sf localhost:3000",
      readyTimeoutMs: 5000,
      cwd: "/home/user/app",
    };
    expect(await launchStartup(tx, "sandbox.create", sandbox)).toEqual(expected);
    expect(await launchStartup(tx, "sandbox.reconnect", sandbox)).toEqual(expected);
    expect(findFirst).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: "rev1", userId: "u1" } }),
    );
    expect(await launchStartup(tx, "command.run", sandbox)).toBeUndefined();
    expect(
      await launchStartup(tx, "sandbox.create", { ...sandbox, buildId: "b1" }),
    ).toBeUndefined();
    findFirst.mockResolvedValueOnce({
      startCmd: null,
      readyCmd: null,
      readyTimeoutMs: null,
      defaultCwd: "/app",
    });
    expect(await launchStartup(tx, "sandbox.create", sandbox)).toBeUndefined();
  });
});

const NOW = new Date("2026-11-03T12:00:00.000Z");
const HOST_OWNER = "host-owner";
const FOREIGN = "pool-user";
const OPEN = { mode: "open", domains: [], cidrs: [] };
const ALLOWLIST = { domains: ["pypi.org"], cidrs: [] };

type HostState = {
  guard: "leased" | "expired" | "down" | "stale_epoch" | "never";
  egressOpen: boolean;
  consent: boolean;
};

function txFor(state: HostState | null) {
  const row =
    state === null
      ? null
      : {
          connectionEpoch: 7,
          daemonFeatures: { egressPolicy: true, ...(state.egressOpen ? { egressOpen: true } : {}) },
          daemonOpenEgressForOthers: state.consent,
          daemonEgressGuardOk: state.guard !== "down" && state.guard !== "never",
          daemonEgressGuardEpoch:
            state.guard === "never" ? null : state.guard === "stale_epoch" ? 6 : 7,
          daemonEgressGuardLeaseUntil:
            state.guard === "leased" || state.guard === "stale_epoch"
              ? new Date(NOW.getTime() + 15_000)
              : state.guard === "expired"
                ? new Date(NOW.getTime() - 1_000)
                : null,
        };
  return {
    sandboxHost: { findFirst: vi.fn(async () => row) },
  } as unknown as Prisma.TransactionClient;
}

const gate = (state: HostState | null, sandboxOwnerId: string, policy: unknown) =>
  createEgressAdmissible(txFor(state), {
    hostId: "host",
    hostOwnerId: HOST_OWNER,
    sandboxOwnerId,
    policy,
    now: NOW,
  });

describe("createEgressAdmissible (§1.4, M7/M11/M18; security-critical)", () => {
  it("truth table: guard × mode × own/foreign × consent × egressOpen", async () => {
    const guards: HostState["guard"][] = ["leased", "expired", "down", "stale_epoch", "never"];
    for (const guard of guards)
      for (const mode of ["open", "allowlist"] as const)
        for (const owner of [HOST_OWNER, FOREIGN])
          for (const consent of [false, true])
            for (const egressOpen of [false, true]) {
              const verdict = await gate(
                { guard, egressOpen, consent },
                owner,
                mode === "open" ? OPEN : ALLOWLIST,
              );
              const expected =
                guard !== "leased"
                  ? "egress_guard_unavailable"
                  : mode === "allowlist"
                    ? null
                    : !egressOpen || (owner !== HOST_OWNER && !consent)
                      ? "open_egress_not_permitted"
                      : null;
              expect(verdict, JSON.stringify({ guard, mode, owner, consent, egressOpen })).toBe(
                expected,
              );
            }
  });

  it("the lease boundary is strict: a lease ending exactly now is expired", async () => {
    const tx = {
      sandboxHost: {
        findFirst: vi.fn(async () => ({
          connectionEpoch: 1,
          daemonFeatures: {},
          daemonOpenEgressForOthers: false,
          daemonEgressGuardOk: true,
          daemonEgressGuardEpoch: 1,
          daemonEgressGuardLeaseUntil: new Date(NOW),
        })),
      },
    } as unknown as Prisma.TransactionClient;
    expect(
      await createEgressAdmissible(tx, {
        hostId: "host",
        hostOwnerId: HOST_OWNER,
        sandboxOwnerId: HOST_OWNER,
        policy: ALLOWLIST,
        now: NOW,
      }),
    ).toBe("egress_guard_unavailable");
  });

  it("a missing host is refused; a non-canonical policy is never treated as open", async () => {
    expect(await gate(null, HOST_OWNER, ALLOWLIST)).toBe("egress_guard_unavailable");
    const leased = { guard: "leased", egressOpen: false, consent: false } as const;
    // An explicit "allowlist" spelling or junk is not open; launch
    // validation refuses it later.
    expect(await gate(leased, FOREIGN, { mode: "allowlist", domains: [], cidrs: [] })).toBeNull();
    expect(await gate(leased, FOREIGN, "open")).toBeNull();
    expect(await gate(leased, FOREIGN, { mode: "open", domains: [], cidrs: [], x: 1 })).toBeNull();
  });

  it('has exactly two call sites, both guarded by kind === "sandbox.create" or a restore', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const sites: string[] = [];
    for (const file of ["outbox-processor.ts", "dispatch-gates.ts", "operation-handlers.ts"]) {
      const source = readFileSync(join(dir, file), "utf8");
      const lines = source.split("\n");
      lines.forEach((line, index) => {
        if (!/createEgressAdmissible\(tx/.test(line)) return;
        // The guard sits in the same expression, at most three lines above.
        const window = lines.slice(Math.max(0, index - 3), index + 1).join("\n");
        expect(window, `${file}:${index + 1}`).toMatch(/kind === "sandbox\.create"/);
        // a restore is gated like a create (U9.1).
        expect(window, `${file}:${index + 1}`).toMatch(/\|\| (input\.)?restore\b/);
        sites.push(`${file}:${index + 1}`);
      });
    }
    expect(sites).toHaveLength(2);
    expect(sites.some((site) => site.startsWith("outbox-processor.ts"))).toBe(true);
    expect(sites.some((site) => site.startsWith("dispatch-gates.ts"))).toBe(true);
  });
});

// "Server gates" and U9.1: a restore reconnect is checked
// like `sandbox.create` (new roots allowed, not draining), from the
// operation row's launch mode, and both callers pass it.
describe("retainedStorageAdmits restore arm", () => {
  const storage = vi.mocked(requireRetainedStorage);
  const tx = {} as Prisma.TransactionClient;
  const base = { hostId: "h", ownerId: "o", sandboxId: "s" };
  const admits = (
    kind: string,
    sandboxState: string,
    restore: boolean,
    pool: { newRootsAllowed: boolean; draining: boolean },
  ) => {
    storage.mockResolvedValue(pool as never);
    return retainedStorageAdmits(tx, { ...base, kind, sandboxState, restore });
  };
  it("a restore needs new roots and no drain, exactly like a create", async () => {
    for (const pool of [
      { newRootsAllowed: true, draining: false },
      { newRootsAllowed: false, draining: false },
      { newRootsAllowed: true, draining: true },
    ]) {
      const create = await admits("sandbox.create", "PROVISIONING", false, pool);
      const restore = await admits("sandbox.reconnect", "PROVISIONING", true, pool);
      expect(restore).toBe(create);
    }
    expect(
      await admits("sandbox.reconnect", "PROVISIONING", true, {
        newRootsAllowed: false,
        draining: false,
      }),
    ).toBe(false);
  });
  it("a non-restore reconnect keeps today's rules", async () => {
    const closed = { newRootsAllowed: false, draining: true };
    // Cold: retained storage present suffices; warm/provisioning: no check.
    expect(await admits("sandbox.reconnect", "STOPPED", false, closed)).toBe(true);
    storage.mockClear();
    expect(await admits("sandbox.reconnect", "PROVISIONING", false, closed)).toBe(true);
    expect(storage).not.toHaveBeenCalled();
  });
  it("a restore flag on any other kind is a producer bug and refuses", async () => {
    expect(
      await admits("sandbox.create", "PROVISIONING", true, {
        newRootsAllowed: true,
        draining: false,
      }),
    ).toBe(false);
  });
  it("both callers derive `restore` from the operation row, never the payload", () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const calls: string[] = [];
    for (const file of ["outbox-processor.ts", "dispatch-gates.ts", "operation-handlers.ts"]) {
      const source = readFileSync(join(dir, file), "utf8");
      for (const match of source.matchAll(/retainedStorageAdmits\(tx, \{[^}]*\}/g)) {
        expect(match[0], file).toMatch(/restore(input\.restore)?,/);
        calls.push(file);
      }
      // Gates never read a restore flag from the outbox payload.
      expect(source, file).not.toMatch(/payload\.(restore|launchMode)\b/);
    }
    expect(calls.sort()).toEqual(["dispatch-gates.ts", "outbox-processor.ts"]);
    const outbox = readFileSync(join(dir, "outbox-processor.ts"), "utf8");
    expect(outbox).toMatch(/const restoreOffloadId = restoreOffloadOf\(operation\);/);
    const handlers = readFileSync(join(dir, "operation-handlers.ts"), "utf8");
    expect(handlers.match(/restore: restoreOffloadOf\(located\) !== null,/g)).toHaveLength(2);
  });
});

describe("diskOffloadHostUnsupported (U9.2)", () => {
  it("refuses only on positive current-epoch evidence", () => {
    const host = { status: "CONNECTED", connectionEpoch: 3, admissionEpoch: 3 };
    expect(diskOffloadHostUnsupported({ ...host, daemonDiskOffload: false })).toBe(true);
    expect(diskOffloadHostUnsupported({ ...host, daemonDiskOffload: true })).toBe(false);
    expect(
      diskOffloadHostUnsupported({ ...host, admissionEpoch: 2, daemonDiskOffload: false }),
    ).toBe(false);
    expect(
      diskOffloadHostUnsupported({ ...host, status: "DISCONNECTED", daemonDiskOffload: false }),
    ).toBe(false);
    expect(diskOffloadHostUnsupported(null)).toBe(false);
  });
});

describe("tunnelPortsHostUnsupported", () => {
  it("refuses declared tunnel ports only on positive current-epoch evidence", () => {
    const host = { status: "CONNECTED", connectionEpoch: 3, admissionEpoch: 3 };
    expect(tunnelPortsHostUnsupported({ ...host, daemonTunnelPorts: false })).toBe(true);
    expect(tunnelPortsHostUnsupported({ ...host, daemonTunnelPorts: true })).toBe(false);
    expect(
      tunnelPortsHostUnsupported({ ...host, admissionEpoch: 2, daemonTunnelPorts: false }),
    ).toBe(false);
    expect(
      tunnelPortsHostUnsupported({ ...host, status: "DISCONNECTED", daemonTunnelPorts: false }),
    ).toBe(false);
    expect(tunnelPortsHostUnsupported(null)).toBe(false);
  });
});
