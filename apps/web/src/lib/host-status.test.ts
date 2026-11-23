import { describe, expect, it } from "vitest";

import {
  formatAge,
  HOST_HEARTBEAT_STALE_AFTER_MS,
  HOST_RECONNECTING_WINDOW_MS,
  type HostConnectionFields,
  hostCapacityState,
  hostCommands,
  hostConnectionState,
  hostDeleteBlocker,
  hostDrainBadge,
  hostEgressBlocker,
  hostGuardState,
  hostMutationProblem,
  hostResourceFit,
  nextHostStateChangeAt,
  type StorageSummary,
  shellWord,
  storageDisplayState,
} from "./host-status";

const NOW = Date.parse("2026-09-26T12:00:00Z");
const host = (overrides: Partial<HostConnectionFields> = {}): HostConnectionFields => ({
  status: "CONNECTED",
  lastConnectedAt: new Date(NOW - 60_000),
  lastHeartbeatAt: new Date(NOW - 1_000),
  deletionRequestedAt: null,
  ...overrides,
});

describe("hostConnectionState", () => {
  it.each([
    ["fresh connected heartbeat", host(), "ready"],
    [
      "heartbeat exactly at the window",
      host({ lastHeartbeatAt: new Date(NOW - HOST_HEARTBEAT_STALE_AFTER_MS) }),
      "ready",
    ],
    [
      "heartbeat one ms past the window",
      host({ lastHeartbeatAt: new Date(NOW - HOST_HEARTBEAT_STALE_AFTER_MS - 1) }),
      "stale",
    ],
    ["connected without any heartbeat", host({ lastHeartbeatAt: null }), "stale"],
    ["connected with an unparseable heartbeat", host({ lastHeartbeatAt: "garbage" }), "stale"],
    ["server-marked STALE even with a fresh heartbeat", host({ status: "STALE" }), "stale"],
    [
      "disconnected, last attempt past the reconnecting window",
      host({
        status: "DISCONNECTED",
        lastConnectedAt: new Date(NOW - HOST_RECONNECTING_WINDOW_MS - 1),
      }),
      "offline",
    ],
    // E3-B-02: a daemon that keeps connecting is not "offline".
    ["disconnected, attempted within the window", host({ status: "DISCONNECTED" }), "reconnecting"],
    [
      "disconnected, attempting, its inventory refused",
      host({ status: "DISCONNECTED", quarantinedAt: new Date(NOW - 600_000) }),
      "quarantined",
    ],
    [
      "quarantined but no recent attempt is offline",
      host({
        status: "DISCONNECTED",
        quarantinedAt: new Date(NOW - 600_000),
        lastConnectedAt: new Date(NOW - HOST_RECONNECTING_WINDOW_MS - 1),
      }),
      "offline",
    ],
    [
      "disconnected and never connected",
      host({ status: "DISCONNECTED", lastConnectedAt: null, lastHeartbeatAt: null }),
      "never",
    ],
    ["revoked", host({ status: "REVOKED" }), "revoked"],
    [
      "pending deletion wins over connected",
      host({ deletionRequestedAt: new Date(NOW) }),
      "deleting",
    ],
    [
      "ISO strings are accepted",
      host({ lastHeartbeatAt: new Date(NOW - 2_000).toISOString() }),
      "ready",
    ],
  ] as const)("%s → %s", (_name, fields, expected) => {
    expect(hostConnectionState(fields, NOW)).toBe(expected);
  });

  it("a stale connection is never ready, however long the page stays open", () => {
    const silent = host({ lastHeartbeatAt: new Date(NOW) });
    for (const later of [0, 10_000, 30_000, 30_001, 3_600_000]) {
      const state = hostConnectionState(silent, NOW + later);
      expect(state).toBe(later <= HOST_HEARTBEAT_STALE_AFTER_MS ? "ready" : "stale");
    }
  });
});

describe("nextHostStateChangeAt", () => {
  it("schedules a reconnecting host's turn to offline", () => {
    const trying = host({ status: "DISCONNECTED", lastConnectedAt: new Date(NOW - 30_000) });
    const at = nextHostStateChangeAt([trying], NOW);
    expect(at).toBe(NOW - 30_000 + HOST_RECONNECTING_WINDOW_MS + 1);
    expect(hostConnectionState(trying, at! - 1)).toBe("reconnecting");
    expect(hostConnectionState(trying, at!)).toBe("offline");
  });

  it("schedules a quarantined host's turn to offline", () => {
    const refused = host({
      status: "DISCONNECTED",
      lastConnectedAt: new Date(NOW - 30_000),
      quarantinedAt: new Date(NOW - 60_000),
    });
    const at = nextHostStateChangeAt([refused], NOW);
    expect(at).toBe(NOW - 30_000 + HOST_RECONNECTING_WINDOW_MS + 1);
    expect(hostConnectionState(refused, at! - 1)).toBe("quarantined");
    expect(hostConnectionState(refused, at!)).toBe("offline");
  });

  it("is the earliest ready host's stale deadline, ignoring hosts that are not ready", () => {
    const soon = host({ lastHeartbeatAt: new Date(NOW - 20_000) });
    const later = host({ lastHeartbeatAt: new Date(NOW - 5_000) });
    const offline = host({ status: "DISCONNECTED", lastHeartbeatAt: new Date(NOW - 29_000) });
    const at = nextHostStateChangeAt([later, offline, soon], NOW);
    expect(at).toBe(NOW - 20_000 + HOST_HEARTBEAT_STALE_AFTER_MS + 1);
    expect(hostConnectionState(soon, at!)).toBe("stale");
    expect(hostConnectionState(soon, at! - 1)).toBe("ready");
  });

  it("keeps a future DB heartbeat ready and schedules its eventual stale transition", () => {
    const ahead = host({ lastHeartbeatAt: new Date(NOW + 10_000) });
    expect(hostConnectionState(ahead, NOW)).toBe("ready");
    const at = nextHostStateChangeAt([ahead], NOW);
    expect(at).toBe(NOW + 10_000 + HOST_HEARTBEAT_STALE_AFTER_MS + 1);
    expect(hostConnectionState(ahead, at! - 1)).toBe("ready");
    expect(hostConnectionState(ahead, at!)).toBe("stale");
    expect(nextHostStateChangeAt([ahead], at!)).toBeNull();
  });

  it("is null when nothing can turn stale (empty list, only offline hosts)", () => {
    expect(nextHostStateChangeAt([], NOW)).toBeNull();
    expect(
      nextHostStateChangeAt(
        [host({ status: "DISCONNECTED", lastConnectedAt: new Date(NOW - 3_600_000) })],
        NOW,
      ),
    ).toBeNull();
  });
});

describe("controls", () => {
  it("offers deletion only with no live sandboxes and no pending deletion", () => {
    expect(hostDeleteBlocker({ liveSandboxCount: 0, deletionRequestedAt: null })).toBeNull();
    expect(hostDeleteBlocker({ liveSandboxCount: 1, deletionRequestedAt: null })).toBe("live");
    expect(hostDeleteBlocker({ liveSandboxCount: 0, deletionRequestedAt: new Date() })).toBe(
      "pending",
    );
  });

  it("explains a missing egress capability only for a reporting FAKE or Incus host", () => {
    expect(hostEgressBlocker({ daemonRuntime: "INCUS_KVM", egressEnforcement: false })).toBe(
      "incusHint",
    );
    expect(hostEgressBlocker({ daemonRuntime: "FAKE", egressEnforcement: false })).toBe("fakeHint");
    expect(hostEgressBlocker({ daemonRuntime: "INCUS_KVM", egressEnforcement: true })).toBeNull();
    expect(
      hostEgressBlocker({ daemonRuntime: "UNSUPPORTED", egressEnforcement: false }),
    ).toBeNull();
    expect(hostEgressBlocker({ daemonRuntime: null, egressEnforcement: false })).toBeNull();
  });

  it("reads the guard as running only with an active lease", () => {
    const guard = (ok: boolean, reason: string | null, leaseActive: boolean) =>
      hostGuardState({ egressGuard: { ok, reason, leaseActive } });
    expect(guard(true, null, true)).toBe("running");
    expect(guard(true, null, false)).toBe("guard_lease_expired");
    expect(guard(false, "guard_quarantined", false)).toBe("guard_quarantined");
    expect(guard(false, "guard_deployment_source", false)).toBe("guard_deployment_source");
    expect(guard(false, null, false)).toBe("unknown");
    expect(guard(false, "something_new", false)).toBe("unknown");
  });

  it("badges draining vs drained only while the drain flag is on", () => {
    expect(hostDrainBadge({ draining: false, drained: true })).toBeNull();
    expect(hostDrainBadge({ draining: true, drained: false })).toBe("draining");
    expect(hostDrainBadge({ draining: true, drained: true })).toBe("drained");
  });

  it.each([
    [{ code: "CONFLICT", data: { code: "sandbox.host_capacity" } }, "capacity"],
    [{ code: "CONFLICT", data: { code: "sandbox.host_draining" } }, "draining"],
    [{ code: "CONFLICT", data: { code: "sandbox.host_delete_conflict" } }, "pendingDeletion"],
    [{ code: "CONFLICT", data: { code: "sandbox.state_conflict" } }, "changed"],
    [{ code: "NOT_FOUND" }, "notFound"],
    [{ status: 404 }, "notFound"],
    [{ code: "FORBIDDEN" }, "forbidden"],
    [new Error("network"), "generic"],
    [null, "generic"],
  ])("maps %j to %s", (error, expected) => {
    expect(hostMutationProblem(error)).toBe(expected);
  });
});

describe("commands", () => {
  it("quotes only unsafe shell words", () => {
    expect(shellWord("https://api.example.com:8443")).toBe("https://api.example.com:8443");
    expect(shellWord("a b")).toBe("'a b'");
    expect(shellWord("it's")).toBe(`'it'\\''s'`);
    expect(shellWord("$(rm)")).toBe("'$(rm)'");
  });

  it("builds nonsecret enrollment and connect commands for a host", () => {
    const commands = hostCommands("https://api.example.com", { id: "h_1", slug: "desk-01" });
    expect(commands).toEqual({
      install:
        "curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 https://api.example.com/install.sh | sh",
      deviceLogin: "wssp host enroll --slug desk-01 --server https://api.example.com",
      connect: "wssp host run",
      tokenConnect:
        "wssp host run --server https://api.example.com --host-id h_1 --host-token-env WSSP_HOST_TOKEN",
    });
    // Only an env var NAME appears, never a credential value or prefix.
    expect(JSON.stringify(commands)).not.toMatch(/wssp_(host|device|sdk)_/);
    expect(hostCommands("https://api.example.com").tokenConnect).toBeNull();
  });

  it("installs from the server's own /install.sh, https-only for an https server", () => {
    expect(hostCommands("https://api.example.com/").install).toBe(
      "curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 https://api.example.com/install.sh | sh",
    );
    expect(hostCommands("http://localhost:3000").install).toBe(
      "curl -fsSL --max-time 120 http://localhost:3000/install.sh | sh",
    );
  });

  it("connect commands use automatic local resource defaults", () => {
    const commands = hostCommands("https://api.example.com", { id: "h_1", slug: "desk-01" });
    expect(commands.connect).toBe("wssp host run");
    expect(commands.tokenConnect).not.toContain("--max-live-sandboxes");
  });

  it("formats heartbeat ages in seconds under a minute, in the page locale", () => {
    expect(formatAge(NOW - 12_000, "en-US", NOW)).toBe("12 seconds ago");
    expect(formatAge(NOW - 3 * 60_000, "es-MX", NOW)).toBe("hace 3 minutos");
    // A heartbeat ahead of the browser clock reads as now, not "in N seconds".
    expect(formatAge(NOW + 5_000, "en-US", NOW)).toBe("0 seconds ago");
  });
});

describe("VM budget freshness", () => {
  it("expires locally even if the last server report was current", () => {
    const now = Date.now();
    const host = {
      status: "CONNECTED" as const,
      lastConnectedAt: new Date(now),
      lastHeartbeatAt: new Date(now),
      deletionRequestedAt: null,
      capacity: { memoryBudgetMiB: 4096, current: true },
    };
    expect(hostCapacityState(host, now)).toBe("current");
    expect(hostCapacityState(host, now + 30001)).toBe("stale");
    expect(
      hostCapacityState({ ...host, capacity: { memoryBudgetMiB: null, current: false } }, now),
    ).toBe("never");
    expect(
      hostCapacityState({ ...host, capacity: { memoryBudgetMiB: 2048, current: false } }, now),
    ).toBe("stale");
  });
});

const storage = (overrides: Partial<StorageSummary> = {}): StorageSummary => ({
  id: "storage-1",
  name: "default",
  marker: "marker-1",
  capacityGiB: 96,
  totalBasedCapacityGiB: null,
  capacitySource: "explicit",
  derivationTotalBytes: null,
  derivationFreeBytes: null,
  derivationCommittedBytes: null,
  derivationActualBytes: null,
  derivationHeadroomBytes: null,
  implicitCeilingGiB: null,
  draining: false,
  health: "healthy",
  reason: null,
  totalBytes: 200 * 2 ** 30,
  usedBytes: 50 * 2 ** 30,
  freeBytes: 150 * 2 ** 30,
  diskReservedGiB: 0,
  reportedAt: new Date(NOW).toISOString(),
  ...overrides,
});
const fitHost = () => ({
  ...host(),
  retainedRootCount: 4,
  storagePools: [storage()],
  capacity: {
    memoryBudgetMiB: 4096,
    memoryReservedMiB: 0,
    memoryAvailableMiB: 4096,
    memoryOvercommittedMiB: 0,
    maxCpuCount: 4,
    maxMemoryMiB: 4096,
    vcpuBudget: 8,
    vcpuReserved: 0,
    vcpuAvailable: 8,
    vcpuOvercommitted: 0,
    retainedRootCount: 4,
    current: true,
    reportedAt: new Date(NOW).toISOString(),
  },
});
const requested = { cpuCount: 2, memoryMiB: 1024, diskGiB: 32 };

describe("resource fit hints", () => {
  it("uses charged RAM, summed vCPU and disk allowance independently of live count", () => {
    const h = fitHost();
    expect(hostResourceFit(h, requested, NOW)).toBe("fits");
    h.capacity.memoryAvailableMiB = 1024;
    expect(hostResourceFit(h, requested, NOW)).toBe("ram");
    h.capacity.memoryAvailableMiB = 4096;
    h.capacity.vcpuAvailable = 1;
    expect(hostResourceFit(h, requested, NOW)).toBe("vcpu");
    h.capacity.vcpuAvailable = 8;
    h.storagePools = [storage({ capacityGiB: 32 })];
    expect(hostResourceFit(h, requested, NOW)).toBe("disk");
    h.storagePools = [storage({ capacityGiB: 33 })];
    expect(hostResourceFit(h, requested, NOW)).toBe("fits");
  });
  it("distinguishes healthy zero cap, pool drain, missing size and stale storage", () => {
    const h = fitHost();
    h.storagePools = [storage({ capacityGiB: 0, capacitySource: "implicit" })];
    expect(storageDisplayState(h.storagePools[0]!, NOW)).toBe("healthy");
    expect(hostResourceFit(h, requested, NOW)).toBe("disk");
    h.storagePools = [storage({ draining: true })];
    expect(hostResourceFit(h, requested, NOW)).toBe("storage");
    h.storagePools = [storage()];
    expect(hostResourceFit(h, {}, NOW)).toBe("unknown");
    expect(hostResourceFit(h, requested, NOW + 15001)).toBe("storage");
    expect(nextHostStateChangeAt([h], NOW)).toBe(NOW + 15001);
    h.storagePools.push(
      storage({
        id: "sibling",
        marker: "sibling",
        reportedAt: new Date(NOW + 15001).toISOString(),
      }),
    );
    expect(hostResourceFit(h, requested, NOW + 15001)).toBe("fits");
    h.retainedRootCount = 250;
    expect(hostResourceFit(h, requested, NOW + 15001)).toBe("ceiling");
  });
});
