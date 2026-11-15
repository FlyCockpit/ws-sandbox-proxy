import { afterEach, describe, expect, it, vi } from "vitest";
import { HostTerminalPolicies } from "./host-terminal-policy";

describe("current-link host policy (unit; no database authority)", () => {
  afterEach(() => vi.useRealTimers());
  function rig() {
    const sent: string[] = [];
    const socket = {
      send: (s: string) => {
        sent.push(s);
      },
    };
    const invalidate = vi.fn();
    const registry = new HostTerminalPolicies(invalidate);
    let authorized = true;
    registry.register(
      { hostId: "host", ownerId: "owner", epoch: 3, socket, authorized: () => authorized },
      { hostTerminal: true, requireHostTerminalTotp: false, policyRevision: 2 },
    );
    return {
      registry,
      socket,
      sent,
      invalidate,
      revoke: () => {
        authorized = false;
      },
    };
  }
  it("local off invalidates with a specific host-terminal close reason", () => {
    const r = rig();
    r.registry.report("host", r.socket, {
      type: "host.terminal-policy",
      connectionEpoch: 3,
      sequence: 1,
      hostTerminal: false,
      requireHostTerminalTotp: false,
      policyRevision: 3,
    });
    expect(r.invalidate).toHaveBeenLastCalledWith("host", "host_terminals_disabled");
  });
  it("refuses offline/foreign raises and confirms only a newer persisted required report", async () => {
    const r = rig();
    expect(await r.registry.raise("missing", "owner")).toBe(false);
    expect(await r.registry.raise("host", "foreign")).toBe(false);
    const raised = r.registry.raise("host", "owner");
    expect(JSON.parse(r.sent[0]!)).toMatchObject({
      type: "host.terminal-policy.raise",
      connectionEpoch: 3,
    });
    const report = {
      type: "host.terminal-policy",
      connectionEpoch: 3,
      sequence: 1,
      hostTerminal: true,
      requireHostTerminalTotp: true,
      policyRevision: 3,
    } as const;
    expect(r.registry.report("host", { send() {} }, report)).toBe(false);
    expect(r.registry.report("host", r.socket, { ...report, connectionEpoch: 2 })).toBe(false);
    expect(r.registry.report("host", r.socket, { ...report, policyRevision: 2 })).toBe(false);
    expect(r.registry.report("host", r.socket, report)).toBe(true);
    expect(await raised).toBe(true);
    expect(r.invalidate).toHaveBeenCalledWith("host");
    expect(r.registry.report("host", r.socket, { ...report, requireHostTerminalTotp: false })).toBe(
      false,
    );
    // Explicit local lower is authoritative only at a newer revision and sequence.
    expect(
      r.registry.report("host", r.socket, {
        ...report,
        sequence: 2,
        policyRevision: 4,
        requireHostTerminalTotp: false,
      }),
    ).toBe(true);
  });
  it("timeout/disconnect never stores an offline request or carries a raise to another epoch", async () => {
    vi.useFakeTimers();
    const r = rig();
    const timed = r.registry.raise("host", "owner");
    await vi.advanceTimersByTimeAsync(5000);
    expect(await timed).toBe(false);
    const disconnected = r.registry.raise("host", "owner");
    r.registry.remove("host", r.socket);
    expect(await disconnected).toBe(false);
    expect(r.registry.read("host", "owner")).toBeUndefined();
    r.registry.register(
      { hostId: "host", ownerId: "owner", epoch: 4, socket: r.socket, authorized: () => true },
      { hostTerminal: true, requireHostTerminalTotp: false, policyRevision: 2 },
    );
    expect(r.registry.read("host", "owner")?.requireHostTerminalTotp).toBe(false);
    expect(
      r.registry.report("host", r.socket, {
        type: "host.terminal-policy",
        connectionEpoch: 3,
        sequence: 100,
        policyRevision: 100,
        hostTerminal: true,
        requireHostTerminalTotp: true,
      }),
    ).toBe(false);
  });
  it("drops capability on credential failure and scopes removal to the current socket", () => {
    const r = rig();
    r.registry.remove("host", { send() {} });
    expect(r.registry.read("host", "owner")).toBeDefined();
    expect(r.registry.read("host", "foreign")).toBeUndefined();
    r.revoke();
    expect(r.registry.read("host", "owner")).toBeUndefined();
  });
});
it("a pending dashboard lower refuses terminal access even while the live node still reports on", () => {
  const invalidate = vi.fn();
  const policies = new HostTerminalPolicies(invalidate);
  const socket = { send() {} };
  policies.register(
    { hostId: "host", ownerId: "owner", epoch: 1, socket, authorized: () => true },
    { hostTerminal: true, requireHostTerminalTotp: false, policyRevision: 1 },
  );
  policies.lower("host", "owner");
  expect(policies.read("host", "owner")?.hostTerminal).toBe(false);
  expect(invalidate).toHaveBeenCalledWith("host", "host_terminals_disabled");
});

it("invalid and valid off reports cannot lift a dashboard veto, nor can a subsequent on report", () => {
  const policies = new HostTerminalPolicies(vi.fn());
  const socket = { send() {} };
  policies.register(
    { hostId: "host", ownerId: "owner", epoch: 1, socket, authorized: () => true },
    { hostTerminal: true, requireHostTerminalTotp: false, policyRevision: 1 },
  );
  policies.lower("host", "owner");
  const report = {
    type: "host.terminal-policy",
    connectionEpoch: 1,
    sequence: 1,
    hostTerminal: false,
    requireHostTerminalTotp: false,
    policyRevision: 1,
  } as const;
  expect(policies.report("host", socket, report)).toBe(false);
  expect(policies.read("host", "owner")).toMatchObject({
    hostTerminal: false,
    nodeHostTerminal: true,
  });
  expect(policies.report("host", socket, { ...report, policyRevision: 2 })).toBe(true);
  expect(
    policies.report("host", socket, {
      ...report,
      sequence: 2,
      policyRevision: 3,
      hostTerminal: true,
    }),
  ).toBe(true);
  expect(policies.read("host", "owner")).toMatchObject({
    hostTerminal: false,
    nodeHostTerminal: true,
  });
  policies.lift("host", "foreign");
  expect(policies.read("host", "owner")?.hostTerminal).toBe(false);
  policies.lift("host", "owner");
  expect(policies.read("host", "owner")?.hostTerminal).toBe(true);
});

it("terminal off witnesses use raw reports and remain bound to the connected epoch", () => {
  const store = new HostTerminalPolicies(vi.fn());
  const socket = { send: vi.fn() };
  let connected = true;
  let authorized = true;
  const link = {
    hostId: "host",
    ownerId: "owner",
    epoch: 2,
    socket,
    authorized: () => authorized,
    connected: () => connected,
  };
  const policy = { hostTerminal: true, requireHostTerminalTotp: true, policyRevision: 1 };
  store.register(link, policy);
  store.lower("host", "owner");
  expect(store.read("host", "owner")?.hostTerminal).toBe(false);
  expect(store.offWitness("host", "owner")).toBeNull();
  store.report("host", socket, {
    type: "host.terminal-policy",
    connectionEpoch: 2,
    sequence: 1,
    hostTerminal: false,
    requireHostTerminalTotp: true,
    policyRevision: 2,
  });
  expect(store.offWitness("host", "foreign")).toBeNull();
  const witness = store.offWitness("host", "owner");
  expect(witness?.epoch).toBe(2);
  expect(witness?.isOff()).toBe(true);
  authorized = false;
  expect(store.offWitness("host", "owner")).toBeNull();
  expect(witness?.isOff()).toBe(true);
  connected = false;
  expect(witness?.isOff()).toBe(false);
  connected = authorized = true;
  store.report("host", socket, {
    type: "host.terminal-policy",
    connectionEpoch: 2,
    sequence: 2,
    hostTerminal: true,
    requireHostTerminalTotp: true,
    policyRevision: 3,
  });
  expect(witness?.isOff()).toBe(false);
  store.register({ ...link, epoch: 3 }, { ...policy, hostTerminal: false });
  expect(witness?.isOff()).toBe(false);
  const fresh = store.offWitness("host", "owner");
  expect(fresh?.isOff()).toBe(true);
  store.remove("host", socket);
  expect(fresh?.isOff()).toBe(false);
});
