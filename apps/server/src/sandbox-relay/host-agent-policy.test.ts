import { expect, it } from "vitest";
import { HostAgentPolicies } from "./host-agent-policy";

it("requires live owner-bound policy, enforces sequence/epoch/revision and vetoes pending lowering", () => {
  const store = new HostAgentPolicies();
  const socket = {};
  let authorized = true;
  store.register(
    { hostId: "host", ownerId: "a", epoch: 2, socket, authorized: () => authorized },
    {
      hostCommands: true,
      hostFiles: true,
      hostCommandMaxMs: 600000,
      agentPolicyRevision: 1,
      lowerPending: false,
    },
  );
  expect(store.read("host", "b")).toBeNull();
  expect(store.read("host", "a")?.hostCommands).toBe(true);
  store.lower("host", "a");
  expect(store.read("host", "a")).toMatchObject({
    hostCommands: false,
    hostFiles: false,
    lowerPending: true,
  });
  const report = {
    type: "host.agent-policy",
    connectionEpoch: 2,
    sequence: 1,
    hostCommands: false,
    hostFiles: false,
    agentPolicyRevision: 2,
  } as const;
  expect(store.report("host", {}, report)).toBe(false);
  expect(store.report("host", socket, { ...report, connectionEpoch: 1 })).toBe(false);
  expect(store.report("host", socket, { ...report, agentPolicyRevision: 1 })).toBe(false);
  expect(store.report("host", socket, report)).toBe(true);
  expect(store.read("host", "a")).toMatchObject({ hostCommands: false, lowerPending: true });
  expect(store.report("host", socket, report)).toBe(false);
  expect(
    store.report("host", socket, {
      ...report,
      sequence: 2,
      agentPolicyRevision: 3,
      hostCommands: true,
      hostFiles: true,
      hostCommandMaxMs: 600000,
    }),
  ).toBe(true);
  expect(store.read("host", "a")).toMatchObject({
    hostCommands: false,
    hostFiles: false,
    nodeHostCommands: true,
    lowerPending: true,
  });
  store.lift("host", "b");
  expect(store.read("host", "a")?.hostCommands).toBe(false);
  store.lift("host", "a");
  expect(store.read("host", "a")?.hostCommands).toBe(true);
  authorized = false;
  expect(store.read("host", "a")).toBeNull();
});

it("off witnesses require raw off and invalidate on disconnect, on reports and a new epoch", () => {
  const store = new HostAgentPolicies();
  const socket = {};
  let connected = true;
  let authorized = true;
  const link = {
    hostId: "host",
    ownerId: "a",
    epoch: 2,
    socket,
    authorized: () => authorized,
    connected: () => connected,
  };
  const policy = {
    hostCommands: true,
    hostFiles: true,
    agentPolicyRevision: 1,
    lowerPending: true,
  };
  store.register(link, policy);
  expect(store.read("host", "a")?.hostCommands).toBe(false);
  expect(store.offWitness("host", "a")).toBeNull();
  store.report("host", socket, {
    type: "host.agent-policy",
    connectionEpoch: 2,
    sequence: 1,
    hostCommands: false,
    hostFiles: false,
    agentPolicyRevision: 2,
  });
  expect(store.offWitness("host", "b")).toBeNull();
  const witness = store.offWitness("host", "a");
  expect(witness?.epoch).toBe(2);
  expect(witness?.isOff()).toBe(true);
  authorized = false; // Our own authority fence does not change a raw off report.
  expect(store.offWitness("host", "a")).toBeNull();
  expect(witness?.isOff()).toBe(true);
  connected = false;
  expect(witness?.isOff()).toBe(false);
  connected = authorized = true;
  store.report("host", socket, {
    type: "host.agent-policy",
    connectionEpoch: 2,
    sequence: 2,
    hostCommands: true,
    hostFiles: true,
    agentPolicyRevision: 3,
  });
  expect(witness?.isOff()).toBe(false);
  store.register({ ...link, epoch: 3 }, { ...policy, hostCommands: false });
  expect(witness?.isOff()).toBe(false);
  const fresh = store.offWitness("host", "a");
  expect(fresh?.isOff()).toBe(true);
  store.remove("host", socket);
  expect(fresh?.isOff()).toBe(false);
});
