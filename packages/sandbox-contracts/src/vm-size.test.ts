import { describe, expect, it } from "vitest";
// The same staged fixtures are decoded in Rust before negotiation is activated.
import capacityCases from "../../../crates/sandbox-protocol/fixtures/capacity_cases.json";
import helloV11 from "../../../crates/sandbox-protocol/fixtures/control_hello_daemon.json";
import { knownRelayProtocolVersion } from "./relay-version";
import {
  hostAdmissionV11Schema,
  hostHelloV11Schema,
  hostInventoryUpdateV11Schema,
  hostMemoryBudgetFromBytes,
  hostVcpuBudgetDefault,
  pinnedAllocationV11Schema,
  resolveVmSize,
  storagePoolV11Schema,
  vmCapacitySchema,
  vmLiveMemoryChargeMiB,
  vmRootChargeGiB,
  vmSizeOverridesSchema,
  vmSizeSchema,
} from "./vm-size";

describe("strict 1.0 TS/Rust fixtures", () => {
  const codecs = {
    size: vmSizeSchema,
    overrides: vmSizeOverridesSchema,
    // The shared fixture's `revision` kind is the daemon's VM-size default
    // resolution (Rust `revision_defaults`), not the control plane's revision row.
    revision: vmSizeOverridesSchema.transform((overrides) =>
      resolveVmSize({ cpuCount: 1, memoryMiB: 1024, diskGiB: 32 }, overrides),
    ),
    capacity: vmCapacitySchema,
    pool: storagePoolV11Schema,
    hello: hostHelloV11Schema,
    inventory: hostInventoryUpdateV11Schema,
    allocation: pinnedAllocationV11Schema,
  };
  for (const fixture of capacityCases) {
    it(fixture.name, () => {
      const result = codecs[fixture.kind as keyof typeof codecs].safeParse(fixture.input);
      expect(result.success).toBe(fixture.valid);
      if (result.success) expect(result.data).toEqual(fixture.expected);
    });
  }
  it("advertises only 1.0 and rejects static cap rewrites in health updates", () => {
    expect(knownRelayProtocolVersion("1.0")).toBe(true);
    const { vmCapacity, storagePools, inventory } = helloV11;
    const admission = {
      type: "host.admission",
      journalId: "a".repeat(32),
      connectionEpoch: 1,
      runtimeKind: "fake",
      schedulable: true,
      egressPolicy: true,
      terminal: true,
      vmCapacity,
      storagePools,
    };
    expect(hostAdmissionV11Schema.safeParse(admission).success).toBe(true);
    expect(hostAdmissionV11Schema.safeParse({ ...admission, journalId: undefined }).success).toBe(
      false,
    );
    const health = storagePools.map(
      ({ name, marker, health, reason, totalBytes, usedBytes, freeBytes }) => ({
        name,
        marker,
        health,
        reason,
        totalBytes,
        usedBytes,
        freeBytes,
      }),
    );
    const update = {
      type: "inventory.update",
      id: "update_1",
      connectionEpoch: 1,
      observationSequence: 1,
      inventory,
      storagePools: health,
    };
    expect(hostInventoryUpdateV11Schema.safeParse(update).success).toBe(true);
    // Policy reports are a distinct current-link control, never inventory state.
    for (const patch of [
      { hostTerminal: true },
      { requireHostTerminalTotp: false },
      { policyRevision: 1 },
    ])
      expect(hostInventoryUpdateV11Schema.safeParse({ ...update, ...patch }).success).toBe(false);
    expect(hostInventoryUpdateV11Schema.safeParse({ ...update, storagePools }).success).toBe(false);
    expect(
      hostInventoryUpdateV11Schema.safeParse({
        ...update,
        observationSequence: Number.MAX_SAFE_INTEGER + 1,
      }).success,
    ).toBe(false);
  });
});
it("shares named charges, byte rounding and independent disk overrides", () => {
  expect(vmLiveMemoryChargeMiB(512)).toBe(832);
  expect(vmRootChargeGiB(32)).toBe(33);
  expect(hostVcpuBudgetDefault(32)).toBe(64);
  expect(() => hostVcpuBudgetDefault(0)).toThrow();
  expect(() => hostVcpuBudgetDefault(Number.MAX_SAFE_INTEGER)).toThrow();
  expect(hostMemoryBudgetFromBytes(124n * 1024n ** 3n)).toBe(95232);
  expect(hostMemoryBudgetFromBytes(4n * 1024n ** 3n - 1n)).toBe(0);
  expect(hostMemoryBudgetFromBytes(1024n)).toBe(0);
  expect(() => hostMemoryBudgetFromBytes(-1n)).toThrow();
  expect(hostMemoryBudgetFromBytes(18446744073709551615n)).toBeGreaterThan(16777216);
  expect(() => hostMemoryBudgetFromBytes(18446744073709551616n)).toThrow();
  const revision = { cpuCount: 8, memoryMiB: 4096, diskGiB: 64 };
  expect(() => resolveVmSize({ ...revision, diskGiB: 0 }, { diskGiB: 32 })).toThrow();
  expect(resolveVmSize(revision, { diskGiB: undefined })).toEqual(revision);
  expect(resolveVmSize(revision, { diskGiB: 32 })).toEqual({ ...revision, diskGiB: 32 });
  expect(resolveVmSize(revision, { memoryMiB: 2048 })).toEqual({ ...revision, memoryMiB: 2048 });
});

it("Prisma defaults and managed numeric bounds match the canonical policy", async () => {
  const { readFileSync } = await import("node:fs");
  const { VM_SIZE_LIMITS: limits } = await import("./vm-size");
  const schema = readFileSync(
    new URL("../../db/prisma/schema/sandbox.prisma", import.meta.url),
    "utf8",
  );
  const revisionBlock = schema.split("model SandboxTemplateRevision {")[1]?.split("\n}")[0];
  expect(revisionBlock).toMatch(
    new RegExp(`defaultDiskGiB\\s+Int\\s+@default\\(${limits.diskGiBDefault}\\)`),
  );
  expect(revisionBlock).toMatch(
    new RegExp(`minDiskGiB\\s+Int\\s+@default\\(${limits.diskGiBDefault}\\)`),
  );
  expect(revisionBlock).toContain(
    `"minDiskGiB" >= ${limits.diskGiBMin} AND "minDiskGiB" <= "defaultDiskGiB" AND "defaultDiskGiB" <= ${limits.diskGiBMax}`,
  );
  for (const model of ["Sandbox", "SandboxPlacement"]) {
    const block = schema.split(`model ${model} {`)[1]?.split("\n}")[0];
    expect(block).toBeDefined();
    for (const [key, value] of [
      ["cpuCount", limits.cpuCountDefault],
      ["memoryMiB", limits.memoryMiBDefault],
      ["diskGiB", limits.diskGiBDefault],
    ]) {
      expect(block).toMatch(new RegExp(`${key}\\s+Int\\s+@default\\(${value}\\)`));
    }
    expect(block).toContain(
      `"diskGiB" >= ${limits.diskGiBMin} AND "diskGiB" <= ${limits.diskGiBMax}`,
    );
  }
  expect(schema).toContain(
    `"daemonVcpuBudget" >= ${limits.hostVcpuBudgetMin} AND "daemonVcpuBudget" <= ${limits.hostVcpuBudgetMax}`,
  );
  expect(schema).toContain(`"rootCount" <= ${limits.hostManagedSandboxCeiling}`);
  expect(schema).toContain(
    `"vcpuReserved" <= ${limits.hostManagedSandboxCeiling * limits.cpuCountMax}`,
  );
  expect(schema).toContain(`"capacityGiB" <= ${limits.storageCapacityGiBMax}`);
});

it("accepts an optional, strict, duplicate-free channels hello capability", () => {
  const withChannels = (channels: unknown) => ({
    ...helloV11,
    daemon: {
      ...helloV11.daemon,
      capabilities: { ...helloV11.daemon.capabilities, channels },
    },
  });
  expect(hostHelloV11Schema.safeParse(helloV11).success).toBe(true);
  for (const kinds of [["pty", "exec"], ["exec"], ["pty"]])
    expect(hostHelloV11Schema.safeParse(withChannels({ kinds })).success).toBe(true);
  for (const bad of [
    { kinds: [] },
    { kinds: ["pty", "pty"] },
    { kinds: ["shell"] },
    { kinds: ["exec"], extra: 1 },
    null,
  ])
    expect(hostHelloV11Schema.safeParse(withChannels(bad)).success, JSON.stringify(bad)).toBe(
      false,
    );
});
