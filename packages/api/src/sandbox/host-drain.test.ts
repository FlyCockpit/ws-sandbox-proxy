vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { readdirSync, readFileSync } from "node:fs";
import { expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
const { hostDrainStatus, lockWorkAdmissionHost, reserveLiveResources } = await import(
  "./host-admission"
);
const { setHostDrainingInput } = await import("./contracts");
const { default: db } = await import("@wssp/db");

it("drained requires drain admission and zero reservations", () => {
  for (const draining of [false, true])
    for (const count of [0, 1, 4]) {
      expect(
        hostDrainStatus({
          id: "h",
          draining,
          liveCount: count,
          memoryReservedMiB: count * 1280,
          vcpuReserved: count,
        }),
      ).toMatchObject({
        draining,
        liveSandboxCount: count,
        drained: draining && count === 0,
      });
    }
});
it("drain input is strict and bounds identifiers before database IO", () => {
  for (const value of [
    { id: "h", draining: "true" },
    { id: "h", draining: true, ownerId: "other" },
    { id: "a".repeat(65), draining: true },
    { id: "h\0", draining: true },
    { id: "h", draining: true, offload: "yes" },
  ])
    expect(setHostDrainingInput.safeParse(value).success).toBe(false);
  expect(setHostDrainingInput.parse({ id: "host-1", draining: true, offload: true })).toEqual({
    id: "host-1",
    draining: true,
    offload: true,
  });
  expect(setHostDrainingInput.parse({ id: "host-1", draining: false })).toEqual({
    id: "host-1",
    draining: false,
  });
});
it("new work refuses draining before capacity and before an already held slot returns", async () => {
  db.sandboxHost.findFirst.mockResolvedValue({
    id: "h",
    userId: "u",
    connectionEpoch: 1,
    draining: true,
  } as never);
  db.sandboxHost.updateMany.mockResolvedValue({ count: 1 });
  db.sandbox.findFirst.mockResolvedValue({
    liveResourcesHeld: true,
    hostOwnerId: "u",
    SandboxHost: { userId: "u" },
  } as never);
  await expect(lockWorkAdmissionHost(db, "h", "u")).rejects.toMatchObject({
    code: "CONFLICT",
    data: { code: "sandbox.host_draining" },
  });
  await expect(
    reserveLiveResources(db, { hostId: "h", ownerId: "u", sandboxId: "s" }),
  ).rejects.toMatchObject({ data: { code: "sandbox.host_draining" } });
  expect(db.sandbox.updateMany).not.toHaveBeenCalled();
});
it("admission inventory routes every new guest and template through the drain chokepoint", () => {
  const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");
  const sandbox = read("./services/sandboxes.ts"),
    template = read("./services/templates.ts"),
    admission = read("./host-admission.ts");
  const writers: string[] = [];
  const walk = (dir: URL) => {
    for (const file of readdirSync(dir, { withFileTypes: true })) {
      const url = new URL(file.name + (file.isDirectory() ? "/" : ""), dir);
      if (file.isDirectory() && file.name !== "testing") walk(url);
      else if (file.name.endsWith(".ts") && !file.name.endsWith(".test.ts")) {
        const source = readFileSync(url, "utf8");
        for (const match of source.matchAll(/\.(sandbox|sandboxTemplate)\.create(?:Many)?\(/g))
          writers.push(`${file.name}:${match[1]}`);
      }
    }
  };
  walk(new URL("../", import.meta.url));
  walk(new URL("../../../../apps/server/src/", import.meta.url));
  // A launchable sandbox row is created only by materializePlacement, after
  // resolvePlacement (the drain chokepoint) and before its live reservation.
  // The capacity queue's row is a hostless WAITING_FOR_CAPACITY row with no
  // holds; its placement goes through resolvePlacement → materializePlacement.
  // A template build's target slug creates an EMPTY logical template (no
  // image, no host, no revision): nothing is admitted to any host until its
  // build VM is placed (resolvePlacement) and captured (the capture path).
  // A community template (template-builds/community/service.ts) is the same:
  // its UPSTREAM pin has no availability and boots only as its build VM.
  expect(writers.sort()).toEqual([
    "capacity-queue.ts:sandbox",
    "placement-materialize.ts:sandbox",
    "service.ts:sandboxTemplate",
    "service.ts:sandboxTemplate",
    "templates.ts:sandboxTemplate",
  ]);
  const materialize = read("./placement-materialize.ts"),
    queue = read("./capacity-queue.ts");
  expect([...sandbox.matchAll(/await reserveLiveResources\(/g)]).toHaveLength(1);
  expect([...sandbox.matchAll(/await tx\.sandbox\.create\(/g)]).toHaveLength(0);
  expect(sandbox.slice(sandbox.indexOf("export const createSandbox"))).toMatch(
    /await resolvePlacement\([\s\S]+await materializePlacement\(/,
  );
  expect(materialize).toMatch(
    /await tx\.sandbox\.create\([\s\S]+await reserveLiveResources\([\s\S]+await reserveRootResources\(/,
  );
  expect(queue).toMatch(/await tx\.sandbox\.create\(\{[\s\S]+?state: "WAITING_FOR_CAPACITY"/);
  expect(queue).not.toMatch(/reserveLiveResources|reserveRootResources/);
  expect(queue.slice(queue.indexOf("async function placeLocked"))).toMatch(
    /await resolvePlacement\([\s\S]+await materializePlacement\(/,
  );
  expect(template).toMatch(/await lockWorkAdmissionHost\([\s\S]+tx\.sandboxTemplate\.create\(/);
  const reserve = admission.slice(
    admission.indexOf("export async function reserveLiveResources"),
    admission.indexOf("async function releaseLiveResources"),
  );
  expect(reserve).toMatch(/await lockWorkAdmissionHost\([\s\S]+if \(sandbox.liveResourcesHeld\)/);
});
