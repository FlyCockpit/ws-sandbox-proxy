import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));

const {
  assertManagedSandboxAccess,
  guardManagedSandboxTarget,
  LISTED_SANDBOX_PURPOSES,
  MANAGED_PURPOSE_POLICY,
  managedSandboxListFilter,
} = await import("./managed-sandbox");
const { SERVICE_ACTIONS, SERVICE_ACTION_REQUIREMENTS } = await import("../lib/service-scopes");

const session = { kind: "session", ownerId: "owner" } as const;
const key = { kind: "sdkKey", ownerId: "owner" } as never;

describe("MS0 managed-sandbox policy", () => {
  it("WORKLOAD admits every action for every principal", () => {
    for (const action of SERVICE_ACTIONS) {
      expect(() =>
        assertManagedSandboxAccess(session, action, { purpose: "WORKLOAD" }),
      ).not.toThrow();
      expect(() => assertManagedSandboxAccess(key, action, { purpose: "WORKLOAD" })).not.toThrow();
    }
  });

  it("only WORKLOAD is listed and emits webhooks", () => {
    expect(LISTED_SANDBOX_PURPOSES).toEqual(["WORKLOAD"]);
    expect(managedSandboxListFilter()).toEqual({ purpose: { in: ["WORKLOAD"] } });
    for (const [purpose, policy] of Object.entries(MANAGED_PURPOSE_POLICY))
      expect(policy.webhooks, purpose).toBe(purpose === "WORKLOAD");
  });

  it("CREDENTIAL_LOGIN refuses every SDK action and every session mutation", () => {
    const sessionAllowed = new Set(["sandboxes.get", "operations.get", "terminal.open"]);
    for (const action of [
      ...SERVICE_ACTIONS,
      "terminal.open",
      "credentials.attach",
      "credentials.free",
      "sharing",
      "env.private",
    ] as const) {
      expect(() =>
        assertManagedSandboxAccess(key, action, { purpose: "CREDENTIAL_LOGIN" }),
      ).toThrow(/managed by wssp/);
      const call = () =>
        assertManagedSandboxAccess(session, action, { purpose: "CREDENTIAL_LOGIN" });
      if (sessionAllowed.has(action)) expect(call, action).not.toThrow();
      else expect(call, action).toThrow(/managed by wssp/);
    }
  });

  it("CREDENTIAL_LOGIN admits the login flow's own lifecycle actions to its flow principal only", () => {
    const flow = { kind: "session", ownerId: "owner", flow: "credentialLogin" } as const;
    const flowAllowed = new Set([
      "sandboxes.get",
      "operations.get",
      "terminal.open",
      "sandboxCredentials.free",
      "commands.run",
      "sandboxes.kill",
    ]);
    for (const action of [...SERVICE_ACTIONS, "terminal.open", "sharing", "env.private"] as const) {
      const call = () => assertManagedSandboxAccess(flow, action, { purpose: "CREDENTIAL_LOGIN" });
      if (flowAllowed.has(action)) expect(call, action).not.toThrow();
      else expect(call, action).toThrow(/managed by wssp/);
    }
    // The flow principal gains nothing on other managed purposes.
    expect(() =>
      assertManagedSandboxAccess(flow, "sandboxes.kill", { purpose: "TEMPLATE_BUILD" }),
    ).toThrow(/managed by wssp/);
  });

  it("TEMPLATE_BUILD admits owner metadata reads and only the matching build principal", () => {
    const vm = { purpose: "TEMPLATE_BUILD" as const, buildId: "build-1" };
    const build = { kind: "build", ownerId: "owner", buildId: "build-1", keyId: null } as never;
    const otherBuild = {
      kind: "build",
      ownerId: "owner",
      buildId: "build-2",
      keyId: null,
    } as never;
    const buildAllowed = new Set([
      "sandboxes.createIntent",
      "sandboxes.create",
      "commands.run",
      "files.write",
      "sandboxes.setTimeout",
      "sandboxes.capture",
      "sandboxes.stop",
      "sandboxes.kill",
      "sandboxes.get",
      "sandboxes.replayCreate",
      "operations.get",
      "operations.getReceipt",
      "operations.getCommandResult",
      "operations.getCommandOutput",
      "operations.getFileMutationResult",
    ]);
    for (const action of SERVICE_ACTIONS) {
      const metadata = action === "sandboxes.get" || action === "operations.get";
      for (const principal of [session, key, otherBuild]) {
        const call = () => assertManagedSandboxAccess(principal, action, vm);
        if (metadata) expect(call, action).not.toThrow();
        else expect(call, action).toThrow(/managed by wssp/);
      }
      const own = () => assertManagedSandboxAccess(build, action, vm);
      if (buildAllowed.has(action)) expect(own, action).not.toThrow();
      else expect(own, action).toThrow(/managed by wssp/);
      // A build VM without a recorded build id admits no build principal.
      if (!metadata)
        expect(() =>
          assertManagedSandboxAccess(build, action, { purpose: "TEMPLATE_BUILD" }),
        ).toThrow(/managed by wssp/);
    }
    for (const action of ["terminal.open", "credentials.attach", "sharing", "env.private"] as const)
      for (const principal of [session, build])
        expect(() => assertManagedSandboxAccess(principal, action, vm)).toThrow(/managed by wssp/);
  });

  it("reads the VM's build id with its purpose", async () => {
    const queryRaw = vi.fn().mockResolvedValue([{ purpose: "TEMPLATE_BUILD", buildId: "build-1" }]);
    const client = { $queryRaw: queryRaw } as never;
    const build = { kind: "build", ownerId: "owner", buildId: "build-1", keyId: null } as never;
    await expect(
      guardManagedSandboxTarget(client, build, "commands.run", { sandboxId: "sbx" }),
    ).resolves.toBeUndefined();
    await expect(
      guardManagedSandboxTarget(client, key, "commands.run", { sandboxId: "sbx" }),
    ).rejects.toThrow(/managed by wssp/);
  });

  it("refusal carries the stable code and the purpose", () => {
    try {
      assertManagedSandboxAccess(key, "commands.run", { purpose: "TEMPLATE_BUILD" });
      expect.unreachable();
    } catch (error) {
      expect((error as { data: unknown }).data).toEqual({
        code: "sandbox.managed",
        purpose: "template_build",
      });
    }
  });

  it("resolves sandbox and operation targets to the owner's managed sandbox", async () => {
    const queryRaw = vi.fn().mockResolvedValue([{ purpose: "CREDENTIAL_LOGIN" }]);
    const client = { $queryRaw: queryRaw } as never;
    await expect(
      guardManagedSandboxTarget(client, key, "files.read", { sandboxId: "sbx" }),
    ).rejects.toThrow(/managed by wssp/);
    const sql = (call: unknown[]) => (call[0] as string[]).join("?");
    expect(sql(queryRaw.mock.calls.at(-1)!)).toMatch(/FROM sandbox_instance s WHERE s.id = \?/);
    expect(queryRaw.mock.calls.at(-1)!.slice(1)).toEqual(["sbx", "owner"]);
    // Every operation-targeted action resolves through the operation's sandbox.
    for (const action of SERVICE_ACTIONS.filter(
      (name) => SERVICE_ACTION_REQUIREMENTS[name].requiresSandbox && name.startsWith("operations."),
    )) {
      if (action === "operations.get") continue;
      await expect(
        guardManagedSandboxTarget(client, key, action, { operationId: "op" }),
      ).rejects.toThrow(/managed by wssp/);
    }
    expect(sql(queryRaw.mock.calls.at(-1)!)).toMatch(
      /JOIN sandbox_instance s ON s.id = o."sandboxId"/,
    );
    expect(queryRaw.mock.calls.at(-1)!.slice(1)).toEqual(["op", "owner"]);
    // WORKLOAD, missing and foreign targets return no row: no oracle, no refusal.
    queryRaw.mockClear();
    await guardManagedSandboxTarget(client, key, "sandboxes.list", {});
    expect(queryRaw).not.toHaveBeenCalled();
    queryRaw.mockResolvedValueOnce([]);
    await expect(
      guardManagedSandboxTarget(client, key, "files.read", { sandboxId: "missing" }),
    ).resolves.toBeUndefined();
  });
});

describe("TEMPLATE_VERIFY (community-base I4b, review4 U3, U10)", () => {
  const vm = { purpose: "TEMPLATE_VERIFY" as const, verifyBuildId: "build-1" };
  const build = { kind: "build", ownerId: "owner", buildId: "build-1", keyId: null } as never;
  const other = { kind: "build", ownerId: "owner", buildId: "build-2", keyId: null } as never;

  it("is hidden and emits no webhooks", () => {
    expect(MANAGED_PURPOSE_POLICY.TEMPLATE_VERIFY.listed).toBe(false);
    expect(MANAGED_PURPOSE_POLICY.TEMPLATE_VERIFY.webhooks).toBe(false);
  });

  it("owner sessions and keys get metadata reads only", () => {
    for (const principal of [session, key]) {
      for (const action of ["sandboxes.get", "operations.get"] as const)
        expect(() => assertManagedSandboxAccess(principal, action, vm)).not.toThrow();
      for (const action of [
        "commands.run",
        "files.write",
        "files.read",
        "processes.signal",
        "terminal.open",
        "sandboxes.kill",
      ] as const)
        expect(() => assertManagedSandboxAccess(principal, action, vm)).toThrow(/managed/);
    }
  });

  it("its build principal gets the verify steps, cleanup and reads; nothing else", () => {
    for (const action of [
      "commands.run",
      "sandboxes.kill",
      "sandboxes.stop",
      "sandboxes.replayCreate",
      "operations.getCommandResult",
    ] as const)
      expect(() => assertManagedSandboxAccess(build, action, vm)).not.toThrow();
    for (const action of [
      "files.write",
      "files.read",
      "sandboxes.capture",
      "sandboxes.setTimeout",
      "sandboxes.reconnect",
      "processes.signal",
      "terminal.open",
    ] as const)
      expect(() => assertManagedSandboxAccess(build, action, vm)).toThrow(/managed/);
    expect(() => assertManagedSandboxAccess(other, "commands.run", vm)).toThrow(/managed/);
    // A build VM's binding never admits the verify VM, and vice versa.
    expect(() =>
      assertManagedSandboxAccess(build, "commands.run", {
        purpose: "TEMPLATE_VERIFY",
        buildId: "build-1",
      }),
    ).toThrow(/managed/);
  });
});
