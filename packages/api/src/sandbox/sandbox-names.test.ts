import { isValidSandboxName } from "@wssp/sandbox-contracts";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));

const {
  assertSandboxNameFree,
  isSandboxNameViolation,
  pickFreeSandboxName,
  resolveCreateSandboxName,
  SANDBOX_NAME_ADJECTIVES,
  SANDBOX_NAME_NOUNS,
  sandboxNameRandom,
} = await import("./sandbox-names");

/** A transaction whose live-name lookup answers from `taken`. */
function txWith(taken: Iterable<string>) {
  const names = new Set(taken);
  const findMany = vi.fn(async (args: { where: { name: { in: string[] } }; take: number }) =>
    args.where.name.in.filter((name) => names.has(name)).map((name) => ({ name })),
  );
  return { tx: { sandbox: { findMany } } as never, findMany };
}

/** A seeded RNG: a simple LCG, deterministic per seed. */
function seeded(seed: number) {
  let state = seed >>> 0;
  return (max: number) => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state % max;
  };
}

afterEach(() => vi.restoreAllMocks());

describe("word lists", () => {
  it("are 128 unique lowercase ASCII words each, and every pair is a valid name", () => {
    for (const list of [SANDBOX_NAME_ADJECTIVES, SANDBOX_NAME_NOUNS]) {
      expect(list).toHaveLength(128);
      expect(new Set(list).size).toBe(list.length);
      for (const word of list) expect(word).toMatch(/^[a-z]+$/);
    }
    for (const adjective of SANDBOX_NAME_ADJECTIVES)
      expect(isValidSandboxName(`${adjective}-${SANDBOX_NAME_NOUNS[0]}-zzzz`)).toBe(true);
  });
});

describe("pickFreeSandboxName", () => {
  it("returns the first free of 8 candidates after one owner-scoped live lookup", async () => {
    vi.spyOn(sandboxNameRandom, "int").mockImplementation(seeded(7));
    const { tx, findMany } = txWith([]);
    const name = await pickFreeSandboxName(tx, "owner");
    expect(name).toMatch(/^[a-z]+-[a-z]+$/);
    expect(findMany).toHaveBeenCalledTimes(1);
    const args = findMany.mock.calls[0]![0] as unknown as {
      where: Record<string, unknown> & { name: { in: string[] } };
      take: number;
    };
    expect(args.where).toMatchObject({
      userId: "owner",
      state: { not: "DELETED" },
      purpose: "WORKLOAD",
    });
    expect(args.where.name.in.length).toBeLessThanOrEqual(8);
    expect(args.where.name.in[0]).toBe(name);
    expect(args.take).toBe(args.where.name.in.length);
  });

  it("skips taken candidates", async () => {
    vi.spyOn(sandboxNameRandom, "int").mockImplementation(seeded(7));
    const first = await pickFreeSandboxName(txWith([]).tx, "owner");
    vi.spyOn(sandboxNameRandom, "int").mockImplementation(seeded(7));
    const second = await pickFreeSandboxName(txWith([first]).tx, "owner");
    expect(second).not.toBe(first);
    expect(second).toMatch(/^[a-z]+-[a-z]+$/);
  });

  it("falls back to a -xxxx suffix when every plain candidate is taken", async () => {
    // Index 0 every time: every plain candidate is the same taken name.
    vi.spyOn(sandboxNameRandom, "int").mockReturnValue(0);
    const plain = `${SANDBOX_NAME_ADJECTIVES[0]}-${SANDBOX_NAME_NOUNS[0]}`;
    const { tx, findMany } = txWith([plain]);
    const name = await pickFreeSandboxName(tx, "owner");
    expect(name).toBe(`${plain}-0000`);
    expect(findMany).toHaveBeenCalledTimes(2);
  });

  it("fails with sandbox.name_taken after the plain round and 3 suffix rounds", async () => {
    vi.spyOn(sandboxNameRandom, "int").mockReturnValue(0);
    const plain = `${SANDBOX_NAME_ADJECTIVES[0]}-${SANDBOX_NAME_NOUNS[0]}`;
    const { tx, findMany } = txWith([plain, `${plain}-0000`]);
    await expect(pickFreeSandboxName(tx, "owner")).rejects.toMatchObject({
      code: "CONFLICT",
      data: { code: "sandbox.name_taken" },
    });
    expect(findMany).toHaveBeenCalledTimes(4);
  });
});

describe("assertSandboxNameFree / resolveCreateSandboxName", () => {
  it("refuses an invalid name before any lookup, never transforming it", async () => {
    const { tx, findMany } = txWith([]);
    await expect(assertSandboxNameFree(tx, "owner", "Bad_Name")).rejects.toMatchObject({
      data: { code: "sandbox.name_invalid" },
    });
    expect(findMany).not.toHaveBeenCalled();
  });

  it("refuses a taken name and excludes the renamed sandbox itself", async () => {
    const { tx, findMany } = txWith(["quiet-otter"]);
    await expect(assertSandboxNameFree(tx, "owner", "quiet-otter")).rejects.toMatchObject({
      data: { code: "sandbox.name_taken" },
    });
    await expect(assertSandboxNameFree(tx, "owner", "brisk-heron", "sbx")).resolves.toBe(undefined);
    expect(findMany.mock.calls[1]![0]).toMatchObject({ where: { id: { not: "sbx" } } });
  });

  it("keeps an explicit free name and generates one when omitted", async () => {
    vi.spyOn(sandboxNameRandom, "int").mockImplementation(seeded(3));
    const { tx } = txWith([]);
    await expect(resolveCreateSandboxName(tx, "owner", "ci-runner")).resolves.toBe("ci-runner");
    await expect(resolveCreateSandboxName(tx, "owner", undefined)).resolves.toMatch(
      /^[a-z]+-[a-z]+$/,
    );
  });
});

describe("isSandboxNameViolation", () => {
  const p2002 = (meta: unknown) => Object.assign(new Error("unique"), { code: "P2002", meta });
  it.each([
    { target: "sandbox_instance_owner_live_name" },
    { target: ["userId", "name"] },
    { target: ["name", "userId"] },
    {
      driverAdapterError: { cause: { constraint: { index: "sandbox_instance_owner_live_name" } } },
    },
    { driverAdapterError: { cause: { constraint: { fields: ["userId", "name"] } } } },
    // The Prisma 7 adapter's real shape (sandbox-name.pg.test.ts).
    { driverAdapterError: { cause: { constraint: { fields: ['"userId"', "name"] } } } },
  ])("maps the name index %j", (meta) => {
    expect(isSandboxNameViolation(p2002(meta))).toBe(true);
  });
  it.each([
    { target: ["buildId"] },
    { target: ["currentPlacementId"] },
    { target: ["userId", "idempotencyKey"] },
    { target: ["userId", "name", "x"] },
    { driverAdapterError: { cause: { constraint: { fields: ["buildId"] } } } },
    { driverAdapterError: { cause: { constraint: { index: "sandbox_instance_buildId_key" } } } },
    null,
  ])("ignores another unique %j", (meta) => {
    expect(isSandboxNameViolation(p2002(meta))).toBe(false);
  });
  it("ignores a non-P2002 error", () => {
    expect(
      isSandboxNameViolation(
        Object.assign(new Error("fk"), {
          code: "P2003",
          meta: { target: "sandbox_instance_owner_live_name" },
        }),
      ),
    ).toBe(false);
  });
});
