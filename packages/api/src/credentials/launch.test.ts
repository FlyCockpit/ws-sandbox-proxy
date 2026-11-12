import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));

type Entry = { name: string; proxy?: { baseUrlEnv: string; placeholderEnv?: string } };
const state = vi.hoisted(() => ({
  defaults: [] as [string, string][],
  logins: {} as Record<string, { env?: Entry[]; paths?: string[] }>,
}));
vi.mock("../sandbox/execution-config", () => ({
  loadExecutionConfig: async () => (state.defaults.length === 0 ? null : { env: state.defaults }),
}));
vi.mock("./verified-login", () => ({
  loadVerifiedLogin: async (_tx: unknown, id: string) => {
    const login = state.logins[id];
    if (!login) return null;
    return {
      credentialId: id,
      definition: {
        credentials: {
          env: login.env ?? [],
          files: { required: login.paths ?? [], optional: [], exclude: [] },
        },
      },
    };
  },
}));

const { requireDisjointAttachmentSet } = await import("./launch");

const check = (credentialIds: string[]) =>
  requireDisjointAttachmentSet({} as never, {
    ownerId: "owner",
    sandboxId: "sandbox",
    credentialIds,
  }).then(
    () => "ok",
    (error: unknown) => {
      const data = (error as { data?: { code?: string; reason?: string } }).data;
      return data?.reason ? `${data.code}:${data.reason}` : data?.code;
    },
  );

/**
 * final-1: the set admission the claim gate runs for create, resume and live
 * attach (and re-pin): env names disjoint from the private defaults and from
 * each other (proxy names included), the env union bounded, paths disjoint.
 */
describe("requireDisjointAttachmentSet", () => {
  it("refuses an env name shared with the sandbox's private defaults", async () => {
    state.defaults = [["TOOL_TOKEN", "x"]];
    state.logins = { a: { env: [{ name: "TOOL_TOKEN" }], paths: [".a"] } };
    expect(await check(["a"])).toBe("credential.env_conflict");
    state.defaults = [["OTHER", "x"]];
    expect(await check(["a"])).toBe("ok");
  });

  it("refuses a proxy name shared between two logins", async () => {
    state.defaults = [];
    state.logins = {
      a: { env: [{ name: "A", proxy: { baseUrlEnv: "BASE_URL" } }], paths: [".a"] },
      b: { env: [{ name: "B", proxy: { baseUrlEnv: "BASE_URL" } }], paths: [".b"] },
    };
    expect(await check(["a", "b"])).toBe("credential.env_conflict");
  });

  it("refuses overlapping paths in either order, accepts disjoint ones", async () => {
    state.defaults = [];
    state.logins = {
      a: { paths: [".config/tool"] },
      b: { paths: [".config/tool/sub"] },
      c: { paths: [".config/toolbox"] },
    };
    expect(await check(["a", "b"])).toBe("credential.path_conflict");
    expect(await check(["b", "a"])).toBe("credential.path_conflict");
    expect(await check(["a", "c"])).toBe("ok");
  });

  it("bounds the env union, private defaults included", async () => {
    const { ENV_LIMITS } = await import("@wssp/sandbox-contracts");
    state.defaults = Array.from(
      { length: ENV_LIMITS.maxEntries },
      (_, n) => [`D${n}`, "x"] as [string, string],
    );
    state.logins = { a: { env: [{ name: "EXTRA" }], paths: [".a"] } };
    expect(await check(["a"])).toBe("credential.env_conflict:env_limit");
  });

  it("a corrupt definition refuses the set", async () => {
    state.defaults = [];
    state.logins = {};
    expect(await check(["gone"])).toBe("credential.definition_corrupt");
  });
});
