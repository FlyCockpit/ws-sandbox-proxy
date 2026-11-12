import { expect, it, vi } from "vitest";

// A non-default declaration: the harness must follow it, not a copied literal.
vi.mock("@wssp/env/vars/shared", () => ({
  sharedVars: {
    DATABASE_POOL_MAX: { parse: (value: unknown) => (value === undefined ? 37 : value) },
  },
}));

it("the harness pool size is the production DATABASE_POOL_MAX default, read from its declaration", async () => {
  const { PRODUCTION_DEFAULT_POOL_MAX } = await import("./pg");
  expect(PRODUCTION_DEFAULT_POOL_MAX).toBe(37);
});

const CONTAINER = "wssp-test-pg-0b5e7c1a-2f4d-4e8a-9c3b-1d2e3f4a5b6c";
const CLONE = "wssp_t_0123456789abcdef0123456789abcdef";
const ADMIN = "postgresql://postgres:pw@127.0.0.1:41234/postgres";

it("the per-file drop refuses any target but a clone this process made on the harness container", async () => {
  const { dropRefusal } = await import("./pg");
  const created = new Set([CLONE]);
  const ok = { adminUrl: ADMIN, container: `${CONTAINER}:41234`, clone: CLONE, created };
  expect(dropRefusal(ok)).toBeUndefined();
  for (const [change, reason] of [
    [{ container: "wssp-dev-postgres:41234" }, /not one `pnpm test:pg` started/],
    [{ container: CONTAINER }, /not one `pnpm test:pg` started/],
    [{ adminUrl: "postgresql://postgres:pw@db.example.com:41234/postgres" }, /loopback/],
    [{ adminUrl: "postgresql://postgres:pw@localhost:41234/postgres" }, /loopback/],
    [{ adminUrl: "postgresql://postgres:pw@127.0.0.1:5432/postgres" }, /loopback/],
    [{ adminUrl: "not a url" }, /does not parse/],
    [{ clone: "wssp_pg_template" }, /not a per-file clone/],
    [{ clone: "postgres" }, /not a per-file clone/],
    [{ clone: `${CLONE}_upgrade_1` }, /not a per-file clone/],
    [{ created: new Set<string>() }, /did not create that clone/],
  ] as const) {
    expect(dropRefusal({ ...ok, ...change }), JSON.stringify(change)).toMatch(reason);
  }
});
