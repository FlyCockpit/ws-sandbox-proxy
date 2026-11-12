import { expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("../../api/src/test/mock-prisma");
  return { default: await createMockPrisma() };
});
const { createTerminalAuthHooks } = await import("./terminal-hooks");
const a = { user: { id: "a" }, session: { id: "a-session" } };
const b = { user: { id: "b" }, session: { id: "b-session" } };
it.each([
  [a, null],
  [null, a],
  [a, b],
  [a, { ...a, session: { id: "other" } }],
])(
  "independent cached/durable disagreement refuses both oracle paths before DB/verifier",
  async (cached, durable) => {
    for (const path of ["/two-factor/verify-totp", "/two-factor/get-totp-uri"]) {
      const resolve = vi.fn().mockResolvedValueOnce(cached).mockResolvedValueOnce(durable);
      const hooks = createTerminalAuthHooks(resolve);
      await expect(
        hooks.before({
          path,
          headers: new Headers({ cookie: "better-auth.session_token=present" }),
          context: {},
          body: { code: "123456" },
        } as never),
      ).rejects.toMatchObject({ status: "UNAUTHORIZED" });
      expect(resolve.mock.calls.map((call) => call[1])).toEqual([false, true]);
      expect(resolve.mock.calls[0]![0]).not.toBe(resolve.mock.calls[1]![0]);
    }
  },
);
it("dual session lookup failure refuses without a challenge fallback", async () => {
  const hooks = createTerminalAuthHooks(vi.fn().mockRejectedValue(new Error("unavailable")));
  await expect(
    hooks.before({ path: "/two-factor/verify-totp", headers: new Headers(), context: {} } as never),
  ).rejects.toMatchObject({ status: "UNAUTHORIZED" });
});
