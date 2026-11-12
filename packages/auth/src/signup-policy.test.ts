import { expect, it, vi } from "vitest";

const findUnique = vi.hoisted(() => vi.fn());
vi.mock("@wssp/db", () => ({ default: { appSetting: { findUnique } } }));
vi.mock("@wssp/env/server", () => ({ SIGNUP_ENABLED: false }));
const isEmailConfigured = vi.hoisted(() => vi.fn(() => true));
vi.mock("@wssp/mailer", () => ({ isEmailConfigured }));
const { getSignupEnabled } = await import("./signup-policy");
it("uses the deployment default and applies explicit signup changes without caching", async () => {
  findUnique
    .mockResolvedValueOnce(null)
    .mockResolvedValueOnce({ value: "true" })
    .mockResolvedValueOnce({ value: "false" })
    .mockResolvedValueOnce({ value: "invalid" });
  expect(await getSignupEnabled()).toBe(false);
  expect(await getSignupEnabled()).toBe(true);
  expect(await getSignupEnabled()).toBe(false);
  expect(await getSignupEnabled()).toBe(false);
  expect(findUnique).toHaveBeenCalledWith({
    where: { key: "signupEnabled" },
    select: { value: true },
  });
});

it("does not let a stored override enable signup once email delivery is gone", async () => {
  isEmailConfigured.mockReturnValue(false);
  findUnique.mockResolvedValueOnce({ value: "true" }).mockResolvedValueOnce({ value: "false" });
  expect(await getSignupEnabled()).toBe(false);
  expect(await getSignupEnabled()).toBe(false);
  isEmailConfigured.mockReturnValue(true);
});
