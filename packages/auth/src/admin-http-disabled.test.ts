import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { admin } from "better-auth/plugins";
import { expect, it } from "vitest";
import { DISABLED_BETTER_AUTH_PATHS } from "./host-device-login-scope";

it("disables every mounted admin HTTP endpoint before library side effects while retaining server invites", async () => {
  const db: Record<string, Record<string, unknown>[]> = {
    user: [],
    session: [],
    account: [],
    verification: [],
  };
  const auth = betterAuth({
    baseURL: "http://localhost:3000",
    secret: "admin-http-disabled-test-secret-at-least-32-chars",
    database: memoryAdapter(db),
    plugins: [admin()],
    disabledPaths: [...DISABLED_BETTER_AUTH_PATHS],
  });
  for (const endpoint of Object.values(admin().endpoints)) {
    for (const method of ["GET", "POST"]) {
      const response = await auth.handler(
        new Request(`http://localhost:3000/api/auth${endpoint.path}`, { method }),
      );
      expect(response.status, `${method} ${endpoint.path}`).toBe(404);
    }
  }
  expect(db.user).toHaveLength(0);
  expect(db.session).toHaveLength(0);
  const created = await auth.api.createUser({
    body: {
      email: "invited@example.test",
      name: "Invited",
      password: "test-invite-password-only",
      role: "user",
    },
  });
  expect(created.user.email).toBe("invited@example.test");
  expect(db.user).toHaveLength(1);
  expect(db.session).toHaveLength(0);
});
