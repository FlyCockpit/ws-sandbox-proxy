import { randomUUID } from "node:crypto";

import { afterAll, expect, it } from "vitest";
import { hasActiveAdministrator } from "./admin-governance";
import { pgTestDatabase } from "./testing/pg";

const db = await pgTestDatabase();
afterAll(() => db.close());

type UserFields = {
  role?: string;
  emailVerified?: boolean;
  banned?: boolean | null;
  banExpires?: Date | null;
  deletionRequestedAt?: Date | null;
};

async function seed(fields: UserFields) {
  const id = randomUUID();
  await db.inspect.user.create({
    data: { id, name: "User", email: `${id}@example.test`, emailVerified: true, ...fields },
  });
  return id;
}

it("reports an administrator only when an ACTIVE admin exists (M7-S14 setup-hint condition)", async () => {
  // Nobody at all, then only people who cannot use the admin area.
  expect(await hasActiveAdministrator(db.prisma)).toBe(false);
  await seed({ role: "user" });
  await seed({ role: "administrator,editor" });
  await seed({ role: "admin", emailVerified: false });
  await seed({ role: "admin", banned: true, banExpires: null });
  await seed({ role: "admin", banned: true, banExpires: new Date(Date.now() + 3_600_000) });
  await seed({ role: "admin", deletionRequestedAt: new Date() });
  expect(await hasActiveAdministrator(db.prisma)).toBe(false);

  // An expired ban no longer disqualifies; multi-role tokens match like parseRoles.
  const expired = await seed({
    role: "admin",
    banned: true,
    banExpires: new Date(Date.now() - 1_000),
  });
  expect(await hasActiveAdministrator(db.prisma)).toBe(true);
  await db.inspect.user.delete({ where: { id: expired } });
  expect(await hasActiveAdministrator(db.prisma)).toBe(false);

  await seed({ role: "editor, ADMIN﻿, billing" });
  expect(await hasActiveAdministrator(db.prisma)).toBe(true);
});
