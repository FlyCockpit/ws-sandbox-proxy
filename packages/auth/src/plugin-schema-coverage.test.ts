import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

/**
 * M7-S12 regression class: better-auth's two-factor plugin wrote a column the
 * Prisma `TwoFactor` model lacked, so enrollment returned 500 while every gate
 * stayed green. This test asks the CONFIGURED auth instance (core tables plus
 * every enabled plugin: admin, two-factor, device-authorization, and anything
 * added later) for the schema Better Auth reads and writes, and fails when a
 * model or field is missing from the Prisma schema, has an incompatible type,
 * or is required in Prisma where Better Auth may omit it.
 */

const db = vi.hoisted(() => ({ oauthResource: [], oauthClientResource: [] }));
vi.mock("@wssp/db", () => ({ default: { $extends: () => ({}) } }));
vi.mock("@wssp/env/shared", () => ({ env: { DATABASE_POOL_MAX: 10 } }));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "plugin-schema-coverage-secret-at-least-32-chars",
    NODE_ENV: "test",
    MCP_ENABLED: true,
  },
  ADMIN_EMAILS: new Set(),
  SIGNUP_ENABLED: true,
}));
vi.mock("@wssp/mailer", () => ({
  // Email configured, so the optional email-OTP branch of the two-factor
  // plugin is part of the checked configuration too.
  isEmailConfigured: () => true,
  renderResetPassword: vi.fn(),
  renderTwoFactorOtp: vi.fn(),
  renderVerifyEmail: vi.fn(),
  sendEmail: vi.fn(),
}));
vi.mock("better-auth/adapters/prisma", async () => ({ prismaAdapter: () => memoryAdapter(db) }));
const { memoryAdapter } = await import("better-auth/adapters/memory");
const { getSchema } = await import("better-auth/db");
const { auth, passwordPepper } = await import("./index");

it("uses the password pepper in the configured auth context", async () => {
  const password = (await auth.$context).password;
  expect(password.hash).toBe(passwordPepper.hash);
  expect(password.verify).toBe(passwordPepper.verify);
});

type PrismaField = { type: string; optional: boolean; list: boolean; hasDefault: boolean };

const SCHEMA_DIR = join(fileURLToPath(new URL(".", import.meta.url)), "../../db/prisma/schema");

/** Model name → scalar fields, parsed from every `*.prisma` file. */
function parsePrismaModels(source: string): Map<string, Map<string, PrismaField>> {
  const models = new Map<string, Map<string, PrismaField>>();
  for (const match of source.matchAll(/^model\s+(\w+)\s*\{([\s\S]*?)^\}/gm)) {
    const fields = new Map<string, PrismaField>();
    for (const raw of (match[2] ?? "").split("\n")) {
      const line = raw.replace(/\/\/.*$/, "").trim();
      const field = /^(\w+)\s+(\w+)(\[\])?(\?)?(.*)$/.exec(line);
      if (!field || line.startsWith("@@")) continue;
      const [, name, type, list, optional, rest] = field;
      fields.set(name as string, {
        type: type as string,
        optional: optional === "?",
        list: list === "[]",
        hasDefault: /@default\(|@updatedAt/.test(rest ?? ""),
      });
    }
    models.set(match[1] as string, fields);
  }
  return models;
}

function prismaSource(): string {
  return readdirSync(SCHEMA_DIR)
    .filter((file) => file.endsWith(".prisma"))
    .map((file) => readFileSync(join(SCHEMA_DIR, file), "utf8"))
    .join("\n");
}

const COMPATIBLE: Record<string, string[]> = {
  string: ["String"],
  number: ["Int", "BigInt", "Float", "Decimal"],
  boolean: ["Boolean"],
  date: ["DateTime"],
  json: ["Json"],
};

type AuthField = {
  type: unknown;
  required?: boolean;
  defaultValue?: unknown;
  fieldName?: string;
};

/** Every mismatch between Better Auth's configured schema and the Prisma models. */
function schemaMismatches(
  authSchema: Record<string, { fields: Record<string, AuthField> }>,
  models: Map<string, Map<string, PrismaField>>,
): string[] {
  const problems: string[] = [];
  for (const [modelName, table] of Object.entries(authSchema)) {
    // The Prisma adapter resolves `modelName` as the client delegate, which is
    // the Prisma model name with a lowercase first letter.
    const prismaName = [...models.keys()].find(
      (name) => name.charAt(0).toLowerCase() + name.slice(1) === modelName,
    );
    if (!prismaName) {
      problems.push(`model ${modelName}: no Prisma model`);
      continue;
    }
    const fields = models.get(prismaName) as Map<string, PrismaField>;
    for (const [key, spec] of Object.entries(table.fields)) {
      const name = spec.fieldName ?? key;
      const field = fields.get(name);
      if (!field) {
        problems.push(`${prismaName}.${name}: missing (Better Auth declares ${String(spec.type)})`);
        continue;
      }
      const type = String(spec.type);
      const list = type.endsWith("[]");
      const base = list ? type.slice(0, -2) : type;
      const allowed = COMPATIBLE[base];
      // OAuth allowedScopes is a nullable JSON array: Prisma cannot model nullable scalar lists.
      const jsonArray = list && field.type === "Json" && !field.list;
      if (allowed && !jsonArray && (!allowed.includes(field.type) || field.list !== list))
        problems.push(
          `${prismaName}.${name}: Prisma ${field.type}${field.list ? "[]" : ""} vs Better Auth ${type}`,
        );
      const mayBeOmitted = spec.required === false && spec.defaultValue === undefined;
      // Prisma scalar lists may be omitted (empty array on read), unlike required scalars.
      if (mayBeOmitted && !field.optional && !field.hasDefault && !field.list)
        problems.push(`${prismaName}.${name}: required in Prisma but optional in Better Auth`);
    }
  }
  return problems;
}

describe("Better Auth plugin schema coverage", () => {
  it("keeps every field the configured auth instance and its plugins use in the Prisma schema", () => {
    const authSchema = getSchema(auth.options) as Record<
      string,
      { fields: Record<string, AuthField> }
    >;
    // Guard against a vacuous pass: the enabled plugins' tables are present.
    expect(Object.keys(authSchema)).toEqual(
      expect.arrayContaining([
        "user",
        "session",
        "account",
        "verification",
        "twoFactor",
        "deviceCode",
        "oauthClient",
        "oauthResource",
        "oauthClientResource",
        "oauthRefreshToken",
        "oauthAccessToken",
        "oauthConsent",
        "oauthClientAssertion",
        "jwks",
      ]),
    );
    expect(Object.keys(authSchema.twoFactor?.fields ?? {})).toEqual(
      expect.arrayContaining(["failedVerificationCount", "lockedUntil"]),
    );
    expect(schemaMismatches(authSchema, parsePrismaModels(prismaSource()))).toEqual([]);
  });

  it("reports a field Better Auth writes that the Prisma model lacks", () => {
    const models = parsePrismaModels(`model TwoFactor {
  id     String @id
  secret String
}
`);
    expect(
      schemaMismatches(
        {
          twoFactor: {
            fields: {
              secret: { type: "string", required: true },
              failedVerificationCount: { type: "number", required: false, defaultValue: 0 },
            },
          },
          deviceCode: { fields: {} },
        },
        models,
      ),
    ).toEqual([
      "TwoFactor.failedVerificationCount: missing (Better Auth declares number)",
      "model deviceCode: no Prisma model",
    ]);
  });
});
