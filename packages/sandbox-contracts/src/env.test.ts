import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  canonicalEnvJson,
  commandPayloadBytes,
  defaultEnvSchema,
  ENV_LIMITS,
  envSchema,
} from "./env";
import { commandBodySchema } from "./mutations";

type Case = {
  name: string;
  pairs: { key: string; unit: string; repeat: number; tail: string }[];
  bytes: number;
  valid: boolean;
};
const cases: Case[] = JSON.parse(
  readFileSync(
    new URL("../../../crates/sandbox-protocol/fixtures/env_cases.json", import.meta.url),
    "utf8",
  ),
);

describe("command envs", () => {
  it("rejects an empty command name but preserves empty arguments", () => {
    for (const schema of [commandBodySchema]) {
      const parsed = schema.safeParse({ argv: [""] });
      expect(parsed.success).toBe(false);
      if (!parsed.success) expect(parsed.error.issues[0]?.message).toBe("sandbox.command_invalid");
      expect(schema.safeParse({ argv: ["printf", ""] }).success).toBe(true);
    }
  });
  it("preserves the host's UTF-16 argv bound for supplementary characters", () => {
    expect(commandBodySchema.safeParse({ argv: ["😀".repeat(256)] }).success).toBe(true);
    expect(commandBodySchema.safeParse({ argv: ["😀".repeat(257)] }).success).toBe(false);
  });
  it("env_limits_ts_rust_parity", () => {
    for (const fixture of cases) {
      const pairs = fixture.pairs.map((p) => [p.key, p.unit.repeat(p.repeat) + p.tail]);
      const envs = Object.fromEntries(pairs);
      const unique = new Set(pairs.map(([k]) => k)).size === pairs.length;
      expect(new TextEncoder().encode(canonicalEnvJson(envs)).byteLength, fixture.name).toBe(
        fixture.bytes,
      );
      expect(unique && envSchema.safeParse(envs).success, fixture.name).toBe(fixture.valid);
    }
  });
  it("maximal_contract_env_passes_frame_encoder", () => {
    for (const fixture of cases.filter((c) => c.name.startsWith("maximal-"))) {
      const envs = Object.fromEntries(
        fixture.pairs.map((p) => [p.key, p.unit.repeat(p.repeat) + p.tail]),
      );
      expect(fixture.bytes).toBe(ENV_LIMITS.jsonBytes);
      expect(commandBodySchema.safeParse({ argv: ["true"], envs }).success).toBe(true);
      expect(commandPayloadBytes({ argv: ["true"], envs })).toBeLessThanOrEqual(32768);
    }
  });
  it("rejects legacy tuples, malformed Unicode and reserved stored defaults", () => {
    for (const body of [{ env: [] }, { envs: [["K", "v"]] }, { envs: { A: "\ud800" } }]) {
      expect(commandBodySchema.safeParse({ argv: ["true"], ...body }).success).toBe(false);
    }
    for (const key of ["HOME", "SHELL", "TERM"]) {
      expect(
        commandBodySchema.safeParse({ argv: ["true"], envs: { [key]: "override" } }).success,
      ).toBe(true);
      expect(defaultEnvSchema.safeParse({ [key]: "override" }).success).toBe(false);
    }
  });
  it("manifest-only CLI CI trigger coverage", () => {
    const workflow = readFileSync(
      new URL("../../../.github/workflows/cli-ci.yml", import.meta.url),
      "utf8",
    );
    for (const path of [
      "packages/sandbox-contracts/src/env-limits.json",
      "packages/config/src/*.json",
    ]) {
      expect(workflow.split(`- "${path}"`)).toHaveLength(3);
    }
  });
});
