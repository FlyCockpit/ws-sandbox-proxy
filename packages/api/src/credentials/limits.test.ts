import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import protocolLimits from "../../../config/src/credential-protocol-limits.json";

const envState = vi.hoisted(() => ({}) as { CREDENTIAL_MAX_INSTANCES_PER_OWNER?: number | null });
vi.mock("@wssp/env/server", () => ({ env: envState }));

const { CREDENTIAL_LIMITS, maxInstancesPerOwner } = await import("./limits");

describe("credential limits", () => {
  it("the schema CHECK equals the one spec cap in credential-protocol-limits.json", () => {
    const schema = readFileSync(
      new URL("../../../db/prisma/schema/credential.prisma", import.meta.url),
      "utf8",
    );
    // Single source: credential-protocol-limits.json (lane B); the CHECK pins it.
    expect(schema).toContain(`octet_length("bytes") <= ${protocolLimits.specMaxBytes}`);
    expect(CREDENTIAL_LIMITS).not.toHaveProperty("credentialSpecMaxBytes");
  });

  it("instance cap: default when unset, null for unlimited, configured otherwise", () => {
    expect(maxInstancesPerOwner()).toBe(1000);
    envState.CREDENTIAL_MAX_INSTANCES_PER_OWNER = null;
    expect(maxInstancesPerOwner()).toBeNull();
    envState.CREDENTIAL_MAX_INSTANCES_PER_OWNER = 5;
    expect(maxInstancesPerOwner()).toBe(5);
  });
});
