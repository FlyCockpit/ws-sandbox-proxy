import { type LoginDefinition, parseLoginDefinition } from "@wssp/login-definition";
import {
  CREDENTIAL_SPEC_MAX_BYTES,
  credentialSpecV11Schema,
  parseCredentialSpec,
} from "@wssp/sandbox-contracts";
import { describe, expect, it } from "vitest";
import {
  assertDefinitionSpecContribution,
  encodeCredentialSpec,
  SPEC_LEASE_ENTRY_MAX_BYTES,
  SPEC_RESIDUE_ENTRY_MAX_BYTES,
  specLeaseEntry,
} from "./specs";

function definition(document: unknown): LoginDefinition {
  const parsed = parseLoginDefinition(document);
  if (!parsed.success) throw new Error(JSON.stringify(parsed.error));
  return parsed.definition;
}

const GUEST = definition({
  schemaVersion: 1,
  id: "tool",
  displayName: "Tool",
  login: { command: "tool login", method: "device-code" },
  credentials: {
    files: { required: [".config/tool"], optional: [".tool.json"], exclude: [] },
    env: [{ name: "TOOL_PROFILE", required: false }],
    rotates: "yes",
  },
});

const PROXY = definition({
  schemaVersion: 1,
  id: "api",
  displayName: "API",
  login: { command: "true", method: "paste" },
  credentials: {
    env: [
      {
        name: "API_KEY",
        required: true,
        proxy: {
          upstream: "https://api.example.com/v1",
          header: "Authorization",
          format: "Bearer {value}",
          baseUrlEnv: "API_BASE_URL",
        },
      },
    ],
    sharing: "shareable",
  },
});

const base = {
  leaseId: "lease-1",
  credentialId: "cred-1",
  instanceId: "inst-1",
  definitionDigest: "a".repeat(64),
  exclusive: true,
  kind: "WORKLOAD" as const,
  action: "inject" as const,
};

describe("credential specs", () => {
  it("builds lease entries the wire schema and parser accept, guest and proxy", () => {
    const guest = specLeaseEntry({
      ...base,
      definition: GUEST,
      delivery: "GUEST",
      copyBack: true,
      checkpointIntervalMin: 30,
    });
    const proxy = specLeaseEntry({
      ...base,
      leaseId: "lease-2",
      credentialId: "cred-2",
      definition: PROXY,
      delivery: "PROXY",
      copyBack: false,
      exclusive: false,
    });
    expect(guest).toMatchObject({
      delivery: "guest",
      rotates: "yes",
      env: ["TOOL_PROFILE"],
      proxy: [],
    });
    expect(proxy.proxy).toEqual([
      {
        name: "API_KEY",
        upstream: "https://api.example.com/v1",
        header: "Authorization",
        format: "Bearer {value}",
        baseUrlEnv: "API_BASE_URL",
      },
    ]);
    const spec = {
      version: 1 as const,
      sandboxId: "sbx-1",
      sandboxOwnerId: "owner-1",
      hostOwnerId: "owner-1",
      leases: [guest, proxy],
      residue: [
        {
          residueId: "res-1",
          bindingId: "bind-0",
          leaseId: "lease-0",
          action: "scrub" as const,
          paths: [".config/tool"],
        },
      ],
    };
    expect(credentialSpecV11Schema.safeParse(spec).success).toBe(true);
    const encoded = encodeCredentialSpec(spec);
    expect(parseCredentialSpec(encoded.bytes)).toEqual(spec);
    expect(encoded.digestHex).toMatch(/^[0-9a-f]{64}$/);
    // Canonical: the same spec always encodes to the same bytes.
    expect(Buffer.from(encodeCredentialSpec(spec).bytes).equals(Buffer.from(encoded.bytes))).toBe(
      true,
    );
  });

  it("an ordinary definition passes the contribution check", () => {
    expect(() => assertDefinitionSpecContribution(GUEST)).not.toThrow();
    expect(() => assertDefinitionSpecContribution(PROXY)).not.toThrow();
  });

  it("refuses definition.spec_too_large when the escaped residue or lease entry would exceed its bound", () => {
    // Control bytes escape to six JSON bytes each: 64 paths × 255 of them
    // measure ~98 KB per residue entry, far over the 18 432-byte bound.
    const heavy = "\u0001".repeat(255);
    const paths = Array.from({ length: 64 }, (_, i) => `${i}${heavy}`.slice(0, 255));
    const synthetic = {
      ...GUEST,
      credentials: { ...GUEST.credentials, files: { required: paths, optional: [], exclude: [] } },
    } as LoginDefinition;
    expect(() => assertDefinitionSpecContribution(synthetic)).toThrow(
      expect.objectContaining({
        data: expect.objectContaining({ code: "definition.spec_too_large" }),
      }),
    );
    expect(SPEC_RESIDUE_ENTRY_MAX_BYTES).toBeLessThan(SPEC_LEASE_ENTRY_MAX_BYTES);
    // 8 leases + 16 residue rows at their bounds fit the one spec cap.
    expect(
      8 * SPEC_LEASE_ENTRY_MAX_BYTES + 16 * SPEC_RESIDUE_ENTRY_MAX_BYTES + 1024,
    ).toBeLessThanOrEqual(CREDENTIAL_SPEC_MAX_BYTES);
  });
});
