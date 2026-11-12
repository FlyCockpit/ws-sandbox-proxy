import { sandboxDiskSchema } from "@wssp/sandbox-contracts";
import { describe, expect, it } from "vitest";
import { OFFLOADABLE_SANDBOX_PURPOSES } from "../managed-sandbox";
import {
  DISK_VIEW_OFFLOADABLE_PURPOSES,
  type SandboxDiskFacts,
  sandboxDiskDto,
  sandboxDiskSelect,
} from "./disk-view";

const STORED_AT = new Date("2026-11-06T12:00:00.000Z");

function facts(overrides: Partial<SandboxDiskFacts> = {}): SandboxDiskFacts {
  return {
    state: "STOPPED",
    generation: 4,
    purpose: "WORKLOAD",
    diskOffloadId: null,
    cachedOffloadSeq: null,
    offloadPin: "ANY",
    credentialFilesEver: false,
    DiskOffloads: [],
    SandboxTemplateRevision: { Template: { imagePlacement: "INHERIT" } },
    User: { ImagePolicy: null },
    ...overrides,
  };
}

const stored = (state = "STORED") => ({
  id: "off-2",
  seq: 2,
  state,
  sourceGeneration: 4,
  storedAt: STORED_AT,
  sizeBytes: 5_368_709_120n,
  failureCode: null,
});

describe("sandboxDiskDto (offload plan §1, C8)", () => {
  it("mirrors the managed-purpose policy", () => {
    expect([...DISK_VIEW_OFFLOADABLE_PURPOSES].sort()).toEqual(
      [...OFFLOADABLE_SANDBOX_PURPOSES].sort(),
    );
  });

  it("a stopped disk with no offload is on its host", () => {
    const dto = sandboxDiskDto(facts());
    expect(sandboxDiskSchema.parse(dto)).toEqual(dto);
    expect(dto).toEqual({
      location: "host",
      offloadState: "none",
      offloadFailure: null,
      offloadedAt: null,
      sizeBytes: null,
      eligibility: "any_host",
      offloadPin: "ANY",
    });
  });

  it("an in-flight upload is still host-only, with its phase", () => {
    const dto = sandboxDiskDto(
      facts({ DiskOffloads: [{ ...stored("UPLOADING"), storedAt: null, sizeBytes: null }] }),
    );
    expect(dto).toMatchObject({ location: "host", offloadState: "uploading", sizeBytes: null });
  });

  it("a stored copy that the host still caches is host_and_store", () => {
    const dto = sandboxDiskDto(
      facts({ diskOffloadId: "off-2", cachedOffloadSeq: 2, DiskOffloads: [stored()] }),
    );
    expect(dto).toMatchObject({
      location: "host_and_store",
      offloadState: "stored",
      offloadedAt: STORED_AT.toISOString(),
      sizeBytes: 5_368_709_120,
    });
  });

  it("OFFLOADED, or a restore still fetching, is store", () => {
    expect(
      sandboxDiskDto(
        facts({ state: "OFFLOADED", diskOffloadId: "off-2", DiskOffloads: [stored()] }),
      ),
    ).toMatchObject({ location: "store", offloadState: "stored" });
    expect(
      sandboxDiskDto(
        facts({ state: "PROVISIONING", diskOffloadId: "off-2", DiskOffloads: [stored()] }),
      ),
    ).toMatchObject({ location: "store" });
    expect(
      sandboxDiskDto(
        facts({ diskOffloadId: "off-2", cachedOffloadSeq: 2, DiskOffloads: [stored("EVICTING")] }),
      ),
    ).toMatchObject({ location: "host_and_store", offloadState: "evicting" });
  });

  it("a failed offload of the current disk names only public failure codes", () => {
    const failed = (failureCode: string, sourceGeneration = 4) =>
      sandboxDiskDto(
        facts({ DiskOffloads: [{ ...stored("FAILED"), failureCode, sourceGeneration }] }),
      );
    expect(failed("quota_exceeded")).toMatchObject({
      location: "host",
      offloadState: "failed",
      offloadFailure: "quota_exceeded",
      offloadedAt: null,
      sizeBytes: null,
    });
    expect(failed("corrupt")).toMatchObject({ offloadFailure: "other" });
    // An older generation's failure says nothing about this disk.
    expect(failed("quota_exceeded", 3)).toMatchObject({
      offloadState: "none",
      offloadFailure: null,
    });
    // A consumed copy (the sandbox started) is no current offload.
    expect(
      sandboxDiskDto(facts({ state: "READY", DiskOffloads: [stored("CONSUMED")] })),
    ).toMatchObject({ location: "host", offloadState: "none" });
  });

  it("has no disk while waiting for capacity or deleted", () => {
    expect(sandboxDiskDto(facts({ state: "WAITING_FOR_CAPACITY" }))).toBeNull();
    expect(sandboxDiskDto(facts({ state: "DELETED" }))).toBeNull();
  });

  it("eligibility: pin, login history and owned-only placement narrow it; managed is never", () => {
    expect(sandboxDiskDto(facts({ offloadPin: "OWN_HOSTS" }))).toMatchObject({
      eligibility: "own_hosts",
      offloadPin: "OWN_HOSTS",
    });
    expect(sandboxDiskDto(facts({ credentialFilesEver: true }))?.eligibility).toBe("own_hosts");
    expect(
      sandboxDiskDto(
        facts({ SandboxTemplateRevision: { Template: { imagePlacement: "OWNED_NODES_ONLY" } } }),
      )?.eligibility,
    ).toBe("own_hosts");
    expect(
      sandboxDiskDto(facts({ User: { ImagePolicy: { imagePlacement: "OWNED_NODES_ONLY" } } }))
        ?.eligibility,
    ).toBe("own_hosts");
    // A template's explicit ANY_NODE overrides the account policy.
    expect(
      sandboxDiskDto(
        facts({
          SandboxTemplateRevision: { Template: { imagePlacement: "ANY_NODE" } },
          User: { ImagePolicy: { imagePlacement: "OWNED_NODES_ONLY" } },
        }),
      )?.eligibility,
    ).toBe("any_host");
    expect(sandboxDiskDto(facts({ purpose: "TEMPLATE_BUILD" }))?.eligibility).toBe("never");
  });

  it("never selects key material, object keys, fingerprints or the source host", () => {
    const offload = JSON.stringify(sandboxDiskSelect.DiskOffloads.select);
    for (const forbidden of [
      "objectKey",
      "wrappedKey",
      "fingerprint",
      "rootKid",
      "sourceHostId",
      "completedSessionId",
    ])
      expect(offload).not.toContain(forbidden);
  });
});
