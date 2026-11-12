import type { Prisma, SandboxState } from "@wssp/db";
import type {
  SandboxDiskDto,
  SandboxDiskOffloadFailure,
  SandboxDiskOffloadStateDto,
} from "@wssp/sandbox-contracts";

/**
 * The owner-facing disk projection: where the root disk
 * lives, the current offload attempt or stored copy, and which hosts may
 * restore it. Shared by the `/v1` DTO (`public-dto.ts`), the dashboard view
 * and the webhook renderer. Type-only imports: the external worker renders
 * through this module too.
 *
 * Disclosure boundary: only the newest offload's state, sequence, generation,
 * stored time, plaintext size and failure code are read; never its object
 * key, wrap columns, fingerprint or source host.
 */
export const sandboxDiskSelect = {
  state: true,
  generation: true,
  purpose: true,
  diskOffloadId: true,
  cachedOffloadSeq: true,
  offloadPin: true,
  credentialFilesEver: true,
  // The newest attempt. A live offload (at most one per sandbox, its seq the
  // highest) is always the newest, so this is the live one when any exists.
  DiskOffloads: {
    orderBy: { seq: "desc" },
    take: 1,
    select: {
      id: true,
      seq: true,
      state: true,
      sourceGeneration: true,
      storedAt: true,
      sizeBytes: true,
      failureCode: true,
    },
  },
  SandboxTemplateRevision: {
    select: { Template: { select: { imagePlacement: true } } },
  },
  User: { select: { ImagePolicy: { select: { imagePlacement: true } } } },
} satisfies Prisma.SandboxSelect;

export type SandboxDiskFacts = {
  state: SandboxState;
  generation: number;
  purpose: string;
  diskOffloadId: string | null;
  cachedOffloadSeq: number | null;
  offloadPin: "ANY" | "OWN_HOSTS";
  credentialFilesEver: boolean;
  DiskOffloads: {
    id: string;
    seq: number;
    state: string;
    sourceGeneration: number;
    storedAt: Date | null;
    sizeBytes: bigint | null;
    failureCode: string | null;
  }[];
  SandboxTemplateRevision: { Template: { imagePlacement: string } };
  User: { ImagePolicy: { imagePlacement: string } | null };
};

/** Mirrors `OFFLOADABLE_SANDBOX_PURPOSES` (managed-sandbox.ts; asserted in disk-view.test.ts). */
export const DISK_VIEW_OFFLOADABLE_PURPOSES: readonly string[] = ["WORKLOAD"];

const LIVE_STATE: Readonly<Record<string, SandboxDiskOffloadStateDto>> = {
  PENDING: "pending",
  EXPORTING: "exporting",
  UPLOADING: "uploading",
  VERIFYING: "verifying",
  STORED: "stored",
  EVICTING: "evicting",
};

const PUBLIC_FAILURES: ReadonlySet<string> = new Set<SandboxDiskOffloadFailure>([
  "quota_exceeded",
  "size_exceeded",
  "staging_full",
]);

function failureOf(code: string | null): SandboxDiskOffloadFailure {
  return code !== null && PUBLIC_FAILURES.has(code) ? (code as SandboxDiskOffloadFailure) : "other";
}

/** Null while the sandbox has no disk (a create waiting for capacity, or deleted). */
export function sandboxDiskDto(row: SandboxDiskFacts): SandboxDiskDto | null {
  if (row.state === "WAITING_FOR_CAPACITY" || row.state === "DELETED") return null;
  const latest = row.DiskOffloads[0] ?? null;
  const current = latest && row.diskOffloadId === latest.id ? latest : null;
  const location =
    row.state === "OFFLOADED"
      ? "store"
      : current
        ? row.cachedOffloadSeq === current.seq
          ? "host_and_store"
          : // A restore still fetching the stored disk onto its new host.
            "store"
        : "host";
  const live =
    latest && Object.hasOwn(LIVE_STATE, latest.state) ? LIVE_STATE[latest.state] : undefined;
  const failed =
    !live &&
    latest?.state === "FAILED" &&
    latest.sourceGeneration === row.generation &&
    row.state === "STOPPED";
  const placement =
    row.SandboxTemplateRevision.Template.imagePlacement === "INHERIT"
      ? (row.User.ImagePolicy?.imagePlacement ?? "ANY_NODE")
      : row.SandboxTemplateRevision.Template.imagePlacement;
  const eligibility = !DISK_VIEW_OFFLOADABLE_PURPOSES.includes(row.purpose)
    ? "never"
    : row.offloadPin === "OWN_HOSTS" || row.credentialFilesEver || placement !== "ANY_NODE"
      ? "own_hosts"
      : "any_host";
  return {
    location,
    offloadState: live ?? (failed ? "failed" : "none"),
    offloadFailure: failed ? failureOf(latest?.failureCode ?? null) : null,
    offloadedAt: current?.storedAt ? current.storedAt.toISOString() : null,
    sizeBytes: current?.sizeBytes != null ? Number(current.sizeBytes) : null,
    eligibility,
    offloadPin: row.offloadPin,
  };
}
