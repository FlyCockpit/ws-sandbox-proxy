import { isDeepStrictEqual } from "node:util";
import { maskBit } from "@wssp/api/sandbox/command-output";
import { sessionPrincipal } from "@wssp/api/sandbox/contracts";
import { hashRevisionDefaultsBody, requestDigestMetadata } from "@wssp/api/sandbox/idempotency";
import { attributionOf } from "@wssp/api/sandbox/principal-kinds";
import { storedAttributionOf } from "@wssp/api/sandbox/stored-principal";
import type { Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import { vmLiveMemoryChargeMiB } from "@wssp/sandbox-contracts";
import { vi } from "vitest";
import {
  digestContextSnapshot,
  ENV_FREE_DIGEST_DOMAIN,
  REQUEST_DIGEST_DOMAIN,
} from "../../../../packages/api/src/sandbox/digest-context";
import { capacityFixture } from "./capacity-fixtures";

/** Predicate-evaluating READ COMMITTED double with per-row write locks.
 * Each statement sees committed rows plus its own writes. Locks last through
 * commit/rollback; only touched rows publish atomically, so unrelated commits
 * cannot be lost. UPDATE rechecks predicates after waiting for a row lock.
 * Hooks are controlled barriers, never forced query outcomes. Not PostgreSQL. */
export type Row = Record<string, unknown> & { id: string };
export type HostRow = Row & {
  userId: string;
  connectionEpoch: number;
  daemonVcpuBudget?: number;
  liveCount?: number;
};
export type SandboxRow = Row & {
  userId: string;
  generation: number;
  state: string;
  sandboxHostId: string | null;
  liveResourcesHeld?: boolean;
  leaseRevision?: number;
  leaseExpiresAt?: Date | null;
  leaseExpireAction?: string;
};
export type OperationRow = Row & {
  userId: string;
  sandboxId: string;
  kind: string;
  state: string;
  generation: number;
  dispatchAttempt: number;
  dispatchedHostId: string | null;
  dispatchedConnectionEpoch?: number | null;
};
export type OutboxRow = Row & {
  userId: string;
  aggregateType: string;
  aggregateId: string;
  processedAt: Date | null;
  payload: Record<string, unknown>;
};
/** Outbox rows seeded by a test get the `operationId` column every production
 * writer copies from `payload.operationId`, unless the row names it itself.
 * A plain Map (non-enumerable `set`), so cloned snapshots still compare equal. */
function outboxMap(rows: [string, OutboxRow][]) {
  const map = new Map<string, OutboxRow>();
  const set = map.set.bind(map);
  Object.defineProperty(map, "set", {
    enumerable: false,
    value: (id: string, row: OutboxRow) => {
      row = {
        ...row,
        payload: {
          authorizingPrincipal: attributionOf(sessionPrincipal(row.userId)),
          ...row.payload,
        },
      };
      const operationId = row.payload?.operationId;
      return set(
        id,
        Object.hasOwn(row, "operationId") || typeof operationId !== "string"
          ? row
          : { ...row, operationId },
      );
    },
  });
  for (const [id, row] of rows) map.set(id, row);
  return map;
}
export type FenceStore = {
  hosts: Map<string, HostRow>;
  storagePools: Map<string, Row>;
  templates: Map<string, Row>;
  placements: Map<string, Row>;
  configs: Map<string, Row>;
  revisionConfigs: Map<string, Row>;
  availability: Map<string, Row>;
  imageCache: Map<string, Row>;
  credentialCensuses: Map<string, Row>;
  sandboxes: Map<string, SandboxRow>;
  operations: Map<string, OperationRow>;
  receipts: Map<string, Row>;
  outbox: Map<string, OutboxRow>;
  /** Durable command output header rows (id = operation ID) and their segments. */
  results: Map<string, Row>;
  outputs: Map<string, Row>;
  outputSegments: Map<string, Row>;
  barriers: {
    beforeHostLock?: () => Promise<void>;
    beforeSandboxLock?: () => Promise<void>;
    beforeOperationWrite?: () => Promise<void>;
    afterCommit?: () => Promise<void>;
    beforeCommit?: () => Promise<void>;
  };
  onLockWait?: (key: string) => void;
  writes: string[];
  /** Ordered raw SQL and row inserts, for lock-before-insert assertions. */
  trace: string[];
};
export function createFenceStore(init: {
  hosts?: HostRow[];
  templates?: Row[];
  sandboxes?: SandboxRow[];
  operations?: OperationRow[];
  outbox?: OutboxRow[];
}): FenceStore {
  return {
    imageCache: new Map(),
    credentialCensuses: new Map(),
    storagePools: new Map(
      (init.hosts ?? []).map((h) => [
        `storage:${h.id}`,
        {
          id: `storage:${h.id}`,
          sandboxHostId: h.id,
          userId: h.userId,
          name: "default",
          marker: "a".repeat(32),
          capacityGiB: 8192,
          diskReservedGiB:
            (init.sandboxes ?? []).filter(
              (s) => s.sandboxHostId === h.id && (s.diskReservationHeld ?? s.state === "STOPPED"),
            ).length * 33,
          health: "healthy",
          healthReason: null,
          newRootsAllowed: true,
          draining: false,
          connectionEpoch: h.connectionEpoch,
          reportedAt: new Date(),
        },
      ]),
    ),
    templates: new Map(
      (init.templates ?? []).map((r) => [
        r.id,
        {
          retiredAt: null,
          archivedAt: null,
          Template: { archivedAt: null },
          templateId: r.id,
          revision: 1,
          cpuCount: 1,
          memoryMiB: 1024,
          diskGiB: 32,
          ...r,
        },
      ]),
    ),
    placements: new Map(
      (init.sandboxes ?? []).flatMap((r) => {
        const t = init.templates?.find((t) => t.id === r.templateId) ?? {
          incusFingerprint: `sha256:${"a".repeat(64)}`,
          architecture: "x86_64",
          guestUid: 1000,
          guestGid: 1000,
          guestHome: "/home/user",
          guestShell: "/bin/bash",
        };
        return [
          [
            `placement:${r.id}`,
            {
              ...t,
              id: `placement:${r.id}`,
              sandboxId: r.id,
              userId: r.userId,
              hostOwnerId:
                r.hostOwnerId ??
                init.hosts?.find((h) => h.id === r.sandboxHostId)?.userId ??
                r.userId,
              cpuCount: r.cpuCount ?? 1,
              memoryMiB: r.memoryMiB ?? 1024,
              originHostId: r.sandboxHostId,
              diskGiB: r.diskGiB ?? 32,
              storagePoolId: `storage:${r.sandboxHostId}`,
              storagePoolName: "default",
              storageMarker: "a".repeat(32),
              rootChargeGiB: 33,
              chargedMemoryMiB: vmLiveMemoryChargeMiB(Number(r.memoryMiB ?? 1024)),
              chargedVcpu: r.cpuCount ?? 1,
              artifact: t.incusFingerprint,
              generation: r.generation ?? 1,
              Sandbox: { currentPlacementId: `placement:${r.id}` },
            },
          ],
        ];
      }),
    ),
    configs: new Map(),
    revisionConfigs: new Map(
      (init.templates ?? []).map((r) => [
        r.id,
        {
          id: r.id,
          revisionId: r.id,
          userId: r.userId,
          Revision: { userId: r.userId },
          defaultEnvs: {},
          checksum: hashRevisionDefaultsBody({ revisionId: r.id, env: [] }, String(r.userId)),
          digestScheme: requestDigestMetadata().requestDigestScheme,
          digestKeyId: requestDigestMetadata().requestDigestKeyId,
        },
      ]),
    ),
    availability: new Map(
      (init.templates ?? []).map((r) => [
        r.id,
        {
          id: r.id,
          userId: r.userId,
          hostOwnerId: init.hosts?.find((h) => h.id === r.sandboxHostId)?.userId ?? r.userId,
          revisionId: r.id,
          hostId: r.sandboxHostId,
          status: "AVAILABLE",
          localFingerprint: r.incusFingerprint,
          architecture: r.architecture,
          manifestDigest: r.manifestDigest,
          verifiedConnectionEpoch: 1,
        },
      ]),
    ),
    hosts: new Map(
      (init.hosts ?? []).map((r) => [
        r.id,
        {
          relayProtocolVersion: "1.0",
          relayProtocolEpoch: r.connectionEpoch,
          inventorySeq: 0,

          liveCount: 0,
          memoryReservedMiB: (r.liveCount ?? 0) * vmLiveMemoryChargeMiB(1024),
          vcpuReserved: r.liveCount ?? 0,
          daemonVcpuBudget: 64,
          rootCount: (init.sandboxes ?? []).filter(
            (s) => s.sandboxHostId === r.id && (s.diskReservationHeld ?? s.state === "STOPPED"),
          ).length,
          capacityReport: {
            ...capacityFixture(r.id),
            storagePools: capacityFixture(r.id).storagePools.map((pool) => ({
              ...pool,
              marker: "a".repeat(32),
            })),
          },
          daemonMemoryBudgetMiB: 65536,
          daemonMaxCpuCount: 32,
          daemonMaxLeaseMs: 86_400_000,
          deletionRequestedAt: null,
          // Harness hosts model current daemons: egress-capable unless a test
          // explicitly downgrades the capability.
          egressEnforcement: true,
          status: "CONNECTED",
          lastHeartbeatAt: new Date(),
          admissionEpoch: r.connectionEpoch,
          inventoryAcknowledgedEpoch: r.connectionEpoch,
          daemonSchedulable: true,
          admissionRuntime: "FAKE",

          daemonFeatures: { egressPolicy: true },
          // Healthy egress guard lease at this epoch (default-open egress).
          daemonEgressGuardOk: true,
          daemonEgressGuardEpoch: r.connectionEpoch,
          daemonEgressGuardLeaseUntil: new Date("2999-01-01T00:00:00.000Z"),
          daemonOpenEgressForOthers: false,
          journalKeyVersion: 1,
          journalKeyId: requestDigestMetadata().requestDigestKeyId,
          journalKeyAcknowledgedEpoch: r.connectionEpoch,
          User: {
            deletionRequestedAt: null,
            banned: false,
            banExpires: null,
            twoFactorEnabled: true,
            role: "user",
            createdAt: new Date(0),
          },
          ...r,
        },
      ]),
    ),
    sandboxes: new Map(
      (init.sandboxes ?? []).map((r) => {
        const base: SandboxRow = {
          id: r.id,
          userId: r.userId,
          hostOwnerId:
            r.hostOwnerId ?? init.hosts?.find((h) => h.id === r.sandboxHostId)?.userId ?? r.userId,
          usagePoolId: null,
          usageMemberId: null,
          accessGraceUntil: null,
          accessGraceReason: null,
          generation: 1,
          state: r.state,
          sandboxHostId: r.sandboxHostId,
          liveResourcesHeld: false,
          cpuCount: 1,
          memoryMiB: 1024,
          diskGiB: 32,
          diskReservationHeld: r.state === "STOPPED",
          storagePoolId: `storage:${r.sandboxHostId}`,
          storagePoolName: "default",
          storageMarker: "a".repeat(32),
          rootChargeGiB: 33,
          currentPlacementId: `placement:${r.id}`,
          templateRevisionId: String(r.templateId),
          originPoolId: null,
          leaseRevision: 1,
          leaseExpiresAt: null,
          leaseExpireAction: "STOP",
        };
        return [r.id, { ...base, ...r }];
      }),
    ),
    operations: new Map(
      (init.operations ?? []).map((r) => [
        r.id,
        {
          dispatchedConnectionEpoch: 1,
          authorizingKeyId: null,
          ...requestDigestMetadata(r.kind),
          digestContext: digestContextSnapshot(
            {
              domain: ["STOP_SANDBOX", "KILL_SANDBOX"].includes(r.kind)
                ? ENV_FREE_DIGEST_DOMAIN
                : REQUEST_DIGEST_DOMAIN,
              hostId: r.dispatchedHostId,
              hostOwnerId:
                init.hosts?.find((host) => host.id === r.dispatchedHostId)?.userId ?? r.userId,
            },
            { generation: r.generation },
          ),
          nextStdinSequence: 0,
          stdinClosed: false,
          resultVersion: r.kind === "RUN_COMMAND" ? 1 : null,
          processId: r.kind === "RUN_COMMAND" ? `proc-${r.id}` : null,
          processPid: null,
          processBootId: null,
          processStartTicks: null,
          processStartedAt: null,
          // A nullable column every row carries; the typed result store
          // compares it with NULL before its first write.
          scalarResult: null,
          acceptedAttempt: ["ACCEPTED", "RUNNING", "CANCEL_REQUESTED"].includes(r.state)
            ? r.dispatchAttempt
            : null,
          ...r,
        },
      ]),
    ),
    outbox: outboxMap(
      (init.outbox ?? []).map((r): [string, OutboxRow] => [
        r.id,
        {
          sentAt: null,
          claimToken: null,
          claimedAt: null,
          sentConnectionEpoch: null,
          ...r,
          payload: {
            authorizingPrincipal: (() => {
              const keyId = init.operations?.find(
                (operation) => operation.id === r.payload.operationId,
              )?.authorizingKeyId;
              return storedAttributionOf({
                userId: r.userId,
                authorizingKeyId: typeof keyId === "string" ? keyId : null,
                sandboxBuildId: null,
                sandboxVerifyBuildId: null,
              });
            })(),
            idempotencyKey:
              init.operations?.find((operation) => operation.id === r.payload.operationId)
                ?.idempotencyKey ?? r.payload.operationId,
            ...r.payload,
          },
        },
      ]),
    ),
    receipts: new Map(),
    results: new Map(),
    outputs: new Map(),
    outputSegments: new Map(),
    barriers: {},
    writes: [],
    trace: [],
  };
}

/** Committed durable output of one operation, reassembled per stream. */
export function storedCommandOutput(store: FenceStore, operationId: string) {
  const header = store.outputs.get(operationId);
  if (!header) return undefined;
  const segments = [...store.outputSegments.values()]
    .filter((row) => row.outputId === operationId)
    .sort((a, b) => Number(a.startOffset) - Number(b.startOffset));
  const streams = { stdout: [] as number[], stderr: [] as number[] };
  let retained = 0;
  for (const segment of segments) {
    const bytes = segment.bytes as Uint8Array;
    retained += bytes.length;
    for (let i = 0; i < bytes.length; i++)
      (maskBit(segment.stderrMask as Uint8Array, i) ? streams.stderr : streams.stdout).push(
        bytes[i]!,
      );
  }
  return {
    retained,
    segments: segments.length,
    receivedEnd: Number(header.receivedEnd),
    totalBytes: header.totalBytes == null ? null : Number(header.totalBytes),
    stdout: Buffer.from(streams.stdout),
    stderr: Buffer.from(streams.stderr),
  };
}
export function matches(row: Row, where: Record<string, unknown> = {}): boolean {
  return Object.entries(where).every(([key, value]) => {
    if (value && typeof value === "object" && !Array.isArray(value) && "some" in value) {
      return (
        Array.isArray(row[key]) &&
        row[key].some((r: Row) => matches(r, (value as { some: Record<string, unknown> }).some))
      );
    }
    if (value && typeof value === "object" && "is" in value) {
      return value.is === null
        ? row[key] == null
        : row[key] != null && matches(row[key] as Row, value.is as Record<string, unknown>);
    }
    if (key === "userId_idempotencyKey") return matches(row, value as Record<string, unknown>);
    if (key === "NOT") return !matches(row, value as Record<string, unknown>);
    if (key === "OR" || key === "AND") {
      const clauses = value as Record<string, unknown>[];
      return key === "OR"
        ? clauses.some((w) => matches(row, w))
        : clauses.every((w) => matches(row, w));
    }
    if (value && typeof value === "object" && !(value instanceof Date)) {
      if ("equals" in value && !("path" in value)) return isDeepStrictEqual(row[key], value.equals);
      // An absent fake column is SQL NULL (`{ not: null }` excludes it).
      if ("not" in value) return (row[key] ?? null) !== value.not;
      if ("in" in value) return (value.in as unknown[]).includes(row[key]);
      // String keyset ranges (`id: { gt, lte }`) compare lexicographically.
      if (typeof row[key] === "string" && "lte" in value && "gt" in value)
        return String(row[key]) > String(value.gt) && String(row[key]) <= String(value.lte);
      if (typeof row[key] === "string" && "lte" in value)
        return String(row[key]) <= String(value.lte);
      if ("path" in value && "gte" in value) {
        let found: unknown = row[key];
        for (const part of value.path as string[])
          found = (found as Record<string, unknown>)?.[part];
        return found != null && value.gte != null && Number(found) >= Number(value.gte);
      }
      if ("gte" in value)
        return row[key] != null && value.gte != null && Number(row[key]) >= Number(value.gte);
      if ("lte" in value)
        return row[key] != null && value.lte != null && Number(row[key]) <= Number(value.lte);
      if ("lt" in value && !("path" in value))
        return row[key] != null && value.lt != null && Number(row[key]) < Number(value.lt);
      if ("gt" in value)
        return (
          row[key] != null &&
          value.gt != null &&
          (typeof row[key] === "number" || row[key] instanceof Date
            ? Number(row[key]) > Number(value.gt)
            : String(row[key]) > String(value.gt))
        );
      if ("path" in value && "lt" in value) {
        let found: unknown = row[key];
        for (const part of value.path as string[])
          found = (found as Record<string, unknown>)?.[part];
        return found != null && value.lt != null && Number(found) < Number(value.lt);
      }
      if ("path" in value && "equals" in value) {
        let found: unknown = row[key];
        for (const part of value.path as string[])
          found = (found as Record<string, unknown>)?.[part];
        return found === value.equals;
      }
    }
    if (
      value &&
      typeof value === "object" &&
      !(value instanceof Date) &&
      row[key] &&
      typeof row[key] === "object"
    ) {
      return matches(row[key] as Row, value as Record<string, unknown>);
    }
    if (value instanceof Date) return Number(row[key]) === value.getTime();
    // Prisma `field: null` is IS NULL; a fixture row may omit the column.
    if (value === null) return row[key] == null;
    return row[key] === value;
  });
}
function apply(row: Row, data: Record<string, unknown>) {
  for (const [key, value] of Object.entries(data))
    row[key] =
      value === PrismaValue.DbNull
        ? null
        : value && typeof value === "object" && "increment" in value
          ? Number(row[key]) + Number(value.increment)
          : value && typeof value === "object" && "decrement" in value
            ? Number(row[key]) - Number(value.decrement)
            : value;
}

export function installFenceTransaction(
  db: {
    $transaction: ReturnType<typeof vi.fn>;
    sandboxOperation?: { findFirst: ReturnType<typeof vi.fn> };
    sandboxActionReceipt?: { findUnique: ReturnType<typeof vi.fn> };
    sandboxTemplateAvailability?: { findMany: ReturnType<typeof vi.fn> };
    sandbox?: { findFirst: ReturnType<typeof vi.fn>; findMany?: ReturnType<typeof vi.fn> };
  },
  store: FenceStore,
) {
  db.sandboxTemplateAvailability?.findMany.mockImplementation(() =>
    prismaPromise(Promise.resolve([])),
  );
  // Preflight reads occur outside write transactions and must evaluate the
  // same predicates. This remains a unit double; PG proves real arbitration.
  db.sandboxOperation?.findFirst.mockImplementation((args: { where?: Record<string, unknown> }) =>
    prismaPromise(
      Promise.resolve(
        [...store.operations.values()].find((row) =>
          matches({ ...row, Sandbox: store.sandboxes.get(row.sandboxId) }, args?.where),
        ) ?? null,
      ),
    ),
  );
  db.sandbox?.findMany?.mockImplementation(
    (args: {
      where?: Record<string, unknown>;
      take: number;
      select?: { Operations?: { where?: Record<string, unknown>; take: number } };
    }) =>
      prismaPromise(
        Promise.resolve(
          [...store.sandboxes.values()]
            .map((row) => ({
              ...row,
              CurrentPlacement: store.placements.get(String(row.currentPlacementId)) ?? null,
              Operations: [...store.operations.values()].filter((op) => op.sandboxId === row.id),
            }))
            .filter((row) => matches(row, args.where))
            .sort((a, b) => a.id.localeCompare(b.id))
            .slice(0, args.take)
            .map((row) =>
              args.select?.Operations
                ? {
                    ...row,
                    Operations: row.Operations.filter((op) =>
                      matches(op, args.select?.Operations?.where),
                    )
                      .sort((a, b) => b.generation - a.generation)
                      .slice(0, args.select.Operations.take),
                  }
                : row,
            ),
        ),
      ),
  );
  db.sandbox?.findFirst.mockImplementation((args: { where?: Record<string, unknown> }) =>
    prismaPromise(
      Promise.resolve(
        [...store.sandboxes.values()]
          .map((row) => ({
            ...row,
            SandboxHost: store.hosts.get(String(row.sandboxHostId)) ?? null,
            CurrentPlacement: store.placements.get(String(row.currentPlacementId)) ?? null,
          }))
          .find((row) => matches(row, args?.where)) ?? null,
      ),
    ),
  );
  db.sandboxActionReceipt?.findUnique.mockImplementation(
    (args: { where?: Record<string, unknown> }) =>
      prismaPromise(
        Promise.resolve(
          [...store.receipts.values()].find((row) => matches(row, args?.where)) ?? null,
        ),
      ),
  );
  type Model =
    | "receipts"
    | "hosts"
    | "storagePools"
    | "templates"
    | "placements"
    | "configs"
    | "revisionConfigs"
    | "availability"
    | "imageCache"
    | "credentialCensuses"
    | "sandboxes"
    | "operations"
    | "outbox"
    | "results"
    | "outputs"
    | "outputSegments";
  const tails = new Map<string, Promise<void>>();
  let nextId = 0;
  db.$transaction.mockImplementation(async (work: (tx: unknown) => Promise<unknown>) => {
    const pending = new Map<Model, Map<string, Row>>();
    const removed = new Map<Model, Set<string>>();
    const releases = new Map<string, () => void>();
    async function lock(name: Model, id: string) {
      const key = `${name}:${id}`;
      if (releases.has(key)) return;
      const previous = tails.get(key);
      if (previous) store.onLockWait?.(key);
      let release!: () => void;
      const tail = new Promise<void>((resolve) => {
        release = resolve;
      });
      tails.set(key, tail);
      await previous;
      releases.set(key, () => {
        release();
        if (tails.get(key) === tail) tails.delete(key);
      });
    }
    function releaseLocks() {
      for (const release of releases.values()) release();
      releases.clear();
    }
    function stage(name: Model, row: Row) {
      let rows = pending.get(name);
      if (!rows) {
        rows = new Map();
        pending.set(name, rows);
      }
      rows.set(row.id, row);
    }
    function model(name: Model) {
      const rows = () =>
        new Map<string, Row>(
          [...store[name], ...(pending.get(name) ?? [])]
            .filter(([id]) => !removed.get(name)?.has(id))
            .map(([id, row]) => [
              id,
              name === "operations"
                ? {
                    authorizingKeyId: null,
                    processPid: null,
                    ...row,
                    Sandbox:
                      pending.get("sandboxes")?.get(String(row.sandboxId)) ??
                      store.sandboxes.get(String(row.sandboxId)),
                  }
                : name === "placements"
                  ? {
                      ...row,
                      Sandbox:
                        pending.get("sandboxes")?.get(String(row.sandboxId)) ??
                        store.sandboxes.get(String(row.sandboxId)),
                    }
                  : name === "sandboxes"
                    ? {
                        ...row,
                        SandboxHost:
                          pending.get("hosts")?.get(String(row.sandboxHostId)) ??
                          store.hosts.get(String(row.sandboxHostId)) ??
                          null,
                        CurrentPlacement:
                          pending.get("placements")?.get(String(row.currentPlacementId)) ??
                          store.placements.get(String(row.currentPlacementId)) ??
                          null,
                      }
                    : name === "configs"
                      ? {
                          ...row,
                          Sandbox: (() => {
                            const sandbox =
                              pending.get("sandboxes")?.get(String(row.sandboxId)) ??
                              store.sandboxes.get(String(row.sandboxId));
                            return sandbox
                              ? {
                                  ...sandbox,
                                  CurrentPlacement:
                                    pending
                                      .get("placements")
                                      ?.get(String(sandbox.currentPlacementId)) ??
                                    store.placements.get(String(sandbox.currentPlacementId)) ??
                                    null,
                                  SandboxHost:
                                    pending.get("hosts")?.get(String(sandbox.sandboxHostId)) ??
                                    store.hosts.get(String(sandbox.sandboxHostId)) ??
                                    null,
                                }
                              : null;
                          })(),
                        }
                      : row,
            ]),
        );
      async function beforeWrite() {
        if (name === "hosts") await store.barriers.beforeHostLock?.();
        if (name === "sandboxes") await store.barriers.beforeSandboxLock?.();
        if (name === "operations") await store.barriers.beforeOperationWrite?.();
        store.writes.push(name);
      }
      async function updateRows(where: Record<string, unknown>, data: Record<string, unknown>) {
        await beforeWrite();
        const changed: Row[] = [];
        for (const candidate of rows().values()) {
          if (!matches(candidate, where)) continue;
          await lock(name, candidate.id);
          const current = rows().get(candidate.id);
          if (!current || !matches(current, where)) continue;
          const row = structuredClone(current);
          delete row.CurrentPlacement;
          delete row.SandboxHost;
          apply(row, data);
          stage(name, row);
          changed.push(row);
        }
        return changed;
      }
      return {
        deleteMany: async ({ where }: { where: Record<string, unknown> }) => {
          await beforeWrite();
          let count = 0;
          for (const candidate of rows().values()) {
            if (!matches(candidate, where)) continue;
            await lock(name, candidate.id);
            const current = rows().get(candidate.id);
            if (!current || !matches(current, where)) continue;
            if (
              name === "hosts" &&
              // This transaction's view: its own staged detach overrides the committed row.
              [...new Map([...store.sandboxes, ...(pending.get("sandboxes") ?? [])]).values()].some(
                (row) => row.sandboxHostId === candidate.id,
              )
            ) {
              throw Object.assign(new Error("Sandbox placement FK restrict"), { code: "P2003" });
            }
            let ids = removed.get(name);
            if (!ids) {
              ids = new Set();
              removed.set(name, ids);
            }
            ids.add(candidate.id);
            count++;
          }
          return { count };
        },
        findMany: async ({ where, take }: { where?: Record<string, unknown>; take: number }) =>
          structuredClone(
            [...rows().values()]
              .filter((r) =>
                matches(
                  name === "sandboxes"
                    ? {
                        ...r,
                        Operations: [
                          ...new Map([
                            ...store.operations,
                            ...(pending.get("operations") ?? []),
                          ]).values(),
                        ].filter((op) => op.sandboxId === r.id),
                      }
                    : r,
                  where,
                ),
              )
              .sort((a, b) => a.id.localeCompare(b.id))
              .slice(0, take),
          ),
        findFirst: async ({
          where,
          orderBy,
        }: {
          where?: Record<string, unknown>;
          orderBy?: Record<string, "asc" | "desc">;
        }) => {
          const found = [...rows().values()].filter((r) =>
            matches(
              name === "sandboxes"
                ? {
                    ...r,
                    Operations: [
                      ...new Map([
                        ...store.operations,
                        ...(pending.get("operations") ?? []),
                      ]).values(),
                    ].filter((op) => op.sandboxId === r.id),
                    SandboxTemplate:
                      pending.get("templates")?.get(String(r.templateId)) ??
                      store.templates.get(String(r.templateId)),
                  }
                : name === "operations"
                  ? {
                      ...r,
                      Sandbox:
                        pending.get("sandboxes")?.get(String(r.sandboxId)) ??
                        store.sandboxes.get(String(r.sandboxId)),
                    }
                  : r,
              where,
            ),
          );
          if (orderBy)
            for (const [key, direction] of Object.entries(orderBy)) {
              // Number() orders numeric, bigint and Date keys alike.
              found.sort(
                (a, b) => (Number(a[key]) - Number(b[key])) * (direction === "desc" ? -1 : 1),
              );
            }
          const row = found[0];
          return structuredClone(
            row && name === "operations"
              ? {
                  ...row,
                  Sandbox:
                    pending.get("sandboxes")?.get(String(row.sandboxId)) ??
                    store.sandboxes.get(String(row.sandboxId)),
                }
              : (row ?? null),
          );
        },
        findFirstOrThrow: async ({ where }: { where: Record<string, unknown> }) => {
          const row = [...rows().values()].find((r) => matches(r, where));
          if (!row) throw new Error(`Missing ${name}`);
          return structuredClone(row);
        },
        findUnique: async ({ where }: { where: Record<string, unknown> }) =>
          structuredClone([...rows().values()].find((r) => matches(r, where)) ?? null),
        updateMany: async ({
          where,
          data,
        }: {
          where: Record<string, unknown>;
          data: Record<string, unknown>;
        }) => {
          const changed = await updateRows(where, data);
          return { count: changed.length };
        },
        update: async ({
          where,
          data,
        }: {
          where: Record<string, unknown>;
          data: Record<string, unknown>;
        }) => {
          const [row] = await updateRows(where, data);
          if (!row) throw new Error(`${name}: not found`);
          return structuredClone(row);
        },
        upsert: async ({
          where,
          create,
          update,
        }: {
          where:
            | { sandboxHostId_marker: { sandboxHostId: string; marker: string } }
            | { hostId: string };
          create: Row;
          update: Record<string, unknown>;
        }) => {
          const predicate = "sandboxHostId_marker" in where ? where.sandboxHostId_marker : where;
          const existing = [...rows().values()].find((r) => matches(r, predicate));
          if (existing) {
            const [row] = await updateRows({ id: existing.id }, update);
            return structuredClone(row);
          }
          return model(name).create({ data: create });
        },
        // `_sum` over the visible matching rows (the result-quota reader).
        aggregate: async ({
          where,
          _sum,
        }: {
          where?: Record<string, unknown>;
          _sum: Record<string, true>;
        }) => {
          const matched = [...rows().values()].filter((r) => matches(r, where));
          return {
            _sum: Object.fromEntries(
              Object.keys(_sum).map((key) => [
                key,
                matched.length === 0 ? null : matched.reduce((t, r) => t + Number(r[key] ?? 0), 0),
              ]),
            ),
          };
        },
        create: async ({ data }: { data: Row }) => {
          await beforeWrite();
          store.trace.push(`create:${name}`);
          if (
            name === "sandboxes" &&
            data.sandboxHostId != null &&
            (!store.hosts.has(String(data.sandboxHostId)) ||
              removed.get("hosts")?.has(String(data.sandboxHostId)))
          ) {
            throw Object.assign(new Error("Sandbox placement FK missing host"), { code: "P2003" });
          }
          if (name === "operations" && typeof data.idempotencyKey === "string") {
            // Emulate the declared owner-wide unique index, including waiting
            // for an uncommitted insert on a different sandbox/host.
            await lock(name, `unique:${data.userId}:${data.idempotencyKey}`);
            if (
              [...rows().values()].some(
                (r) => r.userId === data.userId && r.idempotencyKey === data.idempotencyKey,
              )
            ) {
              throw Object.assign(new Error("Owner idempotency key already exists"), {
                code: "P2002",
              });
            }
          }
          let id = data.id;
          while (!id || rows().has(id)) {
            if (data.id) throw new Error(`${name}: duplicate id`);
            id = `${name}-${++nextId}`;
          }
          await lock(name, id);
          const row = {
            ...(name === "storagePools"
              ? { diskReservedGiB: 0, observationSequence: 0n, healthReason: null }
              : {}),
            ...(name === "sandboxes"
              ? {
                  generation: 1,
                  leaseRevision: 1,
                  leaseExpiresAt: null,
                  leaseExpireAction: "STOP",
                  liveResourcesHeld: false,
                  diskReservationHeld: false,
                  currentPlacementId: null,
                }
              : {}),
            ...(name === "hosts"
              ? {
                  liveCount: 0,
                  memoryReservedMiB: 0,
                  vcpuReserved: 0,
                  rootCount: 0,
                  daemonVcpuBudget: 64,
                  capacityReport: null,
                  daemonMemoryBudgetMiB: 65536,
                  daemonMaxCpuCount: 32,
                }
              : {}),
            ...(["sandboxes", "placements", "templates"].includes(name)
              ? { cpuCount: 1, memoryMiB: 1024, diskGiB: 32 }
              : {}),
            ...(name === "operations"
              ? {
                  dispatchAttempt: 0,
                  acceptedAttempt: null,
                  dispatchedHostId: null,
                  dispatchedConnectionEpoch: null,
                  nextStdinSequence: 0,
                  stdinClosed: false,
                  authorizingKeyId: null,
                  ...requestDigestMetadata(String(data.kind)),
                  digestContext: digestContextSnapshot(
                    {
                      domain: ["STOP_SANDBOX", "KILL_SANDBOX"].includes(String(data.kind))
                        ? ENV_FREE_DIGEST_DOMAIN
                        : REQUEST_DIGEST_DOMAIN,
                    },
                    { generation: typeof data.generation === "number" ? data.generation : null },
                  ),
                  // Real rows always carry the column; the nullable default
                  // matters to first-write-wins completedAt filtering (C26).
                  completedAt: null,
                  // An insert reads NULL for what its writer leaves unset.
                  // Only seeded rows keep these absent unless set.
                  processId: null,
                  resultVersion: null,
                  processPid: null,
                  processBootId: null,
                  processStartTicks: null,
                  processStartedAt: null,
                  scalarResult: null,
                }
              : {}),
            ...(name === "outbox"
              ? {
                  processedAt: null,
                  sentAt: null,
                  claimToken: null,
                  claimedAt: null,
                  sentConnectionEpoch: null,
                }
              : {}),
            createdAt: new Date(),
            ...data,
            ...(name === "configs"
              ? { Sandbox: { userId: data.userId }, acknowledgedEpoch: 1 }
              : {}),
            ...(name === "operations" ? { authorizingKeyId: data.authorizingKeyId ?? null } : {}),
            id,
          };
          stage(name, row);
          return structuredClone(row);
        },
      };
    }
    try {
      const result = await work({
        $executeRaw: async (parts: TemplateStringsArray, ...values: unknown[]) => {
          const sql = parts.join("?");
          if (sql.includes("UPDATE sandbox_host h SET")) {
            const held = [...store.sandboxes.values()].filter(
              (row) =>
                row.sandboxHostId === values[0] &&
                row.userId === values[1] &&
                row.liveResourcesHeld,
            );
            const boots = held.map((row) => store.placements.get(String(row.currentPlacementId))!);
            return (
              await model("hosts").updateMany({
                where: { id: values[0], userId: values[1] },
                data: {
                  liveCount: held.length,
                  memoryReservedMiB: boots.reduce((sum, b) => sum + Number(b.chargedMemoryMiB), 0),
                  vcpuReserved: boots.reduce((sum, b) => sum + Number(b.chargedVcpu), 0),
                  rootCount: [...store.sandboxes.values()].filter(
                    (row) => row.sandboxHostId === values[0] && row.diskReservationHeld,
                  ).length,
                },
              })
            ).count;
          }
          if (sql.includes("UPDATE sandbox_host_storage_pool")) return 1;
          // This double has no credential bindings, pending captures or return
          // keys. A complete census still records its epoch below; its cleanup
          // statements affect zero rows in these empty tables.
          // Matches the intercepted pending-capture cleanup text (its WHERE
          // clause follows on the next line in production SQL).
          if (/^DELETE\s+FROM\s+credential_pending_capture\b/.test(sql.trimStart())) return 0;
          if (sql.trimStart().startsWith("UPDATE credential_host_return_key")) return 0;
          throw new Error("Unsupported executeRaw in fenced unit double");
        },
        $queryRaw: async (
          query: TemplateStringsArray | PrismaValue.Sql,
          ...templateValues: unknown[]
        ) => {
          // Tagged-template calls and composed `Prisma.sql` queries alike.
          const parts = query instanceof PrismaValue.Sql ? query.strings : query;
          const values = query instanceof PrismaValue.Sql ? query.values : templateValues;
          const sql = parts.join("?");
          store.trace.push(`sql:${sql}`);
          if (sql.includes("FROM credential_lease l")) return [];
          if (sql.includes("FROM sandbox_host") && sql.includes('"connectionEpoch" =')) {
            const where = {
              id: values[0],
              connectionEpoch: values[1],
              ...(values[2] ? { userId: values[2] } : {}),
            };
            const result = await model("hosts").updateMany({
              where,
              data: { connectionEpoch: values[1] },
            });
            return result.count === 1 ? [{ id: values[0] }] : [];
          }
          if (sql.includes("FROM sandbox_host") && sql.includes("FOR UPDATE")) {
            const result = await model("hosts").updateMany({
              where: { id: values[0], userId: values[1] },
              data: {},
            });
            return result.count === 1 ? [{ id: values[0] }] : [];
          }
          if (sql.includes("FROM sandbox_instance WHERE") && !sql.includes("generation =")) {
            await store.barriers.beforeSandboxLock?.();
            await lock("sandboxes", String(values[0]));
            return store.sandboxes.has(String(values[0])) ? [{ id: values[0] }] : [];
          }
          if (sql.includes("FROM sandbox_mutation_operation WHERE") && sql.includes("FOR UPDATE")) {
            await lock("operations", String(values[0]));
            return store.operations.has(String(values[0])) ? [{ id: values[0] }] : [];
          }
          if (sql.includes("FROM sandbox_instance WHERE") && sql.includes("generation =")) {
            const where = { id: values[0], userId: values[1], generation: values[2] };
            const result = await model("sandboxes").updateMany({
              where,
              data: { generation: values[2] },
            });
            return result.count === 1 ? [{ id: values[0] }] : [];
          }
          if (sql.includes('AS "hostMaxLeaseMs"')) {
            // Lease-path layers (lease-policy.ts readPathLayers). This double
            // has no sharing graph, so only the host and deployment layers.
            const sandbox = store.sandboxes.get(String(values[0]));
            if (!sandbox) return [];
            const host = sandbox.sandboxHostId
              ? await model("hosts").findFirst({ where: { id: sandbox.sandboxHostId } })
              : null;
            return [
              {
                userId: sandbox.userId,
                hostFound: host != null,
                hostMaxLeaseMs: host?.daemonMaxLeaseMs ?? null,
                poolId: null,
                poolOwnerId: null,
                poolMaxLeaseMs: null,
                unlimitedLeaseForShares: null,
                memberMaxLeaseMs: null,
              },
            ];
          }
          if (sql.includes("FROM sandbox_template_availability a JOIN")) {
            return model("availability").findMany({
              where: {
                revisionId: values[0],
                hostId: values[1],
                userId: values[2],
                hostOwnerId: values[3],
                status: "AVAILABLE",
                localFingerprint: values[4],
                architecture: values[5],
                manifestDigest: values[6],
              },
              take: 1,
            });
          }
          return parts.join("?").includes("clock_timestamp()") ? [{ now: new Date() }] : [];
        },
        user: {
          findUnique: async () => ({
            deletionRequestedAt: null,
            banned: false,
            banExpires: null,
            twoFactorEnabled: true,
            role: "user",
            createdAt: new Date(0),
          }),
        },
        appSetting: { findMany: async () => [] },
        sandboxHost: model("hosts"),
        sandboxHostStoragePool: model("storagePools"),
        sandboxTemplate: model("templates"),
        sandboxTemplateRevision: model("templates"),
        // This double has no sharing graph. Real graph arbitration is covered
        // by sharing-access.pg.test.ts, never inferred from these empty models.
        sandboxPool: { findMany: async () => [] },
        sandboxPoolMember: {
          findMany: async () => [],
          updateMany: async () => ({ count: 0 }),
          deleteMany: async () => ({ count: 0 }),
        },
        sandboxPlacement: model("placements"),
        sandboxTemplateAvailability: model("availability"),
        sandboxHostImageCache: model("imageCache"),
        credentialHostCensus: model("credentialCensuses"),
        sandboxRevisionConfig: model("revisionConfigs"),
        sandboxExecutionConfig: model("configs"),
        sandbox: model("sandboxes"),
        sandboxOperation: model("operations"),
        sandboxActionReceipt: model("receipts"),
        sandboxTransfer: { findUnique: async () => null, findFirst: async () => null },
        // No capacity queue in this double: no create here ever waits.
        sandboxCapacityWait: {
          findFirst: async () => null,
          findUnique: async () => null,
          count: async () => 0,
        },
        // No detached disk copies in this double: nothing
        // is discard input (disk-offload/evict.pg.test.ts proves the rows).
        sandboxDiskCopy: {
          findFirst: async () => null,
          updateMany: async () => ({ count: 0 }),
        },
        // No disk offloads and no waiting restores in this double:
        // admission supersedes nothing and no wait is
        // cancelled (restore-wait.pg.test.ts proves the real rows).
        sandboxDiskOffload: { findUnique: async () => null, findFirst: async () => null },
        sandboxRestoreWait: { findFirst: async () => null },
        // No template captures in this double: no capture holds host
        // resources (template-builds/orchestrator.pg.test.ts proves the real holds).
        sandboxTemplateCapture: {
          aggregate: async () => ({ _sum: { chargedMemoryMiB: null, chargedVcpu: null } }),
        },
        // No CLI-login rows in this double: host deletion discards nothing.
        // Real quarantine discard is covered by credentials/relay.pg.test.ts.
        credentialCaptureRejection: { updateMany: async () => ({ count: 0 }) },
        // No leases: every launch passes the READY gate and settles nothing
        // (credentials/launch.pg.test.ts proves the real gate).
        credentialLease: { count: async () => 0 },
        credentialOperationSpec: { deleteMany: async () => ({ count: 0 }) },
        // No residue either: DELETED settlement clears nothing here
        // (credential-teardown.pg.test.ts proves the real settlement).
        credentialResidue: { updateMany: async () => ({ count: 0 }), count: async () => 0 },
        outboxEvent: model("outbox"),
        sandboxOperationResult: model("results"),
        sandboxCommandOutput: model("outputs"),
        sandboxCommandOutputSegment: model("outputSegments"),
      });
      await store.barriers.beforeCommit?.();
      for (const [name, rows] of pending)
        for (const [id, row] of rows) (store[name] as Map<string, Row>).set(id, row);
      for (const [name, ids] of removed) for (const id of ids) store[name].delete(id);
      releaseLocks();
      await store.barriers.afterCommit?.();
      return result;
    } finally {
      releaseLocks();
    }
  });
}

export function gate() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

export function relayStore(kind = "RUN_COMMAND", state = "RUNNING") {
  return createFenceStore({
    hosts: [
      {
        id: "host-1",
        userId: "user-1",
        connectionEpoch: 1,
        egressEnforcement: true,
      },
    ],
    templates: [
      {
        id: "tpl-1",
        userId: "user-1",
        sandboxHostId: "host-1",
        incusFingerprint: `sha256:${"a".repeat(64)}`,
        architecture: "x86_64",
        guestUid: 1000,
        guestGid: 1000,
        guestHome: "/home/user",
        guestShell: "/bin/bash",
      },
    ],
    sandboxes: [
      {
        id: "sbx-1",
        userId: "user-1",
        generation: 1,
        state: "READY",
        sandboxHostId: "host-1",
        leaseRevision: 1,
        leaseExpiresAt: new Date(Date.now() + 3_600_000),
        leaseExpireAction: "STOP",
        diskReservationHeld: true,
        templateId: "tpl-1",
      },
    ],
    operations: [
      {
        id: "op-1",
        userId: "user-1",
        sandboxId: "sbx-1",
        kind,
        state,
        // Real rows always carry their (non-null) idempotency key.
        idempotencyKey: "op-1",
        requestBodyHash: "a".repeat(64),
        authorizingKeyId: null,
        ...requestDigestMetadata(kind),
        digestContext: digestContextSnapshot(
          {
            domain: ["STOP_SANDBOX", "KILL_SANDBOX"].includes(kind)
              ? ENV_FREE_DIGEST_DOMAIN
              : REQUEST_DIGEST_DOMAIN,
            hostId: "host-1",
            hostOwnerId: "user-1",
          },
          { generation: 1 },
        ),
        generation: 1,
        dispatchAttempt: 1,
        dispatchedHostId: "host-1",
        dispatchedConnectionEpoch: 1,
        // Real rows always carry the column; the nullable default matters to
        // first-write-wins completedAt filtering (C26).
        completedAt: null,
      },
    ],
    outbox: [
      {
        id: "evt-1",
        userId: "user-1",
        aggregateType: "sandbox",
        aggregateId: "sbx-1",
        processedAt: null,
        payload: {
          operationId: "op-1",
          sandboxId: "sbx-1",
          sandboxHostId: "host-1",
          generation: 1,
          dispatchAttempt: 1,
          kind: "command.run",
          argv: ["true"],
          lease: {
            revision: 1,
            deadlineUnixMs: Date.now() + 3_600_000,
            action: "stop",
            expiryPolicy: "retry-force-60s",
          },
        },
      },
    ],
  });
}

/** Prisma's delegate mock needs the branded promise used by its generated signature. */
export function prismaPromise<T>(promise: Promise<T>): Prisma.PrismaPromise<T> {
  return Object.defineProperty(promise, Symbol.toStringTag, {
    value: "PrismaPromise",
  }) as Prisma.PrismaPromise<T>;
}

/** A complete census that reports every placed sandbox running: it converges
 * nothing, so relay fixtures keep their seeded lifecycle state. */
export function runningCensusFrames(
  store: FenceStore,
  hostId = "host-1",
  terminal = false,
): string[] {
  const ids = [...store.sandboxes.values()]
    .filter((row) => row.sandboxHostId === hostId)
    .map((row) => row.id)
    .sort();
  const host = store.hosts.get(hostId)!;
  const tuple =
    typeof host.capacityReport === "string" ? JSON.parse(host.capacityReport) : host.capacityReport;
  const pages: string[] = [
    JSON.stringify({
      type: "host.admission",
      ...(typeof tuple === "object" && tuple !== null ? tuple : {}),
      journalId: "1234567890abcdef1234567890abcdef",
      connectionEpoch: host.connectionEpoch,
      runtimeKind: "fake",
      schedulable: true,
      egressPolicy: host.egressEnforcement ?? true,
      terminal,
    }),
    JSON.stringify({
      type: "journal.key.ack",
      connectionEpoch: host.connectionEpoch,
      keyVersion: 1,
      keyId: host.journalKeyId,
    }),
  ];
  for (let page = 0; page === 0 || page * 64 < ids.length; page += 1)
    pages.push(
      JSON.stringify({
        type: "sandbox.inventory",
        page,
        complete: (page + 1) * 64 >= ids.length,
        entries: ids.slice(page * 64, (page + 1) * 64).map((sandboxId) => {
          const row = store.sandboxes.get(sandboxId)!;
          return {
            sandboxOwnerId: row.userId,
            sandboxId,
            state: "ready",
            root: {
              storagePoolName: row.storagePoolName,
              storageMarker: row.storageMarker,
              diskGiB: row.diskGiB,
              state: "present",
              networkCleanupComplete: false,
              observationSequence: 1,
            },
          };
        }),
      }),
    );
  return pages;
}

/** Current command receipt with deterministic guest-attested process identity. */
export function commandResultFixture(store: FenceStore, operationId = "op-1", exitCode = 0) {
  const operation = store.operations.get(operationId)!;
  const startedAt = "2026-10-27T00:00:00.000Z";
  const observedAt = "2026-10-27T00:00:00.001Z";
  const process = {
    sandboxId: operation.sandboxId,
    generation: operation.generation,
    processId: operation.processId,
    attempt: operation.dispatchAttempt,
    pid: operation.processPid ?? 123,
  };
  return {
    version: 1,
    observedAt,
    payload: { type: "command", process, startedAt, exitCode },
    continuation: null,
    birth: {
      type: "process.started",
      operationId,
      ...process,
      bootId: "12345678-1234-4234-8234-123456789abc",
      startTicks: "123456",
      startedAt,
      observedAt,
    },
    failure: null,
    outputBytes: 0,
  };
}
