import { z } from "zod";
import { credentialCapabilitiesV11Schema } from "./credential-wire";
import { egressCapabilitiesV11Schema } from "./egress-wire";
import { imageAdmissionV11Schema, imageCapabilitiesV11Schema } from "./image-wire";
import { LEASE_FINITE_MAX_MS, LEASE_LIMIT_MIN_MS } from "./lease-limits";
import limits from "./vm-size-limits.json";

/** Configured guest RAM, not resident memory or dedicated CPU capacity. */
// Calibrated on a reference host (Incus 7.5, ~124 GiB / 32 threads), 2026-11-01: noisy upper estimate 253 MiB + 64 MiB margin, rounded to 320; host reserve max(4096 MiB, 25%).
export const VM_SIZE_LIMITS = Object.freeze({
  ...limits,
  hostMemoryReserve: Object.freeze(limits.hostMemoryReserve),
});
export const vmCpuCountSchema = z.number().int().min(limits.cpuCountMin).max(limits.cpuCountMax);
export const vmMemoryMiBSchema = z
  .number()
  .int()
  .min(limits.memoryMiBMin)
  .max(limits.memoryMiBMax)
  .multipleOf(limits.memoryMiBStep);

export const vmDiskGiBSchema = z.number().int().min(limits.diskGiBMin).max(limits.diskGiBMax);
export const hostVcpuBudgetSchema = z
  .number()
  .int()
  .min(limits.hostVcpuBudgetMin)
  .max(limits.hostVcpuBudgetMax);
export const vmSizeSchema = z.strictObject({
  cpuCount: vmCpuCountSchema,
  memoryMiB: vmMemoryMiBSchema,
  diskGiB: vmDiskGiBSchema,
});
export type VmSize = z.infer<typeof vmSizeSchema>;

/** No defaults here: omission is part of keyed create intent. */
export const vmSizeOverridesSchema = vmSizeSchema.partial();
export type VmSizeOverrides = z.infer<typeof vmSizeOverridesSchema>;

/**
 * A revision's size: CPU and memory defaults, the disk a create gets when it
 * omits `diskGiB` (`defaultDiskGiB`) and the image's root disk, below which no
 * create or build may go (`minDiskGiB`, at most the default).
 */
export const revisionSizeOverridesSchema = z.strictObject({
  cpuCount: vmCpuCountSchema.optional(),
  memoryMiB: vmMemoryMiBSchema.optional(),
  defaultDiskGiB: vmDiskGiBSchema.optional(),
  minDiskGiB: vmDiskGiBSchema.optional(),
});
export type RevisionSizeOverrides = z.infer<typeof revisionSizeOverridesSchema>;

/**
 * A revision append is self-contained; it never inherits another revision.
 * An omitted `minDiskGiB` is the default: wssp cannot see a registered image's
 * root, so a smaller floor is the registrant's explicit claim.
 */
export const vmRevisionSizeSchema = revisionSizeOverridesSchema
  .transform((size) => {
    const defaultDiskGiB = size.defaultDiskGiB ?? limits.diskGiBDefault;
    return {
      cpuCount: size.cpuCount ?? limits.cpuCountDefault,
      memoryMiB: size.memoryMiB ?? limits.memoryMiBDefault,
      defaultDiskGiB,
      minDiskGiB: size.minDiskGiB ?? defaultDiskGiB,
    };
  })
  .refine((size) => size.minDiskGiB <= size.defaultDiskGiB, {
    message: "minDiskGiB must not exceed defaultDiskGiB.",
    path: ["minDiskGiB"],
  });
export type VmRevisionSize = z.infer<typeof vmRevisionSizeSchema>;

/** The create defaults of a revision (its disk default, not its floor). */
export function revisionDefaultSize(revision: {
  cpuCount: number;
  memoryMiB: number;
  defaultDiskGiB: number;
}): VmSize {
  return {
    cpuCount: revision.cpuCount,
    memoryMiB: revision.memoryMiB,
    diskGiB: revision.defaultDiskGiB,
  };
}

/**
 * Headroom a build adds over its base's `minDiskGiB` when neither the request
 * nor the recipe sizes the disk. Small on purpose: the build's disk becomes
 * the published revision's floor and every descendant's (roots never shrink);
 * a recipe that needs more says so with `diskGiB`.
 */
export const BUILD_DISK_HEADROOM_GIB = 2;

export function resolveVmSize(revision: VmSize, overrides: VmSizeOverrides): VmSize {
  const defaults = vmSizeSchema.parse(revision);
  const supplied = vmSizeOverridesSchema.parse(overrides);
  return {
    cpuCount: supplied.cpuCount ?? defaults.cpuCount,
    memoryMiB: supplied.memoryMiB ?? defaults.memoryMiB,
    diskGiB: supplied.diskGiB ?? defaults.diskGiB,
  };
}

export const vmCapacitySchema = z.strictObject({
  memoryBudgetMiB: z
    .number()
    .int()
    .min(limits.memoryMiBMin)
    .max(limits.hostMemoryBudgetMiBMax)
    .multipleOf(limits.memoryMiBStep),
  maxCpuCount: vmCpuCountSchema,
  vcpuBudget: hostVcpuBudgetSchema,
});
export type VmCapacity = z.infer<typeof vmCapacitySchema>;

/** The per-VM memory ceiling is derived, never independently advertised. */
export function vmMaxMemoryMiB(capacity: VmCapacity): number {
  return Math.min(limits.memoryMiBMax, vmCapacitySchema.parse(capacity).memoryBudgetMiB);
}

export function vmLiveMemoryChargeMiB(memoryMiB: number): number {
  return vmMemoryMiBSchema.parse(memoryMiB) + limits.vmHostOverheadMiB;
}
export function vmRootChargeGiB(diskGiB: number): number {
  return vmDiskGiBSchema.parse(diskGiB) + limits.rootDiskOverheadGiB;
}
export function hostVcpuBudgetDefault(threads: number): number {
  return hostVcpuBudgetSchema.parse(
    z.number().int().positive().max(Number.MAX_SAFE_INTEGER).parse(threads) *
      limits.hostVcpuBudgetDefaultThreadsMultiplier,
  );
}
/** Byte arithmetic preserves ceil reserve before aligning the final budget. */
export function hostMemoryBudgetFromBytes(totalBytes: bigint): number {
  if (totalBytes < 0n || totalBytes > 18446744073709551615n)
    throw new RangeError("invalid host memory");
  const mib = 1024n * 1024n;
  const percentage = (totalBytes * BigInt(limits.hostMemoryReserve.percent) + 99n) / 100n;
  const minimum = BigInt(limits.hostMemoryReserve.minimumMiB) * mib;
  // biome-ignore lint/complexity/useMathMinMax: reserve arithmetic is bigint; Math.max accepts only numbers.
  const reserve = percentage > minimum ? percentage : minimum;
  const step = BigInt(limits.memoryMiBStep) * mib;
  return Number(
    (totalBytes > reserve ? (totalBytes - reserve) / step : 0n) * BigInt(limits.memoryMiBStep),
  );
}

const safeScalar = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
export const storageIdentityV11Schema = z.strictObject({
  name: z
    .string()
    .min(1)
    .max(63)
    .regex(/^[A-Za-z0-9][A-Za-z0-9_.-]*$/),
  marker: z
    .string()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9_-]+$/),
});
export const storageHealthV11Schema = z
  .strictObject({
    ...storageIdentityV11Schema.shape,
    health: z.enum(["healthy", "unavailable"]),
    reason: z
      .enum(["missing", "identity", "permission", "unsupported", "io", "incomplete"])
      .nullable(),
    totalBytes: safeScalar.nullable(),
    usedBytes: safeScalar.nullable(),
    freeBytes: safeScalar.nullable(),
  })
  .refine((pool) => {
    if (pool.totalBytes === null) return pool.usedBytes === null && pool.freeBytes === null;
    return (
      pool.totalBytes > 0 &&
      pool.usedBytes !== null &&
      pool.freeBytes !== null &&
      pool.usedBytes <= pool.totalBytes &&
      pool.freeBytes === pool.totalBytes - pool.usedBytes
    );
  }, "invalid storage usage");
const capacityGiB = z.number().int().min(0).max(limits.storageCapacityGiBMax);
export const storagePoolV11Schema = storageHealthV11Schema
  .safeExtend({
    capacityGiB,
    totalBasedCapacityGiB: safeScalar.nullable(),
    capacitySource: z.enum(["implicit", "explicit"]),
    derivationTotalBytes: safeScalar.nullable(),
    derivationFreeBytes: safeScalar.nullable(),
    derivationCommittedBytes: safeScalar.nullable(),
    derivationActualBytes: safeScalar.nullable(),
    derivationHeadroomBytes: safeScalar.nullable(),
    implicitCeilingGiB: safeScalar.nullable(),
    draining: z.boolean(),
  })
  .refine((pool) => {
    const inputs = [
      pool.totalBasedCapacityGiB,
      pool.derivationTotalBytes,
      pool.derivationFreeBytes,
      pool.derivationCommittedBytes,
      pool.derivationActualBytes,
      pool.derivationHeadroomBytes,
      pool.implicitCeilingGiB,
    ];
    if (pool.capacitySource === "explicit")
      return pool.capacityGiB > 0 && inputs.every((value) => value === null);
    if (inputs.some((value) => value === null)) return false;
    const {
      derivationTotalBytes: t,
      derivationFreeBytes: f,
      derivationCommittedBytes: c,
      derivationActualBytes: a,
      derivationHeadroomBytes: h,
      implicitCeilingGiB: p,
      totalBasedCapacityGiB: b,
    } = pool;
    return (
      t !== null &&
      f !== null &&
      c !== null &&
      a !== null &&
      h !== null &&
      p !== null &&
      b !== null &&
      t > 0 &&
      f <= t &&
      a <= c &&
      h <= t &&
      pool.capacityGiB <= p &&
      pool.capacityGiB <= b
    );
  }, "invalid storage derivation");
function uniquePools(pools: { name: string; marker: string }[]): boolean {
  return (
    new Set(pools.map((pool) => pool.name)).size === pools.length &&
    new Set(pools.map((pool) => pool.marker)).size === pools.length
  );
}
export const hostStaticCapacityV11Schema = z.strictObject({
  vmCapacity: vmCapacitySchema,
  storagePools: z.array(storagePoolV11Schema).max(limits.storagePoolMax).refine(uniquePools),
});
export const hostInventoryV11Schema = z.strictObject({
  hostId: z.string().min(1).max(128),
  schedulable: z.boolean(),
  sandboxCount: z.number().int().min(0).max(limits.hostManagedSandboxCeiling),
});
export const hostAdmissionV11Schema = z.strictObject({
  type: z.literal("host.admission"),
  journalId: z.string().regex(/^[0-9a-f]{32}$/),
  connectionEpoch: z.number().int().min(1).max(2147483647),
  runtimeKind: z.enum(["fake", "incus_kvm", "unsupported"]),
  schedulable: z.boolean(),
  egressPolicy: z.boolean(),
  terminal: z.boolean(),
  /** Image cache admission facts; absent from daemons without the image feature. */
  image: imageAdmissionV11Schema.optional(),
  /** Static `egressOpen` feature bit; omitted when false. */
  egressOpen: z.boolean().optional(),
  ...hostStaticCapacityV11Schema.shape,
});
export const hostInventoryUpdateV11Schema = z.strictObject({
  type: z.literal("inventory.update"),
  id: z.string().min(1).max(128),
  connectionEpoch: z.number().int().min(1).max(2147483647),
  observationSequence: safeScalar,
  inventory: hostInventoryV11Schema,
  storagePools: z.array(storageHealthV11Schema).max(limits.storagePoolMax).refine(uniquePools),
});
export const pinnedAllocationV11Schema = z
  .strictObject({
    ...vmSizeSchema.shape,
    storagePoolName: storageIdentityV11Schema.shape.name,
    storageMarker: storageIdentityV11Schema.shape.marker,
    // Pinned historical weights do not depend on the current overhead policy.
    chargedMemoryMiB: z.number().int().min(limits.memoryMiBMin).max(2147483647),
    chargedVcpu: vmCpuCountSchema,
    rootChargeGiB: z.number().int().min(limits.diskGiBMin).max(2147483647),
  })
  .refine(
    (allocation) =>
      allocation.chargedMemoryMiB >= allocation.memoryMiB &&
      allocation.chargedVcpu === allocation.cpuCount &&
      allocation.rootChargeGiB >= allocation.diskGiB,
  );

/** A host lease ceiling report: finite ms in the shared range, or null (unlimited). */
export const hostLeaseCeilingSchema = z.union([
  z.number().int().min(LEASE_LIMIT_MIN_MS).max(LEASE_FINITE_MAX_MS),
  z.null(),
]);
/** Required output-chunk offer and answer, bounded by the protocol minimum
 * and binary frame ceiling. */
export const OUTPUT_CHUNK_MIN_BYTES = 8192;
export const outputChunkBytesSchema = z.number().int().min(OUTPUT_CHUNK_MIN_BYTES).max(1048576);
/**
 * WP8 (D5): a host keeps a sandbox PTY whose relay connection was lost
 * detached for `graceMs` (default 120 s, at most 10 min) and accepts
 * `terminal.resume` for it after its next `reconcile.complete`.
 */
export const TERMINAL_RESUME_GRACE_MIN_MS = 1_000;
export const TERMINAL_RESUME_GRACE_MAX_MS = 600_000;
export const terminalResumeCapabilitySchema = z.strictObject({
  graceMs: z.number().int().min(TERMINAL_RESUME_GRACE_MIN_MS).max(TERMINAL_RESUME_GRACE_MAX_MS),
});
export const daemonCapabilitiesV11Schema = z.strictObject({
  protocolVersion: z.literal("1.0"),
  binaryFrames: z.literal(true),
  cancellation: z.literal(true),
  operationWal: z.literal(true),
  hostInventory: z.literal(true),
  maxBinaryChunkBytes: z.literal(1048576),
  streamWindowChunks: z.literal(4),
  runtimeKind: z.enum(["fake", "incus_kvm", "unsupported"]),
  egressPolicy: z.boolean(),
  terminal: z.boolean(),
  hostTerminal: z.boolean(),
  requireHostTerminalTotp: z.boolean(),
  policyRevision: safeScalar,
  hostManagedSandboxCeiling: z.literal(limits.hostManagedSandboxCeiling),
  /** Required host lease ceiling; null means unlimited. */
  maxLeaseMs: hostLeaseCeilingSchema,
  /** Image cache features; omitted by daemons with the cache disabled. */
  image: imageCapabilitiesV11Schema.optional(),
  /** B12 blocked-name hints (`egress.refused`); absent means false. */
  egressRefusedHints: z.boolean().optional(),
  /** Optional runtime support for template start and ready commands. */
  templateStartup: z.boolean().optional(),
  /** CLI-login credential features; omitted by daemons without them. */
  credentials: credentialCapabilitiesV11Schema.optional(),
  /** Required open-egress and guard capability evidence. */
  egress: egressCapabilitiesV11Schema,
  /** Required command-output chunk ceiling offered to the server. */
  maxOutputChunkBytes: outputChunkBytesSchema,
  /** WP7 graceful quiesce (`host.quiesce`, `hello.quiescing`); absent = false. */
  quiesce: z.boolean().optional(),
  /** Required support for per-entry inventory census results. */
  censusEntryResults: z.literal(true),
  /** Required support for receipts still being resolved after reconnect. */
  pendingReceipts: z.literal(true),
  /** Required support for per-entry connected expiry results. */
  expiryStatusResults: z.literal(true),
  /** Required observation ordering for connected expiry results. */
  observationFence: z.literal(true),
  /** Required support for retiring unknown commands on host proof. */
  commandRetire: z.literal(true),
  /** Whether guests may elevate privileges; unavailable on unsupported runtimes. */
  guestSudo: z.literal(true).optional(),
  /** Optional stopped-disk offload support; requires image fetching. */
  diskOffload: z.literal(true).optional(),
  /** WP8 terminal reattach grace; omitted by daemons that never detach a PTY. */
  terminalResume: terminalResumeCapabilitySchema.optional(),
});
export const hostHelloV11Schema = z
  .strictObject({
    type: z.literal("hello"),
    id: z.string().min(1).max(128),
    protocolVersion: z.literal("1.0"),
    supportedProtocolVersions: z.tuple([z.literal("1.0")]),
    daemon: z.strictObject({
      hostId: z.string().min(1).max(128),
      label: z.string().max(256),
      version: z.string().max(128).optional(),
      capabilities: daemonCapabilitiesV11Schema,
    }),
    inventory: hostInventoryV11Schema,
    ...hostStaticCapacityV11Schema.shape,
    /** WP7: a reconnect while quiescing; only with the `quiesce` capability. */
    quiescing: z.boolean().optional(),
  })
  .refine(
    (hello) =>
      hello.daemon.hostId === hello.inventory.hostId &&
      (hello.quiescing !== true || hello.daemon.capabilities.quiesce === true) &&
      (hello.daemon.capabilities.diskOffload !== true ||
        hello.daemon.capabilities.image?.fetch === true),
  );
