import { env } from "@wssp/env/shared";

import { createConnectAuditPrismaClient, createPrismaClient } from "./client";

export type {
  BuildContextState,
  CredentialDelivery,
  CredentialInstanceState,
  CredentialLeaseState,
  CredentialMode,
  HostConnectionStatus,
  NodeDaemonRuntime,
  OperationState,
  OutboxEvent,
  Prisma,
  Sandbox,
  SandboxBuildContext,
  SandboxEgressModeReason,
  SandboxGuestSudoReason,
  SandboxHost,
  SandboxHostStoragePool,
  SandboxLaunchMode,
  SandboxLeaseExpireAction,
  SandboxOffloadMode,
  SandboxOperation,
  SandboxOperationKind,
  SandboxPlacement,
  SandboxPurpose,
  SandboxState,
  SandboxTeardownIntent,
  SandboxTemplate,
  SandboxTemplateAvailability,
  SandboxTemplateBuild,
  SandboxTemplateRevision,
  SandboxTransfer,
  SandboxTransferState,
  SdkKey,
  SdkKeyOrigin,
  SdkKeyResourceMode,
  TemplateAvailabilityStatus,
  TemplateBuildCleanupState,
  TemplateBuildPrincipalKind,
  TemplateBuildSourceFormat,
  TemplateBuildState,
  TemplateCaptureState,
} from "../prisma/generated/client";

const prisma = createPrismaClient({
  connectionString: env.DATABASE_URL,
  max: env.DATABASE_POOL_MAX,
});

export default prisma;

let connectAudit: ReturnType<typeof createConnectAuditPrismaClient> | undefined;

/**
 * The connect audit's isolated client (`CONNECT_AUDIT_POOL`: at most two
 * connections), created on first use only, so the worker and every process
 * that never records a CLI connection never opens it.
 */
export function connectAuditPrisma() {
  connectAudit ??= createConnectAuditPrismaClient(env.DATABASE_URL);
  return connectAudit;
}

/** Bounds the audit client's disconnect at shutdown. */
export const CONNECT_AUDIT_DISCONNECT_MS = 2_000;

/**
 * Closes the audit client if it was ever created: bounded by
 * `CONNECT_AUDIT_DISCONNECT_MS`, never rejects.
 */
export async function disconnectConnectAuditPrisma(): Promise<void> {
  const client = connectAudit;
  if (!client) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  await Promise.race([
    client.$disconnect().catch(() => undefined),
    new Promise<void>((resolve) => {
      timer = setTimeout(resolve, CONNECT_AUDIT_DISCONNECT_MS);
      timer.unref?.();
    }),
  ]);
  clearTimeout(timer);
}

export {
  type DataDeletionNotice,
  listUnnotifiedDataDeletions,
  markDataDeletionNotified,
} from "./data-deletion-notices";
