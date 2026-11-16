import { env } from "@wssp/env/shared";

import { createPrismaClient } from "./client";

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

export {
  type DataDeletionNotice,
  listUnnotifiedDataDeletions,
  markDataDeletionNotified,
} from "./data-deletion-notices";
