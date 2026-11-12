import { getPoolCapacity } from "../capacity-view";
import { setSandboxOffloadPin as setOffloadPin } from "../disk-offload/pin";
import { mintHostTerminalTicket, raiseHostTerminalTotp } from "../host-terminal-tickets";
import { captureSandbox } from "../image-store/captures";
import * as imageSettingServices from "../image-store/settings";
import { getOperationResult } from "../operation-results";
import { connectProcess } from "../process-connect";
import { cancelAction, writeStdinAction } from "../process-controls";
import * as capabilityServices from "./capabilities";
import * as hostServices from "./hosts";
import * as operationViewServices from "./operation-views";
import * as poolServices from "./pools";
import * as sandboxViewServices from "./sandbox-views";
import * as sandboxServices from "./sandboxes";
import * as sharingServices from "./sharing";
import * as templateServices from "./templates";

/**
 * Complete procedure → service inventory. Router keys must match these maps
 * exactly; the inventory test fails if a procedure is added without a service
 * or a service wrapper is added without a procedure.
 */
export const SANDBOX_PROCEDURE_INVENTORY = {
  getOperationResult,
  getSandboxCapabilities: capabilityServices.getSandboxCapabilities,
  connectProcess,
  killProcess: cancelAction,
  sendProcessStdin: writeStdinAction,
  getLimits: capabilityServices.getSandboxLimits,
  list: sandboxViewServices.listSandboxViews,
  getSandbox: sandboxViewServices.getSandboxView,
  listOperations: operationViewServices.listOperationViews,
  getOperationView: operationViewServices.getOperationView,
  probeSandbox: sandboxServices.probeSandbox,
  getOperation: sandboxServices.getOperation,
  getCommandOutput: sandboxServices.getCommandOutput,
  createSandbox: sandboxServices.createSandbox,
  killSandbox: sandboxServices.killSandbox,
  runCommand: sandboxServices.runCommand,
  readFile: sandboxServices.readFile,
  reconnectSandbox: sandboxServices.reconnectSandbox,
  stopSandbox: sandboxServices.stopSandbox,
  listDir: sandboxServices.listDir,
  statPath: sandboxServices.statPath,
  mkdir: sandboxServices.mkdir,
  removePath: sandboxServices.removePath,
  movePath: sandboxServices.movePath,
  createSnapshot: sandboxServices.createSnapshot,
  restoreSnapshot: sandboxServices.restoreSnapshot,
  forkSandbox: sandboxServices.forkSandbox,
  listProcesses: sandboxServices.listProcesses,
  signalProcess: sandboxServices.signalProcess,
  writeStdin: sandboxServices.writeStdin,
  setSandboxTimeout: sandboxServices.setSandboxTimeout,
  updateSandbox: sandboxServices.renameSandbox,
  retryCleanup: sandboxServices.retryRestoreCleanup,
  setOffloadPin,
  cancelOperation: sandboxServices.cancelOperation,
  captureSandbox,
} as const;

export const HOST_PROCEDURE_INVENTORY = {
  listHosts: hostServices.listHosts,
  getHost: hostServices.getHost,
  listHostGuests: hostServices.listHostGuests,
  listHostStoragePools: hostServices.listHostStoragePools,
  createHost: hostServices.createHost,
  updateHost: hostServices.updateHost,
  setHostDraining: hostServices.setHostDraining,
  deleteHost: hostServices.deleteHost,
  forgetHost: hostServices.forgetHost,
  listHostTokens: hostServices.listHostTokens,
  createHostToken: hostServices.createHostToken,
  revokeHostToken: hostServices.revokeHostToken,
  listDeviceCredentials: hostServices.listDeviceCredentials,
  revokeDeviceCredential: hostServices.revokeDeviceCredential,
  imageCache: imageSettingServices.listHostImageCache,
} as const;

export const TEMPLATE_PROCEDURE_INVENTORY = {
  retireRevision: templateServices.retireTemplateRevision,
  listRevisionChoices: templateServices.listRevisionChoices,
  getTemplateRevision: templateServices.getTemplateRevision,
  listRevisions: templateServices.listTemplateRevisions,
  listAvailability: templateServices.listTemplateAvailability,
  appendRevision: templateServices.appendTemplateRevision,
  associateAvailability: templateServices.associateTemplateAvailability,
  setTag: templateServices.setTemplateTag,
  listTemplates: templateServices.listTemplates,
  getTemplate: templateServices.getTemplate,
  createTemplate: templateServices.createTemplate,
  retireTemplate: templateServices.retireTemplate,
  getImageSettings: imageSettingServices.getTemplateImageSettings,
  updateImageSettings: imageSettingServices.updateTemplateImageSettings,
  publishRevision: imageSettingServices.publishTemplateRevision,
  pruneNow: imageSettingServices.pruneTemplateNow,
} as const;

export const POOL_PROCEDURE_INVENTORY = {
  listShared: sharingServices.listSharedPools,
  listUsable: sharingServices.listUsablePools,
  getUsable: sharingServices.getUsablePool,
  listUsableMembers: sharingServices.listUsablePoolMembers,
  listContributions: sharingServices.listPoolContributions,
  grantShare: sharingServices.grantPoolShare,
  updateShare: sharingServices.updatePoolShare,
  revokeShare: sharingServices.revokePoolShare,
  leave: sharingServices.leavePool,
  resendInvite: sharingServices.resendPoolInvite,
  revokeInvite: sharingServices.revokePoolInvite,
  acceptInvite: sharingServices.acceptPoolInvite,
  contributeHost: sharingServices.contributePoolHost,
  withdrawHost: sharingServices.withdrawPoolHost,

  listShares: sharingServices.listPoolShares,
  listInvites: sharingServices.listPoolInvites,
  list: poolServices.listPools,
  get: poolServices.getPool,
  create: poolServices.createPool,
  update: poolServices.updatePool,
  delete: poolServices.deletePool,
  listMembers: poolServices.listPoolMembers,
  addMember: poolServices.addPoolMember,
  updateMember: poolServices.updatePoolMember,
  removeMember: poolServices.removePoolMember,
  previewLeaseLowering: poolServices.previewLeaseLowering,
  capacity: getPoolCapacity,
  queue: poolServices.listPoolQueue,
} as const;

/** Cookie-only ticket services require both durable user AND session identity. */
export const HOST_TERMINAL_PROCEDURE_INVENTORY = {
  createSession: mintHostTerminalTicket,
  raiseHostTerminalTotp,
} as const;
