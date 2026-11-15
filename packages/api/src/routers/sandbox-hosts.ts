import { liveOwnerSessionProcedure, protectedProcedure } from "../index";
import { sessionPrincipal } from "../sandbox";
import {
  createHostInput,
  createHostTokenInput,
  hostIdInput,
  listHostsInput,
  listHostTokensInput,
  listPageInput,
  revokeDeviceCredentialInput,
  revokeHostTokenInput,
  setHostDrainingInput,
  updateHostInput,
} from "../sandbox/contracts";
import { hostImageCacheInput, listHostImageCache } from "../sandbox/image-store/settings";
import {
  liftAgentHostCommandsVeto,
  liftHostTerminalVeto,
  lowerAgentHostCommands,
  lowerHostTerminal,
} from "../sandbox/services/host-policy";
import {
  createHost,
  createHostToken,
  deleteHost,
  forgetHost,
  getHost,
  listDeviceCredentials,
  listHostGuests,
  listHostStoragePools,
  listHosts,
  listHostTokens,
  revokeDeviceCredential,
  revokeHostToken,
  setHostDraining,
  updateHost,
} from "../sandbox/services/hosts";

export const sandboxHostsRouter = {
  liftAgentHostCommandsVeto: liveOwnerSessionProcedure
    .input(hostIdInput)
    .handler(({ input, context }) =>
      liftAgentHostCommandsVeto(sessionPrincipal(context.session.user.id), input),
    ),
  liftHostTerminalVeto: liveOwnerSessionProcedure
    .input(hostIdInput)
    .handler(({ input, context }) =>
      liftHostTerminalVeto(sessionPrincipal(context.session.user.id), input),
    ),
  lowerAgentHostCommands: liveOwnerSessionProcedure
    .input(hostIdInput)
    .handler(({ input, context }) =>
      lowerAgentHostCommands(sessionPrincipal(context.session.user.id), input),
    ),
  lowerHostTerminal: liveOwnerSessionProcedure
    .input(hostIdInput)
    .handler(({ input, context }) =>
      lowerHostTerminal(sessionPrincipal(context.session.user.id), input),
    ),
  /** The host's image cache (owner only): own entries paged, foreign bytes aggregate. */
  imageCache: protectedProcedure
    .input(hostImageCacheInput)
    .handler(({ input, context }) =>
      listHostImageCache(sessionPrincipal(context.session.user.id), input),
    ),
  getHost: protectedProcedure
    .input(hostIdInput)
    .handler(async ({ input, context }) =>
      getHost(sessionPrincipal(context.session.user.id), input),
    ),
  listHosts: protectedProcedure.input(listHostsInput).handler(async ({ input, context }) => {
    return listHosts(sessionPrincipal(context.session.user.id), input);
  }),

  listHostGuests: protectedProcedure
    .input(hostIdInput.merge(listPageInput))
    .handler(({ input, context }) =>
      listHostGuests(sessionPrincipal(context.session.user.id), input),
    ),
  listHostStoragePools: protectedProcedure
    .input(hostIdInput.merge(listPageInput))
    .handler(async ({ input, context }) =>
      listHostStoragePools(sessionPrincipal(context.session.user.id), input),
    ),

  createHost: liveOwnerSessionProcedure
    .input(createHostInput)
    .handler(async ({ input, context }) => {
      return createHost(sessionPrincipal(context.session.user.id), input);
    }),

  updateHost: liveOwnerSessionProcedure
    .input(updateHostInput)
    .handler(async ({ input, context }) => {
      return updateHost(sessionPrincipal(context.session.user.id), input);
    }),

  setHostDraining: protectedProcedure
    .input(setHostDrainingInput)
    .handler(async ({ input, context }) => {
      return setHostDraining(sessionPrincipal(context.session.user.id), input);
    }),

  deleteHost: liveOwnerSessionProcedure.input(hostIdInput).handler(async ({ input, context }) => {
    return deleteHost(sessionPrincipal(context.session.user.id), input);
  }),

  /** owner session only, type-to-confirm in the UI. */
  forgetHost: liveOwnerSessionProcedure.input(hostIdInput).handler(async ({ input, context }) => {
    return forgetHost(sessionPrincipal(context.session.user.id), input);
  }),

  listHostTokens: protectedProcedure
    .input(listHostTokensInput)
    .handler(async ({ input, context }) => {
      return listHostTokens(sessionPrincipal(context.session.user.id), input);
    }),

  createHostToken: liveOwnerSessionProcedure
    .input(createHostTokenInput)
    .handler(async ({ input, context }) => {
      return createHostToken(sessionPrincipal(context.session.user.id), input);
    }),

  revokeHostToken: protectedProcedure
    .input(revokeHostTokenInput)
    .handler(async ({ input, context }) => {
      return revokeHostToken(sessionPrincipal(context.session.user.id), input);
    }),

  listDeviceCredentials: protectedProcedure
    .input(listHostTokensInput)
    .handler(async ({ input, context }) => {
      return listDeviceCredentials(sessionPrincipal(context.session.user.id), input);
    }),

  revokeDeviceCredential: protectedProcedure
    .input(revokeDeviceCredentialInput)
    .handler(async ({ input, context }) => {
      return revokeDeviceCredential(sessionPrincipal(context.session.user.id), input);
    }),
};
