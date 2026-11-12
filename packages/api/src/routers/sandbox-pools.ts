import { liveOwnerSessionProcedure, protectedProcedure } from "../index";
import { getPoolCapacity } from "../sandbox/capacity-view";
import { sessionPrincipal } from "../sandbox/contracts";
import {
  addPoolMemberInput,
  createPoolInput,
  listPoolMembersInput,
  listPoolQueueInput,
  listPoolsInput,
  poolCapacityInput,
  poolIdInput,
  poolMemberInput,
  previewLeaseLoweringInput,
  updatePoolInput,
  updatePoolMemberInput,
} from "../sandbox/pool-input";
import {
  addPoolMember,
  createPool,
  deletePool,
  getPool,
  listPoolMembers,
  listPoolQueue,
  listPools,
  previewLeaseLowering,
  removePoolMember,
  updatePool,
  updatePoolMember,
} from "../sandbox/services/pools";

import {
  acceptPoolInvite,
  contributePoolHost,
  getUsablePool,
  grantPoolShare,
  leavePool,
  listPoolContributions,
  listPoolInvites,
  listPoolShares,
  listSharedPools,
  listUsablePoolMembers,
  listUsablePools,
  resendPoolInvite,
  revokePoolInvite,
  revokePoolShare,
  updatePoolShare,
  withdrawPoolHost,
} from "../sandbox/services/sharing";
import {
  acceptPoolInviteInput,
  contributePoolHostInput,
  grantPoolShareInput,
  leavePoolInput,
  poolInviteInput,
  revokePoolShareInput,
  updatePoolShareInput,
} from "../sandbox/sharing-input";

export const sandboxPoolsRouter = {
  /** Pool owner: its waiting creates, oldest first (bounded pages). */
  queue: protectedProcedure
    .input(listPoolQueueInput)
    .handler(({ input, context }) =>
      listPoolQueue(sessionPrincipal(context.session.user.id), input),
    ),
  /** Schedulable capacity, what fits now and the queue (own-host detail only). */
  capacity: protectedProcedure
    .input(poolCapacityInput)
    .handler(({ input, context }) =>
      getPoolCapacity(sessionPrincipal(context.session.user.id), input),
    ),
  /** Read-only: how many running sandboxes a lease-limit lowering would shorten. */
  previewLeaseLowering: protectedProcedure
    .input(previewLeaseLoweringInput)
    .handler(({ input, context }) =>
      previewLeaseLowering(sessionPrincipal(context.session.user.id), input),
    ),
  listShared: protectedProcedure
    .input(listPoolsInput)
    .handler(({ input, context }) =>
      listSharedPools(sessionPrincipal(context.session.user.id), input),
    ),
  listUsable: protectedProcedure
    .input(listPoolsInput)
    .handler(({ input, context }) =>
      listUsablePools(sessionPrincipal(context.session.user.id), input),
    ),
  getUsable: protectedProcedure
    .input(poolIdInput)
    .handler(({ input, context }) =>
      getUsablePool(sessionPrincipal(context.session.user.id), input),
    ),
  listUsableMembers: protectedProcedure
    .input(listPoolMembersInput)
    .handler(({ input, context }) =>
      listUsablePoolMembers(sessionPrincipal(context.session.user.id), input),
    ),
  listContributions: protectedProcedure
    .input(listPoolMembersInput)
    .handler(({ input, context }) =>
      listPoolContributions(sessionPrincipal(context.session.user.id), input),
    ),
  grantShare: liveOwnerSessionProcedure
    .input(grantPoolShareInput)
    .handler(({ input, context }) =>
      grantPoolShare(sessionPrincipal(context.session.user.id), input),
    ),
  updateShare: liveOwnerSessionProcedure
    .input(updatePoolShareInput)
    .handler(({ input, context }) =>
      updatePoolShare(sessionPrincipal(context.session.user.id), input),
    ),
  revokeShare: liveOwnerSessionProcedure
    .input(revokePoolShareInput)
    .handler(({ input, context }) =>
      revokePoolShare(sessionPrincipal(context.session.user.id), input),
    ),
  leave: liveOwnerSessionProcedure
    .input(leavePoolInput)
    .handler(({ input, context }) => leavePool(sessionPrincipal(context.session.user.id), input)),
  resendInvite: liveOwnerSessionProcedure
    .input(poolInviteInput)
    .handler(({ input, context }) =>
      resendPoolInvite(sessionPrincipal(context.session.user.id), input),
    ),
  revokeInvite: liveOwnerSessionProcedure
    .input(poolInviteInput)
    .handler(({ input, context }) =>
      revokePoolInvite(sessionPrincipal(context.session.user.id), input),
    ),
  acceptInvite: liveOwnerSessionProcedure
    .input(acceptPoolInviteInput)
    .handler(({ input, context }) =>
      acceptPoolInvite(sessionPrincipal(context.session.user.id), input),
    ),
  contributeHost: liveOwnerSessionProcedure
    .input(contributePoolHostInput)
    .handler(({ input, context }) =>
      contributePoolHost(sessionPrincipal(context.session.user.id), input),
    ),
  withdrawHost: liveOwnerSessionProcedure
    .input(poolMemberInput)
    .handler(({ input, context }) =>
      withdrawPoolHost(sessionPrincipal(context.session.user.id), input),
    ),

  listShares: liveOwnerSessionProcedure
    .input(listPoolMembersInput)
    .handler(({ input, context }) =>
      listPoolShares(sessionPrincipal(context.session.user.id), input),
    ),
  listInvites: liveOwnerSessionProcedure
    .input(listPoolMembersInput)
    .handler(({ input, context }) =>
      listPoolInvites(sessionPrincipal(context.session.user.id), input),
    ),
  list: protectedProcedure
    .input(listPoolsInput)
    .handler(({ input, context }) => listPools(sessionPrincipal(context.session.user.id), input)),
  get: protectedProcedure
    .input(poolIdInput)
    .handler(({ input, context }) => getPool(sessionPrincipal(context.session.user.id), input)),
  create: liveOwnerSessionProcedure
    .input(createPoolInput)
    .handler(({ input, context }) => createPool(sessionPrincipal(context.session.user.id), input)),
  update: liveOwnerSessionProcedure
    .input(updatePoolInput)
    .handler(({ input, context }) => updatePool(sessionPrincipal(context.session.user.id), input)),
  delete: liveOwnerSessionProcedure
    .input(poolIdInput)
    .handler(({ input, context }) => deletePool(sessionPrincipal(context.session.user.id), input)),
  listMembers: protectedProcedure
    .input(listPoolMembersInput)
    .handler(({ input, context }) =>
      listPoolMembers(sessionPrincipal(context.session.user.id), input),
    ),
  addMember: liveOwnerSessionProcedure
    .input(addPoolMemberInput)
    .handler(({ input, context }) =>
      addPoolMember(sessionPrincipal(context.session.user.id), input),
    ),
  updateMember: liveOwnerSessionProcedure
    .input(updatePoolMemberInput)
    .handler(({ input, context }) =>
      updatePoolMember(sessionPrincipal(context.session.user.id), input),
    ),
  removeMember: liveOwnerSessionProcedure
    .input(poolMemberInput)
    .handler(({ input, context }) =>
      removePoolMember(sessionPrincipal(context.session.user.id), input),
    ),
};
