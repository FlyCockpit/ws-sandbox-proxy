import { liveOwnerSessionProcedure, protectedProcedure } from "../index";
import { sessionPrincipal } from "../sandbox";
import {
  createSdkKey,
  createSdkKeyInput,
  listSdkKeys,
  listSdkKeysInput,
  revokeSdkKey,
  revokeSdkKeyInput,
} from "../sandbox/services/sdk-keys";

export const sdkKeysRouter = {
  list: protectedProcedure.input(listSdkKeysInput).handler(async ({ input, context }) => {
    return listSdkKeys(sessionPrincipal(context.session.user.id), input);
  }),

  create: liveOwnerSessionProcedure.input(createSdkKeyInput).handler(async ({ input, context }) => {
    return createSdkKey(
      sessionPrincipal(context.session.user.id, context.session.session.id),
      input,
    );
  }),

  revoke: protectedProcedure.input(revokeSdkKeyInput).handler(async ({ input, context }) => {
    return revokeSdkKey(sessionPrincipal(context.session.user.id), input);
  }),
};
