import * as live from "../credentials/live";
import * as loginSessions from "../credentials/login-sessions";
import * as logins from "../credentials/service";
import { liveOwnerSessionProcedure, protectedProcedure } from "../index";
import { sessionPrincipal } from "../sandbox";
import { attachSandboxCredentialInput, freeSandboxCredentialInput } from "../sandbox/contracts";

/**
 * Browser plane for CLI logins. Reads and ordinary
 * writes are `protectedProcedure` (session + required 2FA). Login create (it
 * may choose PROXY delivery or foreign opt-in), copy-back/foreign policy and
 * re-pin are `liveOwnerSessionProcedure`: durable, non-impersonated owner
 * session. Force-release and "discard rejected captures" (C11) are owner
 * recovery actions on an instance, budgeted inside their services. Budgets are consumed inside the shared services, so `/v1` and the
 * dashboard share one count per owner. Values are write-only.
 */
export const loginsRouter = {
  status: protectedProcedure.handler(({ context }) =>
    logins.status(sessionPrincipal(context.session.user.id), undefined),
  ),
  listDefinitions: protectedProcedure
    .input(logins.credentialPageInput)
    .handler(({ input, context }) =>
      logins.listDefinitions(sessionPrincipal(context.session.user.id), input),
    ),
  getDefinition: protectedProcedure
    .input(logins.credentialIdInput)
    .handler(({ input, context }) =>
      logins.getDefinition(sessionPrincipal(context.session.user.id), input),
    ),
  listLogins: protectedProcedure
    .input(logins.credentialPageInput)
    .handler(({ input, context }) =>
      logins.listLogins(sessionPrincipal(context.session.user.id), input),
    ),
  getLogin: protectedProcedure
    .input(logins.credentialIdInput)
    .handler(({ input, context }) =>
      logins.getLogin(sessionPrincipal(context.session.user.id), input),
    ),
  listEvents: protectedProcedure
    .input(logins.credentialScopedPageInput)
    .handler(({ input, context }) =>
      logins.listEvents(sessionPrincipal(context.session.user.id), input),
    ),
  listAccounts: protectedProcedure
    .input(logins.credentialScopedPageInput)
    .handler(({ input, context }) =>
      logins.listAccounts(sessionPrincipal(context.session.user.id), input),
    ),
  listInstances: protectedProcedure
    .input(logins.accountScopedPageInput)
    .handler(({ input, context }) =>
      logins.listInstances(sessionPrincipal(context.session.user.id), input),
    ),
  createDefinition: protectedProcedure
    .input(logins.createDefinitionInput)
    .handler(({ input, context }) =>
      logins.createDefinition(sessionPrincipal(context.session.user.id), input),
    ),
  archiveDefinition: protectedProcedure
    .input(logins.credentialIdInput)
    .handler(({ input, context }) =>
      logins.archiveDefinition(sessionPrincipal(context.session.user.id), input),
    ),
  updateLogin: protectedProcedure
    .input(logins.updateLoginInput)
    .handler(({ input, context }) =>
      logins.updateLogin(sessionPrincipal(context.session.user.id), input),
    ),
  deleteLogin: protectedProcedure
    .input(logins.credentialIdInput)
    .handler(({ input, context }) =>
      logins.deleteLogin(sessionPrincipal(context.session.user.id), input),
    ),
  createAccount: protectedProcedure
    .input(logins.createAccountInput)
    .handler(({ input, context }) =>
      logins.createAccount(sessionPrincipal(context.session.user.id), input),
    ),
  updateAccount: protectedProcedure
    .input(logins.updateAccountInput)
    .handler(({ input, context }) =>
      logins.updateAccount(sessionPrincipal(context.session.user.id), input),
    ),
  deleteAccount: protectedProcedure
    .input(logins.accountIdInput)
    .handler(({ input, context }) =>
      logins.deleteAccount(sessionPrincipal(context.session.user.id), input),
    ),
  createInstance: protectedProcedure
    .input(logins.createInstanceInput)
    .handler(({ input, context }) =>
      logins.createInstance(sessionPrincipal(context.session.user.id), input),
    ),
  updateInstance: protectedProcedure
    .input(logins.updateInstanceInput)
    .handler(({ input, context }) =>
      logins.updateInstance(sessionPrincipal(context.session.user.id), input),
    ),
  deleteInstance: protectedProcedure
    .input(logins.instanceIdInput)
    .handler(({ input, context }) =>
      logins.deleteInstance(sessionPrincipal(context.session.user.id), input),
    ),
  writeValue: protectedProcedure
    .input(logins.writeValueInput)
    .handler(({ input, context }) =>
      logins.writeValue(sessionPrincipal(context.session.user.id), input),
    ),
  listInstanceLeases: protectedProcedure
    .input(logins.instanceScopedPageInput)
    .handler(({ input, context }) =>
      logins.listInstanceLeases(sessionPrincipal(context.session.user.id), input),
    ),
  listRejectedCaptures: protectedProcedure
    .input(logins.instanceScopedPageInput)
    .handler(({ input, context }) =>
      logins.listRejectedCaptures(sessionPrincipal(context.session.user.id), input),
    ),
  forceRelease: protectedProcedure
    .input(logins.forceReleaseInput)
    .handler(({ input, context }) =>
      logins.forceRelease(sessionPrincipal(context.session.user.id), input),
    ),
  discardRejectedCaptures: protectedProcedure
    .input(logins.discardRejectedInput)
    .handler(({ input, context }) =>
      logins.discardRejectedCaptures(sessionPrincipal(context.session.user.id), input),
    ),
  createLogin: liveOwnerSessionProcedure
    .input(logins.createLoginInput)
    .handler(({ input, context }) =>
      logins.createLogin(sessionPrincipal(context.session.user.id), input),
    ),
  updateLoginPolicy: liveOwnerSessionProcedure
    .input(logins.updateLoginPolicyInput)
    .handler(({ input, context }) =>
      logins.updateLoginPolicy(sessionPrincipal(context.session.user.id), input),
    ),
  repinLogin: liveOwnerSessionProcedure
    .input(logins.repinLoginInput)
    .handler(({ input, context }) =>
      logins.repinLogin(sessionPrincipal(context.session.user.id), input),
    ),
  // The login sandbox flow (§11): start, read, finish (save), verify and
  // cancel. Session-only and budgeted inside the services; the flow acts on
  // its managed sandbox with its own principal.
  startLogin: protectedProcedure
    .input(loginSessions.startLoginInput)
    .handler(({ input, context }) =>
      loginSessions.startLogin(sessionPrincipal(context.session.user.id), input),
    ),
  getLoginSession: protectedProcedure
    .input(loginSessions.loginSessionIdInput)
    .handler(({ input, context }) =>
      loginSessions.getLoginSession(sessionPrincipal(context.session.user.id), input),
    ),
  listLoginSessions: protectedProcedure
    .input(loginSessions.listLoginSessionsInput)
    .handler(({ input, context }) =>
      loginSessions.listLoginSessions(sessionPrincipal(context.session.user.id), input),
    ),
  finishLogin: protectedProcedure
    .input(loginSessions.loginSessionIdInput)
    .handler(({ input, context }) =>
      loginSessions.finishLogin(sessionPrincipal(context.session.user.id), input),
    ),
  verifyLogin: protectedProcedure
    .input(loginSessions.loginSessionIdInput)
    .handler(({ input, context }) =>
      loginSessions.verifyLogin(sessionPrincipal(context.session.user.id), input),
    ),
  cancelLogin: protectedProcedure
    .input(loginSessions.loginSessionIdInput)
    .handler(({ input, context }) =>
      loginSessions.cancelLogin(sessionPrincipal(context.session.user.id), input),
    ),
  // Live attach / free on a sandbox (budgeted in the
  // services; the same procedures back `/v1`).
  attachSandboxCredential: protectedProcedure
    .input(attachSandboxCredentialInput)
    .handler(({ input, context }) =>
      live.attachSandboxCredential(sessionPrincipal(context.session.user.id), input),
    ),
  freeSandboxCredential: protectedProcedure
    .input(freeSandboxCredentialInput)
    .handler(({ input, context }) =>
      live.freeSandboxCredential(sessionPrincipal(context.session.user.id), input),
    ),
  // The sandbox detail Credentials panel: open attachments, metadata only.
  listSandboxCredentials: protectedProcedure
    .input(live.listSandboxCredentialsInput)
    .handler(({ input, context }) =>
      live.listSandboxCredentials(sessionPrincipal(context.session.user.id), input),
    ),
};
