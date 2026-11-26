import type { RouterClient } from "@orpc/server";
import { getSignupEnabled } from "@wssp/auth/signup-policy";
import { ADMIN_EMAILS } from "@wssp/env/server";
import { isEmailConfigured } from "@wssp/mailer";
import { publicProcedure } from "../index";
import { adminExistsForAppConfig } from "../lib/admin-presence";
import { adminDataKeysRouter } from "./admin-data-keys";
import { adminObservabilityRouter } from "./admin-observability";
import { adminTunnelRouter } from "./admin-tunnel";
import { agentTokensRouter } from "./agent-tokens";
import { authRouter } from "./auth";
import { communityTemplatesRouter } from "./community-templates";
import { hostCredentialsRouter } from "./host-credentials";
import { hostQueuedCommandsRouter } from "./host-queued-commands";
import { hostTerminalsRouter } from "./host-terminals";
import { loginsRouter } from "./logins";
import { mcpGrantsRouter } from "./mcp-grants";
import { pushRouter } from "./push";
import { queueRouter } from "./queue";
import { sandboxHostsRouter } from "./sandbox-hosts";
import { sandboxPoolsRouter } from "./sandbox-pools";
import { sandboxTemplatesRouter } from "./sandbox-templates";
import { sandboxTerminalsRouter } from "./sandbox-terminals";
import { sandboxesRouter } from "./sandboxes";
import { sdkKeysRouter } from "./sdk-keys";
import { settingsRouter } from "./settings";
import { setupRouter } from "./setup";
import { templateBuildsRouter } from "./template-builds";
import { terminalsRouter } from "./terminals";
import { userLoginsRouter } from "./user-logins";
import { usersRouter } from "./users";
import { webhooksRouter } from "./webhooks";

export const appRouter = {
  hostQueuedCommands: hostQueuedCommandsRouter,
  health: {
    // No RPC readiness probe: a DB-touching `ready` procedure would be an
    // anonymous datastore-drain vector bounded only by the generic /rpc
    // limiter. Readiness is the HTTP /ready route, which has its own
    // readyLimiter bucket (apps/server/src/rate-limit.ts).
    check: publicProcedure.handler(() => {
      return "OK";
    }),
  },
  appConfig: publicProcedure.handler(async () => {
    const signupEnabled = await getSignupEnabled();
    return {
      signupEnabled,
      // Sign-up is closed, `ADMIN_EMAILS` names the operator, and no active
      // administrator exists yet: the landing page leads with "Set up this
      // server". Once one exists this turns false and the pages show the
      // invite-only state, so an established server never greets visitors
      // with a set-up step. Revealing "no admin yet" is acceptable: such a
      // server is not usable by anyone else either. The DB read is skipped
      // unless the sign-up rules make bootstrap possible, and a "yes" is
      // cached (lib/admin-presence.ts).
      adminBootstrapSignupEnabled:
        !signupEnabled && ADMIN_EMAILS.size > 0 && !(await adminExistsForAppConfig()),
      // Gates the login challenge's "email me a code" affordance. The delivery
      // unreliability of Better-Auth's send-otp endpoint (it swallows SMTP
      // failures) is handled separately by the `auth.verifyEmailTransport`
      // preflight; this flag only reflects whether email is configured at all.
      emailEnabled: isEmailConfigured(),
    };
  }),
  auth: authRouter,
  settings: settingsRouter,
  // First-admin setup link (SETUP_KEY) — lib/admin-bootstrap.ts.
  setup: setupRouter,
  push: pushRouter,
  queue: queueRouter,
  users: usersRouter,
  adminObservability: adminObservabilityRouter,
  adminDataKeys: adminDataKeysRouter,
  adminTunnel: adminTunnelRouter,
  hostCredentials: hostCredentialsRouter,
  userLogins: userLoginsRouter,
  sandboxHosts: sandboxHostsRouter,
  sandboxPools: sandboxPoolsRouter,
  sandboxTemplates: sandboxTemplatesRouter,
  templateBuilds: templateBuildsRouter,
  communityTemplates: communityTemplatesRouter,
  sandboxes: sandboxesRouter,
  sandboxTerminals: sandboxTerminalsRouter,
  hostTerminals: hostTerminalsRouter,
  terminals: terminalsRouter,
  sdkKeys: sdkKeysRouter,
  agentTokens: agentTokensRouter,
  mcpGrants: mcpGrantsRouter,
  webhooks: webhooksRouter,
  logins: loginsRouter,
};
export type AppRouter = typeof appRouter;
export type AppRouterClient = RouterClient<typeof appRouter>;
