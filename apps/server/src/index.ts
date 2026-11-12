// Load repo-root `.env` before validated config and the application graph.
import "@wssp/env/load-dotenv";

import { serve } from "@hono/node-server";
import { templateBuildsConfig } from "@wssp/api/template-builds/config";
import { loadWebhookConfig } from "@wssp/api/webhooks/config";
import prisma from "@wssp/db";
import { hasActiveAdministrator } from "@wssp/db/admin-governance";
import { ADMIN_EMAILS, env } from "@wssp/env/server";
import { WebSocketServer } from "ws";
import { logAdminSetupHint } from "./admin-setup-log.js";
import { createApp } from "./app.js";
import { createServerLifecycle } from "./lifecycle.js";
import { selectWebSocketSubprotocol } from "./sandbox-relay/browser-terminal-upgrade.js";
import { deploymentEgressBlocklist } from "./sandbox-relay/egress-blocklist.js";
import { SANDBOX_FRAME_MAX_BYTES } from "./sandbox-relay/protocol.js";

// Fail boot on an invalid webhook allowlist instead of at the first create.
loadWebhookConfig();
// Template builds never fail boot: this logs a lease clamp or the reason builds
// are unavailable once, at start (capabilities re-resolve per request).
templateBuildsConfig();
// Validate (and log) the deployment egress blocklist at boot; never fails boot.
deploymentEgressBlocklist();

const lifecycle = createServerLifecycle();
export const app = await createApp(lifecycle);

const sandboxRelayWebsocket = {
  server: new WebSocketServer({
    maxPayload: SANDBOX_FRAME_MAX_BYTES,
    noServer: true,
    // Path-aware: the relay and the browser terminal (C53) each select
    // only their own subprotocol; the terminal ticket is never echoed.
    handleProtocols(protocols, request) {
      return selectWebSocketSubprotocol(protocols, request.url);
    },
  }),
};

await lifecycle.start(
  () =>
    new Promise<ReturnType<typeof serve>>((resolve, reject) => {
      const onError = (error: Error) => reject(error);
      const server = serve(
        {
          fetch: app.fetch,
          port: env.SERVER_PORT ?? env.PORT ?? 3000,
          // Node's default keepAliveTimeout (5s) is shorter than the idle-reuse window of
          // fronting proxies (nginx keepalive_timeout defaults to 60-75s; Traefik similar),
          // so the app would drop sockets the proxy still considers open → sporadic 502s/
          // ECONNRESETs. The app timeout must exceed the proxy's (65s here), and Node
          // requires headersTimeout > keepAliveTimeout (66s).
          serverOptions: {
            keepAliveTimeout: 65_000,
            headersTimeout: 66_000,
          },
          websocket: sandboxRelayWebsocket,
        },
        (info) => {
          console.log(`Server is running on http://localhost:${info.port}`);
          server.off("error", onError);
          resolve(server);
        },
      );
      server.once("error", onError);
    }),
);

// Operator-only hint (M7-S14): the web UI shows no admin-setup banner.
void logAdminSetupHint({
  hasActiveAdministrator: () => hasActiveAdministrator(prisma),
  adminEmailsConfigured: ADMIN_EMAILS.size > 0,
});
