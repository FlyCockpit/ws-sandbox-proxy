import { createORPCClient, onError } from "@orpc/client";
import { RPCLink } from "@orpc/client/fetch";
import {
  BatchLinkPlugin,
  ClientRetryPlugin,
  DedupeRequestsPlugin,
  SimpleCsrfProtectionLinkPlugin,
} from "@orpc/client/plugins";
import { createTanstackQueryUtils } from "@orpc/tanstack-query";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { ORPC_BATCH_MAX_SIZE } from "@wssp/config/orpc-batch";
import { env } from "@wssp/env/web";

import {
  guardIdentityResponse,
  isDocumentReplaced,
  reportSessionRejected,
  withExpectedIdentity,
} from "@/lib/document-identity";

const link = new RPCLink({
  url: `${env.VITE_SERVER_URL}/rpc`,
  interceptors: [
    onError((error) => {
      if (
        error &&
        typeof error === "object" &&
        (("code" in error && error.code === "UNAUTHORIZED") ||
          ("status" in error && error.status === 401))
      )
        reportSessionRejected(error);
    }),
  ],
  plugins: [
    new SimpleCsrfProtectionLinkPlugin(),
    // `maxSize` must stay in sync with the server's `BatchHandlerPlugin` —
    // pass the shared constant on both sides, never a literal. A client value
    // above the server's makes the server 413 the whole batch. See
    // `packages/config/src/orpc-batch.ts`.
    new BatchLinkPlugin({
      groups: [{ condition: () => true, context: {} }],
      maxSize: ORPC_BATCH_MAX_SIZE,
    }),
    new DedupeRequestsPlugin({ groups: [{ condition: () => true, context: {} }] }),
    // ClientRetryPlugin only retries procedures that explicitly opt in via
    // `context: { retry: N }`. No procedure in this app opts in, so 429s are
    // never silently retried here — the global error handler in router.tsx
    // surfaces them as a friendly toast instead.
    new ClientRetryPlugin(),
  ],
  async fetch(url, options) {
    if (isDocumentReplaced()) return new Promise<never>(() => {});
    return guardIdentityResponse(
      await fetch(url, {
        ...options,
        credentials: "include",
        headers: withExpectedIdentity(url.headers),
      }),
    );
  },
});

const client: AppRouterClient = createORPCClient(link);

export const orpc = createTanstackQueryUtils(client);
