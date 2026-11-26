import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";
import { createRouter } from "@tanstack/react-router";
import { setupRouterSsrQueryIntegration } from "@tanstack/react-router-ssr-query";
import { createIsomorphicFn } from "@tanstack/react-start";
import { getRequestHeader } from "@tanstack/react-start/server";
import { isSafeAssetScriptPath } from "@wssp/config/locales";
import { toast } from "@wssp/ui/components/sileo";

import ErrorState from "./components/error-state";
import { RouteContentSkeleton } from "./components/route-content-skeleton";
import i18n, { createRequestI18n } from "./i18n";
import {
  onDocumentReplaced,
  sealQueryClient,
  skipErrorToastForIdentity,
  watchDocumentRestore,
} from "./lib/document-identity";
import { MAIN_SCROLLER_SELECTOR } from "./lib/main-scroller";
import { networkFailureKind } from "./lib/network-failure";
import { installOfflineMutationPolicy } from "./lib/offline-mutations";
import { capturePoolInviteFragment } from "./lib/pool-invite";
import { routeTree } from "./routeTree.gen";
import { useOrphanCredentials } from "./stores/orphan-credentials";
import { friendly } from "./utils/friendly-error";
import { orpc } from "./utils/orpc";

// Read the per-request CSP nonce forwarded by the API server on the
// `x-csp-nonce` request header (set in apps/server/src/index.ts). Server-only:
// createIsomorphicFn strips the `.server()` branch — and its server-only
// import — from the client bundle, so this is safe in this shared module.
const getCspNonce = createIsomorphicFn()
  .server(() => getRequestHeader("x-csp-nonce") ?? undefined)
  .client(() => undefined);

// Same-origin URL of the active non-default locale's grouped bundle chunk,
// resolved by the API server from the client Vite manifest and forwarded on
// `x-locale-modulepreload`. Server-only: the client branch is intentionally
// `undefined`. After hydrate, TanStack may drop the SSR-emitted modulepreload
// `<link>` from the document head once router context no longer carries the
// URL — that is fine because `client.tsx` runs `prepareI18n()` *before*
// `hydrateRoot`, so the dynamic locale import already owns the module graph by
// the time the link can disappear.
const getLocaleModulePreloadUrl = createIsomorphicFn()
  .server(() => {
    const href = getRequestHeader("x-locale-modulepreload");
    // Defense in depth: only same-origin /assets/*.js paths may reach the HTML
    // head (the API server already validates, but never trust a request header
    // blindly if it somehow bypassed the strip/set path).
    if (!href || !isSafeAssetScriptPath(href)) {
      return undefined;
    }
    return href;
  })
  .client(() => undefined);

// The i18n instance the app renders from (root `I18nextProvider` +
// `$lang`'s `beforeLoad`). Per-request on the server — `getRouter()` runs once
// per SSR request, and a fresh instance keeps concurrent requests for
// different locales from racing on a shared `changeLanguage`. The client uses
// the module singleton (language detector, localStorage persistence, lazy
// locale loading all live there).
const getI18n = createIsomorphicFn()
  .server(() => createRequestI18n())
  .client(() => i18n);

export function getRouter() {
  if (typeof window !== "undefined") capturePoolInviteFragment();
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { staleTime: 1000 * 60 * 5 },
    },
    queryCache: new QueryCache({
      onError: (error, query) => {
        // Client feedback only. `_public` loaders run ensureQueryData during
        // SSR, and sileo's toast queue is module-scoped with no server-side
        // Toaster to drain it (see __root's <ClientOnly> Toaster) — a toast
        // fired here on the server would sit in the long-lived process
        // forever. Server-side failures already surface through the loader →
        // defaultErrorComponent path.
        if (typeof window === "undefined") return;
        // Before any opt-out: a 401 asks Better Auth to check the session once
        // (a session lost elsewhere then replaces the document,
        // lib/document-identity.ts) instead of toasting once per mounted query.
        if (skipErrorToastForIdentity(error, "query")) return;
        // Polling queries that already render inline state opt out with
        // `meta: { skipGlobalErrorToast: true }` — symmetric with the mutation
        // cache below — so a flaky connection doesn't spam toasts on top of
        // the InlineRetry the page already shows.
        if (query.meta?.skipGlobalErrorToast) return;
        // Offline, the shell's OfflineBanner and the page's own offline state
        // already explain it; one toast per failed query would pile up.
        if (networkFailureKind(error) === "offline") return;
        toast.error(friendly(error), {
          action: {
            label: i18n.t("common:actions.tryAgain"),
            onClick: query.invalidate,
          },
        });
      },
    }),
    mutationCache: new MutationCache({
      // Surface mutation failures by default so no action ever fails silently.
      // Mutations that handle their own errors (e.g. inline form errors) can
      // opt out with `useMutation({ meta: { skipGlobalErrorToast: true } })`.
      // Mutations that just want context-specific fallback copy (instead of the
      // generic "Something didn't work") set
      // `meta: { errorFallbackKey: "ns:key" }` — no per-call onError toast.
      onError: (error, _vars, _ctx, mutation) => {
        // Same SSR guard as the query cache: no Toaster drains the queue on
        // the server.
        if (typeof window === "undefined") return;
        // Before the opt-out, so a 401 on an action with its own error UI
        // still checks the session.
        if (skipErrorToastForIdentity(error, "mutation")) return;
        if (mutation.meta?.skipGlobalErrorToast) return;
        const fallback = mutation.meta?.errorFallbackKey
          ? i18n.t(mutation.meta.errorFallbackKey)
          : undefined;
        toast.error(friendly(error, fallback));
      },
    }),
  });
  // Offline mutations fail fast with "You're offline…" (via friendly()) instead
  // of pausing silently; `meta: { offline: "queue" }` opts a replay-safe write
  // into waiting for the network, with a notice. See docs/design/shell-rules.md
  // § Offline.
  installOfflineMutationPolicy(queryClient, {
    queued: () => toast.info(i18n.t("common:offline.queued")),
    sent: () => toast.success(i18n.t("common:offline.queuedSent")),
  });

  // A signed-in copy of this document restored from the back/forward cache
  // reloads instead of showing a page nobody re-checked; and when another
  // identity is confirmed or an explicit sign-out leaves, this client's data
  // and the in-memory orphan-credential warnings are dropped before the page
  // load (lib/document-identity.ts). Client only; no-ops during SSR.
  watchDocumentRestore();
  if (typeof window !== "undefined") {
    onDocumentReplaced(() => {
      sealQueryClient(queryClient);
      useOrphanCredentials.getState().clear();
    });
  }

  const router = createRouter({
    routeTree,
    defaultPreload: "intent",
    defaultPreloadStaleTime: 0,
    // A loading route shows a skeleton of its own content area, shaped by its
    // `staticData` (lib/pending-layout.ts), inside the shell that is already
    // on screen: never a bare list, never a frame without the nav.
    // See docs/design/shell-rules.md § Route pending states
    defaultPendingComponent: RouteContentSkeleton,
    defaultHashScrollIntoView: false,
    defaultErrorComponent: ErrorState,
    context: {
      orpc,
      queryClient,
      i18n: getI18n(),
      // Server-only: content-hashed locale aggregate for SSR modulepreload.
      // undefined on the client and for the default locale.
      localeModulePreloadUrl: getLocaleModulePreloadUrl(),
    },
    scrollRestoration: true,
    scrollToTopSelectors: [MAIN_SCROLLER_SELECTOR],
    // CSP nonce for SSR-injected inline scripts (hydration, etc.). Matches the
    // nonce in the script-src CSP header set by the API server. undefined on
    // the client (the document already carries the server-rendered nonce).
    ssr: { nonce: getCspNonce() },
  });

  setupRouterSsrQueryIntegration({ router, queryClient });

  return router;
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof getRouter>;
  }
}

declare module "@tanstack/react-query" {
  interface Register {
    queryMeta: {
      /** Suppress the global error toast for this query. */
      skipGlobalErrorToast?: boolean;
    };
    mutationMeta: {
      /** Suppress the global error toast for this mutation. */
      skipGlobalErrorToast?: boolean;
      /**
       * i18n key resolved (outside React, via the app i18n instance) and
       * passed to `friendly()` as the context-specific fallback copy for the
       * global error toast. Use this instead of a per-call `onError` that only
       * called `toast.error(friendly(err, t("ns:key")))`.
       */
      errorFallbackKey?: string;
      /**
       * `"queue"`: while offline, wait and send on reconnect (with a notice)
       * instead of failing fast. Only for writes that are safe to replay. See
       * docs/design/shell-rules.md § Offline.
       */
      offline?: "queue";
    };
  }
}
