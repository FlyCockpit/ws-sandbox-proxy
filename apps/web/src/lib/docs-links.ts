/**
 * Links into the product docs. The docs live in the repository's `docs/`
 * directory. A deployment that publishes them elsewhere sets `VITE_DOCS_URL`;
 * without it every link points at the canonical repository's docs on GitHub,
 * so Help and the in-page guide links always resolve.
 */

/** The canonical repository's docs, used when `VITE_DOCS_URL` is unset. */
export const DEFAULT_DOCS_URL = "https://github.com/FlyCockpit/ws-sandbox-proxy/blob/main/docs";

/** Doc pages the dashboard refers to, relative to the repository's `docs/`. */
export const DOC_PAGES = {
  templates: "operations/templates.md",
  environment: "operations/environment-variables.md",
  hostsQuickStart: "guide/hosts.md#quick-start-your-first-host",
  hostsService: "guide/hosts.md#run-as-a-service",
  guide: "guide/README.md",
  sdkKeys: "guide/auth-planes.md#sdk-plane",
  cli: "guide/cli.md#install",
  tunnels: "guide/tunnels.md",
  connect: "guide/connect.md",
  cliInstall: "guide/cli.md#install",
  poolHostPolicy: "guide/pools.md#what-a-pools-hosts-allow-other-accounts",
} as const;

export type DocPage = keyof typeof DOC_PAGES;

/** Absolute URL of a doc page under `base`, or under `DEFAULT_DOCS_URL` when none is set. */
export function docsUrl(base: string | undefined, page: DocPage): string {
  return `${(base || DEFAULT_DOCS_URL).replace(/\/+$/, "")}/${DOC_PAGES[page]}`;
}
