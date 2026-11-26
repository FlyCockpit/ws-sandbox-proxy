/**
 * Links into the product docs. The docs live in the repository's `docs/`
 * directory; where they are published is deployment configuration
 * (`VITE_DOCS_URL`), never a hard-coded repository URL. With no base
 * configured the page shows the repository path as text instead of a link
 * that may not resolve.
 */

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
} as const;

export type DocPage = keyof typeof DOC_PAGES;

/** Absolute URL of a doc page under `base`, or null when no docs base is configured. */
export function docsUrl(base: string | undefined, page: DocPage): string | null {
  if (!base) return null;
  return `${base.replace(/\/+$/, "")}/${DOC_PAGES[page]}`;
}

/** The page's path in the repository, shown when there is no docs base to link to. */
export function docsRepoPath(page: DocPage): string {
  return `docs/${DOC_PAGES[page]}`;
}
