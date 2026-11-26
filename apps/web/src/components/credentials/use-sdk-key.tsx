import { env } from "@wssp/env/web";
import { CodeSnippet } from "@wssp/ui/components/code-snippet";
import { CopyField } from "@wssp/ui/components/copy-field";
import { useTranslation } from "react-i18next";
import { docsRepoPath, docsUrl } from "@/lib/docs-links";
import { hostCommands } from "@/lib/host-status";

// Wrap long snippets on phones instead of scrolling them under the copy button.
const WRAPPED_SNIPPET = "min-h-13 whitespace-pre-wrap [overflow-wrap:anywhere]";

/** The `/v1` base URL of this server, derived the same way as the MCP URL. */
function sdkApiBaseUrl(serverUrl: string): string {
  return new URL("/v1", serverUrl).href;
}

/**
 * The snippets of the "Use this key" block. The key itself is never in them:
 * they read it from `WSSP_SDK_KEY` / `WSSP_API_KEY`, so copying a snippet
 * never copies the secret.
 */
function sdkKeySnippets(serverUrl: string) {
  const origin = new URL(serverUrl).origin;
  return {
    apiUrl: sdkApiBaseUrl(serverUrl),
    curl: `curl -fsS -H "Authorization: Bearer $WSSP_SDK_KEY" ${new URL("/v1/key", origin).href}`,
    // The SDK takes the server origin and adds /v1 itself (packages/sdk/README.md).
    sdk: [
      'import { createWsspClient } from "@wssp/sdk";',
      "",
      `const wssp = createWsspClient({ baseUrl: "${origin}", apiKey: process.env.WSSP_SDK_KEY ?? "" });`,
      "const key = await wssp.key.get();",
      "console.log(key.name, key.scopes);",
    ].join("\n"),
    cliInstall: hostCommands(origin).install,
    cliUse: [
      `export WSSP_SERVER=${origin}`,
      "export WSSP_API_KEY=$WSSP_SDK_KEY",
      "wssp sandbox list",
    ].join("\n"),
    cliLogin: `wssp login --server ${origin}`,
  };
}

/** A link into the guide, or its repository path when no docs base is configured. */
function GuideLink({ page, label }: { page: "sdkKeys" | "cli"; label: string }) {
  const { t } = useTranslation("sdkKeys");
  const href = docsUrl(env.VITE_DOCS_URL, page);
  return href ? (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      data-docs-link={page}
      className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
    >
      {label}
    </a>
  ) : (
    <span data-docs-path={page} className="text-sm text-muted-foreground">
      {t("useKey.docsPath", { path: docsRepoPath(page) })}
    </span>
  );
}

/**
 * "Use this key": the API base URL, a curl check, the TypeScript SDK and the
 * `wssp` CLI, with links into the guide. Shown under a newly created key and
 * on the SDK keys page.
 */
export function UseSdkKey() {
  const { t } = useTranslation("sdkKeys");
  const snippets = sdkKeySnippets(env.VITE_SERVER_URL);
  return (
    <section
      aria-labelledby="use-sdk-key-title"
      data-use-sdk-key=""
      className="flex min-w-0 flex-col gap-3 rounded-xl border p-4"
    >
      <h2 id="use-sdk-key-title" className="font-semibold">
        {t("useKey.title")}
      </h2>
      <p className="text-sm text-muted-foreground">{t("useKey.description")}</p>
      <p className="text-sm font-medium">{t("useKey.apiUrl")}</p>
      <CopyField value={snippets.apiUrl} copyLabel={t("useKey.copyApiUrl")} />
      <p className="text-sm">{t("useKey.curl")}</p>
      <CodeSnippet
        code={snippets.curl}
        copyLabel={t("useKey.copyCurl")}
        preClassName={WRAPPED_SNIPPET}
      />
      <p className="text-sm">{t("useKey.sdk")}</p>
      <CodeSnippet
        code={snippets.sdk}
        copyLabel={t("useKey.copySdk")}
        preClassName={WRAPPED_SNIPPET}
      />
      <GuideLink page="sdkKeys" label={t("useKey.sdkDocs")} />
      <p className="text-sm">{t("useKey.cli")}</p>
      <CodeSnippet
        code={snippets.cliInstall}
        copyLabel={t("useKey.copyCliInstall")}
        preClassName={WRAPPED_SNIPPET}
      />
      <CodeSnippet
        code={snippets.cliUse}
        copyLabel={t("useKey.copyCliUse")}
        preClassName={WRAPPED_SNIPPET}
      />
      <p className="text-sm text-muted-foreground">{t("useKey.cliLogin")}</p>
      <CodeSnippet
        code={snippets.cliLogin}
        copyLabel={t("useKey.copyCliLogin")}
        preClassName={WRAPPED_SNIPPET}
      />
      <GuideLink page="cli" label={t("useKey.cliDocs")} />
    </section>
  );
}
