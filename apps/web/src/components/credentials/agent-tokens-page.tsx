import { useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import { env } from "@wssp/env/web";
import { Button } from "@wssp/ui/components/button";
import { CodeSnippet } from "@wssp/ui/components/code-snippet";
import { CopyField } from "@wssp/ui/components/copy-field";
import { useTranslation } from "react-i18next";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { useRevoke } from "@/components/credentials/credential-parts";
import { LoadMore } from "@/components/load-more";
import { QueryBoundary } from "@/components/query-boundary";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { orpc } from "@/utils/orpc";
import { SdkKeysPage } from "./sdk-keys-page";

// Wrap long snippets on phones instead of scrolling them under the copy button.
const WRAPPED_SNIPPET = "min-h-13 whitespace-pre-wrap [overflow-wrap:anywhere]";
export function AgentTokensPage({ lang }: { lang: string }) {
  const { t } = useTranslation("agents");
  const url = new URL("/mcp", env.VITE_SERVER_URL).href;
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <SdkKeysPage lang={lang} agent />
      <section className="flex min-w-0 flex-col gap-3 rounded-xl border p-4">
        <h2 className="font-semibold">{t("connect.title")}</h2>
        <p>{t("connect.description")}</p>
        <CopyField value={url} copyLabel={t("connect.copyUrl")} />
        <p>{t("connect.oauth")}</p>
        <CodeSnippet
          code={`claude mcp add --transport http wssp ${url}`}
          copyLabel={t("connect.copyCommand")}
          preClassName={WRAPPED_SNIPPET}
        />
        <CodeSnippet
          code={`[mcp_servers.wssp]\nurl = "${url}"\nbearer_token_env_var = "WSSP_AGENT_TOKEN"`}
          copyLabel={t("connect.copyConfig")}
          preClassName={WRAPPED_SNIPPET}
        />
        <p>{t("connect.token")}</p>
      </section>
      <ConnectedApps lang={lang} />
    </div>
  );
}
function ConnectedApps({ lang }: { lang: string }) {
  const { t } = useTranslation("agents");
  const grants = useInfiniteQuery({
    ...orpc.mcpGrants.list.infiniteOptions({
      input: (cursor: string | undefined) => ({ limit: 20, cursor }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (page) => page.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [grants.error]);
  return (
    <section className="flex min-w-0 flex-col gap-3">
      <h2 className="font-semibold">{t("apps.title")}</h2>
      <QueryBoundary
        query={{ ...grants, data: grants.data?.pages.flatMap((page) => page.items) }}
        skeleton={<SkeletonList count={2} />}
      >
        {(items) => (
          <>
            <ul className="flex min-w-0 flex-col gap-3">
              {items.map((grant) => (
                <ConnectedApp key={grant.id} lang={lang} grant={grant} />
              ))}
            </ul>
            {items.length === 0 ? <p>{t("apps.empty")}</p> : null}
            <LoadMore
              hasNextPage={grants.hasNextPage}
              isFetchingNextPage={grants.isFetchingNextPage}
              onLoadMore={() => void grants.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
    </section>
  );
}
type Grant = Awaited<ReturnType<typeof orpc.mcpGrants.list.call>>["items"][number];
function ConnectedApp({ lang, grant }: { lang: string; grant: Grant }) {
  const { t } = useTranslation(["agents", "credentials", "sdkKeys"]);
  const client = useQueryClient();
  const revoke = useRevoke(
    lang,
    (id) => orpc.mcpGrants.revoke.call({ id }),
    t("agents:apps.revoked"),
    () => void client.invalidateQueries({ queryKey: orpc.mcpGrants.list.key() }),
  );
  return (
    <li className="flex min-w-0 flex-col gap-2 rounded-xl border p-4">
      <p className="break-words font-medium">{grant.SdkKey.name}</p>
      <p className="break-all font-mono text-xs text-muted-foreground">{grant.clientId}</p>
      <ul className="flex flex-wrap gap-2">
        {grant.SdkKey.scopes.map((scope) => (
          <li
            key={scope}
            className="inline-flex items-center rounded-sm border px-2 py-0.5 font-mono text-xs"
          >
            {scope}
          </li>
        ))}
      </ul>
      <p>{t(grant.SdkKey.ownSandboxesOnly ? "agents:apps.ownOnly" : "agents:apps.allSandboxes")}</p>
      <p>{t(`sdkKeys:form.mode.${grant.SdkKey.resourceMode}`)}</p>
      <p>{t(`sdkKeys:poolMode.${grant.SdkKey.poolMode}`)}</p>
      <Button
        size="touch"
        variant="destructive"
        className="sm:self-start"
        onClick={() => revoke.setConfirming(true)}
      >
        {t("credentials:revoke.action")}
      </Button>
      {revoke.problem ? <p role="alert">{t(`credentials:problem.${revoke.problem}`)}</p> : null}
      <ConfirmDeleteDialog
        open={revoke.confirming}
        onOpenChange={revoke.setConfirming}
        title={t("agents:apps.revokeTitle")}
        description={t("agents:apps.revokeDescription")}
        confirmToken={grant.SdkKey.name}
        typePrompt={t("sdkKeys:revoke.typePrompt")}
        copyAriaLabel={t("sdkKeys:revoke.copyName")}
        confirmLabel={t("credentials:revoke.confirm")}
        pendingLabel={t("credentials:revoke.pending")}
        isPending={revoke.mutation.isPending}
        onConfirm={() => revoke.mutation.mutate(grant.id)}
      />
    </li>
  );
}
