import { useInfiniteQuery } from "@tanstack/react-query";
import { env } from "@wssp/env/web";
import { Badge } from "@wssp/ui/components/badge";
import { CopyField } from "@wssp/ui/components/copy-field";
import { Trans, useTranslation } from "react-i18next";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { LoadMore } from "@/components/load-more";
import { QueryBoundary } from "@/components/query-boundary";
import { SandboxDocLink } from "@/components/sandboxes/sandbox-ports";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { formatBytes } from "@/lib/format-bytes";
import { dateTimeTitle } from "@/lib/format-date-time";
import { hostCommands, shellWord } from "@/lib/host-status";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";

/**
 * The sandbox detail "Recent connections" panel: the owner's
 * CLI connections to this sandbox, newest first, one bounded page at a time.
 * Metadata only (key, origin, times, end reason, channel counts, forwarded
 * guest ports, bytes): the server never records what ran.
 */

/** One-time ssh setup (`docs/guide/connect.md`). */
const SSH_CONFIG_INSTALL = "wssp ssh-config --install";

/** The server keeps at most 16 forwarded ports per connection; never show more. */
const FORWARDED_PORTS_SHOWN = 16;

const KNOWN_INTENTS = new Set([
  "client",
  "detached",
  "backpressure",
  "revoked",
  "superseded",
  "protocol_violation",
  "host_disconnected",
  "expired",
  "sandbox_stopped",
  "sandbox_destroyed",
  "lifecycle_unconfirmed",
  "shutdown",
]);

/** The translation key of a close intent (an unknown one reads "other"). */
export function connectionIntentKey(intent: string | null): string | null {
  if (intent === null) return null;
  return `sandboxes:connections.intent.${KNOWN_INTENTS.has(intent) ? intent : "other"}`;
}

function portList(ports: readonly number[], locale: string): string {
  const shown = ports.slice(0, FORWARDED_PORTS_SHOWN).map((port) => String(port));
  return new Intl.ListFormat(locale, { type: "unit", style: "short" }).format(shown);
}

function bytes(value: string, locale: string): string {
  const parsed = Number(value);
  return formatBytes(Number.isFinite(parsed) && parsed >= 0 ? parsed : 0, locale);
}

/**
 * The sandbox detail "Connect" hint: the CLI
 * commands that reach this sandbox, a shell and plain ssh. Commands only;
 * nothing here talks to the sandbox.
 */
export function SandboxConnectHint({ target }: { target: string }) {
  const { t } = useTranslation(["sandboxes"]);
  const cli = hostCommands(env.VITE_SERVER_URL);
  const commands = [
    {
      value: t("sandboxes:connect.shellCommand", { target }),
      copy: t("sandboxes:connect.copyShell"),
    },
    { value: t("sandboxes:connect.sshCommand", { target }), copy: t("sandboxes:connect.copySsh") },
  ];
  return (
    <section
      aria-labelledby="sandbox-connect"
      data-sandbox-connect=""
      className="flex min-w-0 flex-col gap-2 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <h3 id="sandbox-connect" className="font-heading text-sm font-semibold">
        {t("sandboxes:connect.heading")}
      </h3>
      <p className="text-sm text-muted-foreground">{t("sandboxes:connect.description")}</p>
      <ul aria-label={t("sandboxes:connect.label")} className="flex min-w-0 flex-col gap-2">
        {commands.map((command) => (
          <li key={command.value} className="min-w-0">
            <CopyField value={command.value} copyLabel={command.copy} />
          </li>
        ))}
      </ul>
      <p className="text-sm text-muted-foreground">{t("sandboxes:connect.sshSetup")}</p>
      <CopyField value={SSH_CONFIG_INSTALL} copyLabel={t("sandboxes:connect.copySetup")} />
      <details data-get-cli="" className="group min-w-0 text-sm">
        <summary className="inline-flex min-h-11 cursor-pointer items-center font-medium underline-offset-4 hover:underline">
          {t("sandboxes:connect.getCli")}
        </summary>
        <div className="flex min-w-0 flex-col gap-2 pt-1">
          <p className="text-muted-foreground">{t("sandboxes:connect.getCliHint")}</p>
          <CopyField value={cli.install} copyLabel={t("sandboxes:connect.copyInstall")} />
          <CopyField
            value={`wssp login --server ${shellWord(env.VITE_SERVER_URL)}`}
            copyLabel={t("sandboxes:connect.copyLogin")}
          />
          <SandboxDocLink page="cliInstall" label={t("sandboxes:connect.getCli")} />
        </div>
      </details>
    </section>
  );
}

export function SandboxConnections({ lang, sandboxId }: { lang: string; sandboxId: string }) {
  const { t, i18n } = useTranslation(["sandboxes", "dashboard"]);
  const locale = i18n.language;
  const query = useInfiniteQuery({
    ...orpc.sandboxes.listConnectSessions.infiniteOptions({
      input: (cursor: string | undefined) => ({
        id: sandboxId,
        limit: DASHBOARD_PAGE_LIMIT,
        cursor,
      }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [query.error]);
  const rows = query.data?.pages.flatMap((page) => page.items);
  const now = Date.now();

  return (
    <section
      aria-labelledby="sandbox-connections"
      data-sandbox-connections=""
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <h2 id="sandbox-connections" className="text-sm font-medium">
        {t("sandboxes:connections.heading")}
      </h2>
      <p className="text-sm text-muted-foreground">
        <Trans
          t={t}
          i18nKey="sandboxes:connections.description"
          components={{ code: <code className="whitespace-nowrap" /> }}
        />
      </p>
      <QueryBoundary
        query={{
          data: rows,
          isPending: query.isPending,
          isError: query.isError,
          fetchStatus: query.fetchStatus,
          error: query.error,
          refetch: query.refetch,
        }}
        skeleton={<SkeletonList count={2} layout="resource" className="rounded-lg border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(items) => items.length === 0}
        empty={
          <p data-connections-empty="" className="text-sm text-muted-foreground">
            {t("sandboxes:connections.empty")}
          </p>
        }
      >
        {(items) => (
          <>
            <ul
              aria-label={t("sandboxes:connections.label")}
              className="flex min-w-0 flex-col divide-y rounded-lg border"
            >
              {items.map((row) => {
                const opened = new Date(row.openedAt).getTime();
                const intent = connectionIntentKey(row.closeIntent);
                return (
                  <li
                    key={row.id}
                    data-connection-id={row.id}
                    data-connection-status={row.status}
                    className="flex min-w-0 flex-col gap-1 px-3 py-2 text-sm"
                  >
                    <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
                      <span className="min-w-0 break-words font-medium">
                        {row.keyName ?? t("sandboxes:connections.unknownKey")}
                      </span>
                      <span className="flex flex-wrap items-center gap-2">
                        <Badge variant="outline" data-origin={row.origin}>
                          {t(`sandboxes:connections.origin.${row.origin}`)}
                        </Badge>
                        <Badge
                          variant={row.status === "open" ? "default" : "outline"}
                          data-status={row.status}
                        >
                          {t(`sandboxes:connections.status.${row.status}`)}
                        </Badge>
                      </span>
                    </div>
                    <span className="text-muted-foreground" title={dateTimeTitle(opened, locale)}>
                      {t("sandboxes:connections.opened", {
                        when: formatRelativeTime(opened, locale, now),
                      })}
                    </span>
                    {intent ? (
                      <span data-close-intent={row.closeIntent} className="text-muted-foreground">
                        {t("sandboxes:connections.closedReason", { reason: t(intent) })}
                      </span>
                    ) : null}
                    <span className="break-words text-muted-foreground">
                      {[
                        t("sandboxes:connections.shells", { count: row.ptyChannels }),
                        t("sandboxes:connections.commands", { count: row.execChannels }),
                        ...(row.relayChannels > 0
                          ? [t("sandboxes:connections.forwards", { count: row.relayChannels })]
                          : []),
                        t("sandboxes:connections.bytes", {
                          sent: bytes(row.bytesIn, locale),
                          received: bytes(row.bytesOut, locale),
                        }),
                      ].join(" · ")}
                    </span>
                    {row.forwardedPorts.length > 0 ? (
                      <span data-forwarded-ports="" className="break-words text-muted-foreground">
                        {t("sandboxes:connections.ports", {
                          ports: portList(row.forwardedPorts, locale),
                        })}
                      </span>
                    ) : null}
                  </li>
                );
              })}
            </ul>
            <LoadMore
              hasNextPage={query.hasNextPage}
              isFetchingNextPage={query.isFetchingNextPage}
              onLoadMore={() => void query.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
    </section>
  );
}
