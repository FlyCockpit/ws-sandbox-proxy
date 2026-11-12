import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { DATA_KEY_REFUSALS, type DataKeyRefusal } from "@wssp/api/lib/admin-error-codes";
import { Button } from "@wssp/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import { toast } from "@wssp/ui/components/sileo";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { KeyRound } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { WideContent } from "@/components/wide-content";
import { orpc } from "@/utils/orpc";

import { AdminConfirmDialog } from "./admin-confirm-dialog";

const PAGE = 20;

/** The translated sentence for a refused key action (`data.reason`), or a generic one. */
function useRefusalText() {
  const { t } = useTranslation("admin");
  return (error: unknown): string => {
    const data =
      error && typeof error === "object" && "data" in error
        ? (error as { data?: { reason?: unknown } }).data
        : undefined;
    const reason = data?.reason;
    if ((DATA_KEY_REFUSALS as readonly unknown[]).includes(reason))
      return t(`dataKey.refusals.${reason as DataKeyRefusal}`);
    const code = error && typeof error === "object" && "code" in error ? error.code : undefined;
    if (code === "SERVICE_UNAVAILABLE") return t("dataKey.refusals.stale");
    return t("dataKey.refusals.generic");
  };
}

function useInvalidate() {
  const queryClient = useQueryClient();
  return () => void queryClient.invalidateQueries({ queryKey: orpc.adminDataKeys.key() });
}

/**
 * Admin data-key card: which root kid writers
 * seal under (the database epoch), per-kid row counts and `safe to remove`,
 * advisory heartbeats, the promote switch, and the return-key lifecycle
 * (rotate, destroy with type-to-confirm, declare a host lost). Kids, counts and
 * epochs only: no key material ever reaches this page.
 */
export function DataKeyCard() {
  const { t, i18n } = useTranslation(["admin", "common"]);
  const status = useQuery({
    ...orpc.adminDataKeys.status.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });

  if (status.isPending) {
    return (
      <Card>
        <CardHeader className="space-y-2">
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-4 w-64" />
        </CardHeader>
        <CardContent className="space-y-3">
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
        </CardContent>
      </Card>
    );
  }
  if (status.isError) {
    return (
      <Card>
        <CardContent>
          <InlineRetry
            message={t("admin:dataKey.loadFailed")}
            onRetry={() => void status.refetch()}
          />
        </CardContent>
      </Card>
    );
  }
  const data = status.data;
  const number = new Intl.NumberFormat(i18n.language);
  const date = new Intl.DateTimeFormat(i18n.language, { dateStyle: "medium", timeStyle: "short" });

  return (
    <Card data-testid="data-key-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound aria-hidden className="size-4 text-muted-foreground" />
          {t("admin:dataKey.title")}
        </CardTitle>
        <CardDescription>{t("admin:dataKey.description")}</CardDescription>
      </CardHeader>
      <CardContent className="min-w-0 space-y-6">
        {!data.configured && (
          <p role="status" className="text-sm text-destructive">
            {t("admin:dataKey.notConfigured")}
          </p>
        )}
        <section className="space-y-1 text-sm">
          {data.epoch ? (
            <>
              <p>
                {t("admin:dataKey.epoch", {
                  epoch: data.epoch.epoch,
                  kid: data.epoch.currentKid,
                })}
              </p>
              {data.epoch.previousKid && (
                <p className="text-muted-foreground">
                  {t("admin:dataKey.previous", { kid: data.epoch.previousKid })}
                </p>
              )}
              <p className="text-xs text-muted-foreground">
                {t("admin:dataKey.switchedAt", {
                  at: date.format(new Date(data.epoch.switchedAt)),
                })}
              </p>
            </>
          ) : (
            <p className="text-muted-foreground">{t("admin:dataKey.noEpoch")}</p>
          )}
        </section>
        <KidTable kids={data.kids} held={data.held} number={number} />
        <Heartbeats heartbeats={data.heartbeats} />
        <ReturnKeys
          current={data.returnKey}
          canRotate={data.configured && data.returnKey !== null}
          number={number}
        />
      </CardContent>
    </Card>
  );
}

type Kid = { kid: string; rows: number; current: boolean; safeToRemove: boolean };

function KidTable({
  kids,
  held,
  number,
}: {
  kids: Kid[];
  held: string[];
  number: Intl.NumberFormat;
}) {
  const { t } = useTranslation(["admin", "common"]);
  const invalidate = useInvalidate();
  const refusal = useRefusalText();
  const [target, setTarget] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const promote = useMutation({
    ...orpc.adminDataKeys.promote.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: () => {
      setTarget(null);
      toast.success(t("admin:dataKey.promoted"));
      invalidate();
    },
    onError: (error) => setProblem(refusal(error)),
  });
  if (kids.length === 0) return null;
  return (
    <section aria-label={t("admin:dataKey.kidsLabel")} className="min-w-0 space-y-2">
      <h3 className="text-sm font-medium">{t("admin:dataKey.kidsLabel")}</h3>
      <WideContent>
        <table className="w-full min-w-[560px] text-left text-xs">
          <thead className="border-b text-muted-foreground">
            <tr>
              <th className="px-2 py-2 font-medium">{t("admin:dataKey.columns.kid")}</th>
              <th className="px-2 py-2 text-right font-medium">
                {t("admin:dataKey.columns.rows")}
              </th>
              <th className="px-2 py-2 font-medium">{t("admin:dataKey.columns.state")}</th>
              <th className="px-2 py-2 font-medium">
                <span className="sr-only">{t("admin:dataKey.columns.actions")}</span>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {kids.map((kid) => (
              <tr key={kid.kid} data-kid={kid.kid}>
                <td className="px-2 py-2 font-mono">{kid.kid}</td>
                <td className="px-2 py-2 text-right">{number.format(kid.rows)}</td>
                <td className="px-2 py-2">
                  {kid.current
                    ? t("admin:dataKey.state.current")
                    : kid.safeToRemove
                      ? t("admin:dataKey.state.safeToRemove")
                      : t("admin:dataKey.state.inUse")}
                  {held.includes(kid.kid) ? ` · ${t("admin:dataKey.state.held")}` : ""}
                </td>
                <td className="px-2 py-2 text-right">
                  {!kid.current && held.includes(kid.kid) && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="min-h-[44px]"
                      onClick={() => {
                        setProblem(null);
                        setTarget(kid.kid);
                      }}
                    >
                      {t("admin:dataKey.promote")}
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </WideContent>
      <AdminConfirmDialog
        open={target !== null}
        onOpenChange={(open) => {
          if (!open) setTarget(null);
        }}
        title={t("admin:dataKey.promoteTitle")}
        description={t("admin:dataKey.promoteDescription", { kid: target ?? "" })}
        confirmLabel={t("admin:dataKey.promote")}
        pendingLabel={t("admin:dataKey.promoting")}
        isPending={promote.isPending}
        problem={problem}
        onConfirm={() => {
          if (target) promote.mutate({ kid: target });
        }}
      />
    </section>
  );
}

function Heartbeats({
  heartbeats,
}: {
  heartbeats: { role: string; keysHeld: string[]; at: string }[] | null;
}) {
  const { t } = useTranslation("admin");
  return (
    <section aria-label={t("dataKey.heartbeatsLabel")} className="min-w-0 space-y-1 text-xs">
      <h3 className="text-sm font-medium">{t("dataKey.heartbeatsLabel")}</h3>
      <p className="text-muted-foreground">{t("dataKey.heartbeatsAdvisory")}</p>
      {heartbeats === null ? (
        <p className="text-muted-foreground">{t("dataKey.heartbeatsUnavailable")}</p>
      ) : heartbeats.length === 0 ? (
        <p className="text-muted-foreground">{t("dataKey.heartbeatsNone")}</p>
      ) : (
        <ul className="space-y-1">
          {heartbeats.map((beat, index) => (
            <li key={`${beat.role}-${beat.at}-${index}`} className="break-all">
              {t("dataKey.heartbeat", {
                role: t(`dataKey.roles.${beat.role}`, { defaultValue: beat.role }),
                kids: beat.keysHeld.join(", ") || t("dataKey.noKids"),
              })}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

type ReturnKeyRow = {
  kidR: string;
  epoch: string;
  retiredAt: Date | null;
  destroyedAt: Date | null;
  blockingHosts: number;
  blockingHostsCapped: boolean;
  quarantined: number;
};

function ReturnKeys({
  current,
  canRotate,
  number,
}: {
  current: { currentKidR: string; currentEpoch: string } | null;
  canRotate: boolean;
  number: Intl.NumberFormat;
}) {
  const { t } = useTranslation(["admin", "common"]);
  const invalidate = useInvalidate();
  const refusal = useRefusalText();
  const [rotating, setRotating] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const rotate = useMutation({
    ...orpc.adminDataKeys.rotateReturnKey.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: () => {
      setRotating(false);
      toast.success(t("admin:dataKey.returnKeys.rotated"));
      invalidate();
    },
    onError: (error) => setProblem(refusal(error)),
  });
  const list = useInfiniteQuery({
    ...orpc.adminDataKeys.listReturnKeys.infiniteOptions({
      input: (cursor: string | undefined) => ({ limit: PAGE, cursor }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const rows: ReturnKeyRow[] = list.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <section aria-label={t("admin:dataKey.returnKeys.title")} className="min-w-0 space-y-2">
      <h3 className="text-sm font-medium">{t("admin:dataKey.returnKeys.title")}</h3>
      <p className="text-xs text-muted-foreground">
        {current
          ? t("admin:dataKey.returnKeys.current", {
              kid: current.currentKidR,
              epoch: current.currentEpoch,
            })
          : t("admin:dataKey.returnKeys.none")}
      </p>
      {canRotate && (
        <Button
          variant="outline"
          size="sm"
          className="min-h-[44px]"
          onClick={() => {
            setProblem(null);
            setRotating(true);
          }}
        >
          {t("admin:dataKey.returnKeys.rotate")}
        </Button>
      )}
      {list.isPending ? (
        <Skeleton className="h-10 w-full" />
      ) : list.isError ? (
        <InlineRetry message={t("admin:dataKey.loadFailed")} onRetry={() => void list.refetch()} />
      ) : (
        <ul className="min-w-0 divide-y rounded-md border text-xs">
          {rows.map((row) => (
            <ReturnKeyItem key={row.kidR} row={row} number={number} />
          ))}
        </ul>
      )}
      <LoadMore
        hasNextPage={list.hasNextPage}
        isFetchingNextPage={list.isFetchingNextPage}
        onLoadMore={() => void list.fetchNextPage()}
      />
      <AdminConfirmDialog
        open={rotating}
        onOpenChange={setRotating}
        title={t("admin:dataKey.returnKeys.rotateTitle")}
        description={t("admin:dataKey.returnKeys.rotateDescription")}
        confirmLabel={t("admin:dataKey.returnKeys.rotate")}
        pendingLabel={t("admin:dataKey.returnKeys.rotating")}
        isPending={rotate.isPending}
        problem={problem}
        onConfirm={() => rotate.mutate({})}
      />
    </section>
  );
}

function ReturnKeyItem({ row, number }: { row: ReturnKeyRow; number: Intl.NumberFormat }) {
  const { t } = useTranslation(["admin", "common"]);
  const invalidate = useInvalidate();
  const refusal = useRefusalText();
  const [destroying, setDestroying] = useState(false);
  const [showHosts, setShowHosts] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const destroy = useMutation({
    ...orpc.adminDataKeys.destroyReturnKey.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: () => {
      setDestroying(false);
      toast.success(t("admin:dataKey.returnKeys.destroyed"));
      invalidate();
    },
    onError: (error) => {
      setDestroying(false);
      setProblem(refusal(error));
    },
  });
  const live = row.retiredAt !== null && row.destroyedAt === null;
  const state = row.destroyedAt
    ? t("admin:dataKey.returnKeys.state.destroyed")
    : row.retiredAt
      ? t("admin:dataKey.returnKeys.state.retired")
      : t("admin:dataKey.returnKeys.state.current");
  const blockers = row.blockingHostsCapped
    ? t("admin:dataKey.returnKeys.blockingCapped", { count: row.blockingHosts })
    : t("admin:dataKey.returnKeys.blocking", {
        count: row.blockingHosts,
        formatted: number.format(row.blockingHosts),
      });
  return (
    <li data-return-key={row.kidR} className="min-w-0 space-y-2 p-3">
      <div className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-1">
        <span className="break-all font-mono">{row.kidR}</span>
        <span>{t("admin:dataKey.returnKeys.epoch", { epoch: row.epoch })}</span>
        <span>{state}</span>
        {live && <span className="text-muted-foreground">{blockers}</span>}
        {live && row.quarantined > 0 && (
          <span className="text-destructive">
            {t("admin:dataKey.returnKeys.quarantined", {
              count: row.quarantined,
              formatted: number.format(row.quarantined),
            })}
          </span>
        )}
      </div>
      {live && (
        <div className="flex flex-wrap gap-2">
          {row.blockingHosts > 0 && (
            <Button
              variant="outline"
              size="sm"
              className="min-h-[44px]"
              aria-expanded={showHosts}
              onClick={() => setShowHosts((open) => !open)}
            >
              {showHosts
                ? t("admin:dataKey.returnKeys.hideHosts")
                : t("admin:dataKey.returnKeys.showHosts")}
            </Button>
          )}
          <Button
            variant="destructive"
            size="sm"
            className="min-h-[44px]"
            onClick={() => {
              setProblem(null);
              setDestroying(true);
            }}
          >
            {t("admin:dataKey.returnKeys.destroy")}
          </Button>
        </div>
      )}
      {problem && (
        <p role="alert" className="text-destructive">
          {problem}
        </p>
      )}
      {live && showHosts && <BlockingHosts kidR={row.kidR} />}
      <ConfirmDeleteDialog
        open={destroying}
        onOpenChange={setDestroying}
        title={t("admin:dataKey.returnKeys.destroyTitle", { kid: row.kidR })}
        description={
          row.quarantined > 0
            ? t("admin:dataKey.returnKeys.destroyQuarantinedDescription", {
                count: row.quarantined,
              })
            : t("admin:dataKey.returnKeys.destroyDescription")
        }
        confirmToken={row.kidR}
        typePrompt={t("admin:dataKey.returnKeys.destroyPrompt")}
        copyAriaLabel={t("admin:dataKey.returnKeys.copyKid")}
        confirmLabel={
          row.quarantined > 0
            ? t("admin:dataKey.returnKeys.destroyAnyway")
            : t("admin:dataKey.returnKeys.destroy")
        }
        pendingLabel={t("admin:dataKey.returnKeys.destroying")}
        isPending={destroy.isPending}
        onConfirm={(typed) =>
          destroy.mutate({
            kidR: row.kidR,
            confirmKidR: typed,
            destroyQuarantined: row.quarantined > 0,
          })
        }
      />
    </li>
  );
}

function BlockingHosts({ kidR }: { kidR: string }) {
  const { t, i18n } = useTranslation(["admin", "common"]);
  const invalidate = useInvalidate();
  const refusal = useRefusalText();
  const [target, setTarget] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const hosts = useInfiniteQuery({
    ...orpc.adminDataKeys.listReturnKeyBlockers.infiniteOptions({
      input: (cursor: string | undefined) => ({ kidR, limit: PAGE, cursor }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const declare = useMutation({
    ...orpc.adminDataKeys.declareHostLost.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: () => {
      setTarget(null);
      toast.success(t("admin:dataKey.returnKeys.declaredLost"));
      invalidate();
    },
    onError: (error) => setProblem(refusal(error)),
  });
  const date = new Intl.DateTimeFormat(i18n.language, { dateStyle: "medium", timeStyle: "short" });
  const rows = hosts.data?.pages.flatMap((page) => page.items) ?? [];
  if (hosts.isPending) return <Skeleton className="h-8 w-full" />;
  if (hosts.isError)
    return (
      <InlineRetry message={t("admin:dataKey.loadFailed")} onRetry={() => void hosts.refetch()} />
    );
  return (
    <div className="min-w-0 space-y-2">
      <ul className="min-w-0 divide-y rounded-md border">
        {rows.map((host) => (
          <li
            key={host.hostId}
            data-blocking-host={host.hostId}
            className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-1 p-2"
          >
            <span className="break-all font-mono">{host.hostId}</span>
            <span className="text-muted-foreground">
              {host.ackedAt
                ? t("admin:dataKey.returnKeys.ackedAt", {
                    at: date.format(new Date(host.ackedAt)),
                  })
                : t("admin:dataKey.returnKeys.notAcked")}
            </span>
            <Button
              variant="outline"
              size="sm"
              className="min-h-[44px]"
              onClick={() => {
                setProblem(null);
                setTarget(host.hostId);
              }}
            >
              {t("admin:dataKey.returnKeys.declareLost")}
            </Button>
          </li>
        ))}
      </ul>
      <LoadMore
        hasNextPage={hosts.hasNextPage}
        isFetchingNextPage={hosts.isFetchingNextPage}
        onLoadMore={() => void hosts.fetchNextPage()}
      />
      <AdminConfirmDialog
        open={target !== null}
        onOpenChange={(open) => {
          if (!open) setTarget(null);
        }}
        destructive
        title={t("admin:dataKey.returnKeys.declareLostTitle")}
        description={t("admin:dataKey.returnKeys.declareLostDescription", {
          host: target ?? "",
          kid: kidR,
        })}
        confirmLabel={t("admin:dataKey.returnKeys.declareLost")}
        pendingLabel={t("admin:dataKey.returnKeys.declaringLost")}
        isPending={declare.isPending}
        problem={problem}
        onConfirm={() => {
          if (target) declare.mutate({ kidR, hostId: target });
        }}
      />
    </div>
  );
}
