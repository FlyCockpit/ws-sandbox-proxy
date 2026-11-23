import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { cn } from "@wssp/ui/lib/utils";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/page-shell";
import { SettingsBackLink } from "@/components/settings/settings-back-link";
import { useAuthSession } from "@/hooks/use-auth-session";
import { clearPoolInviteToken, poolInviteGeneration, poolInviteToken } from "@/lib/pool-invite";
import { orpc } from "@/utils/orpc";
import { SharingNotice } from "./pool-sharing";

/**
 * Accepting a pool invitation. The invitation secret lives only in memory
 * (lib/pool-invite.ts): it is never put in the query cache (the preview query
 * key carries only the capture generation and the secret is only the call's
 * input), router state, storage or a URL, and it is cleared once accepted.
 * Each captured invitation gets a fresh form (keyed on its generation), and
 * the form accepts exactly the invitation it previewed.
 */
export function AcceptPoolInvite({ lang }: { lang: string }) {
  const generation = poolInviteGeneration();
  return <AcceptPoolInviteForm key={generation} lang={lang} generation={generation} />;
}

function AcceptPoolInviteForm({ lang, generation }: { lang: string; generation: number }) {
  const { t } = useTranslation(["hosts", "common"]);
  const session = useAuthSession();
  const client = useQueryClient();
  const [chosenMode, setMode] = useState<"bearer" | "email" | null>(null);
  const [status, setStatus] = useState<"idle" | "pending" | "done" | "failed">("idle");
  const [failure, setFailure] = useState("failed");
  const formId = useId();
  // The token captured with this generation; a later capture remounts the form.
  const [token] = useState(poolInviteToken);
  const identity = session.state.status === "authenticated" ? session.state.session.user.email : "";
  const preview = useQuery({
    queryKey: ["pool-invite-preview", generation],
    queryFn: () => orpc.sandboxPools.previewInvite.call({ token: token ?? "" }),
    enabled: Boolean(token && identity) && status !== "done",
    staleTime: Number.POSITIVE_INFINITY,
    gcTime: 0,
    retry: false,
  });
  // An invitation addressed to another email can only be accepted as a bearer.
  const mode = chosenMode ?? (preview.data?.addressedToYou === false ? "bearer" : "email");
  return (
    <div data-pool-invite-page="" className="flex min-w-0 flex-col gap-6">
      <PageHeader
        back={<SettingsBackLink lang={lang} />}
        title={t("hosts:sharing.accept")}
        description={identity ? t("hosts:sharing.acceptingAs", { email: identity }) : undefined}
      />
      {token && status !== "done" ? (
        <section
          data-pool-invite-preview=""
          aria-busy={preview.isPending && preview.fetchStatus !== "idle"}
          className="flex min-w-0 flex-col gap-1 rounded-xl border bg-card p-4 text-card-foreground"
        >
          {preview.data ? (
            <>
              <p className="break-words text-sm">
                {t("hosts:sharing.invitedBy", {
                  inviter: preview.data.inviterName,
                  pool: preview.data.poolLabel,
                })}
              </p>
              {preview.data.addressedToYou ? null : (
                <p className="text-sm text-muted-foreground">
                  {t("hosts:sharing.notAddressedToYou")}
                </p>
              )}
            </>
          ) : preview.isError ? (
            <p role="status" className="text-sm text-muted-foreground">
              {t("hosts:sharing.previewUnavailable")}
            </p>
          ) : (
            <Skeleton className="h-5 w-3/4" />
          )}
        </section>
      ) : null}
      <section className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground">
        <SharingNotice />
        <p className="text-sm text-muted-foreground">{t("hosts:sharing.forwarding")}</p>
      </section>
      {status === "done" ? (
        <section
          role="status"
          data-pool-invite-accepted=""
          className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
        >
          <p className="text-sm font-medium">{t("hosts:sharing.accepted")}</p>
          <div className="flex flex-wrap gap-2">
            <Link
              to="/$lang/settings/pools"
              params={{ lang }}
              search={{ tab: "shared" }}
              className={cn(buttonVariants({ size: "touch" }))}
            >
              {t("hosts:sharing.openShared")}
            </Link>
            <Link
              to="/$lang/dashboard/sandboxes"
              params={{ lang }}
              className={cn(buttonVariants({ variant: "outline", size: "touch" }))}
            >
              {t("hosts:sharing.goSandboxes")}
            </Link>
          </div>
        </section>
      ) : (
        <section className="flex min-w-0 flex-col gap-4 rounded-xl border bg-card p-4 text-card-foreground">
          {!token ? (
            <p role="status" data-pool-invite-missing="" className="text-sm">
              {t("hosts:sharing.reopen")}
            </p>
          ) : null}
          <fieldset className="flex min-w-0 flex-col gap-1">
            <legend className="mb-1 text-sm font-medium">{t("hosts:sharing.acceptMode")}</legend>
            {(["email", "bearer"] as const).map((value) => {
              const key = value === "email" ? "emailMode" : "bearer";
              const hintKey = value === "email" ? "emailModeHint" : "bearerHint";
              return (
                <div key={value} className="flex items-start gap-3">
                  <input
                    id={`${formId}-${value}`}
                    type="radio"
                    name="acceptMode"
                    autoComplete="off"
                    className="mt-3"
                    aria-labelledby={`${formId}-${value}-label`}
                    aria-describedby={`${formId}-${value}-hint`}
                    checked={mode === value}
                    onChange={() => setMode(value)}
                  />
                  {/* The whole row (title and hint) is the tap target. */}
                  <label
                    htmlFor={`${formId}-${value}`}
                    className="flex min-h-11 min-w-0 flex-1 flex-col justify-center py-1"
                  >
                    <span id={`${formId}-${value}-label`} className="text-sm">
                      {t(`hosts:sharing.${key}`)}
                    </span>
                    <span id={`${formId}-${value}-hint`} className="text-xs text-muted-foreground">
                      {t(`hosts:sharing.${hintKey}`)}
                    </span>
                  </label>
                </div>
              );
            })}
          </fieldset>
          <Button
            size="touch"
            className="self-start"
            disabled={!token || !identity || status === "pending"}
            onClick={async () => {
              if (!token) return;
              setStatus("pending");
              try {
                await orpc.sandboxPools.acceptInvite.call({ token, mode });
                clearPoolInviteToken();
                setStatus("done");
                await client.invalidateQueries({ queryKey: orpc.sandboxPools.key() });
              } catch (error) {
                const code =
                  error && typeof error === "object" && "code" in error ? error.code : null;
                setFailure(
                  code === "TOO_MANY_REQUESTS"
                    ? "acceptRateLimited"
                    : code === "UNAUTHORIZED"
                      ? "acceptSignedOut"
                      : code === "FORBIDDEN"
                        ? "acceptForbidden"
                        : code === "NOT_FOUND"
                          ? "acceptUnavailable"
                          : code === "CONFLICT"
                            ? "acceptConflict"
                            : "failed",
                );
                setStatus("failed");
              }
            }}
          >
            {t("hosts:sharing.accept")}
          </Button>
          {status === "failed" ? (
            <p role="alert" className="text-sm text-destructive">
              {t(`hosts:sharing.${failure}`)}
            </p>
          ) : null}
        </section>
      )}
    </div>
  );
}
