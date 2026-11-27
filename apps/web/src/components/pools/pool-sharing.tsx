import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { AppRouterClient } from "@wssp/api/routers/index";
import {
  contributePoolHostInput,
  grantPoolShareInput,
  updatePoolShareInput,
} from "@wssp/api/sandbox/sharing-input";
import { Button } from "@wssp/ui/components/button";
import { Checkbox } from "@wssp/ui/components/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { AdvancedSection, FormSection } from "@wssp/ui/components/form-page";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@wssp/ui/components/sheet";
import { toast } from "@wssp/ui/components/sileo";
import { TextField } from "@wssp/ui/components/text-field";
import { focusFirstInvalidField } from "@wssp/ui/lib/focus-first-invalid";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { CopyableId } from "@/components/copyable-id";
import {
  OneTimeSecretPanel,
  RevokeCredentialDialog,
} from "@/components/credentials/credential-parts";
import { EmptyState } from "@/components/empty-state";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { PageActions } from "@/components/page-actions";
import { WideSheet } from "@/components/wide-sheet";
import { useTwoFactorRedirect } from "@/hooks/use-two-factor-redirect";
import { formatDateTime } from "@/lib/format-date-time";
import { formatGraceDuration, formatWait } from "@/lib/format-duration";
import { leaseLimitText, parseLeaseLimit } from "@/lib/lease-duration";
import { orpc } from "@/utils/orpc";
import { PoolCapacityDialog } from "./pool-capacity";
import { PoolHostPolicyNotice } from "./pool-host-policy";

type SharedPool = Awaited<
  ReturnType<AppRouterClient["sandboxPools"]["listShared"]>
>["items"][number];
type Share = Awaited<ReturnType<AppRouterClient["sandboxPools"]["listShares"]>>["items"][number];
type Contribution = Awaited<
  ReturnType<AppRouterClient["sandboxPools"]["listContributions"]>
>["items"][number];
const paging = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (page: { nextCursor: string | null }) => page.nextCursor ?? undefined,
};
/**
 * A contributed host by its name. Contributions carry only the host id (the
 * pool payload never includes host details); the contributor owns the host,
 * so its own host read names it. Falls back to the id.
 */
function OwnHostName({ hostId }: { hostId: string }) {
  const host = useQuery({
    ...orpc.sandboxHosts.getHost.queryOptions({ input: { id: hostId } }),
    meta: { skipGlobalErrorToast: true },
  });
  return (
    <span className="break-all" data-contributed-host={hostId}>
      {host.data ? `${host.data.label} (${host.data.slug})` : hostId}
    </span>
  );
}
export function SharingNotice({ contribution = false }: { contribution?: boolean }) {
  const { t } = useTranslation("hosts");
  return (
    <>
      <p className="text-sm text-muted-foreground" data-sharing-notice="">
        {t(contribution ? "hosts:sharing.contributionNotice" : "hosts:sharing.trust")}
      </p>
      {/* The trust line already says a host's admins reach its sandboxes;
          contributors are also told the converse for their own host. */}
      {contribution ? (
        <p className="text-sm text-muted-foreground" data-node-owner-access="">
          {t("hosts:sharing.nodeOwnerAccess")}
        </p>
      ) : null}
    </>
  );
}
function More({
  query,
}: {
  query: {
    hasNextPage: boolean;
    isFetchingNextPage: boolean;
    fetchNextPage: () => unknown;
    isError: boolean;
    refetch: () => unknown;
  };
}) {
  const { t } = useTranslation("hosts");
  return (
    <>
      {query.isError ? (
        <InlineRetry message={t("hosts:pools.failed")} onRetry={() => void query.refetch()} />
      ) : null}
      <LoadMore
        hasNextPage={query.hasNextPage}
        isFetchingNextPage={query.isFetchingNextPage}
        onLoadMore={() => void query.fetchNextPage()}
      />
    </>
  );
}
/** Copy keys for a refused sharing write, per operation. */
type SharingMessages = { conflict: string; tooMany: string };
const GENERIC_SHARING_MESSAGES: SharingMessages = {
  conflict: "hosts:sharing.failed",
  tooMany: "hosts:sharing.tooManyChanges",
};
/**
 * A refused sharing write, in words: too many requests says to wait, a
 * conflict says what it usually means for this operation (the server keeps
 * one generic conflict so it never reveals other accounts).
 */
function sharingProblem(
  error: unknown,
  messages: SharingMessages,
): { key: string; retryAfterSeconds?: number } {
  const shape =
    error && typeof error === "object" ? (error as { code?: unknown; data?: unknown }) : {};
  if (shape.code === "TOO_MANY_REQUESTS") {
    // Daily limits can mean a wait of hours: say the server's own wait.
    const retry =
      shape.data && typeof shape.data === "object"
        ? (shape.data as { retryAfterSeconds?: unknown }).retryAfterSeconds
        : undefined;
    return typeof retry === "number" && Number.isFinite(retry) && retry > 0
      ? { key: messages.tooMany, retryAfterSeconds: retry }
      : { key: `${messages.tooMany}Later` };
  }
  if (shape.code === "CONFLICT") return { key: messages.conflict };
  return { key: "hosts:sharing.failed" };
}
function useSharingAction(lang: string, messages: SharingMessages = GENERIC_SHARING_MESSAGES) {
  const { t } = useTranslation("hosts");
  const client = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<ReturnType<typeof sharingProblem> | null>(null);
  async function run(work: () => Promise<unknown>, errorMessages = messages) {
    setPending(true);
    setProblem(null);
    try {
      await work();
      await client.invalidateQueries({ queryKey: orpc.sandboxPools.key() });
    } catch (error) {
      if (!redirect(error)) setProblem(sharingProblem(error, errorMessages));
    } finally {
      setPending(false);
    }
  }
  return {
    run,
    pending,
    error: problem ? (
      <p role="alert" data-sharing-problem="" className="col-span-full text-sm text-destructive">
        {problem.retryAfterSeconds === undefined
          ? t(problem.key)
          : t(problem.key, { wait: formatWait(problem.retryAfterSeconds, lang) })}
      </p>
    ) : null,
  };
}
/** Pools shared with you; the Pools page reads the same first page to pick its tab. */
export function useSharedPools() {
  return useInfiniteQuery({
    ...orpc.sandboxPools.listShared.infiniteOptions({
      ...paging,
      input: (cursor: string | undefined) => ({ cursor, limit: 20 }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
}
export function SharedPools({ lang }: { lang: string }) {
  const pools = useSharedPools();
  const { t } = useTranslation("hosts");
  const usable = pools.data?.pages.some((page) =>
    page.items.some((pool) => "share" in pool && pool.share?.canUse),
  );
  return (
    <>
      <SharingNotice />
      {usable ? (
        // Templates are per account: a shared pool lends hosts, not templates.
        <div data-shared-templates-note="" className="flex min-w-0 flex-col items-start text-sm">
          <p>{t("hosts:sharing.templatesNotShared")}</p>
          <Link
            to="/$lang/dashboard/templates"
            params={{ lang }}
            className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
          >
            {t("hosts:sharing.openTemplates")}
          </Link>
        </div>
      ) : null}
      {pools.isPending ? <p role="status">{t("hosts:sharing.loading")}</p> : null}
      <ul className="flex flex-col gap-4">
        {pools.data?.pages
          .flatMap((p) => p.items)
          .map((pool) => (
            <SharedPoolRow key={pool.id} pool={pool} lang={lang} />
          ))}
      </ul>
      {pools.data?.pages[0]?.items.length === 0 ? (
        <EmptyState
          className="border"
          title={t("hosts:sharing.emptyShared")}
          description={t("hosts:sharing.emptySharedHint")}
        />
      ) : null}
      <More query={pools} />
    </>
  );
}
function SharedPoolRow({ pool, lang }: { pool: SharedPool; lang: string }) {
  const { t } = useTranslation(["hosts", "common"]);
  const action = useSharingAction(lang);
  const leave = useMutation({
    ...orpc.sandboxPools.leave.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const withdrawHost = useMutation({
    ...orpc.sandboxPools.withdrawHost.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const [leaving, setLeaving] = useState(false);
  const [contributing, setContributing] = useState(false);
  const [capacity, setCapacity] = useState(false);
  const [editingMember, setEditingMember] = useState<Contribution | null>(null);
  const [withdraw, setWithdraw] = useState<{ id: string; hostId: string } | null>(null);
  const contributions = useInfiniteQuery({
    ...orpc.sandboxPools.listContributions.infiniteOptions({
      ...paging,
      input: (cursor: string | undefined) => ({ poolId: pool.id, cursor, limit: 20 }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  return (
    <li
      data-shared-pool-id={pool.id}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      {/* As on an owned pool's card: names first, the actions in one row
          beside them, Leave in the menu. The slug and id are secondary. */}
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 flex-col gap-1">
          <h2 className="break-words font-medium">{pool.label}</h2>
          {"owner" in pool && pool.owner?.name ? (
            <p className="text-sm">{t("hosts:sharing.sharedBy", { name: pool.owner.name })}</p>
          ) : null}
          <div className="flex min-w-0 flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <span className="break-all font-mono">{pool.slug}</span>
            <span>{t("hosts:sharing.poolIdLabel")}</span>
            <CopyableId value={pool.id} label={t("hosts:sharing.poolId")} />
          </div>
        </div>
        <PageActions
          primary={
            "share" in pool && pool.share?.canUse ? (
              <Button size="touch" variant="outline" onClick={() => setCapacity(true)}>
                {t("hosts:poolCapacity.open")}
              </Button>
            ) : undefined
          }
          secondary={
            "share" in pool && pool.share?.canContribute && !pool.ownHostsOnly ? (
              <Button size="touch" variant="outline" onClick={() => setContributing(true)}>
                {t("hosts:sharing.contribute")}
              </Button>
            ) : undefined
          }
          overflowLabel={t("hosts:pools.actions.more", { label: pool.label })}
          overflow={[
            {
              id: "leave",
              label: t("hosts:sharing.leave"),
              destructive: true,
              onSelect: () => setLeaving(true),
            },
          ]}
        />
      </div>
      {"share" in pool && pool.share ? (
        <div className="flex min-w-0 flex-col gap-1 text-sm">
          <p>
            {t(
              pool.share.canUse && pool.share.canContribute
                ? "hosts:sharing.youCanBoth"
                : pool.share.canUse
                  ? "hosts:sharing.youCanUse"
                  : "hosts:sharing.youCanContribute",
            )}
          </p>
          <p>
            {t("hosts:sharing.yourLimits", {
              memory:
                pool.share.maxMemoryMiB == null
                  ? t("hosts:sharing.unlimited")
                  : `${pool.share.maxMemoryMiB} MiB`,
              vcpu: pool.share.maxVcpu ?? t("hosts:sharing.unlimited"),
              disk:
                pool.share.maxDiskGiB == null
                  ? t("hosts:sharing.unlimited")
                  : `${pool.share.maxDiskGiB} GiB`,
            })}
          </p>
          <p>{t("hosts:sharing.yourUsage", pool.share.usage)}</p>
        </div>
      ) : null}
      {pool.ownHostsOnly ? <p className="text-sm">{t("hosts:sharing.ownHostsOnly")}</p> : null}
      {"share" in pool && pool.share?.canUse ? (
        <PoolHostPolicyNotice
          poolId={pool.id}
          lang={lang}
          ownerName={"owner" in pool ? pool.owner?.name : undefined}
        />
      ) : null}
      <p className="text-sm text-muted-foreground">
        {pool.disconnectGraceSeconds === 0
          ? t("hosts:sharing.graceNone")
          : t("hosts:sharing.gracePlain", {
              duration: formatGraceDuration(pool.disconnectGraceSeconds, lang),
            })}
      </p>
      {capacity ? (
        <PoolCapacityDialog
          poolId={pool.id}
          owner={false}
          lang={lang}
          onClose={() => setCapacity(false)}
        />
      ) : null}
      <ul>
        {contributions.data?.pages
          .flatMap((p) => p.items)
          .map((member) => (
            <li key={member.id} className="flex flex-wrap items-center gap-3">
              <OwnHostName hostId={member.sandboxHostId} />
              <span>
                {t("hosts:sharing.percentages", {
                  memory: member.memoryCapPercent ?? 100,
                  vcpu: member.vcpuCapPercent ?? 100,
                })}
              </span>
              {!member.removedAt ? (
                <Button size="touch" variant="outline" onClick={() => setEditingMember(member)}>
                  {t("hosts:sharing.editPercentages")}
                </Button>
              ) : null}
              {!member.removedAt ? (
                <Button
                  size="touch"
                  variant="outline"
                  onClick={() => setWithdraw({ id: member.id, hostId: member.sandboxHostId })}
                >
                  {t("hosts:sharing.withdraw")}
                </Button>
              ) : (
                <span>{t("hosts:sharing.withdrawn")}</span>
              )}
            </li>
          ))}
      </ul>
      <More query={contributions} />
      {action.error}
      {editingMember ? (
        <ContributionForm
          poolId={pool.id}
          lang={lang}
          member={editingMember}
          onClose={() => setEditingMember(null)}
        />
      ) : null}
      {contributing ? (
        <ContributionForm poolId={pool.id} lang={lang} onClose={() => setContributing(false)} />
      ) : null}
      <ConfirmDeleteDialog
        open={leaving || !!withdraw}
        onOpenChange={(open) => {
          if (!open) {
            setLeaving(false);
            setWithdraw(null);
          }
        }}
        title={t(withdraw ? "hosts:sharing.withdraw" : "hosts:sharing.leave")}
        description={t(
          withdraw ? "hosts:sharing.contributionNotice" : "hosts:sharing.leaveDescription",
        )}
        confirmLabel={t(withdraw ? "hosts:sharing.withdraw" : "hosts:sharing.leave")}
        confirmToken={withdraw?.id ?? pool.slug}
        typePrompt={t("hosts:pools.confirm")}
        copyAriaLabel={t("hosts:pools.copy")}
        isPending={action.pending}
        onConfirm={() =>
          void action.run(async () => {
            if (withdraw)
              await withdrawHost.mutateAsync({
                poolId: pool.id,
                sandboxHostId: withdraw.hostId,
              });
            else await leave.mutateAsync({ poolId: pool.id });
            setWithdraw(null);
            setLeaving(false);
          })
        }
      />
    </li>
  );
}
const nullableNumber = (max: number) =>
  z
    .string()
    .transform((value) => (value.trim() ? Number(value) : null))
    .pipe(z.number().int().min(1).max(max).nullable());
/** Share settings; `email` checks the recipient address when inviting (unused when editing). */
const settingsSchema = (email: z.ZodType<string, string>) =>
  z
    .object({
      canUse: z.boolean(),
      canContribute: z.boolean(),
      maxMemoryMiB: nullableNumber(16777216),
      maxVcpu: nullableNumber(8192),
      maxDiskGiB: nullableNumber(268435456),
      email,
      signupAllowed: z.boolean(),
    })
    .refine((v) => v.canUse || v.canContribute);
export function ShareForm({
  poolId,
  share,
  lang,
  onClose,
}: {
  poolId: string;
  share?: Share;
  lang: string;
  onClose: () => void;
}) {
  const { t } = useTranslation(["hosts", "common"]);
  // Inviting has its own limits and refusals; editing a share is a plain change.
  const action = useSharingAction(
    lang,
    share
      ? GENERIC_SHARING_MESSAGES
      : { conflict: "hosts:sharing.shareConflict", tooMany: "hosts:sharing.tooMany" },
  );
  // An empty, mistyped or over-long address is caught here, under the field,
  // before anything is sent: the server's own email rule, in words.
  const schema = settingsSchema(
    share
      ? z.string()
      : z
          .string()
          .refine(
            (value) => grantPoolShareInput.shape.email.safeParse(value).success,
            t("hosts:sharing.invalidEmail"),
          ),
  );
  const update = useMutation({
    ...orpc.sandboxPools.updateShare.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const [secret, setSecret] = useState<{ link: string; sent: boolean } | null>(null);
  const form = useForm({
    defaultValues: {
      email: "",
      canUse: share?.canUse ?? true,
      canContribute: share?.canContribute ?? true,
      maxMemoryMiB: String(share?.maxMemoryMiB ?? ""),
      maxVcpu: String(share?.maxVcpu ?? ""),
      maxDiskGiB: String(share?.maxDiskGiB ?? ""),
      signupAllowed: false,
    },
    validators: { onSubmit: schema },
    onSubmitInvalid: () =>
      focusFirstInvalidField(document.querySelector<HTMLElement>("[data-share-form]")),
    onSubmit: async ({ value }) =>
      action.run(async () => {
        const settings = schema.parse(value);
        if (share) {
          await update.mutateAsync(
            updatePoolShareInput.parse({
              poolId,
              granteeUserId: share.granteeUserId,
              canUse: settings.canUse,
              canContribute: settings.canContribute,
              maxMemoryMiB: settings.maxMemoryMiB,
              maxVcpu: settings.maxVcpu,
              maxDiskGiB: settings.maxDiskGiB,
            }),
          );
          onClose();
        } else {
          const result = await orpc.sandboxPools.grantShare.call(
            grantPoolShareInput.parse({ ...settings, poolId }),
          );
          toast.success(t("hosts:sharing.sharedToast"));
          if (result.kind === "invite")
            setSecret({
              link: `${window.location.origin}/${lang}/settings/pools/invite#${result.token}`,
              sent: result.sent,
            });
          else onClose();
        }
      }),
  });
  const values = useStore(form.store, (state) => state.values);
  const unlimited = t("hosts:sharing.unlimited");
  const capsSummary = [
    values.maxMemoryMiB.trim() ? `${values.maxMemoryMiB.trim()} MiB` : unlimited,
    values.maxVcpu.trim() ? `${values.maxVcpu.trim()} vCPU` : unlimited,
    values.maxDiskGiB.trim() ? `${values.maxDiskGiB.trim()} GiB` : unlimited,
  ].join(" · ");
  return (
    <WideSheet
      data-share-form=""
      title={t(share ? "hosts:sharing.edit" : "hosts:sharing.add")}
      description={t(share ? "hosts:sharing.nullCaps" : "hosts:sharing.forwardingInviter")}
      closeLabel={t("common:actions.close")}
      busy={action.pending}
      onClose={onClose}
      onSubmit={secret ? undefined : () => void form.handleSubmit()}
      actions={
        secret ? undefined : (
          <>
            <Button size="touch" variant="outline" type="button" onClick={onClose}>
              {t("common:actions.cancel")}
            </Button>
            <form.Subscribe selector={(state) => state.isValid}>
              {(valid) => (
                <Button size="touch" type="submit" disabled={action.pending || !valid}>
                  {t(share ? "common:actions.save" : "hosts:sharing.invite")}
                </Button>
              )}
            </form.Subscribe>
          </>
        )
      }
    >
      {secret ? (
        <>
          <OneTimeSecretPanel
            secret={secret.link}
            label={t("hosts:sharing.copyLink")}
            onDone={onClose}
          />
          <p role="status">{t(secret.sent ? "hosts:sharing.sent" : "hosts:sharing.unsent")}</p>
        </>
      ) : (
        <>
          <FormSection title={t("hosts:sharing.essential")}>
            {!share ? (
              <form.Field name="email">
                {(field) => (
                  <TextField
                    field={field}
                    label={t("hosts:sharing.email")}
                    type="email"
                    autoComplete="email"
                    inputClassName="min-h-11"
                    required
                  />
                )}
              </form.Field>
            ) : null}
            {(["canUse", "canContribute"] as const).map((name) => (
              <form.Field key={name} name={name}>
                {(field) => (
                  <label className="flex min-h-11 items-center gap-3 text-sm">
                    <Checkbox checked={field.state.value} onCheckedChange={field.handleChange} />
                    {t(`hosts:sharing.${name}`)}
                  </label>
                )}
              </form.Field>
            ))}
            {/* A refusal shows here, next to what it is about, not below the fold. */}
            {action.error}
          </FormSection>
          <AdvancedSection
            gridClassName="lg:grid-cols-1"
            title={t("hosts:sharing.limits")}
            summary={capsSummary}
          >
            <p className="text-sm text-muted-foreground">{t("hosts:sharing.nullCaps")}</p>
            {(["maxMemoryMiB", "maxVcpu", "maxDiskGiB"] as const).map((name) => (
              <form.Field key={name} name={name}>
                {(field) => (
                  <TextField
                    field={field}
                    label={t(`hosts:sharing.${name}`)}
                    type="number"
                    min={1}
                    autoComplete="off"
                    inputClassName="min-h-11"
                  />
                )}
              </form.Field>
            ))}
          </AdvancedSection>
          {!share ? (
            <AdvancedSection
              gridClassName="lg:grid-cols-1"
              title={t("hosts:sharing.invitation")}
              summary={t(
                values.signupAllowed
                  ? "hosts:sharing.signupAllowedShort"
                  : "hosts:sharing.signupClosedShort",
              )}
            >
              <form.Field name="signupAllowed">
                {(field) => (
                  <label className="flex min-h-11 items-center gap-3 text-sm">
                    <Checkbox checked={field.state.value} onCheckedChange={field.handleChange} />
                    {t("hosts:sharing.signupAllowed")}
                  </label>
                )}
              </form.Field>
            </AdvancedSection>
          ) : null}
          {/* Before inviting: what the invited person can run on these hosts. */}
          {!share ? <PoolHostPolicyNotice poolId={poolId} lang={lang} /> : null}
          <SharingNotice />
        </>
      )}
    </WideSheet>
  );
}
export function PoolSharing({
  poolId,
  poolLabel,
  lang,
  onClose,
}: {
  poolId: string;
  poolLabel: string;
  lang: string;
  onClose: () => void;
}) {
  const { t } = useTranslation(["hosts", "common"]);
  const [editing, setEditing] = useState<Share | "new" | null>(null);
  /** `hosts`: how many hosts the person has in this pool (0 for an invitation). */
  const [revoking, setRevoking] = useState<{
    id: string;
    grantee?: string;
    name: string;
    hosts: number;
  } | null>(null);
  const [secret, setSecret] = useState<{ link: string; sent: boolean } | null>(null);
  const action = useSharingAction(lang);
  const revokeShare = useMutation({
    ...orpc.sandboxPools.revokeShare.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const revokeInvite = useMutation({
    ...orpc.sandboxPools.revokeInvite.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const shares = useInfiniteQuery({
    ...orpc.sandboxPools.listShares.infiniteOptions({
      ...paging,
      input: (cursor: string | undefined) => ({ poolId, cursor, limit: 20 }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const invites = useInfiniteQuery({
    ...orpc.sandboxPools.listInvites.infiniteOptions({
      ...paging,
      input: (cursor: string | undefined) => ({ poolId, cursor, limit: 20 }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const noPeople =
    shares.data?.pages[0]?.items.length === 0 && invites.data?.pages[0]?.items.length === 0;
  const confirmRevoke = () =>
    void action.run(async () => {
      if (!revoking) return;
      if (revoking.grantee)
        await revokeShare.mutateAsync({
          poolId,
          granteeUserId: revoking.grantee,
        });
      else await revokeInvite.mutateAsync({ poolId, inviteId: revoking.id });
      setRevoking(null);
    });
  return (
    <WideSheet
      data-pool-people=""
      title={t("hosts:sharing.peopleTitle", { label: poolLabel })}
      description={t("hosts:sharing.manageDescription")}
      closeLabel={t("common:actions.close")}
      onClose={onClose}
      actions={
        <>
          <Button size="touch" variant="outline" onClick={onClose}>
            {t("common:actions.close")}
          </Button>
          <Button size="touch" onClick={() => setEditing("new")}>
            {t("hosts:sharing.add")}
          </Button>
        </>
      }
    >
      {secret ? (
        <div className="flex min-w-0 flex-col gap-2">
          <OneTimeSecretPanel
            secret={secret.link}
            label={t("hosts:sharing.copyLink")}
            onDone={() => setSecret(null)}
          />
          <p>{t(secret.sent ? "hosts:sharing.sent" : "hosts:sharing.unsent")}</p>
          {/* Shown beside every revealed link: a new invitation or a resend. */}
          <p className="text-sm text-muted-foreground" data-invite-forwarding="">
            {t("hosts:sharing.forwardingInviter")}
          </p>
        </div>
      ) : null}
      <PoolHostPolicyNotice poolId={poolId} lang={lang} />
      {noPeople ? (
        <p className="text-sm text-muted-foreground">{t("hosts:sharing.noPeople")}</p>
      ) : null}
      <ul className="grid min-w-0 gap-3 lg:grid-cols-2">
        {shares.data?.pages
          .flatMap((p) => p.items)
          .map((share) => (
            <li
              key={share.id}
              className="flex min-w-0 flex-col gap-2 rounded-lg border p-3 text-sm"
            >
              <span className="break-all font-medium">
                {share.Grantee?.name} · {share.Grantee?.email}
              </span>
              {/* The owner reads each person's usage: theirs, not "yours". */}
              <p>
                {t("hosts:sharing.usageOf", {
                  ...share.usage,
                  name:
                    share.Grantee?.name || share.Grantee?.email || t("hosts:sharing.thisPerson"),
                })}
              </p>
              <p>
                {t("hosts:sharing.permissions", {
                  use: t(share.canUse ? "hosts:sharing.yes" : "hosts:sharing.no"),
                  contribute: t(share.canContribute ? "hosts:sharing.yes" : "hosts:sharing.no"),
                })}
              </p>
              <p>
                {t("hosts:sharing.caps", {
                  memory:
                    share.maxMemoryMiB == null
                      ? t("hosts:sharing.unlimited")
                      : `${share.maxMemoryMiB} MiB`,
                  vcpu: share.maxVcpu ?? t("hosts:sharing.unlimited"),
                  disk:
                    share.maxDiskGiB == null
                      ? t("hosts:sharing.unlimited")
                      : `${share.maxDiskGiB} GiB`,
                })}
              </p>
              <div className="flex flex-wrap gap-2">
                <Button size="touch" variant="outline" onClick={() => setEditing(share)}>
                  {t("hosts:sharing.edit")}
                </Button>
                <Button
                  size="touch"
                  variant="destructive"
                  onClick={() =>
                    setRevoking({
                      id: share.id,
                      grantee: share.granteeUserId,
                      name: share.Grantee?.email ?? share.granteeUserId,
                      hosts: share.contributedHosts,
                    })
                  }
                >
                  {t("hosts:sharing.revoke")}
                </Button>
              </div>
            </li>
          ))}
      </ul>
      <More query={shares} />
      <ul className="grid min-w-0 gap-3 lg:grid-cols-2">
        {invites.data?.pages
          .flatMap((p) => p.items)
          .map((invite) => (
            <li
              key={invite.id}
              className="flex min-w-0 flex-col gap-2 rounded-lg border p-3 text-sm"
            >
              <span className="break-all font-medium">{invite.email}</span>
              {invite.revokedAt ? (
                <span>{t("hosts:sharing.inviteRevoked")}</span>
              ) : invite.acceptedAt ? (
                <span>{t("hosts:sharing.inviteAccepted")}</span>
              ) : (
                <span>
                  {t("hosts:sharing.expires", {
                    date: formatDateTime(invite.expiresAt, lang),
                  })}
                </span>
              )}
              {!invite.acceptedAt && !invite.revokedAt ? (
                <span>{t(invite.sentAt ? "hosts:sharing.sent" : "hosts:sharing.unsent")}</span>
              ) : null}
              {!invite.acceptedAt && !invite.revokedAt && !invite.expiredAt ? (
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="touch"
                    variant="outline"
                    disabled={action.pending}
                    onClick={() =>
                      void action.run(
                        async () => {
                          const result = await orpc.sandboxPools.resendInvite.call({
                            poolId,
                            inviteId: invite.id,
                          });
                          setSecret({
                            link: `${window.location.origin}/${lang}/settings/pools/invite#${result.token}`,
                            sent: result.sent,
                          });
                        },
                        {
                          conflict: "hosts:sharing.shareConflict",
                          tooMany: "hosts:sharing.tooMany",
                        },
                      )
                    }
                  >
                    {t("hosts:sharing.resend")}
                  </Button>
                  <Button
                    size="touch"
                    variant="destructive"
                    onClick={() => setRevoking({ id: invite.id, name: invite.email, hosts: 0 })}
                  >
                    {t("hosts:sharing.revoke")}
                  </Button>
                </div>
              ) : null}
            </li>
          ))}
      </ul>
      <More query={invites} />
      {action.error}
      {editing ? (
        <ShareForm
          poolId={poolId}
          lang={lang}
          share={editing === "new" ? undefined : editing}
          onClose={() => setEditing(null)}
        />
      ) : null}
      {/* Hosts the person added leave the pool with them: only then the
          contribution warning and a typed confirmation. Anyone else (and an
          invitation) gets a plain revoke confirmation. */}
      <ConfirmDeleteDialog
        open={!!revoking && revoking.hosts > 0}
        onOpenChange={(open) => {
          if (!open) setRevoking(null);
        }}
        title={t("hosts:sharing.revokeTitle", { name: revoking?.name ?? "", pool: poolLabel })}
        description={
          <>
            {t("hosts:sharing.revokeContributedHosts", {
              name: revoking?.name ?? "",
              count: revoking?.hosts ?? 0,
            })}{" "}
            {t("hosts:sharing.contributionNotice")}
          </>
        }
        confirmToken={revoking?.name ?? ""}
        typePrompt={t("hosts:sharing.confirmEmail")}
        copyAriaLabel={t("hosts:sharing.copyEmail")}
        confirmLabel={t("hosts:sharing.revoke")}
        pendingLabel={t("hosts:sharing.revoking")}
        isPending={action.pending}
        onConfirm={confirmRevoke}
      />
      <RevokeCredentialDialog
        open={!!revoking && revoking.hosts === 0}
        onOpenChange={(open) => {
          if (!open) setRevoking(null);
        }}
        title={t("hosts:sharing.revokeTitle", { name: revoking?.name ?? "", pool: poolLabel })}
        description={t(
          revoking?.grantee ? "hosts:sharing.revokePlain" : "hosts:sharing.revokeInvitePlain",
          { name: revoking?.name ?? "", pool: poolLabel },
        )}
        isPending={action.pending}
        onConfirm={confirmRevoke}
      />
    </WideSheet>
  );
}
function ContributionForm({
  poolId,
  lang,
  onClose,
  member,
}: {
  poolId: string;
  lang: string;
  onClose: () => void;
  member?: Contribution;
}) {
  const { t } = useTranslation(["hosts", "common"]);
  const action = useSharingAction(lang);
  const contribute = useMutation({
    ...orpc.sandboxPools.contributeHost.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const hosts = useInfiniteQuery({
    ...orpc.sandboxHosts.listHosts.infiniteOptions({
      ...paging,
      input: (cursor: string | undefined) => ({ cursor, limit: 100, excludePoolId: poolId }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: {
      sandboxHostId: member?.sandboxHostId ?? "",
      memoryCapPercent: String(member?.memoryCapPercent ?? ""),
      vcpuCapPercent: String(member?.vcpuCapPercent ?? ""),
      maxLease: leaseLimitText(member?.maxLeaseMs ?? null),
    },
    validators: {
      onSubmit: z.object({
        sandboxHostId: z.string().min(1),
        memoryCapPercent: nullableNumber(100),
        vcpuCapPercent: nullableNumber(100),
        maxLease: z
          .string()
          .refine((v) => parseLeaseLimit(v) !== undefined, t("hosts:lease.invalid")),
      }),
    },
    onSubmit: async ({ value }) =>
      action.run(async () => {
        if (
          !member &&
          !hosts.data?.pages.some((p) =>
            p.items.some((h) => h.id === value.sandboxHostId && !h.deletionRequestedAt),
          )
        )
          throw new Error("Unavailable choice");
        await contribute.mutateAsync(
          contributePoolHostInput.parse({
            poolId,
            enabled: member?.enabled ?? true,
            sandboxHostId: value.sandboxHostId,
            memoryCapPercent: value.memoryCapPercent ? Number(value.memoryCapPercent) : null,
            vcpuCapPercent: value.vcpuCapPercent ? Number(value.vcpuCapPercent) : null,
            maxLeaseMs: parseLeaseLimit(value.maxLease) ?? null,
          }),
        );
        onClose();
      }),
  });
  const content = (
    <>
      {member ? (
        <SheetHeader>
          <SheetTitle>{t("hosts:sharing.editPercentages")}</SheetTitle>
          <SheetDescription>{t("hosts:sharing.editPercentagesDescription")}</SheetDescription>
        </SheetHeader>
      ) : (
        <DialogHeader>
          <DialogTitle>{t("hosts:sharing.contribute")}</DialogTitle>
          <DialogDescription>{t("hosts:sharing.contributeDescription")}</DialogDescription>
        </DialogHeader>
      )}
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          void form.handleSubmit();
        }}
      >
        <SharingNotice contribution />
        {!member ? (
          <form.Field name="sandboxHostId">
            {(field) => (
              <fieldset>
                <legend>{t("hosts:pools.host")}</legend>
                {hosts.data?.pages
                  .flatMap((p) => p.items)
                  .filter((h) => !h.deletionRequestedAt)
                  .map((h) => (
                    <label key={h.id} className="flex min-h-11 items-center gap-3">
                      <input
                        type="radio"
                        name="host"
                        autoComplete="off"
                        checked={field.state.value === h.id}
                        onChange={() => field.handleChange(h.id)}
                      />
                      {h.label} ({h.slug})
                    </label>
                  ))}
              </fieldset>
            )}
          </form.Field>
        ) : (
          <p>
            <OwnHostName hostId={member.sandboxHostId} />
          </p>
        )}
        {!member ? <More query={hosts} /> : null}
        {(["memoryCapPercent", "vcpuCapPercent"] as const).map((name) => (
          <form.Field key={name} name={name}>
            {(field) => (
              <TextField
                field={field}
                label={t(`hosts:sharing.${name}`)}
                type="number"
                min={1}
                max={100}
                autoComplete="off"
                inputClassName="min-h-11"
              />
            )}
          </form.Field>
        ))}
        <form.Field name="maxLease">
          {(field) => (
            <TextField
              field={field}
              label={t("hosts:lease.memberField")}
              description={t("hosts:lease.fieldHint")}
              autoComplete="off"
              inputMode="text"
              maxLength={12}
              inputClassName="min-h-11"
            />
          )}
        </form.Field>
        <p className="text-sm text-muted-foreground">{t("hosts:lease.lowerWarning")}</p>
        {action.error}
        <Button size="touch" type="submit" disabled={action.pending}>
          {t("hosts:sharing.contribute")}
        </Button>
        <Button size="touch" type="button" variant="outline" onClick={onClose}>
          {t("common:actions.cancel")}
        </Button>
      </form>
    </>
  );
  return member ? (
    <Sheet
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <SheetContent showCloseButton={false} className="overflow-x-hidden overflow-y-auto">
        {content}
      </SheetContent>
    </Sheet>
  ) : (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent showCloseButton={false}>{content}</DialogContent>
    </Dialog>
  );
}
