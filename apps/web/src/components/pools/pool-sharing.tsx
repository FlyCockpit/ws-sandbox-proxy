import { useForm } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
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
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@wssp/ui/components/sheet";
import { TextField } from "@wssp/ui/components/text-field";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { OneTimeSecretPanel } from "@/components/credentials/credential-parts";
import { EmptyState } from "@/components/empty-state";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { useTwoFactorRedirect } from "@/hooks/use-two-factor-redirect";
import { formatDateTime } from "@/lib/format-date-time";
import { formatGraceDuration } from "@/lib/format-duration";
import { leaseLimitText, parseLeaseLimit } from "@/lib/lease-duration";
import { orpc } from "@/utils/orpc";
import { PoolCapacityDialog } from "./pool-capacity";

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
export function SharingNotice({ contribution = false }: { contribution?: boolean }) {
  const { t } = useTranslation("hosts");
  return (
    <>
      <p className="text-sm text-muted-foreground" data-sharing-notice="">
        {t(contribution ? "hosts:sharing.contributionNotice" : "hosts:sharing.trust")}
      </p>
      <p className="text-sm text-muted-foreground" data-node-owner-access="">
        {t("hosts:sharing.nodeOwnerAccess")}
      </p>
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
function useSharingAction(lang: string) {
  const { t } = useTranslation("hosts");
  const client = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState(false);
  async function run(work: () => Promise<unknown>) {
    setPending(true);
    setProblem(false);
    try {
      await work();
      await client.invalidateQueries({ queryKey: orpc.sandboxPools.key() });
    } catch (error) {
      if (!redirect(error)) setProblem(true);
    } finally {
      setPending(false);
    }
  }
  return { run, pending, error: problem ? <p role="alert">{t("hosts:sharing.failed")}</p> : null };
}
export function SharedPools({ lang }: { lang: string }) {
  const pools = useInfiniteQuery({
    ...orpc.sandboxPools.listShared.infiniteOptions({
      ...paging,
      input: (cursor: string | undefined) => ({ cursor, limit: 20 }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const { t } = useTranslation("hosts");
  return (
    <>
      <SharingNotice />
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
    <li className="flex min-w-0 flex-col gap-3 rounded-xl border p-4">
      <h2>{pool.label}</h2>
      <p className="break-all">
        {pool.slug} · {"owner" in pool ? pool.owner?.name : ""} · {pool.id}
      </p>
      {"share" in pool && pool.share ? (
        <>
          <p>
            {t("hosts:sharing.permissions", {
              use: t(pool.share.canUse ? "hosts:sharing.yes" : "hosts:sharing.no"),
              contribute: t(pool.share.canContribute ? "hosts:sharing.yes" : "hosts:sharing.no"),
            })}
          </p>
          <p>
            {t("hosts:sharing.caps", {
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
          <p>{t("hosts:sharing.usage", pool.share.usage)}</p>
        </>
      ) : null}
      {pool.ownHostsOnly ? <p>{t("hosts:sharing.ownHostsOnly")}</p> : null}
      <p>
        {t("hosts:sharing.grace", {
          duration: formatGraceDuration(pool.disconnectGraceSeconds, lang),
        })}
      </p>
      {"share" in pool && pool.share?.canUse ? (
        <Button size="touch" variant="secondary" onClick={() => setCapacity(true)}>
          {t("hosts:poolCapacity.open")}
        </Button>
      ) : null}
      {capacity ? (
        <PoolCapacityDialog
          poolId={pool.id}
          owner={false}
          lang={lang}
          onClose={() => setCapacity(false)}
        />
      ) : null}
      {"share" in pool && pool.share?.canContribute && !pool.ownHostsOnly ? (
        <Button size="touch" onClick={() => setContributing(true)}>
          {t("hosts:sharing.contribute")}
        </Button>
      ) : null}
      <ul>
        {contributions.data?.pages
          .flatMap((p) => p.items)
          .map((member) => (
            <li key={member.id} className="flex flex-wrap items-center gap-3">
              <span className="break-all">{member.sandboxHostId}</span>
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
      <Button size="touch" variant="destructive" onClick={() => setLeaving(true)}>
        {t("hosts:sharing.leave")}
      </Button>
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
        description={t("hosts:sharing.contributionNotice")}
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
const settingsSchema = z
  .object({
    canUse: z.boolean(),
    canContribute: z.boolean(),
    maxMemoryMiB: nullableNumber(16777216),
    maxVcpu: nullableNumber(8192),
    maxDiskGiB: nullableNumber(268435456),
    email: z.string(),
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
  const action = useSharingAction(lang);
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
    validators: { onSubmit: settingsSchema },
    onSubmit: async ({ value }) =>
      action.run(async () => {
        const settings = settingsSchema.parse(value);
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
          if (result.kind === "invite")
            setSecret({
              link: `${window.location.origin}/${lang}/settings/pools/invite#${result.token}`,
              sent: result.sent,
            });
          else onClose();
        }
      }),
  });
  const fields = (
    <div className="flex flex-col gap-4 p-4">
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
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            void form.handleSubmit();
          }}
        >
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
                <label className="flex min-h-11 items-center gap-3">
                  <Checkbox checked={field.state.value} onCheckedChange={field.handleChange} />
                  {t(`hosts:sharing.${name}`)}
                </label>
              )}
            </form.Field>
          ))}
          <p>{t("hosts:sharing.nullCaps")}</p>
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
          {!share ? (
            <form.Field name="signupAllowed">
              {(field) => (
                <label className="flex min-h-11 items-center gap-3">
                  <Checkbox checked={field.state.value} onCheckedChange={field.handleChange} />
                  {t("hosts:sharing.signupAllowed")}
                </label>
              )}
            </form.Field>
          ) : null}
          <SharingNotice />
          <p>{t("hosts:sharing.forwarding")}</p>
          {action.error}
          <form.Subscribe selector={(state) => state.isValid}>
            {(valid) => (
              <Button size="touch" type="submit" disabled={action.pending || !valid}>
                {t("common:actions.save")}
              </Button>
            )}
          </form.Subscribe>
          <Button size="touch" variant="outline" type="button" onClick={onClose}>
            {t("common:actions.cancel")}
          </Button>
        </form>
      )}
    </div>
  );
  return share ? (
    <Sheet
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <SheetContent showCloseButton={false} className="overflow-x-hidden overflow-y-auto">
        <SheetHeader>
          <SheetTitle>{t("hosts:sharing.edit")}</SheetTitle>
          <SheetDescription>{t("hosts:sharing.nullCaps")}</SheetDescription>
        </SheetHeader>
        {fields}
      </SheetContent>
    </Sheet>
  ) : (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent
        showCloseButton={false}
        className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto"
      >
        <DialogHeader>
          <DialogTitle>{t("hosts:sharing.add")}</DialogTitle>
          <DialogDescription>{t("hosts:sharing.forwarding")}</DialogDescription>
        </DialogHeader>
        {fields}
      </DialogContent>
    </Dialog>
  );
}
export function PoolSharing({
  poolId,
  lang,
  onClose,
}: {
  poolId: string;
  lang: string;
  onClose: () => void;
}) {
  const { t } = useTranslation(["hosts", "common"]);
  const [editing, setEditing] = useState<Share | "new" | null>(null);
  const [revoking, setRevoking] = useState<{ id: string; grantee?: string } | null>(null);
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
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent
        showCloseButton={false}
        className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto"
      >
        <DialogHeader>
          <DialogTitle>{t("hosts:sharing.manage")}</DialogTitle>
          <DialogDescription>{t("hosts:sharing.forwarding")}</DialogDescription>
        </DialogHeader>
        <Button size="touch" onClick={() => setEditing("new")}>
          {t("hosts:sharing.add")}
        </Button>
        {secret ? (
          <>
            <OneTimeSecretPanel
              secret={secret.link}
              label={t("hosts:sharing.copyLink")}
              onDone={() => setSecret(null)}
            />
            <p>{t(secret.sent ? "hosts:sharing.sent" : "hosts:sharing.unsent")}</p>
          </>
        ) : null}
        <ul className="flex flex-col gap-3">
          {shares.data?.pages
            .flatMap((p) => p.items)
            .map((share) => (
              <li key={share.id} className="flex flex-col gap-2 border p-3">
                <span className="break-all">
                  {share.Grantee?.name} · {share.Grantee?.email} · {share.granteeUserId}
                </span>
                <p>{t("hosts:sharing.usage", share.usage)}</p>
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
                <Button size="touch" variant="outline" onClick={() => setEditing(share)}>
                  {t("hosts:sharing.edit")}
                </Button>
                <Button
                  size="touch"
                  variant="destructive"
                  onClick={() => setRevoking({ id: share.id, grantee: share.granteeUserId })}
                >
                  {t("hosts:sharing.revoke")}
                </Button>
              </li>
            ))}
        </ul>
        <More query={shares} />
        <ul className="flex flex-col gap-3">
          {invites.data?.pages
            .flatMap((p) => p.items)
            .map((invite) => (
              <li key={invite.id} className="flex flex-col gap-2 border p-3">
                <span>{invite.email}</span>
                {invite.acceptedAt ? (
                  <span>{t("hosts:sharing.accepted")}</span>
                ) : (
                  <span>
                    {t("hosts:sharing.expires", {
                      date: formatDateTime(invite.expiresAt, lang),
                    })}
                  </span>
                )}
                {!invite.acceptedAt ? (
                  <span>{t(invite.sentAt ? "hosts:sharing.sent" : "hosts:sharing.unsent")}</span>
                ) : null}
                {!invite.acceptedAt && !invite.revokedAt && !invite.expiredAt ? (
                  <>
                    <Button
                      size="touch"
                      variant="outline"
                      disabled={action.pending}
                      onClick={() =>
                        void action.run(async () => {
                          const result = await orpc.sandboxPools.resendInvite.call({
                            poolId,
                            inviteId: invite.id,
                          });
                          setSecret({
                            link: `${window.location.origin}/${lang}/settings/pools/invite#${result.token}`,
                            sent: result.sent,
                          });
                        })
                      }
                    >
                      {t("hosts:sharing.resend")}
                    </Button>
                    <Button
                      size="touch"
                      variant="destructive"
                      onClick={() => setRevoking({ id: invite.id })}
                    >
                      {t("hosts:sharing.revoke")}
                    </Button>
                  </>
                ) : null}
              </li>
            ))}
        </ul>
        <More query={invites} />
        {action.error}
        <Button size="touch" variant="outline" onClick={onClose}>
          {t("common:actions.close")}
        </Button>
        {editing ? (
          <ShareForm
            poolId={poolId}
            lang={lang}
            share={editing === "new" ? undefined : editing}
            onClose={() => setEditing(null)}
          />
        ) : null}
        <ConfirmDeleteDialog
          open={!!revoking}
          onOpenChange={(open) => {
            if (!open) setRevoking(null);
          }}
          title={t("hosts:sharing.revoke")}
          description={t("hosts:sharing.contributionNotice")}
          confirmToken={revoking?.id ?? ""}
          typePrompt={t("hosts:pools.confirm")}
          copyAriaLabel={t("hosts:pools.copy")}
          isPending={action.pending}
          onConfirm={() =>
            void action.run(async () => {
              if (!revoking) return;
              if (revoking.grantee)
                await revokeShare.mutateAsync({
                  poolId,
                  granteeUserId: revoking.grantee,
                });
              else await revokeInvite.mutateAsync({ poolId, inviteId: revoking.id });
              setRevoking(null);
            })
          }
        />
      </DialogContent>
    </Dialog>
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
          <SheetDescription>{t("hosts:sharing.contributionNotice")}</SheetDescription>
        </SheetHeader>
      ) : (
        <DialogHeader>
          <DialogTitle>{t("hosts:sharing.contribute")}</DialogTitle>
          <DialogDescription>{t("hosts:sharing.contributionNotice")}</DialogDescription>
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
          <p className="break-all">{member.sandboxHostId}</p>
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
