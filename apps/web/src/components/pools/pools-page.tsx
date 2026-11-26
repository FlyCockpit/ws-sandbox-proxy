import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { createPoolInput } from "@wssp/api/sandbox/pool-input";
import { Badge } from "@wssp/ui/components/badge";
import { Button } from "@wssp/ui/components/button";
import { Checkbox } from "@wssp/ui/components/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { AdvancedSection, FormSection } from "@wssp/ui/components/form-page";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@wssp/ui/components/sheet";
import { TextField } from "@wssp/ui/components/text-field";
import { focusFirstInvalidField } from "@wssp/ui/lib/focus-first-invalid";
import { Plus } from "lucide-react";
import { useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { EmptyState } from "@/components/empty-state";
import { FormSelect } from "@/components/form-select";
import { formatGiB } from "@/components/hosts/host-row";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { PageActions } from "@/components/page-actions";
import { PageHeader } from "@/components/page-shell";
import { ResourceIdentity } from "@/components/resource-identity";
import { SettingsBackLink } from "@/components/settings/settings-back-link";
import { SkeletonList } from "@/components/skeleton-list";
import { WideSheet } from "@/components/wide-sheet";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { type CredentialProblem, credentialProblem } from "@/lib/credential-rules";
import { formatLeaseDuration, leaseLimitText, parseLeaseLimit } from "@/lib/lease-duration";
import { orpc } from "@/utils/orpc";
import { PoolCapacityDialog } from "./pool-capacity";
import { PoolSharing, SharedPools, SharingNotice } from "./pool-sharing";

type Pool = Awaited<ReturnType<AppRouterClient["sandboxPools"]["list"]>>["items"][number];
type PoolSummary = NonNullable<Pool["summary"]>;

/** Blank inherits the operator limit (null); otherwise a whole number up to `max`. */
function parseLimit(text: string, max: number): number | null | undefined {
  const value = text.trim();
  if (value === "") return null;
  if (!/^\d{1,7}$/.test(value)) return undefined;
  const parsed = Number(value);
  return parsed <= max ? parsed : undefined;
}
function scaled(value: number | null | undefined, unit: number): number | null {
  return value === null || value === undefined ? null : value * unit;
}
function limitText(value: number | null | undefined, unit = 1): string {
  return value === null || value === undefined ? "" : String(Math.floor(value / unit));
}
/** A pool slug from its label, the way the API accepts one. */
export function poolSlugFromLabel(label: string): string {
  return label
    .toLowerCase()
    .normalize("NFKD")
    .replace(/\p{M}/gu, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63)
    .replace(/-+$/g, "");
}
type Member = Awaited<ReturnType<AppRouterClient["sandboxPools"]["listMembers"]>>["items"][number];
const paging = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (page: { nextCursor: string | null }) => page.nextCursor ?? undefined,
};

/** The longest lifetime a sandbox in this pool can have, in words: one answer everywhere. */
function useLongestLifetime(lang: string) {
  const { t } = useTranslation("hosts");
  return (summary: PoolSummary | null) =>
    summary == null
      ? null
      : summary.lease.timeoutZero
        ? t("pools.summary.leaseUnlimited")
        : formatLeaseDuration(summary.lease.maxTimeoutMs, lang);
}

export function PoolsPage({
  lang,
  tab,
  onTabChange,
}: {
  lang: string;
  tab: "owned" | "shared";
  onTabChange: (tab: "owned" | "shared") => void;
}) {
  const { t } = useTranslation(["hosts", "common"]);
  const [creating, setCreating] = useState(false);
  const pools = useInfiniteQuery({
    ...orpc.sandboxPools.list.infiniteOptions({
      ...paging,
      input: (cursor: string | undefined) => ({ cursor, limit: 20 }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [pools.error]);
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        back={<SettingsBackLink lang={lang} />}
        title={t("hosts:pools.title")}
        description={t("hosts:pools.description")}
        actions={
          <Button size="touch" className="self-start" onClick={() => setCreating(true)}>
            <Plus aria-hidden="true" />
            {t("hosts:pools.create")}
          </Button>
        }
      />
      <div role="tablist" aria-label={t("hosts:pools.title")} className="flex gap-2">
        {(["owned", "shared"] as const).map((value) => (
          <Button
            key={value}
            role="tab"
            aria-selected={tab === value}
            size="touch"
            variant={tab === value ? "default" : "outline"}
            onClick={() => onTabChange(value)}
          >
            {t(`hosts:sharing.${value}`)}
          </Button>
        ))}
      </div>
      {tab === "shared" ? (
        <SharedPools lang={lang} />
      ) : (
        <>
          {pools.isPending ? (
            <SkeletonList count={3} />
          ) : pools.isError ? (
            <InlineRetry message={t("hosts:pools.failed")} onRetry={() => void pools.refetch()} />
          ) : (
            <ul className="flex min-w-0 flex-col gap-4">
              {pools.data?.pages
                .flatMap((p) => p.items)
                .map((pool) => (
                  <PoolRow key={pool.id} pool={pool} lang={lang} />
                ))}
            </ul>
          )}
          {pools.data?.pages[0]?.items.length === 0 ? (
            <EmptyState
              className="border"
              title={t("hosts:pools.empty")}
              description={t("hosts:pools.emptyDescription")}
            />
          ) : null}
          <LoadMore
            hasNextPage={pools.hasNextPage}
            isFetchingNextPage={pools.isFetchingNextPage}
            onLoadMore={() => void pools.fetchNextPage()}
          />
        </>
      )}
      {creating ? <CreatePoolDialog lang={lang} onClose={() => setCreating(false)} /> : null}
    </div>
  );
}

const labelSchema = (t: (key: string) => string) =>
  z
    .string()
    .refine(
      (value) => createPoolInput.shape.label.safeParse(value).success,
      t("hosts:pools.invalidLabel"),
    );
const slugSchema = (t: (key: string) => string) =>
  z
    .string()
    .refine(
      (value) => createPoolInput.shape.slug.safeParse(value).success,
      t("hosts:pools.invalidSlug"),
    );

/** Create → Dialog: two fields (label first; the slug follows it until edited). */
function CreatePoolDialog({ lang, onClose }: { lang: string; onClose: () => void }) {
  const { t } = useTranslation(["hosts", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const root = useRef<HTMLFormElement>(null);
  const [problem, setProblem] = useState<CredentialProblem | null>(null);
  const [slugEdited, setSlugEdited] = useState(false);
  const create = useMutation({
    ...orpc.sandboxPools.create.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: { label: "", slug: "" },
    validators: { onSubmit: z.object({ label: labelSchema(t), slug: slugSchema(t) }) },
    onSubmitInvalid: () => focusFirstInvalidField(root.current),
    onSubmit: async ({ value }) => {
      setProblem(null);
      try {
        await create.mutateAsync({ slug: value.slug, label: value.label });
        await queryClient.invalidateQueries({ queryKey: orpc.sandboxPools.key() });
        onClose();
      } catch (error) {
        if (!redirect(error)) setProblem(credentialProblem(error));
      }
    },
  });
  return (
    <Dialog open onOpenChange={(open) => (open || create.isPending ? undefined : onClose())}>
      <DialogContent closeLabel={t("common:actions.close")}>
        <DialogHeader>
          <DialogTitle>{t("hosts:pools.create")}</DialogTitle>
          <DialogDescription>{t("hosts:pools.createDescription")}</DialogDescription>
        </DialogHeader>
        <form
          ref={root}
          noValidate
          data-pool-form="create"
          className="flex min-w-0 flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            void form.handleSubmit();
          }}
        >
          <form.Field name="label">
            {(field) => (
              <TextField
                inputClassName="min-h-11"
                field={field}
                label={t("hosts:pools.label")}
                autoComplete="off"
                inputMode="text"
                maxLength={120}
                onChange={(event) => {
                  if (!slugEdited)
                    form.setFieldValue("slug", poolSlugFromLabel(event.target.value));
                }}
              />
            )}
          </form.Field>
          <form.Field name="slug">
            {(field) => (
              <TextField
                inputClassName="min-h-11 font-mono"
                field={field}
                label={t("hosts:pools.slug")}
                description={t("hosts:pools.slugHint")}
                autoComplete="off"
                inputMode="text"
                maxLength={63}
                onChange={() => setSlugEdited(true)}
              />
            )}
          </form.Field>
          {problem ? (
            <p role="alert" className="text-sm text-destructive">
              {t(`hosts:pools.problem.${problem}`)}
            </p>
          ) : null}
          <DialogFooter>
            <Button type="button" size="touch" variant="outline" onClick={onClose}>
              {t("common:actions.cancel")}
            </Button>
            <Button type="submit" size="touch" disabled={create.isPending}>
              {t("hosts:pools.create")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Edit → wide sheet. Essential: label, slug and the pool's lifetime limit
 * (next to the lifetime sandboxes actually get). Everything else sits in
 * named Advanced sections that summarize their current values.
 */
function EditPoolSheet({ pool, lang, onClose }: { pool: Pool; lang: string; onClose: () => void }) {
  const { t } = useTranslation(["hosts", "common"]);
  const unlimitedId = useId();
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const root = useRef<HTMLDivElement>(null);
  const longest = useLongestLifetime(lang);
  const [problem, setProblem] = useState<CredentialProblem | null>(null);
  const update = useMutation({
    ...orpc.sandboxPools.update.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const preview = useMutation({
    ...orpc.sandboxPools.previewLeaseLowering.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  // Operator ceilings shown beside the pool's own queue limits.
  const limits = useQuery({
    ...orpc.sandboxes.getLimits.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  // A lowering is saved only after its impact on running sandboxes was shown.
  const [warning, setWarning] = useState<{ affected: number; more: boolean } | null>(null);
  const form = useForm({
    defaultValues: {
      slug: pool.slug,
      label: pool.label,
      ownHostsOnly: pool.ownHostsOnly ?? false,
      disconnectGraceSeconds: String(pool.disconnectGraceSeconds ?? 259200),
      maxLease: leaseLimitText(pool.maxLeaseMs ?? null),
      unlimitedLeaseForShares: pool.unlimitedLeaseForShares ? "shares" : "owner",
      memberImageCacheMaxGiB:
        pool.memberImageCacheMaxGiB == null ? "" : String(pool.memberImageCacheMaxGiB),
      preferOwnHosts: pool.preferOwnHosts ?? true,
      capacityWaitMinutes: limitText(pool.capacityWaitMaxMs, 60_000),
      capacityQueuePerKey: limitText(pool.capacityQueuePerKeyMax),
      capacityQueuePerOwner: limitText(pool.capacityQueuePerOwnerMax),
    },
    validators: {
      onSubmit: z.object({
        maxLease: z
          .string()
          .refine((v) => parseLeaseLimit(v) !== undefined, t("hosts:lease.invalid")),
        unlimitedLeaseForShares: z.enum(["owner", "shares"]),
        memberImageCacheMaxGiB: z
          .string()
          .refine(
            (v) =>
              v.trim() === "" ||
              (Number.isInteger(Number(v)) && Number(v) >= 0 && Number(v) <= 1048576),
            t("hosts:pools.imageCacheInvalid"),
          ),
        ownHostsOnly: z.boolean(),
        preferOwnHosts: z.boolean(),
        capacityWaitMinutes: z
          .string()
          .refine((v) => parseLimit(v, 34_560) !== undefined, t("hosts:poolCapacity.invalidLimit")),
        capacityQueuePerKey: z
          .string()
          .refine(
            (v) => parseLimit(v, 100_000) !== undefined,
            t("hosts:poolCapacity.invalidLimit"),
          ),
        capacityQueuePerOwner: z
          .string()
          .refine(
            (v) => parseLimit(v, 100_000) !== undefined,
            t("hosts:poolCapacity.invalidLimit"),
          ),
        disconnectGraceSeconds: z
          .string()
          .refine(
            (v) => Number.isInteger(Number(v)) && Number(v) >= 0 && Number(v) <= 2592000,
            t("hosts:sharing.invalidGrace"),
          ),
        slug: slugSchema(t),
        label: labelSchema(t),
      }),
    },
    onSubmitInvalid: () => focusFirstInvalidField(root.current),
    onSubmit: async ({ value }) => {
      setProblem(null);
      try {
        const maxLeaseMs = parseLeaseLimit(value.maxLease) ?? null;
        const current = pool.maxLeaseMs ?? null;
        const lowering = maxLeaseMs !== null && (current === null || maxLeaseMs < current);
        if (lowering && warning === null) {
          const impact = await preview.mutateAsync({
            scope: "pool",
            poolId: pool.id,
            maxLeaseMs,
          });
          if (impact.affected > 0) {
            setWarning(impact);
            return;
          }
        }
        await update.mutateAsync({
          slug: value.slug,
          label: value.label,
          ownHostsOnly: value.ownHostsOnly,
          disconnectGraceSeconds: Number(value.disconnectGraceSeconds),
          maxLeaseMs,
          unlimitedLeaseForShares: value.unlimitedLeaseForShares === "shares",
          memberImageCacheMaxGiB:
            value.memberImageCacheMaxGiB.trim() === ""
              ? null
              : Number(value.memberImageCacheMaxGiB),
          preferOwnHosts: value.preferOwnHosts,
          capacityWaitMaxMs: scaled(parseLimit(value.capacityWaitMinutes, 34_560), 60_000),
          capacityQueuePerKeyMax: parseLimit(value.capacityQueuePerKey, 100_000) ?? null,
          capacityQueuePerOwnerMax: parseLimit(value.capacityQueuePerOwner, 100_000) ?? null,
          id: pool.id,
        });
        await queryClient.invalidateQueries({ queryKey: orpc.sandboxPools.key() });
        onClose();
      } catch (error) {
        if (!redirect(error)) setProblem(credentialProblem(error));
      }
    },
  });
  const values = useStore(form.store, (state) => state.values);
  const pending = update.isPending || preview.isPending;
  const operatorLimit = t("hosts:pools.edit.operatorLimit");
  const effective = longest(pool.summary);
  return (
    <WideSheet
      title={t("hosts:pools.edit.title", { label: pool.label })}
      description={t("hosts:pools.description")}
      closeLabel={t("common:actions.close")}
      busy={pending}
      onClose={onClose}
      onSubmit={() => void form.handleSubmit()}
      actions={
        <>
          <Button type="button" size="touch" variant="outline" onClick={onClose}>
            {t("common:actions.cancel")}
          </Button>
          <Button type="submit" size="touch" disabled={pending}>
            {t(warning ? "hosts:lease.saveAnyway" : "common:actions.save")}
          </Button>
        </>
      }
    >
      <div ref={root} data-pool-form="edit" className="min-w-0 space-y-8">
        <FormSection title={t("hosts:pools.edit.essential")}>
          <form.Field name="label">
            {(field) => (
              <TextField
                inputClassName="min-h-11"
                field={field}
                label={t("hosts:pools.label")}
                autoComplete="off"
                inputMode="text"
                maxLength={120}
              />
            )}
          </form.Field>
          <form.Field name="slug">
            {(field) => (
              <TextField
                inputClassName="min-h-11 font-mono"
                field={field}
                label={t("hosts:pools.slug")}
                description={t("hosts:pools.slugHint")}
                autoComplete="off"
                inputMode="text"
                maxLength={63}
              />
            )}
          </form.Field>
          <form.Field name="maxLease">
            {(field) => (
              <TextField
                field={field}
                label={t("hosts:lease.poolField")}
                description={
                  <>
                    {t("hosts:lease.fieldHint")}
                    {effective ? (
                      <span data-pool-effective-lease="" className="block">
                        {t("hosts:pools.edit.effectiveLease", { value: effective })}
                      </span>
                    ) : null}
                  </>
                }
                autoComplete="off"
                inputMode="text"
                maxLength={12}
                inputClassName="min-h-11"
                onChange={() => setWarning(null)}
              />
            )}
          </form.Field>
        </FormSection>
        <AdvancedSection
          gridClassName="lg:grid-cols-1"
          title={t("hosts:pools.edit.lifetime")}
          summary={t(
            values.unlimitedLeaseForShares === "shares"
              ? "hosts:lease.unlimitedShares"
              : "hosts:lease.unlimitedOwner",
          )}
        >
          <form.Field name="unlimitedLeaseForShares">
            {(field) => (
              <div className="flex min-w-0 flex-col gap-2">
                <Label htmlFor={unlimitedId}>{t("hosts:lease.unlimitedField")}</Label>
                <FormSelect
                  id={unlimitedId}
                  autoComplete="off"
                  value={field.state.value}
                  onValueChange={(next) => field.handleChange(next as "owner" | "shares")}
                >
                  <SelectItem value="owner">{t("hosts:lease.unlimitedOwner")}</SelectItem>
                  <SelectItem value="shares">{t("hosts:lease.unlimitedShares")}</SelectItem>
                </FormSelect>
                {pool.unlimitedLeaseForShares && field.state.value === "owner" ? (
                  <p className="text-sm text-muted-foreground">
                    {t("hosts:lease.unlimitedRevokeWarning")}
                  </p>
                ) : null}
              </div>
            )}
          </form.Field>
        </AdvancedSection>
        <AdvancedSection
          gridClassName="lg:grid-cols-1"
          title={t("hosts:pools.edit.placement")}
          summary={[
            t(values.preferOwnHosts ? "hosts:pools.edit.preferOwn" : "hosts:pools.edit.anyHost"),
            values.ownHostsOnly ? t("hosts:pools.edit.ownOnly") : null,
          ]
            .filter(Boolean)
            .join(" · ")}
        >
          <form.Field name="preferOwnHosts">
            {(field) => (
              <label className="flex min-h-11 items-center gap-3 text-sm">
                <Checkbox checked={field.state.value} onCheckedChange={field.handleChange} />
                {t("hosts:poolCapacity.preferOwnHosts")}
              </label>
            )}
          </form.Field>
          <form.Field name="ownHostsOnly">
            {(field) => (
              <label className="flex min-h-11 items-center gap-3 text-sm">
                <Checkbox checked={field.state.value} onCheckedChange={field.handleChange} />
                {t("hosts:sharing.ownHostsOnly")}
              </label>
            )}
          </form.Field>
          <form.Field name="disconnectGraceSeconds">
            {(field) => (
              <TextField
                field={field}
                label={t("hosts:sharing.graceSeconds")}
                type="number"
                min={0}
                max={2592000}
                autoComplete="off"
                inputClassName="min-h-11"
              />
            )}
          </form.Field>
        </AdvancedSection>
        <AdvancedSection
          gridClassName="lg:grid-cols-1"
          title={t("hosts:pools.edit.images")}
          summary={
            values.memberImageCacheMaxGiB.trim() === ""
              ? t("hosts:pools.edit.noPoolLimit")
              : t("hosts:pools.edit.gib", { value: values.memberImageCacheMaxGiB.trim() })
          }
        >
          <form.Field name="memberImageCacheMaxGiB">
            {(field) => (
              <TextField
                field={field}
                label={t("hosts:pools.imageCacheField")}
                description={t("hosts:pools.imageCacheHint")}
                type="number"
                min={0}
                max={1048576}
                autoComplete="off"
                inputMode="numeric"
                inputClassName="min-h-11"
              />
            )}
          </form.Field>
        </AdvancedSection>
        <AdvancedSection
          gridClassName="lg:grid-cols-1"
          title={t("hosts:pools.edit.queue")}
          summary={[
            values.capacityWaitMinutes.trim() || operatorLimit,
            values.capacityQueuePerKey.trim() || operatorLimit,
            values.capacityQueuePerOwner.trim() || operatorLimit,
          ].join(" · ")}
        >
          <p className="text-sm text-muted-foreground">
            {t("hosts:poolCapacity.operatorLimits", {
              wait:
                limits.data?.capacityWaitMaxMs == null
                  ? t("hosts:poolCapacity.unlimited")
                  : formatLeaseDuration(limits.data.capacityWaitMaxMs, lang),
              perKey: limits.data?.capacityQueuePerKey ?? t("hosts:poolCapacity.unlimited"),
              perOwner: limits.data?.capacityQueuePerOwner ?? t("hosts:poolCapacity.unlimited"),
            })}
          </p>
          {(
            [
              ["capacityWaitMinutes", "hosts:poolCapacity.waitField"],
              ["capacityQueuePerKey", "hosts:poolCapacity.perKeyField"],
              ["capacityQueuePerOwner", "hosts:poolCapacity.perOwnerField"],
            ] as const
          ).map(([name, label]) => (
            <form.Field key={name} name={name}>
              {(field) => (
                <TextField
                  field={field}
                  label={t(label)}
                  description={t("hosts:poolCapacity.limitHint")}
                  autoComplete="off"
                  inputMode="numeric"
                  maxLength={7}
                  inputClassName="min-h-11"
                />
              )}
            </form.Field>
          ))}
        </AdvancedSection>
        {warning ? (
          <p role="alert" data-lease-warning="" className="text-sm text-destructive">
            {t(warning.more ? "hosts:lease.previewMore" : "hosts:lease.preview", {
              count: warning.affected,
            })}
          </p>
        ) : null}
        <SharingNotice contribution />
        {problem ? (
          <p role="alert" className="text-sm text-destructive">
            {t(`hosts:pools.problem.${problem}`)}
          </p>
        ) : null}
      </div>
    </WideSheet>
  );
}

/** One owned pool: what it is made of, one primary action and the rest in a menu. */
function PoolRow({ pool, lang }: { pool: Pool; lang: string }) {
  const { t, i18n } = useTranslation(["hosts", "common"]);
  const [editing, setEditing] = useState(false);
  const [members, setMembers] = useState(false);
  const [sharing, setSharing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [capacity, setCapacity] = useState(false);
  const [problem, setProblem] = useState<CredentialProblem | null>(null);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const longest = useLongestLifetime(lang);
  const remove = useMutation({
    ...orpc.sandboxPools.delete.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: () => {
      setDeleting(false);
      void queryClient.invalidateQueries({ queryKey: orpc.sandboxPools.key() });
    },
    onError: (error) => {
      if (!redirect(error)) setProblem(credentialProblem(error));
    },
  });
  const summary = pool.summary;
  return (
    <li
      data-pool-id={pool.id}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="break-words font-medium">{pool.label}</h2>
          <p className="break-all font-mono text-xs text-muted-foreground">{pool.slug}</p>
        </div>
        <PageActions
          primary={
            <Button size="touch" onClick={() => setMembers(true)}>
              {t("hosts:pools.actions.hosts")}
            </Button>
          }
          secondary={
            <Button size="touch" variant="outline" onClick={() => setSharing(true)}>
              {t("hosts:pools.actions.people")}
            </Button>
          }
          overflowLabel={t("hosts:pools.actions.more", { label: pool.label })}
          overflow={[
            {
              id: "capacity",
              label: t("hosts:poolCapacity.open"),
              onSelect: () => setCapacity(true),
            },
            { id: "edit", label: t("hosts:pools.edit.action"), onSelect: () => setEditing(true) },
            {
              id: "delete",
              label: t("hosts:pools.delete"),
              destructive: true,
              onSelect: () => setDeleting(true),
            },
          ]}
        />
      </div>
      {summary ? (
        <dl data-pool-summary="" className="grid min-w-0 gap-3 text-sm sm:grid-cols-4">
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">{t("hosts:pools.summary.hosts")}</dt>
            <dd data-pool-summary-hosts="">
              {summary.hosts.total === 0
                ? t("hosts:pools.summary.hostsNone")
                : t("hosts:pools.summary.hostsValue", {
                    count: summary.hosts.total,
                    connected: summary.hosts.connected,
                  })}
            </dd>
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">{t("hosts:pools.summary.people")}</dt>
            <dd data-pool-summary-people="">
              {summary.people === 0
                ? t("hosts:pools.summary.peopleNone")
                : t("hosts:pools.summary.peopleValue", { count: summary.people })}
            </dd>
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">{t("hosts:pools.summary.capacity")}</dt>
            <dd data-pool-summary-capacity="" className="tabular-nums">
              {summary.hosts.enabled === 0
                ? "—"
                : t("hosts:pools.summary.capacityValue", {
                    memory: formatGiB(summary.capacity.memoryMiB, i18n.language),
                    vcpu: summary.capacity.vcpu,
                  })}
            </dd>
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">{t("hosts:pools.summary.lease")}</dt>
            <dd data-pool-summary-lease="">{longest(summary)}</dd>
          </div>
        </dl>
      ) : null}
      {problem ? (
        <p role="alert" className="text-sm text-destructive">
          {t(`hosts:pools.problem.${problem}`)}
        </p>
      ) : null}
      {sharing ? (
        <PoolSharing
          poolId={pool.id}
          poolLabel={pool.label}
          lang={lang}
          onClose={() => setSharing(false)}
        />
      ) : null}
      {editing ? <EditPoolSheet pool={pool} lang={lang} onClose={() => setEditing(false)} /> : null}
      {members ? <MembersSheet pool={pool} lang={lang} onClose={() => setMembers(false)} /> : null}
      {capacity ? (
        <PoolCapacityDialog poolId={pool.id} owner lang={lang} onClose={() => setCapacity(false)} />
      ) : null}
      <ConfirmDeleteDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={t("hosts:pools.deleteTitle", { label: pool.label })}
        description={t("hosts:pools.deleteHint")}
        confirmToken={pool.slug}
        typePrompt={t("hosts:pools.confirm")}
        copyAriaLabel={t("hosts:pools.copy")}
        isPending={remove.isPending}
        onConfirm={() => remove.mutate({ id: pool.id })}
      />
    </li>
  );
}

/** "Hosts": the pool's member hosts (was "Manage members"), in a wide sheet. */
function MembersSheet({ pool, lang, onClose }: { pool: Pool; lang: string; onClose: () => void }) {
  const { t } = useTranslation(["hosts", "common"]);
  const [adding, setAdding] = useState(false);
  const members = useInfiniteQuery({
    ...orpc.sandboxPools.listMembers.infiniteOptions({
      ...paging,
      input: (cursor: string | undefined) => ({ cursor, poolId: pool.id, limit: 20 }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [members.error]);
  return (
    <WideSheet
      data-pool-members=""
      title={t("hosts:pools.membersTitle", { label: pool.label })}
      description={t("hosts:pools.memberHint")}
      closeLabel={t("common:actions.close")}
      onClose={onClose}
      actions={
        <>
          <Button type="button" size="touch" variant="outline" onClick={onClose}>
            {t("common:actions.close")}
          </Button>
          <Button size="touch" onClick={() => setAdding(true)}>
            <Plus aria-hidden="true" />
            {t("hosts:pools.add")}
          </Button>
        </>
      }
    >
      {members.data?.pages[0]?.items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("hosts:pools.noMembers")}</p>
      ) : null}
      {members.isPending ? (
        <SkeletonList count={2} />
      ) : members.isError ? (
        <InlineRetry message={t("hosts:pools.failed")} onRetry={() => void members.refetch()} />
      ) : (
        <ul className="grid min-w-0 gap-3 lg:grid-cols-2">
          {members.data?.pages
            .flatMap((p) => p.items)
            .map((member) => (
              <MemberRow key={member.id} member={member} pool={pool} lang={lang} />
            ))}
        </ul>
      )}
      <LoadMore
        hasNextPage={members.hasNextPage}
        isFetchingNextPage={members.isFetchingNextPage}
        onLoadMore={() => void members.fetchNextPage()}
      />
      {adding ? <AddMember poolId={pool.id} lang={lang} onClose={() => setAdding(false)} /> : null}
    </WideSheet>
  );
}

function AddMember({
  poolId,
  lang,
  onClose,
}: {
  poolId: string;
  lang: string;
  onClose: () => void;
}) {
  const { t } = useTranslation(["hosts", "common"]);
  const id = useId();
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [problem, setProblem] = useState<CredentialProblem | null>(null);
  const hosts = useInfiniteQuery({
    ...orpc.sandboxHosts.listHosts.infiniteOptions({
      ...paging,
      input: (cursor: string | undefined) => ({ cursor, limit: 100, excludePoolId: poolId }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [hosts.error]);
  const add = useMutation({
    ...orpc.sandboxPools.addMember.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: orpc.sandboxPools.key() });
      void queryClient.invalidateQueries({ queryKey: orpc.sandboxHosts.listHosts.key() });
      onClose();
    },
    onError: (error) => {
      if (!redirect(error)) setProblem(credentialProblem(error));
    },
  });
  const form = useForm({
    defaultValues: { sandboxHostId: "" },
    validators: {
      onSubmit: z.object({
        sandboxHostId: z
          .string()
          .min(1, t("hosts:pools.chooseHost"))
          .max(64, t("hosts:pools.chooseHost"))
          .refine(
            (value) =>
              hosts.data?.pages.some((page) =>
                page.items.some((host) => host.id === value && host.deletionRequestedAt == null),
              ) ?? false,
            t("hosts:pools.chooseHost"),
          ),
      }),
    },
    onSubmit: ({ value }) => {
      if (value.sandboxHostId)
        add.mutate({ poolId, sandboxHostId: value.sandboxHostId, enabled: true });
    },
  });
  const choices =
    hosts.data?.pages.flatMap((page) => page.items).filter((host) => !host.deletionRequestedAt) ??
    [];
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent closeLabel={t("common:actions.close")}>
        <DialogHeader>
          <DialogTitle>{t("hosts:pools.add")}</DialogTitle>
          <DialogDescription>{t("hosts:pools.memberHint")}</DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void form.handleSubmit();
          }}
        >
          <Label htmlFor={id}>{t("hosts:pools.host")}</Label>
          <form.Field name="sandboxHostId">
            {(field) => (
              <>
                <FormSelect
                  id={id}
                  optionsSettled={hosts.isSuccess && !hosts.isFetching && !hosts.hasNextPage}
                  autoComplete="off"
                  disabled={add.isPending || choices.length === 0}
                  value={field.state.value}
                  onValueChange={(value) => field.handleChange(value)}
                >
                  <SelectItem value="">{t("hosts:pools.chooseHost")}</SelectItem>
                  {choices.map((h) => (
                    <SelectItem key={h.id} value={h.id}>
                      <ResourceIdentity label={h.label} slug={h.slug} />
                    </SelectItem>
                  ))}
                </FormSelect>
                {field.state.meta.errors.length ? (
                  <p role="alert" className="text-sm text-destructive">
                    {t("hosts:pools.chooseHost")}
                  </p>
                ) : null}
              </>
            )}
          </form.Field>
          {hosts.isPending ? <SkeletonList count={1} /> : null}
          {!hosts.isPending && !hosts.isError && choices.length === 0 ? (
            <p>{t(hosts.hasNextPage ? "hosts:pools.noHostsOnPage" : "hosts:pools.noHostsToAdd")}</p>
          ) : null}
          {hosts.isError ? (
            <InlineRetry message={t("hosts:pools.failed")} onRetry={() => void hosts.refetch()} />
          ) : null}
          <LoadMore
            hasNextPage={hosts.hasNextPage}
            isFetchingNextPage={hosts.isFetchingNextPage}
            onLoadMore={() => void hosts.fetchNextPage()}
          />
          {problem ? (
            <p role="alert" className="text-sm text-destructive">
              {t(`hosts:pools.problem.${problem}`)}
            </p>
          ) : null}
          <DialogFooter>
            <Button type="button" size="touch" variant="outline" onClick={onClose}>
              {t("common:actions.cancel")}
            </Button>
            <Button size="touch" type="submit" disabled={add.isPending || choices.length === 0}>
              {t("hosts:pools.addSubmit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
function MemberRow({ member, pool, lang }: { member: Member; pool: Pool; lang: string }) {
  const { t } = useTranslation(["hosts", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [removing, setRemoving] = useState(false);
  const [editingLease, setEditingLease] = useState(false);
  const [problem, setProblem] = useState<CredentialProblem | null>(null);
  const input = { poolId: member.poolId, sandboxHostId: member.sandboxHostId };
  const onSuccess = () => {
    setProblem(null);
    setRemoving(false);
    void queryClient.invalidateQueries({ queryKey: orpc.sandboxPools.key() });
    void queryClient.invalidateQueries({ queryKey: orpc.sandboxHosts.listHosts.key() });
  };
  const onError = (error: unknown) => {
    if (!redirect(error)) setProblem(credentialProblem(error));
  };
  const update = useMutation({
    ...orpc.sandboxPools.updateMember.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess,
    onError,
  });
  const remove = useMutation({
    ...orpc.sandboxPools.removeMember.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess,
    onError,
  });
  return (
    <li className="flex min-w-0 flex-col gap-3 rounded-lg border bg-card p-3">
      <p className="break-words font-medium">
        <ResourceIdentity label={member.Host.label} slug={member.Host.slug} />
      </p>
      {member.Host.User?.name ? (
        <p className="text-sm text-muted-foreground">{member.Host.User.name}</p>
      ) : null}
      <p data-member-caps="" className="text-sm">
        {/* Owner-local members are exempt from member caps (placement and the
            capacity view ignore them), so none can be set or shown. */}
        {member.hostOwnerId != null && member.hostOwnerId === member.userId
          ? t("hosts:sharing.ownerLocalCaps")
          : t("hosts:sharing.percentages", {
              memory: member.memoryCapPercent ?? 100,
              vcpu: member.vcpuCapPercent ?? 100,
            })}
      </p>
      <p data-member-lease="" className="text-sm">
        {t("hosts:lease.memberValue", {
          value:
            member.maxLeaseMs == null
              ? t("hosts:lease.noLimit")
              : formatLeaseDuration(member.maxLeaseMs, lang),
        })}
      </p>
      <div className="flex flex-wrap gap-1.5">
        <Badge
          className={
            member.enabled
              ? "border-primary/40 bg-primary/10 text-primary"
              : "border-border bg-muted text-muted-foreground"
          }
        >
          {t(member.enabled ? "hosts:pools.enabled" : "hosts:pools.disabled")}
        </Badge>
        {member.Host.draining ? (
          <Badge className="border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400">
            {t("hosts:pools.draining")}
          </Badge>
        ) : null}
      </div>
      <div className="flex flex-wrap gap-2">
        <Button
          size="touch"
          variant="secondary"
          disabled={update.isPending || remove.isPending}
          onClick={() => update.mutate({ ...input, enabled: !member.enabled })}
        >
          {t(member.enabled ? "hosts:pools.disable" : "hosts:pools.enable")}
        </Button>
        {/* Only the host owner sets a membership limit; contributed hosts' limits are theirs. */}
        {member.hostOwnerId === member.userId ? (
          <Button
            size="touch"
            variant="secondary"
            disabled={update.isPending || remove.isPending}
            onClick={() => setEditingLease(true)}
          >
            {t("hosts:lease.editMember")}
          </Button>
        ) : null}
        <Button
          size="touch"
          variant="destructive"
          disabled={update.isPending || remove.isPending}
          onClick={() => setRemoving(true)}
        >
          {t("hosts:pools.remove")}
        </Button>
      </div>
      {editingLease ? (
        <MemberLeaseSheet member={member} lang={lang} onClose={() => setEditingLease(false)} />
      ) : null}
      {problem ? (
        <p role="alert" className="text-sm text-destructive">
          {t(`hosts:pools.problem.${problem}`)}
        </p>
      ) : null}
      <ConfirmDeleteDialog
        open={removing}
        onOpenChange={setRemoving}
        title={t("hosts:pools.removeTitle", { host: member.Host.label, pool: pool.label })}
        description={t("hosts:pools.deleteHint")}
        confirmToken={member.Host.slug}
        typePrompt={t("hosts:pools.confirm")}
        copyAriaLabel={t("hosts:pools.copy")}
        isPending={remove.isPending}
        onConfirm={() => remove.mutate(input)}
      />
    </li>
  );
}

/** Edit → Sheet: an own-host membership's lease limit, with the lowering preview. */
function MemberLeaseSheet({
  member,
  lang,
  onClose,
}: {
  member: Member;
  lang: string;
  onClose: () => void;
}) {
  const { t } = useTranslation(["hosts", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [problem, setProblem] = useState<CredentialProblem | null>(null);
  const [warning, setWarning] = useState<{ affected: number; more: boolean } | null>(null);
  const update = useMutation({
    ...orpc.sandboxPools.updateMember.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const preview = useMutation({
    ...orpc.sandboxPools.previewLeaseLowering.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: { maxLease: leaseLimitText(member.maxLeaseMs) },
    validators: {
      onSubmit: z.object({
        maxLease: z
          .string()
          .refine((v) => parseLeaseLimit(v) !== undefined, t("hosts:lease.invalid")),
      }),
    },
    onSubmit: async ({ value }) => {
      setProblem(null);
      try {
        const maxLeaseMs = parseLeaseLimit(value.maxLease) ?? null;
        if (
          maxLeaseMs !== null &&
          (member.maxLeaseMs === null || maxLeaseMs < member.maxLeaseMs) &&
          warning === null
        ) {
          const impact = await preview.mutateAsync({
            scope: "member",
            poolId: member.poolId,
            sandboxHostId: member.sandboxHostId,
            maxLeaseMs,
          });
          if (impact.affected > 0) {
            setWarning(impact);
            return;
          }
        }
        await update.mutateAsync({
          poolId: member.poolId,
          sandboxHostId: member.sandboxHostId,
          maxLeaseMs,
        });
        await queryClient.invalidateQueries({ queryKey: orpc.sandboxPools.key() });
        onClose();
      } catch (error) {
        if (!redirect(error)) setProblem(credentialProblem(error));
      }
    },
  });
  return (
    <Sheet
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <SheetContent showCloseButton={false}>
        <SheetHeader>
          <SheetTitle>{t("hosts:lease.editMember")}</SheetTitle>
          <SheetDescription>{t("hosts:lease.memberDescription")}</SheetDescription>
        </SheetHeader>
        <SheetBody className="flex min-w-0 flex-col gap-4">
          <form
            className="flex min-w-0 flex-col gap-4 pb-4"
            onSubmit={(event) => {
              event.preventDefault();
              void form.handleSubmit();
            }}
          >
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
                  onChange={() => setWarning(null)}
                />
              )}
            </form.Field>
            {warning ? (
              <p role="alert" data-lease-warning="">
                {t(warning.more ? "hosts:lease.previewMore" : "hosts:lease.preview", {
                  count: warning.affected,
                })}
              </p>
            ) : null}
            {problem ? (
              <p role="alert" className="text-sm text-destructive">
                {t(`hosts:pools.problem.${problem}`)}
              </p>
            ) : null}
            <div className="flex flex-wrap gap-2">
              <Button type="submit" size="touch" disabled={update.isPending || preview.isPending}>
                {t(warning ? "hosts:lease.saveAnyway" : "common:actions.save")}
              </Button>
              <Button type="button" size="touch" variant="outline" onClick={onClose}>
                {t("common:actions.cancel")}
              </Button>
            </div>
          </form>
        </SheetBody>
      </SheetContent>
    </Sheet>
  );
}
