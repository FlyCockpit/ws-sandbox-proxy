import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery } from "@tanstack/react-query";
import {
  USER_LOGIN_EXPIRY_DAYS,
  USER_LOGIN_MAX_LIVE_SANDBOXES,
  USER_LOGIN_POOL_IDS_MAX,
  type UserLoginGrant,
} from "@wssp/config/user-device-login";
import { Button } from "@wssp/ui/components/button";
import { Checkbox } from "@wssp/ui/components/checkbox";
import { Label } from "@wssp/ui/components/label";
import { RadioGroup, RadioGroupItem } from "@wssp/ui/components/radio-group";
import { SelectItem } from "@wssp/ui/components/select";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { FieldError, TextField } from "@wssp/ui/components/text-field";
import type { TFunction } from "i18next";
import { TriangleAlert } from "lucide-react";
import { useId } from "react";
import { Trans, useTranslation } from "react-i18next";
import { z } from "zod";
import { FormSelect } from "@/components/form-select";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { ResourceIdentity } from "@/components/resource-identity";
import {
  DEFAULT_USER_LOGIN_DRAFT,
  draftMaxLiveSandboxes,
  type UserLoginDraft,
  userLoginGrantFromDraft,
} from "@/lib/user-login-grant";
import { orpc } from "@/utils/orpc";

/** The pool picker pages usable pools with Load more (the procedure's page maximum). */
const POOL_PAGE_LIMIT = 100;

const ACCESS = ["read", "write"] as const satisfies readonly UserLoginGrant["access"][];
const POOL_MODES = [
  "ALL_USABLE",
  "SELECTED",
] as const satisfies readonly UserLoginGrant["poolMode"][];

function draftSchema(t: TFunction<"auth">) {
  return z
    .object({
      name: z
        .string()
        .trim()
        .min(1, t("device.user.nameRequired"))
        .max(120, t("device.user.nameTooLong")),
      access: z.enum(ACCESS),
      poolMode: z.enum(POOL_MODES),
      poolIds: z.array(z.string()),
      ownSandboxesOnly: z.boolean(),
      maxLiveSandboxes: z.string().refine(
        (text) => {
          const limit = draftMaxLiveSandboxes(text);
          return (
            limit === null ||
            (limit !== undefined && limit >= 1 && limit <= USER_LOGIN_MAX_LIVE_SANDBOXES)
          );
        },
        t("device.user.maxLiveInvalid", { max: USER_LOGIN_MAX_LIVE_SANDBOXES }),
      ),
      expiresInDays: z.string(),
    })
    .superRefine((draft, context) => {
      if (draft.poolMode !== "SELECTED") return;
      if (draft.poolIds.length === 0)
        context.addIssue({
          code: "custom",
          path: ["poolIds"],
          message: t("device.user.poolsRequired"),
        });
      else if (draft.poolIds.length > USER_LOGIN_POOL_IDS_MAX)
        context.addIssue({
          code: "custom",
          path: ["poolIds"],
          message: t("device.user.poolsTooMany", { count: USER_LOGIN_POOL_IDS_MAX }),
        });
    });
}

export type UserLoginApprovalProps = {
  /** False until the claim and request summary have settled for this request. */
  actionsEnabled: boolean;
  approving: boolean;
  denying: boolean;
  /** Called with a grant that parses with `userLoginGrantSchema`. */
  onApprove: (grant: UserLoginGrant) => void;
  onDeny: () => void;
};

/**
 * `wssp login` (user login) approval: the approver alone chooses what the
 * minted `/v1` key may do. Nothing the CLI sent is shown or preselected.
 */
export function UserLoginApproval({
  actionsEnabled,
  approving,
  denying,
  onApprove,
  onDeny,
}: UserLoginApprovalProps) {
  const { t } = useTranslation("auth");
  const expiryId = useId();
  const accessLabelId = useId();
  const poolModeLabelId = useId();
  const form = useForm({
    defaultValues: DEFAULT_USER_LOGIN_DRAFT,
    validators: { onSubmit: draftSchema(t) },
    onSubmit: ({ value }) => {
      const grant = userLoginGrantFromDraft(value);
      if (grant) onApprove(grant);
    },
  });
  const poolMode = useStore(form.store, (state) => state.values.poolMode);

  return (
    <form
      noValidate
      className="flex min-w-0 flex-col gap-5"
      onSubmit={(event) => {
        event.preventDefault();
        event.stopPropagation();
        if (actionsEnabled) void form.handleSubmit();
      }}
    >
      <div
        role="note"
        data-user-login-warning=""
        className="flex gap-2 rounded-lg border border-amber-500/50 p-3 text-sm text-amber-800 dark:text-amber-300"
      >
        <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
        <div className="min-w-0 space-y-1">
          <p className="font-medium">{t("device.user.warningTitle")}</p>
          <p>
            <Trans
              t={t}
              i18nKey="device.user.warning"
              components={{ code: <code className="whitespace-nowrap" /> }}
            />
          </p>
        </div>
      </div>

      <form.Field name="name">
        {(field) => (
          <TextField
            inputClassName="min-h-11"
            field={field}
            label={t("device.user.nameLabel")}
            description={t("device.user.nameHint")}
            autoComplete="off"
            inputMode="text"
            maxLength={120}
          />
        )}
      </form.Field>

      <form.Field name="access">
        {(field) => (
          <div className="flex min-w-0 flex-col gap-1">
            <p id={accessLabelId} className="text-sm font-medium">
              {t("device.user.accessLabel")}
            </p>
            <RadioGroup
              aria-labelledby={accessLabelId}
              name="access"
              value={field.state.value}
              onValueChange={(value: UserLoginDraft["access"]) => field.handleChange(value)}
            >
              {ACCESS.map((option) => (
                <label
                  key={option}
                  data-access-option={option}
                  className="flex min-h-11 items-start gap-3 py-1 text-sm"
                >
                  <RadioGroupItem value={option} className="mt-1" />
                  <span className="min-w-0">
                    <span className="block">{t(`device.user.access.${option}`)}</span>
                    <span className="block text-xs text-muted-foreground">
                      <Trans
                        t={t}
                        i18nKey={`device.user.accessHint.${option}`}
                        components={{ code: <code className="whitespace-nowrap" /> }}
                      />
                    </span>
                  </span>
                </label>
              ))}
            </RadioGroup>
            <p className="text-xs text-muted-foreground">{t("device.user.accessNever")}</p>
          </div>
        )}
      </form.Field>

      <form.Field name="poolMode">
        {(field) => (
          <div className="flex min-w-0 flex-col gap-1">
            <p id={poolModeLabelId} className="text-sm font-medium">
              {t("device.user.poolsLabel")}
            </p>
            <RadioGroup
              aria-labelledby={poolModeLabelId}
              name="poolMode"
              value={field.state.value}
              onValueChange={(value: UserLoginDraft["poolMode"]) => field.handleChange(value)}
            >
              {POOL_MODES.map((option) => (
                <label key={option} className="flex min-h-11 items-center gap-3 text-sm">
                  <RadioGroupItem value={option} />
                  <span className="min-w-0">{t(`device.user.poolMode.${option}`)}</span>
                </label>
              ))}
            </RadioGroup>
          </div>
        )}
      </form.Field>

      {poolMode === "SELECTED" ? (
        <form.Field name="poolIds">
          {(field) => (
            <UserLoginPoolPicker
              selected={field.state.value}
              onChange={field.handleChange}
              errors={field.state.meta.errors}
            />
          )}
        </form.Field>
      ) : null}

      <form.Field name="ownSandboxesOnly">
        {(field) => (
          <div className="flex min-w-0 flex-col gap-1">
            <label className="flex min-h-11 items-center gap-3 text-sm">
              <Checkbox
                checked={field.state.value}
                onCheckedChange={(value) => field.handleChange(value === true)}
              />
              <span>{t("device.user.ownSandboxesOnly")}</span>
            </label>
            <p className="text-xs text-muted-foreground">{t("device.user.ownSandboxesOnlyHint")}</p>
          </div>
        )}
      </form.Field>

      <form.Field name="maxLiveSandboxes">
        {(field) => (
          <TextField
            inputClassName="min-h-11"
            field={field}
            // Text, not number: a number input reports a half-typed value such
            // as `1e` as "", which would read as "no limit".
            type="text"
            inputMode="numeric"
            label={t("device.user.maxLiveLabel")}
            description={t("device.user.maxLiveHint")}
            autoComplete="off"
          />
        )}
      </form.Field>

      <form.Field name="expiresInDays">
        {(field) => (
          <div className="flex min-w-0 flex-col gap-2">
            <Label htmlFor={expiryId}>{t("device.user.expiryLabel")}</Label>
            <FormSelect
              id={expiryId}
              className="min-h-11"
              value={field.state.value}
              onValueChange={field.handleChange}
            >
              {USER_LOGIN_EXPIRY_DAYS.map((days) => (
                <SelectItem key={days} value={String(days)}>
                  {t("device.user.expiryDays", { count: days })}
                </SelectItem>
              ))}
            </FormSelect>
          </div>
        )}
      </form.Field>

      <div className="flex flex-wrap gap-2">
        <Button type="submit" className="min-h-[44px]" disabled={!actionsEnabled}>
          {approving ? t("device.approving") : t("device.approve")}
        </Button>
        <Button
          type="button"
          variant="outline"
          className="min-h-[44px]"
          disabled={!actionsEnabled}
          onClick={onDeny}
        >
          {denying ? t("device.denying") : t("device.deny")}
        </Button>
      </div>
    </form>
  );
}

/** Usable pools, loaded only once "Only selected pools" is chosen. */
function UserLoginPoolPicker({
  selected,
  onChange,
  errors,
}: {
  selected: readonly string[];
  onChange: (value: string[]) => void;
  errors: readonly unknown[];
}) {
  const { t } = useTranslation("auth");
  const errorId = useId();
  const pools = useInfiniteQuery({
    ...orpc.sandboxPools.listUsable.infiniteOptions({
      input: (cursor: string | undefined) => ({ limit: POOL_PAGE_LIMIT, cursor }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (page: { nextCursor: string | null }) => page.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const items = pools.data?.pages.flatMap((page) => page.items) ?? [];
  const toggle = (id: string, on: boolean) =>
    onChange(
      on
        ? [...selected.filter((value) => value !== id), id]
        : selected.filter((value) => value !== id),
    );

  return (
    <fieldset
      className="flex min-w-0 flex-col gap-1"
      aria-describedby={errors.length > 0 ? errorId : undefined}
    >
      <legend className="sr-only">{t("device.user.poolMode.SELECTED")}</legend>
      {selected.length > 0 ? (
        // Also clears a selected pool that disappeared from the list (lost
        // access): its checkbox is gone, the selection must not be stuck.
        <Button
          type="button"
          variant="ghost"
          className="min-h-11 self-start"
          onClick={() => onChange([])}
        >
          {t("device.user.poolsClear", { count: selected.length })}
        </Button>
      ) : null}
      {pools.isPending ? (
        <div className="flex flex-col gap-2" aria-hidden="true" data-pools-loading="">
          {[0, 1, 2].map((row) => (
            <div key={row} className="flex min-h-11 items-center gap-3">
              <Skeleton className="size-4 rounded-sm" />
              <Skeleton className="h-4 w-2/3" />
            </div>
          ))}
        </div>
      ) : pools.isError && !pools.data ? (
        <InlineRetry
          message={t("device.user.poolsLoadError")}
          onRetry={() => void pools.refetch()}
        />
      ) : items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("device.user.poolsEmpty")}</p>
      ) : (
        items.map((pool) => (
          <label
            key={pool.id}
            data-pool-id={pool.id}
            className="flex min-h-11 items-center gap-3 text-sm"
          >
            <Checkbox
              checked={selected.includes(pool.id)}
              onCheckedChange={(checked) => toggle(pool.id, checked === true)}
            />
            <span className="min-w-0 break-words">
              <ResourceIdentity label={pool.label} slug={pool.slug} />
              <span className="block text-xs text-muted-foreground">
                {"owner" in pool && pool.owner ? pool.owner.name : t("device.user.ownedPool")}
              </span>
            </span>
          </label>
        ))
      )}
      {/* Loaded choices stay usable when a later page (or a refetch) fails. */}
      {pools.isError && pools.data ? (
        <InlineRetry
          message={t("device.user.poolsLoadError")}
          onRetry={() =>
            void (pools.isFetchNextPageError ? pools.fetchNextPage() : pools.refetch())
          }
        />
      ) : null}
      <LoadMore
        hasNextPage={pools.hasNextPage}
        isFetchingNextPage={pools.isFetchingNextPage}
        onLoadMore={() => void pools.fetchNextPage()}
      />
      <FieldError id={errorId} errors={errors} />
    </fieldset>
  );
}
