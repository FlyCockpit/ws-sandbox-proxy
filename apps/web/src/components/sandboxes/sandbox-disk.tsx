import { useForm } from "@tanstack/react-form";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@wssp/ui/components/button";
import { RadioGroup, RadioGroupItem } from "@wssp/ui/components/radio-group";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@wssp/ui/components/sheet";
import { toast } from "@wssp/ui/components/sileo";
import { TextField } from "@wssp/ui/components/text-field";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { DiskLocationBadge } from "@/components/sandboxes/sandbox-parts";
import { useTwoFactorRedirect } from "@/hooks/use-two-factor-redirect";
import { formatDateTime } from "@/lib/format-date-time";
import {
  type DiskView,
  formatBytes,
  OFFLOAD_AFTER_MINUTES_MAX,
  OFFLOAD_AFTER_MINUTES_MIN,
  type OffloadPolicyView,
  offloadDelayParts,
} from "@/lib/sandbox-rules";
import { orpc } from "@/utils/orpc";

/**
 * The Disk card of a sandbox (disk offload, C8): where its root disk lives,
 * the current offload attempt or stored copy, which hosts may restore it, the
 * owner's restore pin and the offload policy (each Edit → Sheet). Only what
 * the server reported; the server decides every export and restore.
 */
export function DiskCard({
  sandboxId,
  disk,
  lang,
  locale,
  editable,
}: {
  sandboxId: string;
  disk: DiskView | null;
  lang: string;
  locale: string;
  editable: boolean;
}) {
  const { t } = useTranslation(["sandboxes"]);
  const [editing, setEditing] = useState<"pin" | "policy" | null>(null);
  if (!disk) return null;
  const narrowed = disk.eligibility === "own_hosts" && disk.offloadPin === "ANY";
  return (
    <section
      aria-labelledby="sandbox-disk"
      data-sandbox-disk=""
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <h2 id="sandbox-disk" className="font-heading text-sm font-semibold">
        {t("sandboxes:disk.title")}
      </h2>
      <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2">
        <div className="min-w-0 sm:col-span-2">
          <dt className="text-xs text-muted-foreground">{t("sandboxes:disk.location.label")}</dt>
          <dd className="flex min-w-0 flex-col gap-1">
            <span>
              <DiskLocationBadge disk={disk} />
            </span>
            <span className="text-xs text-muted-foreground">
              {t(`sandboxes:disk.locationHint.${disk.location}`)}
            </span>
          </dd>
        </div>
        {disk.offloadState !== "none" ? (
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">
              {t("sandboxes:disk.offloadState.label")}
            </dt>
            <dd data-disk-offload-state={disk.offloadState} className="min-w-0 break-words">
              {t(`sandboxes:disk.offloadState.${disk.offloadState}`)}
              {disk.offloadFailure ? (
                <span
                  data-disk-offload-failure={disk.offloadFailure}
                  className="block text-xs text-muted-foreground"
                >
                  {t(`sandboxes:disk.failure.${disk.offloadFailure}`)}
                </span>
              ) : null}
            </dd>
          </div>
        ) : null}
        {disk.sizeBytes !== null ? (
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">{t("sandboxes:disk.size")}</dt>
            <dd data-disk-size="" className="tabular-nums">
              {formatBytes(disk.sizeBytes, locale)}
            </dd>
          </div>
        ) : null}
        {disk.offloadedAt ? (
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">{t("sandboxes:disk.storedAt")}</dt>
            <dd>{formatDateTime(disk.offloadedAt, locale)}</dd>
          </div>
        ) : null}
        <div className="min-w-0 sm:col-span-2">
          <dt className="text-xs text-muted-foreground">{t("sandboxes:disk.eligibility.label")}</dt>
          <dd className="flex min-w-0 flex-wrap items-center gap-2">
            <span data-disk-eligibility={disk.eligibility}>
              {t(`sandboxes:disk.eligibility.${disk.eligibility}`)}
            </span>
            {editable && disk.eligibility !== "never" ? (
              <Button
                type="button"
                size="touch"
                variant="ghost"
                data-disk-pin-edit=""
                onClick={() => setEditing("pin")}
              >
                {t("sandboxes:disk.pin.change")}
              </Button>
            ) : null}
          </dd>
        </div>
        {disk.eligibility !== "never" ? (
          <div className="min-w-0 sm:col-span-2">
            <dt className="text-xs text-muted-foreground">{t("sandboxes:disk.policy.label")}</dt>
            <dd className="flex min-w-0 flex-col gap-1">
              <span className="flex min-w-0 flex-wrap items-center gap-2">
                <span data-disk-offload-policy={disk.offloadPolicy.mode} className="min-w-0">
                  <OffloadPolicyText policy={disk.offloadPolicy} />
                </span>
                {editable ? (
                  <Button
                    type="button"
                    size="touch"
                    variant="ghost"
                    data-disk-policy-edit=""
                    aria-label={t("sandboxes:disk.policy.changeLabel")}
                    onClick={() => setEditing("policy")}
                  >
                    {t("sandboxes:disk.policy.change")}
                  </Button>
                ) : null}
              </span>
              {disk.offloadDueAt ? (
                <span data-disk-offload-due="" className="text-xs text-muted-foreground">
                  {t("sandboxes:disk.policy.dueAt", {
                    time: formatDateTime(disk.offloadDueAt, locale),
                  })}
                </span>
              ) : null}
            </dd>
          </div>
        ) : null}
      </dl>
      {editing === "pin" ? (
        <OffloadPinSheet
          lang={lang}
          sandboxId={sandboxId}
          pin={disk.offloadPin}
          narrowed={narrowed}
          onClose={() => setEditing(null)}
        />
      ) : null}
      {editing === "policy" ? (
        <OffloadPolicySheet
          lang={lang}
          sandboxId={sandboxId}
          policy={disk.offloadPolicy}
          onClose={() => setEditing(null)}
        />
      ) : null}
    </section>
  );
}

const PINS = ["ANY", "OWN_HOSTS"] as const;

/** Edit → Sheet: the owner's restore pin. One request, no idempotency key. */
function OffloadPinSheet({
  lang,
  sandboxId,
  pin,
  narrowed,
  onClose,
}: {
  lang: string;
  sandboxId: string;
  pin: DiskView["offloadPin"];
  /** Login history or an owned-only template keeps it on own hosts anyway. */
  narrowed: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation(["sandboxes", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const labelId = useId();
  const radioName = useId();
  const [failed, setFailed] = useState(false);
  const save = useMutation({
    ...orpc.sandboxes.setOffloadPin.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: { offloadPin: pin },
    onSubmit: async ({ value }) => {
      setFailed(false);
      try {
        await save.mutateAsync({ id: sandboxId, offloadPin: value.offloadPin });
      } catch (error) {
        if (redirect(error)) return;
        setFailed(true);
        return;
      } finally {
        void queryClient.invalidateQueries({ queryKey: orpc.sandboxes.key() });
      }
      toast.success(t("sandboxes:disk.pin.saved"));
      onClose();
    },
  });

  return (
    <Sheet open onOpenChange={(open) => (open ? undefined : onClose())}>
      <SheetContent
        closeLabel={t("common:actions.close")}
        className="overflow-x-hidden overflow-y-auto"
      >
        <SheetHeader>
          <SheetTitle id={labelId}>{t("sandboxes:disk.pin.title")}</SheetTitle>
          <SheetDescription>{t("sandboxes:disk.pin.description")}</SheetDescription>
        </SheetHeader>
        <form
          noValidate
          data-disk-pin-form=""
          className="flex min-w-0 flex-col gap-4 px-4"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            void form.handleSubmit();
          }}
        >
          <form.Field name="offloadPin">
            {(field) => (
              <RadioGroup
                aria-labelledby={labelId}
                name={radioName}
                value={field.state.value}
                onValueChange={(value: DiskView["offloadPin"]) => field.handleChange(value)}
              >
                {PINS.map((value) => (
                  <label key={value} className="flex min-h-11 min-w-0 items-start gap-3 text-sm">
                    <RadioGroupItem value={value} className="mt-1" />
                    <span className="flex min-w-0 flex-col">
                      <span className="font-medium">{t(`sandboxes:disk.pin.${value}`)}</span>
                      <span className="text-xs text-muted-foreground">
                        {t(`sandboxes:disk.pin.${value}Hint`)}
                      </span>
                    </span>
                  </label>
                ))}
              </RadioGroup>
            )}
          </form.Field>
          {narrowed ? (
            <p data-disk-pin-narrowed="" className="text-sm text-muted-foreground">
              {t("sandboxes:disk.pin.narrowed")}
            </p>
          ) : null}
          {failed ? (
            <p role="alert" className="text-sm text-destructive">
              {t("sandboxes:disk.pin.failed")}
            </p>
          ) : null}
          <SheetFooter className="px-0">
            <form.Subscribe selector={(state) => state.isSubmitting}>
              {(submitting) => (
                <Button type="submit" size="touch" disabled={submitting}>
                  {submitting ? t("sandboxes:disk.pin.saving") : t("sandboxes:disk.pin.save")}
                </Button>
              )}
            </form.Subscribe>
            <Button type="button" variant="outline" size="touch" onClick={onClose}>
              {t("common:actions.cancel")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}

/** One line naming an offload policy (Disk card and the stop dialog). */
export function OffloadPolicyText({ policy }: { policy: OffloadPolicyView }) {
  const { t } = useTranslation(["sandboxes"]);
  if (policy.mode !== "after") return <>{t(`sandboxes:disk.policy.${policy.mode}`)}</>;
  const delay = offloadDelayParts(policy.afterMs);
  return (
    <>
      {t("sandboxes:disk.policy.after", {
        delay: t(`sandboxes:disk.policy.delay.${delay.unit}`, { count: delay.count }),
      })}
    </>
  );
}

const MODES = ["on_stop", "after", "on_pressure"] as const;

/**
 * Edit → Sheet: the offload policy (`updateSandbox` with `offload`). One
 * request, no idempotency key. The delay is entered in minutes.
 */
function OffloadPolicySheet({
  lang,
  sandboxId,
  policy,
  onClose,
}: {
  lang: string;
  sandboxId: string;
  policy: OffloadPolicyView;
  onClose: () => void;
}) {
  const { t } = useTranslation(["sandboxes", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const labelId = useId();
  const radioName = useId();
  const [failed, setFailed] = useState(false);
  const save = useMutation({
    ...orpc.sandboxes.updateSandbox.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const minutesValidator = z
    .string()
    .refine(
      (value) =>
        /^[0-9]{1,5}$/.test(value.trim()) &&
        Number(value) >= OFFLOAD_AFTER_MINUTES_MIN &&
        Number(value) <= OFFLOAD_AFTER_MINUTES_MAX,
      {
        message: t("sandboxes:disk.policy.minutesInvalid", {
          min: OFFLOAD_AFTER_MINUTES_MIN,
          max: OFFLOAD_AFTER_MINUTES_MAX,
        }),
      },
    );
  const form = useForm({
    defaultValues: {
      mode: policy.mode as OffloadPolicyView["mode"],
      minutes: policy.mode === "after" ? String(Math.ceil(policy.afterMs / 60_000)) : "120",
    },
    onSubmit: async ({ value }) => {
      setFailed(false);
      const offload: OffloadPolicyView =
        value.mode === "after"
          ? { mode: "after", afterMs: Number(value.minutes.trim()) * 60_000 }
          : { mode: value.mode };
      try {
        await save.mutateAsync({ id: sandboxId, offload });
      } catch (error) {
        if (redirect(error)) return;
        setFailed(true);
        return;
      } finally {
        void queryClient.invalidateQueries({ queryKey: orpc.sandboxes.key() });
      }
      toast.success(t("sandboxes:disk.policy.saved"));
      onClose();
    },
  });

  return (
    <Sheet open onOpenChange={(open) => (open ? undefined : onClose())}>
      <SheetContent
        closeLabel={t("common:actions.close")}
        className="overflow-x-hidden overflow-y-auto"
      >
        <SheetHeader>
          <SheetTitle id={labelId}>{t("sandboxes:disk.policy.title")}</SheetTitle>
          <SheetDescription>{t("sandboxes:disk.policy.description")}</SheetDescription>
        </SheetHeader>
        <form
          noValidate
          data-disk-policy-form=""
          className="flex min-w-0 flex-col gap-4 px-4"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            void form.handleSubmit();
          }}
        >
          <form.Field name="mode">
            {(field) => (
              <RadioGroup
                aria-labelledby={labelId}
                name={radioName}
                value={field.state.value}
                onValueChange={(value: OffloadPolicyView["mode"]) => field.handleChange(value)}
              >
                {MODES.map((value) => (
                  <label key={value} className="flex min-h-11 min-w-0 items-start gap-3 text-sm">
                    <RadioGroupItem value={value} className="mt-1" />
                    <span className="flex min-w-0 flex-col">
                      <span className="font-medium">
                        {t(`sandboxes:disk.policy.option.${value}`)}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {t(`sandboxes:disk.policy.option.${value}Hint`)}
                      </span>
                    </span>
                  </label>
                ))}
              </RadioGroup>
            )}
          </form.Field>
          <form.Subscribe selector={(state) => state.values.mode}>
            {(mode) =>
              mode === "after" ? (
                <form.Field name="minutes" validators={{ onSubmit: minutesValidator }}>
                  {(field) => (
                    <TextField
                      field={field}
                      label={t("sandboxes:disk.policy.minutes")}
                      description={t("sandboxes:disk.policy.minutesHint")}
                      inputMode="numeric"
                      autoComplete="off"
                      inputClassName="min-h-11 tabular-nums"
                    />
                  )}
                </form.Field>
              ) : null
            }
          </form.Subscribe>
          <p className="text-sm text-muted-foreground">{t("sandboxes:disk.policy.pressure")}</p>
          {failed ? (
            <p role="alert" className="text-sm text-destructive">
              {t("sandboxes:disk.policy.failed")}
            </p>
          ) : null}
          <SheetFooter className="px-0">
            <form.Subscribe selector={(state) => state.isSubmitting}>
              {(submitting) => (
                <Button type="submit" size="touch" disabled={submitting}>
                  {submitting ? t("common:actions.saving") : t("common:actions.saveChanges")}
                </Button>
              )}
            </form.Subscribe>
            <Button type="button" variant="outline" size="touch" onClick={onClose}>
              {t("common:actions.cancel")}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}
