import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@wssp/ui/components/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@wssp/ui/components/sheet";
import { toast } from "@wssp/ui/components/sileo";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { TextField } from "@wssp/ui/components/text-field";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { InlineRetry } from "@/components/inline-retry";
import { type AdminProblem, adminProblem, adminProblemKey } from "@/lib/admin-errors";
import { orpc } from "@/utils/orpc";

const STORED_MAX = 1_048_576;
const DOWNLOADS_MAX = 100_000;
const CONCURRENT_BUILDS_MAX = 1_000;
const BUILD_MINUTES_MAX = 1_000_000;

function optionalWhole(max: number) {
  return (value: string) =>
    value.trim() === "" ||
    (Number.isInteger(Number(value)) && Number(value) >= 0 && Number(value) <= max);
}
const blankOrNumber = (value: string) => (value.trim() === "" ? null : Number(value));

/**
 * Admin image-store quota overrides for one account. An override only lowers
 * the deployment ceiling (enforcement takes the smaller); empty means none.
 */
export function AdminImageQuotaSheet({
  user,
  onClose,
}: {
  user: { id: string; name: string; email: string };
  onClose: () => void;
}) {
  const { t } = useTranslation(["admin", "common"]);
  const quota = useQuery({
    ...orpc.users.imageQuota.queryOptions({ input: { userId: user.id } }),
    meta: { skipGlobalErrorToast: true },
  });
  return (
    <Sheet open onOpenChange={(open) => (open ? undefined : onClose())}>
      <SheetContent
        closeLabel={t("common:actions.close")}
        className="overflow-x-hidden overflow-y-auto"
      >
        <SheetHeader>
          <SheetTitle>{t("admin:imageQuota.title", { name: user.name || user.email })}</SheetTitle>
          <SheetDescription>{t("admin:imageQuota.description")}</SheetDescription>
        </SheetHeader>
        {quota.isPending ? <Skeleton className="m-4 h-40" /> : null}
        {quota.isError ? (
          <InlineRetry
            message={t("admin:imageQuota.loadFailed")}
            onRetry={() => void quota.refetch()}
          />
        ) : null}
        {quota.data ? (
          <QuotaForm
            userId={user.id}
            initial={{
              storedGiBMax: quota.data.storedGiBMax,
              downloadsPerHourMax: quota.data.downloadsPerHourMax,
              concurrentBuildsMax: quota.data.concurrentBuildsMax,
              buildMinutesPerMonthMax: quota.data.buildMinutesPerMonthMax,
              offloadGiBMax: quota.data.offloadGiBMax,
            }}
            onClose={onClose}
          />
        ) : null}
      </SheetContent>
    </Sheet>
  );
}

function QuotaForm({
  userId,
  initial,
  onClose,
}: {
  userId: string;
  initial: {
    storedGiBMax: number | null;
    downloadsPerHourMax: number | null;
    concurrentBuildsMax: number | null;
    buildMinutesPerMonthMax: number | null;
    offloadGiBMax: number | null;
  };
  onClose: () => void;
}) {
  const { t } = useTranslation(["admin", "common"]);
  const queryClient = useQueryClient();
  const [problem, setProblem] = useState<AdminProblem | null>(null);
  const save = useMutation({
    ...orpc.users.setImageQuota.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onError: (error: Error) => setProblem(adminProblem(error)),
  });
  const form = useForm({
    defaultValues: {
      storedGiBMax: initial.storedGiBMax === null ? "" : String(initial.storedGiBMax),
      downloadsPerHourMax:
        initial.downloadsPerHourMax === null ? "" : String(initial.downloadsPerHourMax),
      concurrentBuildsMax:
        initial.concurrentBuildsMax === null ? "" : String(initial.concurrentBuildsMax),
      buildMinutesPerMonthMax:
        initial.buildMinutesPerMonthMax === null ? "" : String(initial.buildMinutesPerMonthMax),
      offloadGiBMax: initial.offloadGiBMax === null ? "" : String(initial.offloadGiBMax),
    },
    validators: {
      onSubmit: z.object({
        storedGiBMax: z
          .string()
          .refine(optionalWhole(STORED_MAX), t("admin:imageQuota.invalidStored")),
        downloadsPerHourMax: z
          .string()
          .refine(optionalWhole(DOWNLOADS_MAX), t("admin:imageQuota.invalidDownloads")),
        concurrentBuildsMax: z
          .string()
          .refine(optionalWhole(CONCURRENT_BUILDS_MAX), t("admin:imageQuota.invalidConcurrent")),
        buildMinutesPerMonthMax: z
          .string()
          .refine(optionalWhole(BUILD_MINUTES_MAX), t("admin:imageQuota.invalidMinutes")),
        offloadGiBMax: z
          .string()
          .refine(optionalWhole(STORED_MAX), t("admin:imageQuota.invalidStored")),
      }),
    },
    onSubmit: async ({ value }) => {
      try {
        await save.mutateAsync({
          userId,
          storedGiBMax: blankOrNumber(value.storedGiBMax),
          downloadsPerHourMax: blankOrNumber(value.downloadsPerHourMax),
          concurrentBuildsMax: blankOrNumber(value.concurrentBuildsMax),
          buildMinutesPerMonthMax: blankOrNumber(value.buildMinutesPerMonthMax),
          offloadGiBMax: blankOrNumber(value.offloadGiBMax),
        });
        await queryClient.invalidateQueries({ queryKey: orpc.users.imageQuota.key() });
        toast.success(t("admin:imageQuota.saved"));
        onClose();
      } catch {
        // Explained inline from the typed error (see `problem`).
      }
    },
  });
  return (
    <form
      className="flex min-w-0 flex-col gap-4 p-4"
      onSubmit={(event) => {
        event.preventDefault();
        void form.handleSubmit();
      }}
    >
      <form.Field name="storedGiBMax">
        {(field) => (
          <TextField
            field={field}
            label={t("admin:imageQuota.stored")}
            description={t("admin:imageQuota.blankHint")}
            type="number"
            min={0}
            max={STORED_MAX}
            inputMode="numeric"
            autoComplete="off"
            inputClassName="min-h-11"
          />
        )}
      </form.Field>
      <form.Field name="downloadsPerHourMax">
        {(field) => (
          <TextField
            field={field}
            label={t("admin:imageQuota.downloads")}
            description={t("admin:imageQuota.blankHint")}
            type="number"
            min={0}
            max={DOWNLOADS_MAX}
            inputMode="numeric"
            autoComplete="off"
            inputClassName="min-h-11"
          />
        )}
      </form.Field>
      <form.Field name="concurrentBuildsMax">
        {(field) => (
          <TextField
            field={field}
            label={t("admin:imageQuota.concurrentBuilds")}
            description={t("admin:imageQuota.blankHint")}
            type="number"
            min={0}
            max={CONCURRENT_BUILDS_MAX}
            inputMode="numeric"
            autoComplete="off"
            inputClassName="min-h-11"
          />
        )}
      </form.Field>
      <form.Field name="buildMinutesPerMonthMax">
        {(field) => (
          <TextField
            field={field}
            label={t("admin:imageQuota.buildMinutes")}
            description={t("admin:imageQuota.blankHint")}
            type="number"
            min={0}
            max={BUILD_MINUTES_MAX}
            inputMode="numeric"
            autoComplete="off"
            inputClassName="min-h-11"
          />
        )}
      </form.Field>
      <form.Field name="offloadGiBMax">
        {(field) => (
          <TextField
            field={field}
            label={t("admin:imageQuota.offload")}
            description={t("admin:imageQuota.offloadHint")}
            type="number"
            min={0}
            max={STORED_MAX}
            inputMode="numeric"
            autoComplete="off"
            inputClassName="min-h-11"
          />
        )}
      </form.Field>
      {problem ? (
        <p role="alert" className="text-sm text-destructive">
          {t(adminProblemKey(problem))}
        </p>
      ) : null}
      <Button type="submit" size="touch" disabled={save.isPending}>
        {save.isPending ? t("common:actions.saving") : t("common:actions.save")}
      </Button>
      <Button type="button" size="touch" variant="outline" onClick={onClose}>
        {t("common:actions.cancel")}
      </Button>
    </form>
  );
}
