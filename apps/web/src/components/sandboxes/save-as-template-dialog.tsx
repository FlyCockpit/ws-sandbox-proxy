import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
import { Button } from "@wssp/ui/components/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { AdvancedSection } from "@wssp/ui/components/form-page";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import { TextareaField, TextField } from "@wssp/ui/components/text-field";
import { focusFirstInvalidField } from "@wssp/ui/lib/focus-first-invalid";
import { useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { FormSelect } from "@/components/form-select";
import { useTwoFactorRedirect } from "@/hooks/use-two-factor-redirect";
import { formatBytes } from "@/lib/format-bytes";
import { IntentKeys } from "@/lib/sandbox-rules";
import { orpc } from "@/utils/orpc";

/** One page of target templates (the procedure maximum); the sandbox's own is the default. */
const TEMPLATE_PICKER_LIMIT = 100;
const SCRUB_PATHS_MAX = 16;
const TAG_PATTERN = /^[a-z0-9][a-z0-9._-]{0,62}$/;
export const PROGRESS_REFETCH_MS = 2_000;
const ACTIVE = new Set(["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING"]);

function splitPaths(value: string): string[] {
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function captureProblem(error: unknown): string {
  const data = (error as { data?: { code?: unknown } } | null)?.data;
  const code = typeof data?.code === "string" ? data.code : "";
  switch (code) {
    case "sandbox.capture_busy":
      return "busy";
    case "credential.capture_in_progress":
      return "logins";
    case "sandbox.capture_unsupported":
      return "unsupported";
    case "sandbox.disk_offloaded":
      return "offloaded";
    case "sandbox.capture_policy_forbidden":
      return "policy";
    case "sandbox.image_quota_exceeded":
      return "quota";
    case "sandbox.template_store_unavailable":
      return "store";
    case "sandbox.capture_invalid":
    case "sandbox.vm_size_invalid":
      return "invalid";
    case "sandbox.disk_below_image":
      return "defaultDisk";
    default:
      return "failed";
  }
}

/**
 * Save as template: capture this sandbox's root disk into a new revision of
 * a template (scrubbed in a network-less capture VM), then follow the
 * operation's progress phases until it settles.
 */
export function SaveAsTemplateDialog({
  sandbox,
  lang,
  onClose,
}: {
  sandbox: { id: string; diskGiB: number; template: { id: string; label: string } };
  lang: string;
  onClose: () => void;
}) {
  const { t } = useTranslation(["sandboxes", "common"]);
  const templateId = useId();
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const intents = useRef(new IntentKeys());
  const [operationId, setOperationId] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const templates = useQuery({
    ...orpc.sandboxTemplates.listTemplates.queryOptions({
      input: { status: "active", limit: TEMPLATE_PICKER_LIMIT },
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const capture = useMutation({
    ...orpc.sandboxes.captureSandbox.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: {
      templateId: sandbox.template.id,
      tag: "latest",
      scrubPaths: "",
      defaultDiskGiB: "",
    },
    validators: {
      onSubmit: z.object({
        templateId: z.string().min(1),
        tag: z.string().refine((v) => TAG_PATTERN.test(v), t("sandboxes:capture.invalidTag")),
        scrubPaths: z.string().refine((v) => {
          const paths = splitPaths(v);
          return paths.length <= SCRUB_PATHS_MAX && paths.every((p) => p.startsWith("/"));
        }, t("sandboxes:capture.invalidPaths")),
        // Blank, or a whole size from this sandbox's disk (the new floor) up.
        defaultDiskGiB: z.string().refine(
          (v) => {
            const trimmed = v.trim();
            if (!trimmed) return true;
            const n = /^\d{1,4}$/.test(trimmed) ? Number(trimmed) : Number.NaN;
            return n >= sandbox.diskGiB && n <= VM_SIZE_LIMITS.diskGiBMax;
          },
          t("sandboxes:capture.invalidDefaultDisk", { diskGiB: sandbox.diskGiB }),
        ),
      }),
    },
    onSubmit: async ({ value }) => {
      setProblem(null);
      const body = {
        templateId: value.templateId,
        tag: value.tag,
        scrubPaths: splitPaths(value.scrubPaths),
        ...(value.defaultDiskGiB.trim()
          ? { defaultDiskGiB: Number(value.defaultDiskGiB.trim()) }
          : {}),
      };
      try {
        const input = intents.current.for(
          "capture",
          JSON.stringify({ sandboxId: sandbox.id, body }),
          (idempotencyKey) => ({ id: sandbox.id, idempotencyKey, ...body }),
        );
        const receipt = await capture.mutateAsync(input);
        intents.current.settle();
        setOperationId(receipt.operationId);
        void queryClient.invalidateQueries({ queryKey: orpc.sandboxes.key() });
      } catch (error) {
        if (redirect(error)) return;
        const next = captureProblem(error);
        // A refusal is definite: the next click is a new intent.
        if (next !== "failed") intents.current.settle();
        setProblem(next);
      }
    },
  });
  const templateItems = templates.data?.items ?? [];
  const hasCurrent = templateItems.some((item) => item.id === sandbox.template.id);
  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())}>
      <DialogContent closeLabel={t("common:actions.close")} className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("sandboxes:capture.title")}</DialogTitle>
          <DialogDescription>{t("sandboxes:capture.description")}</DialogDescription>
        </DialogHeader>
        {operationId ? (
          <CaptureProgress operationId={operationId} lang={lang} onClose={onClose} />
        ) : (
          <form
            className="flex min-w-0 flex-col gap-4"
            onSubmit={async (event) => {
              event.preventDefault();
              const root = event.currentTarget;
              await form.handleSubmit();
              // A refused option opens its section and takes focus.
              if (!form.state.isValid) focusFirstInvalidField(root);
            }}
          >
            <p
              role="note"
              className="rounded-md border border-amber-600/40 bg-amber-600/10 p-3 text-sm text-amber-800 dark:text-amber-300"
            >
              {t("sandboxes:capture.warning")}
            </p>
            <form.Field name="templateId">
              {(field) => (
                <div className="flex min-w-0 flex-col gap-2">
                  <Label htmlFor={templateId}>{t("sandboxes:capture.template")}</Label>
                  <FormSelect
                    id={templateId}
                    autoComplete="off"
                    value={field.state.value}
                    optionsSettled={!templates.isPending}
                    onValueChange={field.handleChange}
                  >
                    {hasCurrent ? null : (
                      <SelectItem value={sandbox.template.id}>{sandbox.template.label}</SelectItem>
                    )}
                    {templateItems.map((item) => (
                      <SelectItem key={item.id} value={item.id}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </FormSelect>
                </div>
              )}
            </form.Field>
            <form.Subscribe selector={(state) => state.values}>
              {(current) => (
                <AdvancedSection
                  title={t("sandboxes:capture.options")}
                  data-capture-options=""
                  gridClassName="lg:grid-cols-1"
                  summary={t("sandboxes:capture.optionsSummary", {
                    tag: current.tag || "—",
                    disk: current.defaultDiskGiB.trim() || sandbox.diskGiB,
                    count: splitPaths(current.scrubPaths).length,
                  })}
                >
                  <form.Field name="tag">
                    {(field) => (
                      <TextField
                        field={field}
                        label={t("sandboxes:capture.tag")}
                        description={t("sandboxes:capture.tagHint")}
                        autoComplete="off"
                        inputMode="text"
                        maxLength={63}
                        inputClassName="min-h-11 font-mono"
                      />
                    )}
                  </form.Field>
                  <form.Field name="defaultDiskGiB">
                    {(field) => (
                      <TextField
                        field={field}
                        label={t("sandboxes:capture.defaultDisk")}
                        description={t("sandboxes:capture.minDiskHint", {
                          diskGiB: sandbox.diskGiB,
                        })}
                        type="number"
                        inputMode="numeric"
                        min={sandbox.diskGiB}
                        max={VM_SIZE_LIMITS.diskGiBMax}
                        step={1}
                        autoComplete="off"
                        inputClassName="min-h-11"
                      />
                    )}
                  </form.Field>
                  <form.Field name="scrubPaths">
                    {(field) => (
                      <TextareaField
                        field={field}
                        label={t("sandboxes:capture.scrubPaths")}
                        description={t("sandboxes:capture.scrubPathsHint")}
                        autoComplete="off"
                        rows={3}
                        maxLength={16_384}
                        inputClassName="font-mono"
                      />
                    )}
                  </form.Field>
                </AdvancedSection>
              )}
            </form.Subscribe>
            {problem ? (
              <p role="alert" data-capture-problem={problem} className="text-sm text-destructive">
                {t(`sandboxes:capture.problem.${problem}`)}
              </p>
            ) : null}
            <Button type="submit" size="touch" disabled={capture.isPending}>
              {capture.isPending ? t("sandboxes:capture.pending") : t("sandboxes:capture.submit")}
            </Button>
            <Button type="button" size="touch" variant="outline" onClick={onClose}>
              {t("common:actions.cancel")}
            </Button>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

function CaptureProgress({
  operationId,
  lang,
  onClose,
}: {
  operationId: string;
  lang: string;
  onClose: () => void;
}) {
  const { t } = useTranslation(["sandboxes", "common"]);
  const operation = useQuery({
    ...orpc.sandboxes.getOperationView.queryOptions({ input: { operationId } }),
    refetchInterval: (current) =>
      current.state.data && !ACTIVE.has(current.state.data.state) ? false : PROGRESS_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  const data = operation.data;
  const progress = data?.progress ?? null;
  const settled = data ? !ACTIVE.has(data.state) : false;
  const percent =
    progress?.bytesDone != null && progress.bytesTotal
      ? Math.min(100, Math.floor((progress.bytesDone / progress.bytesTotal) * 100))
      : null;
  return (
    <div className="flex min-w-0 flex-col gap-3" aria-live="polite">
      {data?.state === "SUCCEEDED" ? (
        <div role="status" data-capture-state="succeeded" className="flex flex-col gap-1 text-sm">
          <p>{t("sandboxes:capture.succeeded")}</p>
          <Link
            to="/$lang/dashboard/templates"
            params={{ lang }}
            className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
          >
            {t("sandboxes:capture.openTemplates")}
          </Link>
        </div>
      ) : settled ? (
        <p role="alert" data-capture-state="failed" className="text-sm text-destructive">
          {data?.errorMessage ?? t("sandboxes:capture.failed")}
        </p>
      ) : (
        <p role="status" data-capture-phase={progress?.phase ?? "queued"} className="text-sm">
          {t(`sandboxes:capture.phase.${progress?.phase ?? "queued"}`, {
            defaultValue: t("sandboxes:capture.phase.queued"),
          })}
          {percent === null ? "" : ` · ${percent}%`}
          {progress?.bytesDone != null && progress.bytesTotal
            ? ` (${formatBytes(progress.bytesDone, lang)} / ${formatBytes(progress.bytesTotal, lang)})`
            : ""}
        </p>
      )}
      <Button
        type="button"
        size="touch"
        variant={settled ? "default" : "outline"}
        onClick={onClose}
      >
        {settled ? t("sandboxes:capture.close") : t("sandboxes:capture.background")}
      </Button>
    </div>
  );
}
