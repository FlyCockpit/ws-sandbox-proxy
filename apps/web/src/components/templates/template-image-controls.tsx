import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { Button } from "@wssp/ui/components/button";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@wssp/ui/components/sheet";
import { toast } from "@wssp/ui/components/sileo";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { TextareaField, TextField } from "@wssp/ui/components/text-field";
import { cn } from "@wssp/ui/lib/utils";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { FormSelect } from "@/components/form-select";
import { InlineRetry } from "@/components/inline-retry";
import { useTwoFactorRedirect } from "@/hooks/use-two-factor-redirect";
import { formatBytes } from "@/lib/format-bytes";
import { isLaunchableRevision } from "@/lib/template-build-rules";
import { orpc } from "@/utils/orpc";

/**
 * Image distribution controls on the templates page: revision badges
 * (source, image-store state, size), publish-to-store, the template image
 * settings Sheet and Prune now (type-to-confirm).
 */

type Revision = Awaited<
  ReturnType<AppRouterClient["sandboxTemplates"]["listRevisions"]>
>["items"][number];
type Placement = "INHERIT" | "ANY_NODE" | "OWNED_NODES_ONLY";

const SCRUB_PATHS_MAX = 64;
const IN_STORE = new Set(["STORED", "UPLOADING", "VERIFYING"]);

function invalidateTemplateImages(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listRevisions.key() });
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listTemplates.key() });
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.getImageSettings.key() });
}

/** The deployment's image distribution mode (off / peer / s3); shared, cached query. */
export function useImageMode() {
  const policy = useQuery({
    ...orpc.settings.imagePolicy.queryOptions(),
    staleTime: 60_000,
    meta: { skipGlobalErrorToast: true },
  });
  return policy.data?.mode;
}

function Badge({
  children,
  tone,
  title,
  ...rest
}: { children: string; tone?: string; title?: string } & Record<`data-${string}`, string>) {
  return (
    <span
      {...rest}
      title={title}
      className={cn(
        "inline-flex items-center rounded-sm border px-2 py-0.5 text-xs font-medium",
        tone ?? "border-border bg-muted text-muted-foreground",
      )}
    >
      {children}
    </span>
  );
}

export function RevisionImageBadges({ revision, lang }: { revision: Revision; lang: string }) {
  const { t } = useTranslation("templates");
  const capture = revision.sourceKind === "CAPTURE";
  const image = revision.image;
  return (
    <div className="flex min-w-0 flex-wrap gap-1.5" data-revision-badges="">
      <Badge
        data-revision-source={revision.sourceKind}
        {...(revision.sourceKind === "UPSTREAM"
          ? { title: t("builds.revisionBadge.upstreamHint") }
          : {})}
      >
        {capture
          ? t("images.source.capture", { tag: revision.captureTag ?? "latest" })
          : revision.sourceKind === "BUILD"
            ? t("builds.revisionBadge.build")
            : revision.sourceKind === "UPSTREAM"
              ? t("builds.revisionBadge.upstream")
              : t("images.source.manual")}
      </Badge>
      {revision.pendingVerifyBuildId ? (
        <Badge
          data-revision-verifying=""
          tone="border-sky-600/40 bg-sky-600/10 text-sky-700 dark:text-sky-400"
          title={t("builds.revisionBadge.verifyingHint")}
        >
          {t("builds.revisionBadge.verifying")}
        </Badge>
      ) : null}
      {revision.builtWithRoot ? (
        <Badge
          data-revision-root=""
          tone="border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400"
        >
          {t("builds.revisionBadge.root")}
        </Badge>
      ) : null}
      {revision.capturedWithGuestRoot ? (
        <Badge
          data-revision-guest-root=""
          tone="border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400"
          title={t("builds.revisionBadge.guestRootHint")}
        >
          {t("builds.revisionBadge.guestRoot")}
        </Badge>
      ) : null}
      {revision.builtWithWsspRecipe ? (
        <Badge data-revision-wssp-recipe="" title={t("builds.revisionBadge.wsspRecipeHint")}>
          {t("builds.revisionBadge.wsspRecipe")}
        </Badge>
      ) : null}
      <Badge
        data-image-state={image?.state ?? "NONE"}
        tone={
          image?.state === "CORRUPT" || image?.state === "FAILED"
            ? "border-destructive/40 bg-destructive/10 text-destructive"
            : undefined
        }
      >
        {t(`images.state.${image?.state ?? "NONE"}`)}
      </Badge>
      {image ? (
        <Badge data-image-size="">{formatBytes(Number(image.sizeBytes), lang)}</Badge>
      ) : null}
      {revision.retiredReason ? (
        <Badge data-retired-reason={revision.retiredReason}>
          {t(`images.retired.${revision.retiredReason}`)}
        </Badge>
      ) : null}
    </div>
  );
}

export function PublishRevisionButton({ revision, lang }: { revision: Revision; lang: string }) {
  const { t } = useTranslation("templates");
  const mode = useImageMode();
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const publish = useMutation({
    ...orpc.sandboxTemplates.publishRevision.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: (result) => toast.success(t(`images.publish.${result.status}`)),
    onError: (error) => {
      if (!redirect(error)) toast.error(t("images.publish.failed"));
    },
    onSettled: () => invalidateTemplateImages(queryClient),
  });
  if (mode !== "s3" || revision.retiredAt !== null || !isLaunchableRevision(revision)) return null;
  if (revision.image && IN_STORE.has(revision.image.state)) return null;
  return (
    <Button
      type="button"
      size="touch"
      variant="secondary"
      className="mt-2"
      disabled={publish.isPending}
      onClick={() => publish.mutate({ revisionId: revision.id })}
    >
      {publish.isPending ? t("images.publish.pending") : t("images.publish.action")}
    </Button>
  );
}

/** Settings and Prune now for one active template. */
export function TemplateImageActions({
  template,
  lang,
}: {
  template: { id: string; slug: string; label: string };
  lang: string;
}) {
  const { t } = useTranslation(["templates", "common"]);
  const mode = useImageMode();
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [editing, setEditing] = useState(false);
  const [pruning, setPruning] = useState(false);
  const prune = useMutation({
    ...orpc.sandboxTemplates.pruneNow.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: (result) => {
      setPruning(false);
      toast.success(t("templates:images.prune.done", { count: result.retired }));
    },
    onError: (error) => {
      setPruning(false);
      if (!redirect(error)) toast.error(t("templates:images.prune.failed"));
    },
    onSettled: () => invalidateTemplateImages(queryClient),
  });
  if (mode === undefined || mode === "off") return null;
  return (
    <>
      <Button type="button" size="touch" variant="secondary" onClick={() => setEditing(true)}>
        {t("templates:images.settings.action")}
      </Button>
      <Button type="button" size="touch" variant="outline" onClick={() => setPruning(true)}>
        {t("templates:images.prune.action")}
      </Button>
      {editing ? (
        <TemplateImageSettingsSheet
          template={template}
          lang={lang}
          onClose={() => setEditing(false)}
        />
      ) : null}
      <ConfirmDeleteDialog
        open={pruning}
        onOpenChange={setPruning}
        title={t("templates:images.prune.title", { label: template.label })}
        description={t("templates:images.prune.description")}
        confirmToken={template.slug}
        typePrompt={t("templates:images.prune.typePrompt")}
        copyAriaLabel={t("templates:images.prune.copy")}
        confirmLabel={t("templates:images.prune.confirm")}
        pendingLabel={t("templates:images.prune.pending")}
        isPending={prune.isPending}
        onConfirm={() => prune.mutate({ templateId: template.id })}
      />
    </>
  );
}

function TemplateImageSettingsSheet({
  template,
  lang,
  onClose,
}: {
  template: { id: string; label: string };
  lang: string;
  onClose: () => void;
}) {
  const { t } = useTranslation(["templates", "common"]);
  const settings = useQuery({
    ...orpc.sandboxTemplates.getImageSettings.queryOptions({
      input: { templateId: template.id },
    }),
    meta: { skipGlobalErrorToast: true },
  });
  return (
    <Sheet open onOpenChange={(open) => (open ? undefined : onClose())}>
      <SheetContent
        closeLabel={t("common:actions.close")}
        className="overflow-x-hidden overflow-y-auto"
      >
        <SheetHeader>
          <SheetTitle>{t("templates:images.settings.title", { label: template.label })}</SheetTitle>
          <SheetDescription>{t("templates:images.settings.description")}</SheetDescription>
        </SheetHeader>
        {settings.isPending ? <Skeleton className="m-4 h-64" /> : null}
        {settings.isError ? (
          <InlineRetry
            message={t("templates:images.settings.loadFailed")}
            onRetry={() => void settings.refetch()}
          />
        ) : null}
        {settings.data ? (
          <ImageSettingsForm
            templateId={template.id}
            initial={settings.data}
            lang={lang}
            onClose={onClose}
          />
        ) : null}
      </SheetContent>
    </Sheet>
  );
}

function ImageSettingsForm({
  templateId,
  initial,
  lang,
  onClose,
}: {
  templateId: string;
  initial: {
    imagePlacement: Placement;
    captureKeep: number;
    pruneAfterDays: number | null;
    captureScrubPaths: string[];
  };
  lang: string;
  onClose: () => void;
}) {
  const { t } = useTranslation(["templates", "common"]);
  const placementId = useId();
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [failed, setFailed] = useState(false);
  const update = useMutation({
    ...orpc.sandboxTemplates.updateImageSettings.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: {
      imagePlacement: initial.imagePlacement,
      captureKeep: String(initial.captureKeep),
      pruneAfterDays: initial.pruneAfterDays === null ? "" : String(initial.pruneAfterDays),
      captureScrubPaths: initial.captureScrubPaths.join("\n"),
    },
    validators: {
      onSubmit: z.object({
        imagePlacement: z.enum(["INHERIT", "ANY_NODE", "OWNED_NODES_ONLY"]),
        captureKeep: z
          .string()
          .refine(
            (v) => Number.isInteger(Number(v)) && Number(v) >= 1 && Number(v) <= 50,
            t("templates:images.settings.invalidKeep"),
          ),
        pruneAfterDays: z
          .string()
          .refine(
            (v) =>
              v.trim() === "" ||
              (Number.isInteger(Number(v)) && Number(v) >= 1 && Number(v) <= 3650),
            t("templates:images.settings.invalidPrune"),
          ),
        captureScrubPaths: z.string().refine((v) => {
          const paths = splitPaths(v);
          return paths.length <= SCRUB_PATHS_MAX && paths.every((p) => p.startsWith("/"));
        }, t("templates:images.settings.invalidPaths")),
      }),
    },
    onSubmit: async ({ value }) => {
      setFailed(false);
      try {
        await update.mutateAsync({
          templateId,
          imagePlacement: value.imagePlacement,
          captureKeep: Number(value.captureKeep),
          pruneAfterDays: value.pruneAfterDays.trim() === "" ? null : Number(value.pruneAfterDays),
          captureScrubPaths: splitPaths(value.captureScrubPaths),
        });
        invalidateTemplateImages(queryClient);
        toast.success(t("templates:images.settings.saved"));
        onClose();
      } catch (error) {
        if (!redirect(error)) setFailed(true);
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
      <form.Field name="imagePlacement">
        {(field) => (
          <div className="flex min-w-0 flex-col gap-2">
            <Label htmlFor={placementId}>{t("templates:images.settings.placement")}</Label>
            <FormSelect
              id={placementId}
              autoComplete="off"
              value={field.state.value}
              onValueChange={(next) => field.handleChange(next as Placement)}
            >
              <SelectItem value="INHERIT">{t("templates:images.settings.inherit")}</SelectItem>
              <SelectItem value="ANY_NODE">{t("templates:images.settings.anyNode")}</SelectItem>
              <SelectItem value="OWNED_NODES_ONLY">
                {t("templates:images.settings.ownedOnly")}
              </SelectItem>
            </FormSelect>
            <p className="text-xs text-muted-foreground">
              {t("templates:images.settings.placementHint")}
            </p>
          </div>
        )}
      </form.Field>
      <form.Field name="captureKeep">
        {(field) => (
          <TextField
            field={field}
            label={t("templates:images.settings.keep")}
            description={t("templates:images.settings.keepHint")}
            type="number"
            min={1}
            max={50}
            inputMode="numeric"
            autoComplete="off"
            inputClassName="min-h-11"
          />
        )}
      </form.Field>
      <form.Field name="pruneAfterDays">
        {(field) => (
          <TextField
            field={field}
            label={t("templates:images.settings.prune")}
            description={t("templates:images.settings.pruneHint")}
            type="number"
            min={1}
            max={3650}
            inputMode="numeric"
            autoComplete="off"
            inputClassName="min-h-11"
          />
        )}
      </form.Field>
      <form.Field name="captureScrubPaths">
        {(field) => (
          <TextareaField
            field={field}
            label={t("templates:images.settings.scrubPaths")}
            description={t("templates:images.settings.scrubPathsHint")}
            autoComplete="off"
            rows={4}
            maxLength={65_536}
            inputClassName="font-mono"
          />
        )}
      </form.Field>
      {failed ? (
        <p role="alert" className="text-sm text-destructive">
          {t("templates:images.settings.failed")}
        </p>
      ) : null}
      <Button type="submit" size="touch" disabled={update.isPending}>
        {update.isPending ? t("common:actions.saving") : t("common:actions.save")}
      </Button>
      <Button type="button" size="touch" variant="outline" onClick={onClose}>
        {t("common:actions.cancel")}
      </Button>
    </form>
  );
}

function splitPaths(value: string): string[] {
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}
