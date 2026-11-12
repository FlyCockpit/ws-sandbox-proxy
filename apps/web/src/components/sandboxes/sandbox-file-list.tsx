import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery } from "@tanstack/react-query";
import { type EntryInfo, FS_PROCESS_LIMITS, listDirInput } from "@wssp/api/sandbox/contracts";
import { Badge } from "@wssp/ui/components/badge";
import { Button } from "@wssp/ui/components/button";
import { ResponsiveDialog } from "@wssp/ui/components/responsive-dialog";
import { TextField } from "@wssp/ui/components/text-field";
import { cn } from "@wssp/ui/lib/utils";
import { FileIcon, FolderIcon, LinkIcon } from "lucide-react";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { observationProblem, useSandboxObservation } from "@/hooks/use-sandbox-observation";
import { displayInlineText } from "@/lib/command-output-buffer";
import { orpc } from "@/utils/orpc";
import { ObservationError, ObservationNotice } from "./sandbox-observation";

export function SandboxFileList({ sandboxId }: { sandboxId: string }) {
  const { t } = useTranslation(["sandboxes", "common"]);
  const entryTrigger = useRef<HTMLButtonElement | null>(null);
  const [operationId, setOperationId] = useState<string | null>(null);
  const [entry, setEntry] = useState<EntryInfo | null>(null);
  const capabilities = useQuery({
    ...orpc.sandboxes.getSandboxCapabilities.queryOptions({ input: { id: sandboxId } }),
    staleTime: 0,
    retry: false,
    gcTime: 0,
    meta: { skipGlobalErrorToast: true },
  });
  const result = useSandboxObservation(operationId);
  const list = useMutation({
    ...orpc.sandboxes.listDir.mutationOptions(),
    retry: false,
    gcTime: 0,
    meta: { skipGlobalErrorToast: true },
    onMutate: () => {
      setOperationId(null);
      setEntry(null);
    },
    onSuccess: (receipt) => setOperationId(receipt.operationId),
  });
  const page =
    !result.isError &&
    result.data?.outcome === "succeeded" &&
    result.data.result?.type === "file.list"
      ? result.data.result
      : null;
  const busy =
    list.isPending ||
    (operationId !== null &&
      (!result.data || result.data.outcome === "pending") &&
      !result.isError);
  const available =
    !capabilities.isError &&
    capabilities.data?.unavailableReason === null &&
    capabilities.data.features.includes("files.list");
  const submit = (path: string, cursor?: string) =>
    list.mutate({
      id: sandboxId,
      path,
      depth: 1,
      limit: FS_PROCESS_LIMITS.listMaxLimit,
      cursor,
      idempotencyKey: crypto.randomUUID(),
    });
  const form = useForm({
    defaultValues: { path: "/" },
    validators: {
      onSubmit: z.object({
        path: z.string().refine((value) => listDirInput.shape.path.safeParse(value).success, {
          message: t("sandboxes:files.badPath"),
        }),
      }),
    },
    onSubmit: ({ value }) => {
      if (available && !busy) submit(value.path);
    },
  });
  if (
    [capabilities.error, list.error, result.error].some(
      (error) => error && observationProblem(error) === "unavailable",
    )
  )
    return <ObservationNotice state="unavailable" />;
  return (
    <div className="flex min-w-0 flex-col gap-3" data-file-list="">
      <h3 className="text-sm font-medium">{t("sandboxes:observations.filesTitle")}</h3>
      <p className="text-sm text-muted-foreground">
        {t("sandboxes:observations.livePage", { limit: FS_PROCESS_LIMITS.listMaxLimit })}
      </p>
      {(!available || capabilities.isError) && !capabilities.isPending ? (
        <Button
          type="button"
          size="touch"
          className="self-start"
          variant="outline"
          disabled={capabilities.isFetching}
          onClick={() => void capabilities.refetch()}
        >
          {t("sandboxes:observations.refreshCapabilities")}
        </Button>
      ) : null}
      {capabilities.isError ? (
        <ObservationError error={capabilities.error} />
      ) : !capabilities.data ? (
        <ObservationNotice state="pending" />
      ) : !available ? (
        <ObservationNotice state="unavailable" />
      ) : (
        <>
          <form
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              void form.handleSubmit();
            }}
            className="flex min-w-0 flex-col gap-3"
          >
            <form.Field name="path">
              {(field) => (
                <TextField
                  field={field}
                  label={t("sandboxes:observations.directoryPath")}
                  autoComplete="off"
                  inputMode="text"
                  inputClassName="min-h-11 font-mono"
                />
              )}
            </form.Field>
            <Button
              type="submit"
              className="self-start"
              size="touch"
              variant="outline"
              disabled={busy}
            >
              {t("sandboxes:observations.refreshFiles")}
            </Button>
          </form>
          {list.isError ? (
            <ObservationError error={list.error} />
          ) : result.isError ? (
            <ObservationError error={result.error} />
          ) : busy ? (
            <ObservationNotice state="pending" list="files" />
          ) : result.data && !page ? (
            <ObservationNotice state={result.data.outcome === "unknown" ? "unknown" : "failed"} />
          ) : null}
          {page ? (
            <>
              <p className="break-words [overflow-wrap:anywhere] text-sm" data-current-directory="">
                {t("sandboxes:observations.currentDirectory", {
                  path: displayInlineText(page.path),
                })}
              </p>
              {page.items.length === 0 ? (
                <ObservationNotice state="emptyFiles" />
              ) : (
                <ul className="flex min-w-0 flex-col gap-2">
                  {page.items.map((item) => (
                    <li
                      key={item.path}
                      className="flex min-w-0 flex-wrap items-center gap-3 rounded-lg border p-3"
                    >
                      <Button
                        type="button"
                        size="touch"
                        variant="outline"
                        className="h-auto min-h-11 max-w-full self-start whitespace-pre-wrap break-words text-left font-mono [overflow-wrap:anywhere]"
                        onClick={(event) => {
                          entryTrigger.current = event.currentTarget;
                          setEntry(item);
                        }}
                      >
                        {item.type === "dir" ? (
                          <FolderIcon aria-hidden="true" />
                        ) : item.type === "symlink" ? (
                          <LinkIcon aria-hidden="true" />
                        ) : (
                          <FileIcon aria-hidden="true" />
                        )}
                        <span className="min-w-0">{displayInlineText(item.name)}</span>
                      </Button>
                      <Badge>{t(`sandboxes:entryType.${item.type}`)}</Badge>
                      {item.type === "dir" ? (
                        <Button
                          type="button"
                          size="touch"
                          variant="outline"
                          disabled={busy}
                          onClick={() => {
                            form.setFieldValue("path", item.path);
                            submit(item.path);
                          }}
                        >
                          {t("sandboxes:observations.openDirectory")}
                        </Button>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
              {page.nextCursor ? (
                <Button
                  type="button"
                  size="touch"
                  className="self-start"
                  variant="outline"
                  disabled={busy}
                  onClick={() => submit(page.path, page.nextCursor ?? undefined)}
                >
                  {t("sandboxes:observations.nextPage")}
                </Button>
              ) : null}
            </>
          ) : null}
          <ResponsiveDialog
            finalFocus={entryTrigger}
            closeLabel={t("common:actions.close")}
            title={t("sandboxes:observations.entryTitle")}
            description={t("sandboxes:observations.entryDescription")}
            footer={
              <Button type="button" size="touch" variant="outline" onClick={() => setEntry(null)}>
                {t("common:actions.close")}
              </Button>
            }
            open={entry !== null && page !== null}
            onOpenChange={(open) => {
              if (!open) setEntry(null);
            }}
          >
            {entry && page ? (
              <dl className="grid min-w-0 gap-3 text-sm">
                {Object.entries(entry).map(([key, value]) => (
                  <div key={key}>
                    <dt className="text-xs text-muted-foreground">{t(`sandboxes:entry.${key}`)}</dt>
                    <dd
                      className={cn(
                        "whitespace-pre-wrap break-words [overflow-wrap:anywhere]",
                        value !== null &&
                          [
                            "path",
                            "name",
                            "symlinkTarget",
                            "permissions",
                            "mode",
                            "size",
                            "uid",
                            "gid",
                          ].includes(key) &&
                          "font-mono",
                      )}
                    >
                      {value === null
                        ? t("sandboxes:observations.notRecorded")
                        : key === "type"
                          ? t(`sandboxes:entryType.${value}`)
                          : displayInlineText(String(value))}
                    </dd>
                  </div>
                ))}
              </dl>
            ) : null}
          </ResponsiveDialog>
        </>
      )}
    </div>
  );
}
