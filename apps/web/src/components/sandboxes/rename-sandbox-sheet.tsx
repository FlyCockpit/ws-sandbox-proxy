import { useForm } from "@tanstack/react-form";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { SANDBOX_NAME_MAX, sandboxNameSchema } from "@wssp/api/sandbox/contracts";
import { Button } from "@wssp/ui/components/button";
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
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { useTwoFactorRedirect } from "@/hooks/use-two-factor-redirect";
import { type SandboxProblem, sandboxProblem } from "@/lib/sandbox-rules";
import { orpc } from "@/utils/orpc";

/**
 * Rename (Edit → Sheet). A rename is not an operation: one request, no
 * idempotency key; the server checks the name and answers `name_taken` or
 * `name_invalid`. The field folds case as the user types.
 */
export function RenameSandboxSheet({
  lang,
  sandbox,
  onClose,
}: {
  lang: string;
  sandbox: { id: string; name: string };
  onClose: () => void;
}) {
  const { t } = useTranslation(["sandboxes", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [problem, setProblem] = useState<SandboxProblem | null>(null);
  const rename = useMutation({
    ...orpc.sandboxes.updateSandbox.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const nameValidator = z.string().refine((value) => sandboxNameSchema.safeParse(value).success, {
    message: t("sandboxes:draft.name"),
  });
  const form = useForm({
    defaultValues: { name: sandbox.name },
    onSubmit: async ({ value }) => {
      setProblem(null);
      try {
        await rename.mutateAsync({ id: sandbox.id, name: value.name });
      } catch (error) {
        if (redirect(error)) return;
        setProblem(sandboxProblem(error));
        return;
      } finally {
        void queryClient.invalidateQueries({ queryKey: orpc.sandboxes.key() });
      }
      toast.success(t("sandboxes:rename.done"));
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
          <SheetTitle>{t("sandboxes:rename.title")}</SheetTitle>
          <SheetDescription>{t("sandboxes:rename.description")}</SheetDescription>
        </SheetHeader>
        <form
          noValidate
          className="flex min-w-0 flex-col gap-4 px-4"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            void form.handleSubmit();
          }}
        >
          <form.Field name="name" validators={{ onSubmit: nameValidator }}>
            {(field) => (
              <TextField
                field={field}
                label={t("sandboxes:rename.label")}
                description={t("sandboxes:create.nameHint")}
                inputMode="text"
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                maxLength={SANDBOX_NAME_MAX}
                inputClassName="min-h-11 font-mono"
                onChange={(event) => field.handleChange(event.target.value.toLowerCase())}
              />
            )}
          </form.Field>
          {problem ? (
            <p role="alert" data-rename-problem={problem} className="text-sm text-destructive">
              {t(`sandboxes:problem.${problem}`)}
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
