import { useForm } from "@tanstack/react-form";
import { Button } from "@wssp/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import { toast } from "@wssp/ui/components/sileo";
import { TextField } from "@wssp/ui/components/text-field";
import { KeyRound } from "lucide-react";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import z from "zod";

import { FormAlert } from "@/components/auth/form-alert";
import { authClient } from "@/lib/auth-client";
import { friendly, isRateLimit } from "@/utils/friendly-error";

/**
 * Change the account's password (Better Auth `changePassword`, other sessions
 * revoked). Used by the security settings and by the forced change after an
 * admin-set temporary password, which passes its own copy and `onChanged`.
 */
export function ChangePasswordCard({
  title,
  description,
  onChanged,
}: {
  title?: string;
  description?: string;
  onChanged?: () => void;
} = {}) {
  const { t } = useTranslation(["settings", "validation"]);
  const formRef = useRef<HTMLFormElement>(null);
  // A failure that belongs to no one field, shown next to the button.
  const [formError, setFormError] = useState<string | null>(null);

  const form = useForm({
    defaultValues: {
      currentPassword: "",
      newPassword: "",
      confirmPassword: "",
    },
    validators: {
      onSubmit: z
        .object({
          currentPassword: z.string().min(1),
          newPassword: z.string().min(12).max(128),
          confirmPassword: z.string().min(1),
        })
        .refine((values) => values.newPassword === values.confirmPassword, {
          message: t("validation:passwordsMustMatch"),
          path: ["confirmPassword"],
        }),
    },
    onSubmit: async ({ value }) => {
      setFormError(null);
      // A refusal about one field goes under it, focused, and clears on edit.
      const failField = (name: "currentPassword" | "newPassword", message: string) => {
        form.setFieldMeta(name, (meta) => ({
          ...meta,
          errorMap: { ...meta.errorMap, onSubmit: message },
        }));
        formRef.current?.querySelector<HTMLInputElement>(`input[name="${name}"]`)?.focus();
      };
      try {
        const result = await authClient.changePassword({
          currentPassword: value.currentPassword,
          newPassword: value.newPassword,
          revokeOtherSessions: true,
        });

        if (result.error) {
          if (result.error.code === "INVALID_PASSWORD") {
            failField("currentPassword", t("settings:security.currentPasswordMismatch"));
          } else if (result.error.code === "PASSWORD_REUSED") {
            failField("newPassword", t("settings:security.passwordReused"));
          } else {
            setFormError(
              isRateLimit(result.error)
                ? friendly(result.error, t("settings:security.passwordChangeError"))
                : t("settings:security.passwordChangeError"),
            );
          }
          return;
        }

        toast.success(t("settings:security.passwordChangedSuccess"));
        form.reset();
        onChanged?.();
      } catch (error) {
        setFormError(
          isRateLimit(error)
            ? friendly(error, t("settings:security.passwordChangeError"))
            : t("settings:security.passwordChangeError"),
        );
      }
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound aria-hidden="true" className="size-5 text-muted-foreground" />
          {title ?? t("settings:security.passwordTitle")}
        </CardTitle>
        <CardDescription>
          {description ?? t("settings:security.passwordDescription")}
        </CardDescription>
      </CardHeader>
      <CardContent className="max-w-lg">
        <form
          ref={formRef}
          noValidate
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            form.handleSubmit();
          }}
        >
          <form.Field name="currentPassword">
            {(field) => (
              <TextField
                field={field}
                label={t("settings:security.currentPasswordLabel")}
                type="password"
                autoComplete="current-password"
                onChange={() => setFormError(null)}
                inputClassName="autofill:shadow-[inset_0_0_0px_1000px_var(--color-background)]"
              />
            )}
          </form.Field>

          <form.Field name="newPassword">
            {(field) => (
              <TextField
                field={field}
                label={t("settings:security.newPasswordLabel")}
                type="password"
                autoComplete="new-password"
                onChange={() => setFormError(null)}
                inputClassName="autofill:shadow-[inset_0_0_0px_1000px_var(--color-background)]"
              />
            )}
          </form.Field>

          <form.Field name="confirmPassword">
            {(field) => (
              <TextField
                field={field}
                label={t("settings:security.confirmPasswordLabel")}
                type="password"
                autoComplete="new-password"
                onChange={() => setFormError(null)}
                inputClassName="autofill:shadow-[inset_0_0_0px_1000px_var(--color-background)]"
              />
            )}
          </form.Field>

          <p className="text-sm text-muted-foreground">
            {t("settings:security.passwordSessionRevocation")}
          </p>

          <FormAlert message={formError} />

          <form.Subscribe
            selector={(state) => ({
              canSubmit: state.canSubmit,
              isSubmitting: state.isSubmitting,
            })}
          >
            {({ canSubmit, isSubmitting }) => (
              <Button type="submit" className="min-h-[44px]" disabled={!canSubmit || isSubmitting}>
                {isSubmitting
                  ? t("settings:security.changingPassword")
                  : t("settings:security.changePassword")}
              </Button>
            )}
          </form.Subscribe>
        </form>
      </CardContent>
    </Card>
  );
}
