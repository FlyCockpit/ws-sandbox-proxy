import { useForm } from "@tanstack/react-form";
import { Button } from "@wssp/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import { Input } from "@wssp/ui/components/input";
import { Label } from "@wssp/ui/components/label";
import { toast } from "@wssp/ui/components/sileo";
import { KeyRound } from "lucide-react";
import { useTranslation } from "react-i18next";
import z from "zod";

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
      try {
        const result = await authClient.changePassword({
          currentPassword: value.currentPassword,
          newPassword: value.newPassword,
          revokeOtherSessions: true,
        });

        if (result.error) {
          const message =
            result.error.code === "INVALID_PASSWORD"
              ? t("settings:security.currentPasswordMismatch")
              : result.error.code === "PASSWORD_REUSED"
                ? t("settings:security.passwordReused")
                : isRateLimit(result.error)
                  ? friendly(result.error, t("settings:security.passwordChangeError"))
                  : t("settings:security.passwordChangeError");
          toast.error(message);
          return;
        }

        toast.success(t("settings:security.passwordChangedSuccess"));
        form.reset();
        onChanged?.();
      } catch (error) {
        toast.error(
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
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            form.handleSubmit();
          }}
        >
          <form.Field name="currentPassword">
            {(field) => (
              <div className="space-y-2">
                <Label htmlFor={field.name}>{t("settings:security.currentPasswordLabel")}</Label>
                <Input
                  id={field.name}
                  name={field.name}
                  type="password"
                  inputMode="text"
                  autoComplete="current-password"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(event) => field.handleChange(event.target.value)}
                  className="autofill:shadow-[inset_0_0_0px_1000px_var(--color-background)]"
                />
                {field.state.meta.errors.map((error) => (
                  <p key={error?.message} className="text-sm text-destructive">
                    {error?.message}
                  </p>
                ))}
              </div>
            )}
          </form.Field>

          <form.Field name="newPassword">
            {(field) => (
              <div className="space-y-2">
                <Label htmlFor={field.name}>{t("settings:security.newPasswordLabel")}</Label>
                <Input
                  id={field.name}
                  name={field.name}
                  type="password"
                  inputMode="text"
                  autoComplete="new-password"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(event) => field.handleChange(event.target.value)}
                  className="autofill:shadow-[inset_0_0_0px_1000px_var(--color-background)]"
                />
                {field.state.meta.errors.map((error) => (
                  <p key={error?.message} className="text-sm text-destructive">
                    {error?.message}
                  </p>
                ))}
              </div>
            )}
          </form.Field>

          <form.Field name="confirmPassword">
            {(field) => (
              <div className="space-y-2">
                <Label htmlFor={field.name}>{t("settings:security.confirmPasswordLabel")}</Label>
                <Input
                  id={field.name}
                  name={field.name}
                  type="password"
                  inputMode="text"
                  autoComplete="new-password"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(event) => field.handleChange(event.target.value)}
                  className="autofill:shadow-[inset_0_0_0px_1000px_var(--color-background)]"
                />
                {field.state.meta.errors.map((error) => (
                  <p key={error?.message} className="text-sm text-destructive">
                    {error?.message}
                  </p>
                ))}
              </div>
            )}
          </form.Field>

          <p className="text-sm text-muted-foreground">
            {t("settings:security.passwordSessionRevocation")}
          </p>

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
