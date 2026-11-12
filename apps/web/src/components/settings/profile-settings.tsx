import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@wssp/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import { Checkbox } from "@wssp/ui/components/checkbox";
import { Input } from "@wssp/ui/components/input";
import { Label } from "@wssp/ui/components/label";
import { toast } from "@wssp/ui/components/sileo";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { useTranslation } from "react-i18next";
import z from "zod";
import { QueryBoundary } from "@/components/query-boundary";

import { authClient } from "@/lib/auth-client";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

type ProfileUser = { name?: string | null; email: string; role?: string | null };

function buildProfileSchema() {
  return z.object({
    name: z.string().min(2),
  });
}

function hasAdminRole(role: string | null | undefined): boolean {
  return (role ?? "")
    .split(",")
    .map((part) => part.trim())
    .includes("admin");
}

/**
 * Profile card: display name, read-only email and (admins only) the
 * operational-alerts email preference.
 */
export function ProfileSettings({ user }: { user: ProfileUser }) {
  const { t } = useTranslation(["settings", "auth", "common"]);
  const queryClient = useQueryClient();
  const notificationPrefs = useQuery(orpc.settings.myNotificationPreferences.queryOptions());
  const updateNotificationPrefs = useMutation(
    orpc.settings.updateMyNotificationPreferences.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({
          queryKey: orpc.settings.myNotificationPreferences.queryKey(),
        });
        toast.success(t("settings:profile.notificationsSaved"));
      },
      onError: () => {
        toast.error(t("settings:profile.notificationsSaveError"));
      },
    }),
  );

  const form = useForm({
    defaultValues: {
      name: user.name || "",
    },
    onSubmit: async ({ value }) => {
      const result = await authClient.updateUser({
        name: value.name,
      });
      if (result.error) {
        console.error("[settings.updateUser]", result.error);
        toast.error(friendly(result.error, t("settings:profile.saveError")));
        return;
      }
      toast.success(t("settings:profile.saved"));
    },
    validators: {
      onSubmit: buildProfileSchema(),
    },
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("settings:profile.title")}</CardTitle>
        <CardDescription>{t("settings:profile.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            e.stopPropagation();
            form.handleSubmit();
          }}
          className="space-y-4"
        >
          <div className="space-y-2">
            <Label>{t("auth:fields.email")}</Label>
            <Input value={user.email} disabled />
            <p className="text-xs text-muted-foreground">{t("settings:profile.emailReadonly")}</p>
          </div>

          <form.Field name="name">
            {(field) => (
              <div className="space-y-2">
                <Label htmlFor={field.name}>{t("auth:fields.name")}</Label>
                <Input
                  id={field.name}
                  name={field.name}
                  autoComplete="name"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(e) => field.handleChange(e.target.value)}
                />
                {field.state.meta.errors.map((error) => (
                  <p key={error?.message} className="text-sm text-destructive">
                    {error?.message}
                  </p>
                ))}
              </div>
            )}
          </form.Field>

          <form.Subscribe
            selector={(state) => ({
              canSubmit: state.canSubmit,
              isSubmitting: state.isSubmitting,
            })}
          >
            {({ canSubmit, isSubmitting }) => (
              <Button type="submit" disabled={!canSubmit || isSubmitting}>
                {isSubmitting ? t("common:actions.saving") : t("common:actions.saveChanges")}
              </Button>
            )}
          </form.Subscribe>
        </form>

        {hasAdminRole(user.role) ? (
          <div className="mt-6 border-t pt-6">
            <QueryBoundary
              query={notificationPrefs}
              skeleton={<Skeleton className="h-16 w-full" />}
            >
              {(preferences) => (
                <div className="flex items-start gap-3">
                  <Checkbox
                    id="operational-alerts"
                    checked={preferences.operationalAlerts}
                    disabled={updateNotificationPrefs.isPending}
                    onCheckedChange={(checked) => {
                      updateNotificationPrefs.mutate({ operationalAlerts: checked === true });
                    }}
                  />
                  <div className="space-y-1">
                    <Label htmlFor="operational-alerts">
                      {t("settings:profile.operationalAlerts")}
                    </Label>
                    <p className="text-sm text-muted-foreground">
                      {t("settings:profile.operationalAlertsDescription")}
                    </p>
                  </div>
                </div>
              )}
            </QueryBoundary>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
