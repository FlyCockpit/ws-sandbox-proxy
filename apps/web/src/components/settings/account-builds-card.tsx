import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@wssp/ui/components/alert-dialog";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import { Label } from "@wssp/ui/components/label";
import { toast } from "@wssp/ui/components/sileo";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { Switch } from "@wssp/ui/components/switch";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { InlineRetry } from "@/components/inline-retry";
import { useImagePolicySaved } from "@/hooks/use-image-policy-saved";
import { disabledReasonKey } from "@/lib/template-build-rules";
import { orpc } from "@/utils/orpc";

/**
 * Template builds in account settings: whether
 * builds are available, the account's build quotas and this month's usage,
 * and the owner's consent to run builds on other people's builder nodes.
 * Turning that consent on needs an explicit acknowledgement of the warning.
 */
export function AccountBuildsCard() {
  const { t } = useTranslation(["settings", "templates", "common"]);
  const switchId = useId();
  const imagePolicySaved = useImagePolicySaved();
  const [confirming, setConfirming] = useState(false);
  const usage = useQuery({
    ...orpc.templateBuilds.usage.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const save = useMutation({
    ...orpc.settings.setImagePolicy.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: () => {
      setConfirming(false);
      toast.success(t("settings:builds.saved"));
    },
    onError: () => toast.error(t("settings:builds.saveError")),
    onSettled: imagePolicySaved,
  });
  const data = usage.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("settings:builds.title")}</CardTitle>
        <CardDescription>{t("settings:builds.description")}</CardDescription>
      </CardHeader>
      <CardContent className="flex min-w-0 flex-col gap-4">
        {usage.isPending ? <Skeleton className="h-24 w-full" /> : null}
        {usage.isError ? (
          <InlineRetry
            message={t("settings:builds.loadFailed")}
            onRetry={() => void usage.refetch()}
          />
        ) : null}
        {data ? (
          <>
            {data.enabled ? null : (
              <p role="status" className="text-sm text-muted-foreground">
                {t(`templates:builds.disabled.${disabledReasonKey(data.reason)}`)}
              </p>
            )}
            <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2">
              <div className="min-w-0">
                <dt className="text-xs text-muted-foreground">
                  {t("templates:builds.usage.active")}
                </dt>
                <dd data-build-usage-active="" className="tabular-nums">
                  {data.maxConcurrent === null
                    ? t("templates:builds.usage.activeUnlimited", {
                        count: data.usage.activeBuilds,
                      })
                    : t("templates:builds.usage.activeOf", {
                        count: data.usage.activeBuilds,
                        max: data.maxConcurrent,
                      })}
                </dd>
              </div>
              <div className="min-w-0">
                <dt className="text-xs text-muted-foreground">
                  {t("templates:builds.usage.minutes")}
                </dt>
                <dd data-build-usage-minutes="" className="tabular-nums">
                  {data.minutesPerMonth === null
                    ? t("templates:builds.usage.minutesUnlimited", {
                        used: data.usage.minutesUsedThisMonth,
                      })
                    : t("templates:builds.usage.minutesOf", {
                        used: data.usage.minutesUsedThisMonth,
                        max: data.minutesPerMonth,
                      })}
                </dd>
              </div>
            </dl>
            <div className="flex min-w-0 items-start gap-3">
              <div className="flex min-h-11 min-w-11 items-center justify-center">
                <Switch
                  id={switchId}
                  checked={data.allowForeignBuilds}
                  disabled={save.isPending}
                  onCheckedChange={(next) => {
                    if (next) setConfirming(true);
                    else save.mutate({ allowForeignBuilds: false });
                  }}
                />
              </div>
              <div className="flex min-w-0 flex-col gap-1">
                <Label htmlFor={switchId}>{t("settings:builds.foreign")}</Label>
                <p className="text-xs text-muted-foreground">{t("settings:builds.foreignHint")}</p>
              </div>
            </div>
          </>
        ) : null}
      </CardContent>
      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent className="max-w-[calc(100%-2rem)]! sm:max-w-md!">
          <AlertDialogHeader>
            <AlertDialogTitle>{t("settings:builds.confirmTitle")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("settings:builds.confirmDescription")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="sm:flex-wrap">
            <AlertDialogCancel className="min-h-[44px] w-full sm:w-auto">
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              className="min-h-[44px] w-full sm:w-auto"
              disabled={save.isPending}
              onClick={() =>
                save.mutate({ allowForeignBuilds: true, acknowledgeForeignBuilds: true })
              }
            >
              {t("settings:builds.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  );
}
