import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import { toast } from "@wssp/ui/components/sileo";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { FormSelect } from "@/components/form-select";
import { InlineRetry } from "@/components/inline-retry";
import { useImagePolicySaved } from "@/hooks/use-image-policy-saved";
import { formatBytes } from "@/lib/format-bytes";
import { orpc } from "@/utils/orpc";

const GIB = 1024 ** 3;

/**
 * Account image settings: where fetched copies of this account's template
 * images may be placed by default, and the image-store quotas and usage.
 */
export function AccountImagePolicyCard({ lang }: { lang: string }) {
  const { t } = useTranslation(["settings", "common"]);
  const placementId = useId();
  const imagePolicySaved = useImagePolicySaved();
  const policy = useQuery({
    ...orpc.settings.imagePolicy.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const save = useMutation({
    ...orpc.settings.setImagePolicy.mutationOptions(),
    onSuccess: () => toast.success(t("settings:images.saved")),
    onError: () => toast.error(t("settings:images.saveError")),
    onSettled: imagePolicySaved,
  });
  const data = policy.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("settings:images.title")}</CardTitle>
        <CardDescription>{t("settings:images.description")}</CardDescription>
      </CardHeader>
      <CardContent className="flex min-w-0 flex-col gap-4">
        {policy.isPending ? <Skeleton className="h-24 w-full" /> : null}
        {policy.isError ? (
          <InlineRetry
            message={t("settings:images.loadFailed")}
            onRetry={() => void policy.refetch()}
          />
        ) : null}
        {data ? (
          <>
            {data.mode === "off" ? (
              <p className="text-sm text-muted-foreground">{t("settings:images.off")}</p>
            ) : null}
            <div className="flex min-w-0 flex-col gap-2">
              <Label htmlFor={placementId}>{t("settings:images.placement")}</Label>
              <FormSelect
                id={placementId}
                autoComplete="off"
                value={data.imagePlacement}
                disabled={save.isPending}
                onValueChange={(next) =>
                  save.mutate({ imagePlacement: next as "ANY_NODE" | "OWNED_NODES_ONLY" })
                }
              >
                <SelectItem value="ANY_NODE">{t("settings:images.anyNode")}</SelectItem>
                <SelectItem value="OWNED_NODES_ONLY">{t("settings:images.ownedOnly")}</SelectItem>
              </FormSelect>
              <p className="text-xs text-muted-foreground">{t("settings:images.placementHint")}</p>
            </div>
            {data.mode === "s3" ? (
              <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2">
                <div className="min-w-0">
                  <dt className="text-xs text-muted-foreground">{t("settings:images.stored")}</dt>
                  <dd data-image-stored="" className="tabular-nums">
                    {data.quotas.maxStoredGiB === null
                      ? t("settings:images.storedUnlimited", {
                          used: formatBytes(Number(data.usage.storedBytes), lang),
                        })
                      : t("settings:images.storedOf", {
                          used: formatBytes(Number(data.usage.storedBytes), lang),
                          max: formatBytes(data.quotas.maxStoredGiB * GIB, lang),
                        })}
                  </dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-xs text-muted-foreground">
                    {t("settings:images.downloads")}
                  </dt>
                  <dd data-image-downloads="" className="tabular-nums">
                    {data.quotas.downloadsPerHour === null
                      ? t("settings:images.downloadsUnlimited", {
                          count: data.usage.downloadsLastHour,
                        })
                      : t("settings:images.downloadsOf", {
                          count: data.usage.downloadsLastHour,
                          max: data.quotas.downloadsPerHour,
                        })}
                  </dd>
                </div>
              </dl>
            ) : null}
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}
