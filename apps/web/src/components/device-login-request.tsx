import { Skeleton } from "@wssp/ui/components/skeleton";
import { useTranslation } from "react-i18next";

/**
 * What approving a `wssp host enroll` request authorizes (the
 * `kind: "host"` variant of `hostCredentials.deviceLoginRequest`).
 */
export type DeviceLoginRequestSummary = {
  kind: "host";
  requestId: string;
  slug: string;
  existingHost: { id: string; slug: string; label: string } | null;
};

export function DeviceLoginRequestDetails({ request }: { request: DeviceLoginRequestSummary }) {
  const { t } = useTranslation("auth");
  const existing = request.existingHost;

  return (
    <div className="space-y-2 rounded-md border px-3 py-2 text-sm">
      <p className="font-medium">
        {existing ? t("device.request.replaceTitle") : t("device.request.newTitle")}
      </p>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1">
        {existing ? (
          <>
            <dt className="text-muted-foreground">{t("device.request.hostLabel")}</dt>
            <dd className="min-w-0 break-words">{existing.label}</dd>
          </>
        ) : null}
        <dt className="text-muted-foreground">{t("device.request.slugLabel")}</dt>
        <dd className="min-w-0 break-all font-mono">{request.slug}</dd>
      </dl>
      <p className="text-muted-foreground">{t("device.request.checkSlug")}</p>
      {existing ? <p className="text-muted-foreground">{t("device.request.replaceNote")}</p> : null}
    </div>
  );
}

export function DeviceLoginRequestSkeleton() {
  return (
    <div className="space-y-2 rounded-md border px-3 py-2" aria-hidden="true">
      <Skeleton className="h-5 w-3/4" />
      <Skeleton className="h-4 w-1/2" />
      <Skeleton className="h-4 w-full" />
    </div>
  );
}
