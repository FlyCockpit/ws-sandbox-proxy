import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { env } from "@wssp/env/web";
import { Button } from "@wssp/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import { toast } from "@wssp/ui/components/sileo";
import { ShieldCheck, ShieldX } from "lucide-react";
import { useState } from "react";
import { Trans, useTranslation } from "react-i18next";

import {
  DeviceLoginRequestDetails,
  DeviceLoginRequestSkeleton,
  type DeviceLoginRequestSummary,
} from "@/components/device-login-request";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

type Decision = "approved" | "denied" | null;

type DeviceClaimResult = { deviceRequestId: string };

/** C52-R2-3: approval refused because the account is at its host limit. */
class DeviceHostLimitError extends Error {
  constructor(readonly limit: number) {
    super("host limit reached");
  }
}

function hostLimitFromBody(body: unknown): number | null {
  if (!body || typeof body !== "object" || !("data" in body)) return null;
  const data = (body as { data?: unknown }).data;
  if (!data || typeof data !== "object") return null;
  const { code, limit } = data as { code?: unknown; limit?: unknown };
  return code === "sandbox.owner_host_limit" && typeof limit === "number" ? limit : null;
}

async function deviceDecision(
  action: "claim" | "approve" | "deny",
  userCode: string,
  fallbackMessage: string,
  intent?: { kind: "create" } | { kind: "replace"; hostId: string },
): Promise<DeviceClaimResult | undefined> {
  const suffix = action === "claim" ? "" : `/${action}`;
  const response = await fetch(`${env.VITE_SERVER_URL}/api/auth/device${suffix}`, {
    method: "POST",
    credentials: "include",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ userCode, ...(intent ? { intent } : {}) }),
  });
  if (!response.ok) {
    let message: string | undefined;
    let hostLimit: number | null = null;
    try {
      const body = (await response.json()) as { error_description?: unknown; message?: unknown };
      hostLimit = hostLimitFromBody(body);
      message =
        typeof body.error_description === "string"
          ? body.error_description
          : typeof body.message === "string"
            ? body.message
            : undefined;
    } catch {
      message = undefined;
    }
    if (hostLimit !== null) throw new DeviceHostLimitError(hostLimit);
    throw new Error(message ?? fallbackMessage);
  }
  if (action !== "claim") return;
  const body = (await response.json().catch(() => null)) as {
    deviceRequestId?: unknown;
  } | null;
  const deviceRequestId =
    typeof body?.deviceRequestId === "string" ? body.deviceRequestId : undefined;
  if (!deviceRequestId) throw new Error(fallbackMessage);
  return { deviceRequestId };
}

export function DevicePage(props: { lang: string; userCode: string; ownerId: string }) {
  return <DevicePageRequest key={props.userCode} {...props} />;
}

function DevicePageRequest({
  lang,
  userCode,
  ownerId,
}: {
  lang: string;
  userCode: string;
  ownerId: string;
}) {
  const [decisionsByRequestId, setDecisionsByRequestId] = useState<Record<string, Decision>>({});
  const queryClient = useQueryClient();
  const { t } = useTranslation("auth");

  const claimQuery = useQuery({
    queryKey: ["device-login-claim", ownerId, userCode],
    queryFn: async () => {
      const claim = await deviceDecision("claim", userCode, t("device.request.loadError"));
      return claim as DeviceClaimResult;
    },
    enabled: userCode.length > 0,
    retry: false,
    staleTime: 0,
    refetchOnMount: "always",
    refetchOnWindowFocus: false,
    meta: { skipGlobalErrorToast: true },
  });

  const boundRequestId = claimQuery.data?.deviceRequestId ?? null;
  const decision = boundRequestId ? (decisionsByRequestId[boundRequestId] ?? null) : null;
  const setDecision = (value: Decision) => {
    if (!boundRequestId) return;
    setDecisionsByRequestId((current) => ({ ...current, [boundRequestId]: value }));
  };

  const requestQuery = useQuery({
    ...orpc.hostCredentials.deviceLoginRequest.queryOptions({ input: { userCode } }),
    queryKey: [
      "device-login-request",
      ownerId,
      boundRequestId ?? `pending:${userCode}`,
      { userCode },
    ],
    enabled: claimQuery.isSuccess && !!boundRequestId,
    retry: false,
    meta: { skipGlobalErrorToast: true },
  });
  const requestError = claimQuery.error ?? requestQuery.error;

  const claimSettled = claimQuery.isSuccess && !claimQuery.isFetching && boundRequestId !== null;
  const requestSummary = requestQuery.data;
  const summarySettled =
    claimSettled &&
    requestQuery.isSuccess &&
    !requestQuery.isFetching &&
    requestSummary?.requestId === boundRequestId;

  const approveMutation = useMutation({
    mutationFn: async () => {
      const request = requestQuery.data as DeviceLoginRequestSummary | undefined;
      if (!summarySettled || !request || !boundRequestId) {
        throw new Error(t("device.request.loadError"));
      }
      if (request.requestId !== boundRequestId) {
        throw new Error(t("device.request.loadError"));
      }
      await deviceDecision(
        "approve",
        userCode,
        t("device.approveError"),
        request.existingHost
          ? { kind: "replace", hostId: request.existingHost.id }
          : { kind: "create" },
      );
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: orpc.sandboxHosts.key() }),
        queryClient.invalidateQueries({
          queryKey: ["device-login-request", ownerId],
          refetchType: "none",
        }),
      ]);
    },
    meta: { skipGlobalErrorToast: true },
  });

  const denyMutation = useMutation({
    mutationFn: async () => {
      if (!summarySettled || !boundRequestId) throw new Error(t("device.request.loadError"));
      await deviceDecision("deny", userCode, t("device.denyError"));
    },
    onSuccess: () =>
      queryClient.invalidateQueries({
        queryKey: ["device-login-request", ownerId],
        refetchType: "none",
      }),
    meta: { skipGlobalErrorToast: true },
  });

  const actionsEnabled = summarySettled && !approveMutation.isPending && !denyMutation.isPending;

  if (!userCode) {
    return (
      <DeviceShell>
        <CardHeader>
          <CardTitle>{t("device.enterCodeTitle")}</CardTitle>
          <CardDescription>
            <Trans i18nKey="device.enterCodeDescription" t={t} components={[<code key="0" />]} />
          </CardDescription>
        </CardHeader>
      </DeviceShell>
    );
  }

  if (decision === "approved") {
    return (
      <DeviceShell>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="size-5 text-emerald-600" /> {t("device.approved.title")}
          </CardTitle>
          <CardDescription>{t("device.approved.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Link
            to="/$lang/settings/hosts"
            params={{ lang }}
            className="inline-flex min-h-[44px] items-center rounded-md border px-4 py-2 text-sm font-medium hover:bg-muted"
          >
            {t("device.approved.viewHosts")}
          </Link>
        </CardContent>
      </DeviceShell>
    );
  }

  if (decision === "denied") {
    return (
      <DeviceShell>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldX className="size-5 text-destructive" /> {t("device.denied.title")}
          </CardTitle>
          <CardDescription>{t("device.denied.description")}</CardDescription>
        </CardHeader>
      </DeviceShell>
    );
  }

  return (
    <DeviceShell>
      <CardHeader>
        <CardTitle>{t("device.approveTitle")}</CardTitle>
        <CardDescription>{t("device.approveDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-md border bg-muted/40 px-3 py-2 font-mono text-sm">
          {t("device.userCodeLabel")} <strong>{userCode}</strong>
        </div>
        {summarySettled && requestSummary ? (
          <DeviceLoginRequestDetails request={requestSummary} />
        ) : requestError ? (
          <p role="alert" className="text-sm text-destructive">
            {friendly(requestError, t("device.request.loadError"))}
          </p>
        ) : (
          <DeviceLoginRequestSkeleton />
        )}
        <div className="flex gap-2">
          <Button
            type="button"
            className="min-h-[44px]"
            onClick={() =>
              approveMutation.mutate(undefined, {
                onSuccess: () => {
                  setDecision("approved");
                  toast.success(t("device.approveSuccess"));
                },
                onError: (err: unknown) => {
                  console.error("[device.approve]", err);
                  toast.error(
                    err instanceof DeviceHostLimitError
                      ? t("device.hostLimit", { count: err.limit })
                      : friendly(err, t("device.approveError")),
                  );
                },
              })
            }
            disabled={!actionsEnabled}
          >
            {approveMutation.isPending ? t("device.approving") : t("device.approve")}
          </Button>
          <Button
            type="button"
            variant="outline"
            className="min-h-[44px]"
            onClick={() =>
              denyMutation.mutate(undefined, {
                onSuccess: () => {
                  setDecision("denied");
                  toast.success(t("device.denySuccess"));
                },
                onError: (err: unknown) => {
                  console.error("[device.deny]", err);
                  toast.error(friendly(err, t("device.denyError")));
                },
              })
            }
            disabled={!actionsEnabled}
          >
            {denyMutation.isPending ? t("device.denying") : t("device.deny")}
          </Button>
        </div>
      </CardContent>
    </DeviceShell>
  );
}

function DeviceShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="container mx-auto flex min-h-[80vh] max-w-md items-center px-4 py-8">
      <Card className="w-full">{children}</Card>
    </div>
  );
}
