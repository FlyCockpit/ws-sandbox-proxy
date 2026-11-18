import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { UserLoginGrant } from "@wssp/config/user-device-login";
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
import { InlineRetry } from "@/components/inline-retry";
import { UserLoginApproval } from "@/components/user-login-approval";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

type RequestKind = "host" | "user";
/** The request is gone or not this approver's: never keep showing its form. */
function requestGoneError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const code = "code" in error ? error.code : undefined;
  const status = "status" in error ? error.status : undefined;
  return (
    code === "NOT_FOUND" ||
    code === "FORBIDDEN" ||
    code === "CONFLICT" ||
    status === 404 ||
    status === 403 ||
    status === 409
  );
}

type Decision = { outcome: "approved" | "denied"; kind: RequestKind };

/** Host approvals send the reviewed intent; user logins send the approver's grant. */
type ApproveBody =
  | { intent: { kind: "create" } | { kind: "replace"; hostId: string } }
  | { grant: UserLoginGrant };

type DeviceClaimResult = { deviceRequestId: string };

/** C52-R2-3: approval refused because the account is at its host limit. */
class DeviceHostLimitError extends Error {
  constructor(readonly limit: number) {
    super("host limit reached");
  }
}

/** A user-login approval named a pool the approver can no longer use. */
/** A refused claim/approve/deny with its HTTP status (409/404/403: the request is gone). */
class DeviceDecisionError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

class DevicePoolNotFoundError extends Error {
  constructor() {
    super("pool not found");
  }
}

function errorData(body: unknown): { code?: unknown; limit?: unknown } | null {
  if (!body || typeof body !== "object" || !("data" in body)) return null;
  const data = (body as { data?: unknown }).data;
  return data && typeof data === "object" ? (data as { code?: unknown; limit?: unknown }) : null;
}

function hostLimitFromBody(body: unknown): number | null {
  const data = errorData(body);
  return data?.code === "sandbox.owner_host_limit" && typeof data.limit === "number"
    ? data.limit
    : null;
}

async function deviceDecision(
  action: "claim" | "approve" | "deny",
  userCode: string,
  fallbackMessage: string,
  approval?: ApproveBody,
): Promise<DeviceClaimResult | undefined> {
  const suffix = action === "claim" ? "" : `/${action}`;
  const response = await fetch(`${env.VITE_SERVER_URL}/api/auth/device${suffix}`, {
    method: "POST",
    credentials: "include",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ userCode, ...approval }),
  });
  if (!response.ok) {
    let message: string | undefined;
    let hostLimit: number | null = null;
    let poolNotFound = false;
    try {
      const body = (await response.json()) as { error_description?: unknown; message?: unknown };
      hostLimit = hostLimitFromBody(body);
      poolNotFound = errorData(body)?.code === "sandbox.pool_not_found";
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
    if (poolNotFound) throw new DevicePoolNotFoundError();
    throw new DeviceDecisionError(message ?? fallbackMessage, response.status);
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
    mutationFn: async (grant: UserLoginGrant | undefined): Promise<RequestKind> => {
      const request = requestQuery.data;
      if (!summarySettled || !request || !boundRequestId) {
        throw new Error(t("device.request.loadError"));
      }
      if (request.requestId !== boundRequestId) {
        throw new Error(t("device.request.loadError"));
      }
      // Each kind sends only its own field: the server refuses the other one.
      if (request.kind === "user") {
        if (!grant) throw new Error(t("device.approveError"));
        await deviceDecision("approve", userCode, t("device.approveError"), { grant });
        return "user";
      }
      const host: DeviceLoginRequestSummary = request;
      await deviceDecision("approve", userCode, t("device.approveError"), {
        intent: host.existingHost
          ? { kind: "replace", hostId: host.existingHost.id }
          : { kind: "create" },
      });
      return "host";
    },
    onSuccess: async (kind) => {
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: kind === "user" ? orpc.sdkKeys.list.key() : orpc.sandboxHosts.key(),
        }),
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
  const settledKind: RequestKind | null =
    summarySettled && requestSummary ? requestSummary.kind : null;

  const approve = (grant?: UserLoginGrant) =>
    approveMutation.mutate(grant, {
      onSuccess: (kind) => {
        setDecision({ outcome: "approved", kind });
        toast.success(t(kind === "user" ? "device.user.approveSuccess" : "device.approveSuccess"));
      },
      onError: (err: unknown) => {
        console.error("[device.approve]", err);
        if (err instanceof DevicePoolNotFoundError)
          void queryClient.invalidateQueries({ queryKey: orpc.sandboxPools.listUsable.key() });
        toast.error(
          err instanceof DeviceHostLimitError
            ? t("device.hostLimit", { count: err.limit })
            : err instanceof DevicePoolNotFoundError
              ? t("device.user.poolNotFound")
              : friendly(err, t("device.approveError")),
        );
      },
    });

  const deny = () => {
    const kind = settledKind ?? "host";
    denyMutation.mutate(undefined, {
      onSuccess: () => {
        setDecision({ outcome: "denied", kind });
        toast.success(t("device.denySuccess"));
      },
      onError: (err: unknown) => {
        console.error("[device.deny]", err);
        toast.error(friendly(err, t("device.denyError")));
      },
    });
  };

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

  if (decision?.outcome === "approved") {
    const user = decision.kind === "user";
    return (
      <DeviceShell>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="size-5 text-emerald-600" />{" "}
            {t(user ? "device.user.approved.title" : "device.approved.title")}
          </CardTitle>
          <CardDescription>
            {t(user ? "device.user.approved.description" : "device.approved.description")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Link
            to={user ? "/$lang/settings/sdk-keys" : "/$lang/settings/hosts"}
            params={{ lang }}
            className="inline-flex min-h-[44px] items-center rounded-md border px-4 py-2 text-sm font-medium hover:bg-muted"
          >
            {t(user ? "device.user.approved.viewKeys" : "device.approved.viewHosts")}
          </Link>
        </CardContent>
      </DeviceShell>
    );
  }

  if (decision?.outcome === "denied") {
    return (
      <DeviceShell>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldX className="size-5 text-destructive" /> {t("device.denied.title")}
          </CardTitle>
          <CardDescription>
            {t(
              decision.kind === "user"
                ? "device.user.denied.description"
                : "device.denied.description",
            )}
          </CardDescription>
        </CardHeader>
      </DeviceShell>
    );
  }

  // An access or not-found error hides the retained form; a transient one
  // keeps it with an inline retry (approval stays disabled until it settles).
  const userLogin =
    !requestGoneError(requestQuery.error) &&
    !requestGoneError(claimQuery.error) &&
    requestSummary?.kind === "user" &&
    requestSummary.requestId === boundRequestId;
  return (
    <DeviceShell>
      <CardHeader>
        <CardTitle>{t(userLogin ? "device.user.approveTitle" : "device.approveTitle")}</CardTitle>
        <CardDescription>
          {t(userLogin ? "device.user.approveDescription" : "device.approveDescription")}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-md border bg-muted/40 px-3 py-2 font-mono text-sm">
          {t("device.userCodeLabel")} <strong>{userCode}</strong>
        </div>
        {/* Stays mounted through a background refetch of the same request, so
            the approver's choices survive it (approval waits for the refetch:
            `actionsEnabled` needs a settled summary); a new request id remounts. */}
        {userLogin ? (
          <UserLoginApproval
            key={boundRequestId}
            actionsEnabled={actionsEnabled}
            approving={approveMutation.isPending}
            denying={denyMutation.isPending}
            onApprove={approve}
            onDeny={deny}
          />
        ) : null}
        {userLogin &&
        (claimQuery.isError || requestQuery.isError) &&
        !claimQuery.isFetching &&
        !requestQuery.isFetching ? (
          <InlineRetry
            variant="destructive"
            message={friendly(
              claimQuery.error ?? requestQuery.error,
              t("device.request.loadError"),
            )}
            onRetry={() =>
              void (claimQuery.isError ? claimQuery.refetch() : requestQuery.refetch())
            }
          />
        ) : null}
        {userLogin ? null : (
          <>
            {summarySettled && requestSummary?.kind === "host" ? (
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
                onClick={() => approve()}
                disabled={!actionsEnabled}
              >
                {approveMutation.isPending ? t("device.approving") : t("device.approve")}
              </Button>
              <Button
                type="button"
                variant="outline"
                className="min-h-[44px]"
                onClick={deny}
                disabled={!actionsEnabled}
              >
                {denyMutation.isPending ? t("device.denying") : t("device.deny")}
              </Button>
            </div>
          </>
        )}
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
