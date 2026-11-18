import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ADMIN_ERROR_CODES, TUNNEL_CONFIG_REFUSALS } from "@wssp/api/lib/admin-error-codes";
import { Button } from "@wssp/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import { toast } from "@wssp/ui/components/sileo";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { TextField } from "@wssp/ui/components/text-field";
import { Cable } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { InlineRetry } from "@/components/inline-retry";
import { adminProblem, adminProblemKey } from "@/lib/admin-errors";
import { orpc } from "@/utils/orpc";

import { AdminConfirmDialog } from "./admin-confirm-dialog";

type Refusal = (typeof TUNNEL_CONFIG_REFUSALS)[number];

/** The translation key for a failed save or clear, from the typed error. */
function tunnelProblemKey(error: unknown): string {
  const data =
    error && typeof error === "object" && "data" in error
      ? (error as { data?: { code?: unknown; reason?: unknown } }).data
      : undefined;
  if (
    data?.code === ADMIN_ERROR_CODES.tunnelConfigRefused &&
    (TUNNEL_CONFIG_REFUSALS as readonly unknown[]).includes(data.reason)
  )
    return `settings.tunnel.refused.${data.reason as Refusal}`;
  return adminProblemKey(adminProblem(error));
}

/**
 * Preview tunnels (optional): the tunnel server sandboxes' preview tunnels
 * use. The service credential is write-only; the card shows only whether
 * one is stored. Clearing deletes every tunnel and turns tunnels off.
 */
export function TunnelServerCard() {
  const { t } = useTranslation("admin");
  const queryClient = useQueryClient();
  const config = useQuery({
    ...orpc.adminTunnel.get.queryOptions(),
    meta: { skipGlobalErrorToast: true },
    // Turning off finishes in the background: follow it until the setting goes.
    refetchInterval: (current) => (current.state.data?.turningOff ? 5_000 : false),
  });
  const [problem, setProblem] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [removeNow, setRemoveNow] = useState(false);

  const refresh = () => void queryClient.invalidateQueries({ queryKey: orpc.adminTunnel.key() });
  const save = useMutation({
    ...orpc.adminTunnel.set.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onError: (error: Error) => setProblem(tunnelProblemKey(error)),
  });
  const clear = useMutation({
    ...orpc.adminTunnel.clear.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onSuccess: () => {
      toast.success(t("settings.tunnel.turningOff"));
      setConfirmClear(false);
      setRemoveNow(false);
      refresh();
    },
    onError: (error: Error) => setProblem(tunnelProblemKey(error)),
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Cable aria-hidden className="size-5" />
          {t("settings.tunnel.title")}
        </CardTitle>
        <CardDescription>{t("settings.tunnel.description")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {config.isPending ? (
          <Skeleton className="h-40 w-full" />
        ) : config.isError ? (
          <InlineRetry
            className="py-6"
            message={t("settings.tunnel.loadFailed")}
            onRetry={() => void config.refetch()}
          />
        ) : (
          <>
            <p className="text-sm" data-testid="tunnel-status">
              {config.data.turningOff
                ? t("settings.tunnel.statusTurningOff", { total: config.data.tunnels.total })
                : config.data.configured
                  ? t("settings.tunnel.statusOn", {
                      url: config.data.apiUrl,
                      total: config.data.tunnels.total,
                      connected: config.data.tunnels.connected,
                    })
                  : t("settings.tunnel.statusOff")}
            </p>
            {!config.data.keyAvailable ? (
              <p className="text-sm text-destructive">{t("settings.tunnel.keyMissing")}</p>
            ) : null}
            {config.data.turningOff ? (
              <Button
                type="button"
                variant="outline"
                className="min-h-[44px]"
                onClick={() => {
                  setProblem(null);
                  setRemoveNow(true);
                  setConfirmClear(true);
                }}
              >
                {t("settings.tunnel.removeNow")}
              </Button>
            ) : null}
            {config.data.turningOff ? null : (
              <TunnelServerForm
                data={config.data}
                pending={save.isPending}
                onSave={async (value) => {
                  await save.mutateAsync(value);
                  toast.success(t("settings.tunnel.saved"));
                  refresh();
                }}
                onClear={() => {
                  setProblem(null);
                  setConfirmClear(true);
                }}
              />
            )}
            {problem && !confirmClear ? (
              <p role="alert" className="text-sm text-destructive">
                {t(problem)}
              </p>
            ) : null}
          </>
        )}
      </CardContent>
      {confirmClear ? (
        <AdminConfirmDialog
          open
          onOpenChange={(open) => {
            if (!open) {
              setConfirmClear(false);
              setRemoveNow(false);
              setProblem(null);
            }
          }}
          title={t(removeNow ? "settings.tunnel.removeNowTitle" : "settings.tunnel.confirmTitle")}
          description={t(
            removeNow
              ? "settings.tunnel.removeNowDescription"
              : "settings.tunnel.confirmDescription",
          )}
          confirmLabel={t(removeNow ? "settings.tunnel.removeNow" : "settings.tunnel.clear")}
          pendingLabel={t("settings.updating")}
          destructive
          isPending={clear.isPending}
          problem={problem ? t(problem) : null}
          onConfirm={() => clear.mutate(removeNow ? { removeNow: true } : undefined)}
        />
      ) : null}
    </Card>
  );
}

type TunnelConfigView = {
  configured: boolean;
  apiUrl: string | null;
  maxTunnelsPerOwner: number;
  keyAvailable: boolean;
};

function TunnelServerForm({
  data,
  pending,
  onSave,
  onClear,
}: {
  data: TunnelConfigView;
  pending: boolean;
  onSave: (value: {
    apiUrl: string;
    credential?: string;
    maxTunnelsPerOwner: number;
  }) => Promise<void>;
  onClear: () => void;
}) {
  const { t } = useTranslation("admin");
  const form = useForm({
    defaultValues: {
      apiUrl: data.apiUrl ?? "",
      credential: "",
      maxTunnelsPerOwner: String(data.maxTunnelsPerOwner),
    },
    validators: {
      onSubmit: z.object({
        apiUrl: z
          .string()
          .refine(
            (value) => /^https:\/\/[^/\s]+\/?$/.test(value.trim()),
            t("settings.tunnel.urlInvalid"),
          ),
        credential: z
          .string()
          .refine(
            (value) => value.trim() === "" || /^tnsvc_[A-Za-z0-9_-]{16,120}$/.test(value.trim()),
            t("settings.tunnel.credentialInvalid"),
          ),
        maxTunnelsPerOwner: z
          .string()
          .refine(
            (value) => /^[1-9][0-9]{0,3}$/.test(value.trim()) && Number(value) <= 1000,
            t("settings.tunnel.maxInvalid"),
          ),
      }),
    },
    onSubmit: async ({ value }) => {
      try {
        await onSave({
          apiUrl: value.apiUrl.trim(),
          ...(value.credential.trim() ? { credential: value.credential.trim() } : {}),
          maxTunnelsPerOwner: Number(value.maxTunnelsPerOwner),
        });
        form.setFieldValue("credential", "");
      } catch {
        // Explained inline from the typed error.
      }
    },
  });

  return (
    <form
      noValidate
      className="flex min-w-0 flex-col gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        void form.handleSubmit();
      }}
    >
      <form.Field name="apiUrl">
        {(field) => (
          <TextField
            field={field}
            label={t("settings.tunnel.urlLabel")}
            description={t("settings.tunnel.urlHint")}
            type="url"
            autoComplete="url"
            inputClassName="min-h-11"
          />
        )}
      </form.Field>
      <form.Field name="credential">
        {(field) => (
          <TextField
            field={field}
            label={t("settings.tunnel.credentialLabel")}
            description={
              data.configured
                ? t("settings.tunnel.credentialKeep")
                : t("settings.tunnel.credentialHint")
            }
            type="password"
            autoComplete="off"
            inputClassName="min-h-11"
          />
        )}
      </form.Field>
      <form.Field name="maxTunnelsPerOwner">
        {(field) => (
          <TextField
            field={field}
            label={t("settings.tunnel.maxLabel")}
            description={t("settings.tunnel.maxHint")}
            type="number"
            min={1}
            max={1000}
            inputMode="numeric"
            autoComplete="off"
            inputClassName="min-h-11"
          />
        )}
      </form.Field>
      <div className="flex flex-wrap gap-2">
        <Button type="submit" className="min-h-[44px]" disabled={pending || !data.keyAvailable}>
          {pending ? t("settings.updating") : t("settings.tunnel.save")}
        </Button>
        {data.configured ? (
          <Button type="button" variant="outline" className="min-h-[44px]" onClick={onClear}>
            {t("settings.tunnel.clear")}
          </Button>
        ) : null}
      </div>
    </form>
  );
}
