import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, redirect, useNavigate } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { toast } from "@wssp/ui/components/sileo";
import { TextField } from "@wssp/ui/components/text-field";
import { cn } from "@wssp/ui/lib/utils";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import z from "zod";

import { AuthConfigGate } from "@/components/auth/auth-config-gate";
import { AuthCard } from "@/components/auth/auth-screen";
import { authClient } from "@/lib/auth-client";
import { decideAnonymousOnlyRouteAccess } from "@/lib/route-session-access";
import { isSetupLinkInvalid } from "@/lib/setup-link";
import { getRouteSession } from "@/server/auth-session";
import { friendly, isRateLimit } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/_app/reset-password")({
  staticData: { pendingShape: "auth" },
  validateSearch: (search: Record<string, unknown>) => ({
    token: typeof search.token === "string" ? search.token : undefined,
    error: typeof search.error === "string" ? search.error : undefined,
    // Set by the SETUP_KEY first-admin link (packages/api/src/lib/admin-bootstrap.ts):
    // its token is spent by `setup.claimFirstAdmin`, not by Better-Auth. The
    // search parser may hand `1` back as a number.
    setup: search.setup === 1 || search.setup === "1" ? (1 as const) : undefined,
  }),
  beforeLoad: async ({ params }) => {
    const decision = decideAnonymousOnlyRouteAccess(await getRouteSession());
    if (decision.kind === "error") throw new Error("Route session unavailable");
    if (decision.kind === "redirect-authenticated") {
      throw redirect({ to: "/$lang/settings/security", params: { lang: params.lang } });
    }
  },
  component: ResetPasswordPage,
});

function ResetPasswordPage() {
  const { lang } = Route.useParams();
  const { token, error, setup } = Route.useSearch();
  const isSetup = setup === 1;
  const {
    isPending: configPending,
    isError: configError,
    refetch: refetchConfig,
  } = useQuery(orpc.appConfig.queryOptions());
  const { t } = useTranslation(["auth", "common"]);
  // Better-Auth redirects here with `?error=INVALID_TOKEN` for a bad token; a
  // token that validates on request but is rejected at reset time flips this.
  const [tokenRejected, setTokenRejected] = useState(false);

  const isInvalid = !token || !!error || tokenRejected;

  return (
    <AuthConfigGate
      isPending={configPending}
      isError={configError}
      onRetry={() => refetchConfig()}
      fields={2}
    >
      {isInvalid ? (
        isSetup ? (
          // A setup link is re-issued from the deployment, not by email.
          <AuthCard
            title={t("auth:resetPassword.setup.invalidTitle")}
            description={t("auth:resetPassword.setup.invalidDescription")}
          >
            <Link
              to="/$lang/login"
              params={{ lang }}
              search={{ redirectTo: undefined }}
              className={cn(buttonVariants({ variant: "outline" }), "min-h-[44px] w-full")}
            >
              {t("auth:forgotPassword.backToLogin")}
            </Link>
          </AuthCard>
        ) : (
          <AuthCard
            title={t("auth:resetPassword.invalidTitle")}
            description={t("auth:resetPassword.invalidDescription")}
          >
            <Link
              to="/$lang/forgot-password"
              params={{ lang }}
              search={{ redirectTo: undefined }}
              className={cn(buttonVariants(), "min-h-[44px] w-full")}
            >
              {t("auth:resetPassword.requestNewLink")}
            </Link>
          </AuthCard>
        )
      ) : (
        <AuthCard
          title={isSetup ? t("auth:resetPassword.setup.title") : t("auth:resetPassword.title")}
          description={
            isSetup
              ? t("auth:resetPassword.setup.description")
              : t("auth:resetPassword.description")
          }
        >
          <ResetPasswordForm
            lang={lang}
            token={token}
            isSetup={isSetup}
            onTokenRejected={() => setTokenRejected(true)}
          />
        </AuthCard>
      )}
    </AuthConfigGate>
  );
}

function ResetPasswordForm({
  lang,
  token,
  isSetup,
  onTokenRejected,
}: {
  lang: string;
  token: string;
  isSetup: boolean;
  onTokenRejected: () => void;
}) {
  const navigate = useNavigate();
  const { t } = useTranslation(["auth", "validation"]);
  // Errors are toasted below (a dead link also swaps in the invalid-link card),
  // so the global mutation toast would only repeat them.
  const claimSetupLink = useMutation(
    orpc.setup.claimFirstAdmin.mutationOptions({ meta: { skipGlobalErrorToast: true } }),
  );

  /** The SETUP_KEY link: spent by our own procedure. True when the admin exists. */
  async function claimFirstAdmin(newPassword: string): Promise<boolean> {
    try {
      await claimSetupLink.mutateAsync({ token, newPassword });
      return true;
    } catch (err) {
      console.error("[reset-password.setup]", err);
      if (isSetupLinkInvalid(err)) {
        toast.error(t("auth:resetPassword.setup.invalidTitle"));
        onTokenRejected();
        return false;
      }
      toast.error(friendly(err));
      return false;
    }
  }

  const form = useForm({
    defaultValues: { newPassword: "", confirmPassword: "" },
    onSubmit: async ({ value }) => {
      if (isSetup) {
        if (!(await claimFirstAdmin(value.newPassword))) return;
        toast.success(t("auth:resetPassword.setup.success"));
        navigate({ to: "/$lang/login", params: { lang }, search: { redirectTo: undefined } });
        return;
      }
      const result = await authClient.resetPassword({
        newPassword: value.newPassword,
        token,
      });
      if (result.error) {
        if (isRateLimit(result.error)) {
          toast.error(friendly(result.error));
          return;
        }
        // A rejected token (expired / already used) is the common failure here
        // — surface the invalid state with a path back to forgot-password.
        console.error("[reset-password.reset]", result.error);
        toast.error(t("auth:resetPassword.failed"));
        onTokenRejected();
        return;
      }
      toast.success(t("auth:resetPassword.success"));
      navigate({ to: "/$lang/login", params: { lang }, search: { redirectTo: undefined } });
    },
    validators: {
      // Standard checks (min length, required) localize through the global Zod
      // error map; only the cross-field match needs an explicit message, which
      // lives in the `validation` namespace.
      onSubmit: z
        .object({
          newPassword: z.string().min(12),
          confirmPassword: z.string().min(12),
        })
        .refine((v) => v.newPassword === v.confirmPassword, {
          message: t("validation:passwordsMustMatch"),
          path: ["confirmPassword"],
        }),
    },
  });

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        e.stopPropagation();
        form.handleSubmit();
      }}
      className="space-y-4"
    >
      <form.Field name="newPassword">
        {(field) => (
          <TextField
            field={field}
            label={t("auth:resetPassword.newPasswordLabel")}
            type="password"
            autoComplete="new-password"
          />
        )}
      </form.Field>

      <form.Field name="confirmPassword">
        {(field) => (
          <TextField
            field={field}
            label={t("auth:resetPassword.confirmPasswordLabel")}
            type="password"
            autoComplete="new-password"
          />
        )}
      </form.Field>

      <form.Subscribe
        selector={(state) => ({ canSubmit: state.canSubmit, isSubmitting: state.isSubmitting })}
      >
        {({ canSubmit, isSubmitting }) => (
          <Button
            type="submit"
            className="min-h-[44px] w-full"
            disabled={!canSubmit || isSubmitting}
          >
            {isSubmitting
              ? t("auth:resetPassword.resetting")
              : isSetup
                ? t("auth:resetPassword.setup.submit")
                : t("auth:resetPassword.submit")}
          </Button>
        )}
      </form.Subscribe>
    </form>
  );
}
