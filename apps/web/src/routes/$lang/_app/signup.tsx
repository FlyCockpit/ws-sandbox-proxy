import { useForm } from "@tanstack/react-form";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, redirect } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { toast } from "@wssp/ui/components/sileo";
import { TextField } from "@wssp/ui/components/text-field";
import { cn } from "@wssp/ui/lib/utils";
import { type ReactNode, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import z from "zod";

import { AuthConfigGate } from "@/components/auth/auth-config-gate";
import { AuthCard } from "@/components/auth/auth-screen";
import { FormAlert } from "@/components/auth/form-alert";
import { ResendVerification } from "@/components/auth/resend-verification";
import { useAuthSession } from "@/hooks/use-auth-session";
import { authClient } from "@/lib/auth-client";
import { newPasswordSchema, PASSWORD_MIN_LENGTH } from "@/lib/password-policy";
import { clearPoolInviteToken, poolInviteToken } from "@/lib/pool-invite";
import { resolveRouteSession } from "@/lib/route-session";
import { decideAnonymousOnlyRouteAccess } from "@/lib/route-session-access";
import { signupMode } from "@/lib/signup-mode";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";
import { safeRedirectTo } from "@/utils/safe-redirect";

export const Route = createFileRoute("/$lang/_app/signup")({
  staticData: { pendingShape: "auth" },
  validateSearch: (search: Record<string, unknown>) => ({
    redirectTo: typeof search.redirectTo === "string" ? search.redirectTo : undefined,
  }),
  // A closed (invite-only) server renders its own card below instead of a
  // silent bounce to sign-in, so the visitor learns why there is no form.
  beforeLoad: async ({ params, search }) => {
    const decision = decideAnonymousOnlyRouteAccess(await resolveRouteSession());
    if (decision.kind === "error") throw new Error("Route session unavailable");
    if (decision.kind === "redirect-authenticated") {
      throw redirect({ href: safeRedirectTo(search.redirectTo, params.lang) });
    }
  },
  component: SignupPage,
});

function SignupPage() {
  const { lang } = Route.useParams();
  const { redirectTo } = Route.useSearch();
  const authSession = useAuthSession();
  const {
    data: configData,
    isPending: configPending,
    isError: configError,
    refetch: refetchConfig,
  } = useQuery(orpc.appConfig.queryOptions());
  const { t } = useTranslation(["auth", "common"]);
  // Set once the account exists. Better-Auth is configured with
  // `requireEmailVerification: true`, so a successful signup deliberately does
  // NOT return a session — there is nothing to redirect into yet. The address
  // is kept only to name it back to the user and to target a resend.
  const [pendingEmail, setPendingEmail] = useState<string | null>(null);
  // Whether the signup began from an invitation link. The secret itself is
  // cleared on success (memory only), so only this flag survives to remind the
  // person to reopen the link after verifying.
  const [invited, setInvited] = useState(false);

  // Same gate as /$lang/verify-email: resending needs a working mail transport.
  // Without it the card below must not claim a link was sent, or offer a
  // button that can only ever error.
  const canResend = configData?.emailEnabled === true;
  // lib/signup-mode.ts: the same answer the landing page, header and sign-in
  // give. A held pool invitation opens the form whatever the server setting.
  const mode = signupMode(configData ?? {}, poolInviteToken() !== undefined);
  // Sign-up is closed to the public: only the administrator addresses and
  // invited people get in, so the page says so before the form.
  const byInvitation = mode === "bootstrap";
  const sessionPending =
    authSession.state.status === "pending" || authSession.state.status === "error";

  let body: ReactNode;
  if (pendingEmail) {
    // Terminal state after a successful signup: the account exists but is inert
    // until the emailed link is clicked, so say that plainly instead of dropping
    // the user back on a form or bouncing them off an authenticated route.
    body = (
      <AuthCard
        title={canResend ? t("auth:verifyEmail.sentTitle") : t("auth:verifyEmail.pendingTitle")}
        description={
          canResend
            ? t("auth:verifyEmail.sentDescription", { email: pendingEmail })
            : t("auth:verifyEmail.accountCreatedNoEmail", { email: pendingEmail })
        }
      >
        {invited ? <p data-pool-invite-notice="">{t("auth:poolInviteReopen")}</p> : null}
        <Link
          to="/$lang/login"
          params={{ lang }}
          search={{ redirectTo }}
          className={cn(buttonVariants(), "min-h-[44px] w-full")}
        >
          {t("auth:verifyEmail.signIn")}
        </Link>
        {canResend ? (
          <ResendVerification email={pendingEmail} />
        ) : (
          <p className="text-center text-sm text-muted-foreground">
            {t("auth:verifyEmail.emailUnavailable")}
          </p>
        )}
      </AuthCard>
    );
  } else if (mode === "closed") {
    // Invite-only: say so, and point at the one thing this visitor can do here.
    body = (
      <AuthCard title={t("auth:login.closedTitle")} description={t("auth:login.closedDescription")}>
        <Link
          to="/$lang/login"
          params={{ lang }}
          search={{ redirectTo }}
          data-signup-closed=""
          className={cn(buttonVariants(), "min-h-[44px] w-full")}
        >
          {t("auth:login.signIn")}
        </Link>
      </AuthCard>
    );
  } else {
    body = (
      <AuthCard
        title={t("auth:login.createAccount")}
        description={
          byInvitation
            ? t("auth:login.createDescriptionLimited")
            : t("auth:login.createDescription")
        }
      >
        {mode === "invite" ? (
          <p data-pool-invite-notice="">{t("auth:poolInviteReopen")}</p>
        ) : byInvitation ? (
          <div
            role="note"
            data-signup-limited=""
            className="space-y-1 border border-border bg-muted/50 px-3 py-2 text-sm"
          >
            <p className="font-medium">{t("auth:login.byInvitation")}</p>
            <p className="text-muted-foreground">{t("auth:login.signupLimited")}</p>
          </div>
        ) : null}
        <SignUpForm
          byInvitation={byInvitation}
          onSignedUp={(email, fromInvite) => {
            setInvited(fromInvite);
            setPendingEmail(email);
          }}
        />
        <div className="text-center">
          <Link
            to="/$lang/login"
            params={{ lang }}
            search={{ redirectTo }}
            className={cn(buttonVariants({ variant: "link" }), "min-h-[44px]")}
          >
            {t("auth:login.signinHint")}
          </Link>
        </div>
      </AuthCard>
    );
  }

  return (
    <AuthConfigGate
      isPending={sessionPending || configPending}
      isError={configError}
      onRetry={() => refetchConfig()}
    >
      {body}
    </AuthConfigGate>
  );
}

function SignUpForm({
  byInvitation,
  onSignedUp,
}: {
  /** Sign-up is limited to administrator addresses and invited people. */
  byInvitation: boolean;
  onSignedUp: (email: string, fromInvite: boolean) => void;
}) {
  const { t } = useTranslation(["auth"]);
  const formRef = useRef<HTMLFormElement>(null);
  const [formError, setFormError] = useState<string | null>(null);

  const form = useForm({
    defaultValues: { name: "", email: "", password: "" },
    onSubmit: async ({ value }) => {
      setFormError(null);
      const result = await authClient.signUp.email(
        {
          email: value.email,
          password: value.password,
          name: value.name,
        },
        { body: poolInviteToken() ? { poolInviteToken: poolInviteToken() } : undefined },
      );
      if (result.error) {
        // Better-Auth's database hook rejects an address sign-up is closed to
        // with a plain Error, which the sign-up route converts to a generic
        // 422 FAILED_TO_CREATE_USER — the same answer for every address. With
        // sign-up limited (public config, nothing new disclosed) that answer
        // means "not invited", so say how to get in instead of "try again".
        const notInvited =
          byInvitation &&
          (result.error.code === "FAILED_TO_CREATE_USER" || result.error.status === 422);
        const emailMessage =
          result.error.status === 409
            ? t("auth:errors.accountAlreadyRegistered")
            : notInvited
              ? t("auth:errors.signupByInvitation")
              : null;
        if (emailMessage) {
          form.setFieldMeta("email", (meta) => ({
            ...meta,
            errorMap: { ...meta.errorMap, onSubmit: emailMessage },
          }));
          formRef.current?.querySelector<HTMLInputElement>('input[name="email"]')?.focus();
        } else {
          setFormError(friendly(result.error, t("auth:errors.couldNotCreateAccount")));
        }
        // Better-Auth's database hook rejects signup-disabled attempts with a
        // plain Error, which the sign-up route converts to this generic 422 —
        // the same response for every address, member or not, so reading it
        // reveals nothing about whether an admin already exists (see
        // apps/server/src/signup-gate.ts). Dev-only, and guarded here (not in
        // a shared util) so the hint string tree-shakes out of prod bundles.
        if (import.meta.env.DEV && result.error?.code === "FAILED_TO_CREATE_USER") {
          toast.error(t("auth:errors.signupDisabledDevHint"));
        }
        return;
      }
      toast.success(t("auth:accountCreatedSuccess"));
      // No navigation: `requireEmailVerification` means signUp.email returns no
      // session, so anything behind the `_auth` guard would bounce straight back
      // to login. Hand the address up and let the page render the
      // check-your-email state instead.
      const fromInvite = poolInviteToken() !== undefined;
      clearPoolInviteToken();
      onSignedUp(value.email, fromInvite);
    },
    validators: {
      // Validation messages come from the locale-aware Zod error map installed
      // in `@/i18n/zod`. Don't pass inline strings here — that would override
      // the global map and leak hardcoded English copy into es-MX UIs.
      onSubmit: z.object({
        name: z.string().min(2),
        email: z.email(),
        password: newPasswordSchema(),
      }),
    },
  });

  return (
    <form
      ref={formRef}
      noValidate
      onSubmit={(e) => {
        e.preventDefault();
        e.stopPropagation();
        form.handleSubmit();
      }}
      className="space-y-4"
    >
      <form.Field name="name">
        {(field) => (
          <TextField
            field={field}
            label={t("auth:fields.name")}
            inputMode="text"
            autoComplete="name"
          />
        )}
      </form.Field>

      <form.Field name="email">
        {(field) => (
          <TextField
            field={field}
            label={t("auth:fields.email")}
            type="email"
            autoComplete="email"
            onChange={() => setFormError(null)}
          />
        )}
      </form.Field>

      <form.Field name="password">
        {(field) => (
          <TextField
            field={field}
            label={t("auth:fields.password")}
            description={t("auth:fields.passwordRule", { min: PASSWORD_MIN_LENGTH })}
            type="password"
            autoComplete="new-password"
          />
        )}
      </form.Field>

      <FormAlert message={formError} />

      <form.Subscribe
        selector={(state) => ({ canSubmit: state.canSubmit, isSubmitting: state.isSubmitting })}
      >
        {({ canSubmit, isSubmitting }) => (
          <Button
            type="submit"
            className="min-h-[44px] w-full"
            disabled={!canSubmit || isSubmitting}
          >
            {isSubmitting ? t("auth:login.creatingAccount") : t("auth:login.signUp")}
          </Button>
        )}
      </form.Subscribe>
    </form>
  );
}
