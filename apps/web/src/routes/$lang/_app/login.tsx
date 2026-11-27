import { useForm } from "@tanstack/react-form";
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link, redirect } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { toast } from "@wssp/ui/components/sileo";
import { TextField } from "@wssp/ui/components/text-field";
import { cn } from "@wssp/ui/lib/utils";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import z from "zod";
import { AuthConfigGate } from "@/components/auth/auth-config-gate";
import { AuthCard } from "@/components/auth/auth-screen";
import { FormAlert } from "@/components/auth/form-alert";
import { TwoFactorChallenge } from "@/components/auth/two-factor-challenge";
import { useAuthSessionSettled } from "@/hooks/use-auth-session-settled";
import { authClient } from "@/lib/auth-client";
import { markAnonymousOnlyRoute } from "@/lib/document-identity";
import { currentPasswordSchema } from "@/lib/password-policy";
import { poolInviteToken, postAuthHref } from "@/lib/pool-invite";
import { resolveRouteSession } from "@/lib/route-session";
import { decideAnonymousOnlyRouteAccess } from "@/lib/route-session-access";
import { signupMode } from "@/lib/signup-mode";
import { friendly, isCredentialRejection, isRateLimit } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";
import { safeRedirectTo } from "@/utils/safe-redirect";

export const Route = createFileRoute("/$lang/_app/login")({
  staticData: { pendingShape: "auth" },
  validateSearch: (search: Record<string, unknown>) => ({
    redirectTo: typeof search.redirectTo === "string" ? search.redirectTo : undefined,
  }),
  beforeLoad: async ({ params, search }) => {
    const decision = decideAnonymousOnlyRouteAccess(await resolveRouteSession());
    if (decision.kind === "error") throw new Error("Route session unavailable");
    if (decision.kind === "redirect-authenticated") {
      throw redirect({ href: safeRedirectTo(search.redirectTo, params.lang) });
    }
  },
  component: LoginPage,
});

function LoginPage() {
  markAnonymousOnlyRoute();
  const { lang } = Route.useParams();
  const { redirectTo } = Route.useSearch();
  const [challenge, setChallenge] = useState(false);
  const sessionSettled = useAuthSessionSettled();
  const {
    data: configData,
    isPending: configPending,
    isLoadingError: configError,
    refetch: refetchConfig,
  } = useQuery(orpc.appConfig.queryOptions());
  const { t } = useTranslation(["auth", "common"]);

  // The same mode the landing page, the header and /signup read
  // (lib/signup-mode.ts). The gate below holds the form until config loads.
  const mode = signupMode(configData ?? {}, poolInviteToken() !== undefined);
  // Closed sign-up that the configured administrator addresses may still use.
  const adminBootstrapOnly = mode === "bootstrap";
  const emailEnabled = configData?.emailEnabled ?? false;
  const postAuthRedirect = safeRedirectTo(redirectTo, lang);

  // The password was accepted, so the session and config this page waited for
  // have both loaded. The challenge stays outside the gate: every
  // `/two-factor/*` call makes Better Auth refetch the (still empty) session,
  // and a refetch or a config revalidation must never unmount the challenge
  // and drop its mode (an emailed code would go to the TOTP check).
  if (challenge) {
    return (
      <TwoFactorChallenge
        emailEnabled={emailEnabled}
        onVerified={() => {
          toast.success(t("auth:signedInSuccess"));
          window.location.assign(postAuthHref(postAuthRedirect, lang));
        }}
        onCancel={() => setChallenge(false)}
      />
    );
  }

  return (
    <AuthConfigGate
      // Settled once, not live: the refetch after a sign-in attempt must not
      // swap the form for a skeleton and lose its inline error.
      isPending={!sessionSettled || configPending}
      isError={configError}
      onRetry={() => refetchConfig()}
    >
      <AuthCard title={t("auth:login.signinTitle")} description={t("auth:login.signinDescription")}>
        {/* Only for a visitor who arrived from an invitation link: the secret is
            held in memory (lib/pool-invite.ts), and reopening the link after
            sign-in is the one thing they must know. */}
        {poolInviteToken() ? <p data-pool-invite-notice="">{t("auth:poolInviteReopen")}</p> : null}
        <SignInForm
          lang={lang}
          redirectTo={postAuthRedirect}
          showForgotPassword={emailEnabled}
          onNeeds2FA={() => setChallenge(true)}
        />
        {mode === "open" || mode === "invite" ? (
          // `max-sm:-mt-2`: on phones the link's 44px box may use half of the
          // gap above it (its text sits 12px inside the box), which keeps it
          // above the BottomNav at 320×568.
          <div className="text-center max-sm:-mt-2">
            <Link
              to="/$lang/signup"
              params={{ lang }}
              search={{ redirectTo }}
              className={cn(buttonVariants({ variant: "link" }), "min-h-[44px]")}
            >
              {t("auth:login.signupHint")}
            </Link>
          </div>
        ) : (
          // Sign-up is closed: say how people get in instead of a link that
          // can only fail. Administrator addresses may still bootstrap.
          <div data-signup-closed="" className="space-y-1 text-center max-sm:-mt-2">
            <p className="text-sm text-muted-foreground">{t("auth:login.byInvitation")}</p>
            {adminBootstrapOnly ? (
              <Link
                to="/$lang/signup"
                params={{ lang }}
                search={{ redirectTo }}
                className={cn(
                  buttonVariants({ variant: "link" }),
                  "min-h-[44px] text-muted-foreground",
                )}
              >
                {t("auth:login.adminSignupHint")}
              </Link>
            ) : null}
          </div>
        )}
      </AuthCard>
    </AuthConfigGate>
  );
}

function SignInForm({
  lang,
  redirectTo,
  showForgotPassword,
  onNeeds2FA,
}: {
  lang: string;
  redirectTo: string;
  showForgotPassword: boolean;
  onNeeds2FA: () => void;
}) {
  const { t } = useTranslation(["auth", "validation"]);
  const formRef = useRef<HTMLFormElement>(null);
  // A failure that belongs to no one field (rate limit, network): shown above
  // the button, and it never blocks the next attempt.
  const [formError, setFormError] = useState<string | null>(null);
  const [unverified, setUnverified] = useState(false);

  const form = useForm({
    defaultValues: { email: "", password: "" },
    onSubmit: async ({ value }) => {
      setFormError(null);
      setUnverified(false);
      let result: Awaited<ReturnType<typeof authClient.signIn.email>>;
      try {
        result = await authClient.signIn.email({ email: value.email, password: value.password });
      } catch (error) {
        toast.error(friendly(error));
        return;
      }
      if (result.error) {
        // `requireEmailVerification` rejects correct credentials on an
        // unverified account. Better-Auth distinguishes this itself, so say so
        // — the generic "email or password doesn't match" sends the user to
        // password reset for a problem a link in their inbox already solves.
        // This leaks nothing: the caller supplied the matching password.
        //
        // `emailVerification.sendOnSignIn` is on, so Better-Auth has already
        // mailed a fresh link by the time we get here — but the original may
        // have expired days ago, so the form also offers the resend page
        // rather than leaving a dead end if that mail doesn't arrive.
        if (result.error.code === "EMAIL_NOT_VERIFIED") {
          setFormError(t("auth:verifyEmail.notVerified"));
          setUnverified(true);
          return;
        }
        if (isRateLimit(result.error)) {
          setFormError(friendly(result.error));
          return;
        }
        if (!isCredentialRejection(result.error)) {
          toast.error(friendly(result.error));
          return;
        }
        // Wrong email or password (the server never says which): under the
        // password field, focused, and cleared by the next edit of either.
        form.setFieldMeta("password", (meta) => ({
          ...meta,
          errorMap: { ...meta.errorMap, onSubmit: t("auth:errors.invalidCredentials") },
        }));
        formRef.current?.querySelector<HTMLInputElement>('input[name="password"]')?.focus();
        return;
      }
      if ((result.data as Record<string, unknown>)?.twoFactorRedirect) {
        onNeeds2FA();
        return;
      }
      toast.success(t("auth:signedInSuccess"));
      window.location.assign(postAuthHref(redirectTo, lang));
    },
    validators: {
      // Validation messages come from the locale-aware Zod error map installed
      // in `@/i18n/zod`. Don't pass inline strings here — that would override
      // the global map and leak hardcoded English copy into es-MX UIs.
      onSubmit: z.object({
        email: z.email(),
        // Present, not policy-length: an older, shorter password must still
        // be able to sign in (lib/password-policy.ts).
        password: currentPasswordSchema(t("validation:required")),
      }),
    },
  });

  const clearCredentialsError = () => {
    setFormError(null);
    setUnverified(false);
    form.setFieldMeta("password", (meta) => ({
      ...meta,
      errorMap: { ...meta.errorMap, onSubmit: undefined },
    }));
  };

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
      <form.Field name="email">
        {(field) => (
          <TextField
            field={field}
            label={t("auth:fields.email")}
            type="email"
            autoComplete="email"
            onChange={clearCredentialsError}
          />
        )}
      </form.Field>

      {/* Phones: "Forgot password?" sits in the Password label's row, so
          turning email on does not push the sign-up link below the BottomNav
          at 320×568. Its 44px box fills the space from the email input's
          bottom edge to the password input's top edge (the 6px `pt` makes
          that space 44px) and never overlaps either input; the label is
          aligned to the box's bottom. From `sm` up it keeps its own row under
          the field. DOM order is the same at every width: password, then the
          link, then submit. */}
      <div className={cn("relative space-y-4", showForgotPassword && "max-sm:pt-1.5")}>
        <form.Field name="password">
          {(field) => (
            <TextField
              field={field}
              label={t("auth:fields.password")}
              type="password"
              autoComplete="current-password"
              onChange={() => {
                setFormError(null);
                setUnverified(false);
              }}
            />
          )}
        </form.Field>

        {showForgotPassword && (
          <div className="text-right max-sm:absolute max-sm:-top-4 max-sm:right-0 max-sm:mt-0">
            <Link
              to="/$lang/forgot-password"
              params={{ lang }}
              search={{ redirectTo }}
              className={cn(
                buttonVariants({ variant: "link" }),
                "min-h-[44px] px-0 text-sm text-muted-foreground max-sm:h-11 max-sm:items-end max-sm:pb-[5px]",
              )}
            >
              {t("auth:login.forgotPassword")}
            </Link>
          </div>
        )}
      </div>

      <FormAlert message={formError} />
      {unverified ? (
        <Link
          to="/$lang/verify-email"
          params={{ lang }}
          search={{ error: undefined, ok: undefined }}
          className={cn(buttonVariants({ variant: "link" }), "min-h-[44px] px-0")}
        >
          {t("auth:verifyEmail.resend")}
        </Link>
      ) : null}

      <form.Subscribe
        selector={(state) => ({ canSubmit: state.canSubmit, isSubmitting: state.isSubmitting })}
      >
        {({ canSubmit, isSubmitting }) => (
          <Button
            type="submit"
            className="min-h-[44px] w-full"
            disabled={!canSubmit || isSubmitting}
          >
            {isSubmitting ? t("auth:login.signingIn") : t("auth:login.signIn")}
          </Button>
        )}
      </form.Subscribe>
    </form>
  );
}
