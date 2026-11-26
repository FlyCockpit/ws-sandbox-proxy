import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { isAdminRole } from "@wssp/auth/roles";
import { buttonVariants } from "@wssp/ui/components/button";
import { cn } from "@wssp/ui/lib/utils";
import { ShieldAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import { PAGE_COLUMN_CLASS } from "@/components/page-shell";
import { useAuthSession } from "@/hooks/use-auth-session";
import { DEFAULT_LOCALE, isSupportedLocale } from "@/i18n/config";
import { dateTimeTitle } from "@/lib/format-date-time";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";
import { twoFactorEnrollmentState } from "@/utils/two-factor-policy";

/**
 * Nudges a signed-in admin who has not enrolled a TOTP second factor, and, in
 * the app shell, anyone whose role a forced-2FA policy covers (non-admins
 * only when an admin turned `force2faPublicUsers` on) while their enrollment
 * deadline runs.
 *
 * Enrollment is REQUIRED for admins unless the owner has explicitly turned
 * `force2faInternalUsers` off, so this banner has three voices:
 *   - inside the enrollment grace window → required, with the deadline;
 *   - past it → the gates are already rejecting them, say so;
 *   - enforcement explicitly disabled → the original advisory nudge.
 * It always names where the policy is configured, because the owner reading
 * this banner is usually the person who can change it.
 *
 * Links to the existing /settings/security enrollment flow rather than
 * duplicating it. Rendered by the admin layout; renders nothing until the
 * session and settings resolve, so it never flashes the wrong copy.
 */
export function TwoFactorNudge({ variant = "admin" }: { variant?: "admin" | "shell" } = {}) {
  const { t, i18n } = useTranslation("admin");
  const params = useParams({ strict: false });
  const lang = isSupportedLocale(params.lang) ? params.lang : DEFAULT_LOCALE;
  const authSession = useAuthSession();
  const { data: appSettings } = useQuery(orpc.settings.getAll.queryOptions());

  if (authSession.state.status !== "authenticated") return null;
  const user = authSession.state.session.user;
  if (user.twoFactorEnabled === true) return null;
  if (!appSettings) return null;

  const enrollment = twoFactorEnrollmentState(appSettings, user);
  if (enrollment.status === "enrolled") return null;
  // The app shell (outside /admin) shows only the running deadline: a blocked
  // admin is already taken over by ForcedTwoFactorGate, and an owner who turned
  // the policy off should not be nagged on every page.
  if (variant === "shell" && enrollment.status !== "grace") return null;

  // Non-admins only ever see the shell's running deadline, in their own words:
  // the policy that applies to them is the one for non-admin accounts.
  const admin = isAdminRole(user.role);
  const title =
    enrollment.status === "grace"
      ? admin
        ? t("twoFactorNudge.requiredTitle")
        : t("twoFactorNudge.userRequiredTitle")
      : enrollment.status === "blocked"
        ? t("twoFactorNudge.blockedTitle")
        : t("twoFactorNudge.title");
  const message =
    enrollment.status === "grace"
      ? t(admin ? "twoFactorNudge.requiredMessage" : "twoFactorNudge.userRequiredMessage", {
          deadline: formatRelativeTime(enrollment.deadlineMs, i18n.language),
        })
      : enrollment.status === "blocked"
        ? t("twoFactorNudge.blockedMessage")
        : t("twoFactorNudge.message");

  return (
    <div
      role="alert"
      data-two-factor-nudge={variant}
      className="border-b border-yellow-300 bg-yellow-100 py-3 text-sm text-yellow-900 dark:border-yellow-700 dark:bg-yellow-950 dark:text-yellow-100"
    >
      {/* The band spans the content area; its content sits in the page column,
          so the message and its action stay together on a wide screen. See
          docs/design/shell-rules.md § Viewport scale */}
      <div className={cn(PAGE_COLUMN_CLASS, "flex flex-col gap-3 sm:flex-row sm:items-start")}>
        <ShieldAlert className="mt-0.5 size-5 shrink-0" aria-hidden="true" />
        <div className="flex-1 space-y-1 [&_p]:max-w-prose">
          <p className="font-medium">{title}</p>
          <p
            className="text-yellow-900/90 dark:text-yellow-100/90"
            title={
              enrollment.status === "grace"
                ? dateTimeTitle(enrollment.deadlineMs, i18n.language)
                : undefined
            }
          >
            {message}
          </p>
          {variant === "admin" ? (
            <p className="text-yellow-900/80 dark:text-yellow-100/80">
              {t("twoFactorNudge.configurable")}
            </p>
          ) : null}
        </div>
        <Link
          to="/$lang/settings/security"
          params={{ lang }}
          className={cn(buttonVariants({ variant: "outline", size: "sm" }), "min-h-[44px]")}
        >
          {t("twoFactorNudge.cta")}
        </Link>
      </div>
    </div>
  );
}
