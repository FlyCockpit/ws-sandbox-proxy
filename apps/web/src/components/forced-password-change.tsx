import { useTranslation } from "react-i18next";

import { ChangePasswordCard } from "@/components/settings/change-password-card";

/**
 * The `_auth` layout's takeover while the account still has the temporary
 * password an admin set when inviting it: the invitee chooses their own
 * password before anything else. Decided from the user row in the same guard
 * round trip as the session (`getProtectedRouteSession`), so no protected
 * content renders first. A successful change clears the flag server-side
 * (Better Auth's after hook, password-change-guard.ts) and reloads the document, an identity
 * boundary like the 2FA takeover's; the guard then lets the app render.
 *
 * UX, not the security boundary: the procedures refuse independently
 * (`PASSWORD_CHANGE_REQUIRED_ERROR_CODE`).
 */
export function ForcedPasswordChange() {
  const { t } = useTranslation("auth");
  return (
    <div
      data-forced-password-change=""
      className="flex min-h-[80vh] items-center justify-center px-4"
    >
      <div className="w-full max-w-md">
        <ChangePasswordCard
          title={t("passwordChange.requiredTitle")}
          description={t("passwordChange.requiredDescription")}
          onChanged={() => window.location.reload()}
        />
      </div>
    </div>
  );
}
