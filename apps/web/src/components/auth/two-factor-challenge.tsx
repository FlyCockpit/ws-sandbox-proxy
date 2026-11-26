import { Button } from "@wssp/ui/components/button";
import { toast } from "@wssp/ui/components/sileo";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { AuthCard } from "@/components/auth/auth-screen";
import { InlineInputField } from "@/components/auth/inline-input-field";
import { authClient } from "@/lib/auth-client";
import { friendly, isRateLimit } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

/**
 * How the second factor is proved: the authenticator app's 6-digit code, a
 * 6-digit code sent by email (only with a mail transport), or one of the
 * single-use backup codes handed out at enrolment (`xxxxx-xxxxx`).
 */
type ChallengeMode = "totp" | "email" | "backup";

const SIX_DIGITS = /^\d{6}$/;

/**
 * Better-Auth's backup codes are ten letters and digits shown as
 * `xxxxx-xxxxx` and compared exactly. Accept what people paste or type
 * (spaces, no dash) and send the stored form; anything else goes through
 * unchanged and fails verification like any wrong code.
 */
export function normalizeBackupCode(raw: string): string {
  const compact = raw.replace(/\s+/g, "");
  const plain = compact.replace(/-/g, "");
  return /^[A-Za-z0-9]{10}$/.test(plain) ? `${plain.slice(0, 5)}-${plain.slice(5)}` : compact;
}

/** Whether the typed code is complete enough to submit in this mode. */
export function codeIsComplete(mode: ChallengeMode, code: string): boolean {
  if (mode === "backup") return /^[A-Za-z0-9]{5}-[A-Za-z0-9]{5}$/.test(normalizeBackupCode(code));
  return SIX_DIGITS.test(code.trim());
}

type ChallengeState = {
  mode: ChallengeMode;
  code: string;
  error: string | null;
  verifying: boolean;
  sendingOtp: boolean;
};

const initialState: ChallengeState = {
  mode: "totp",
  code: "",
  error: null,
  verifying: false,
  sendingOtp: false,
};

/**
 * The sign-in 2FA step. One state object so a mode switch (authenticator,
 * email code, backup code) clears the code and the error in one render.
 * Errors sit under the code field and focus returns to it.
 */
export function TwoFactorChallenge({
  emailEnabled,
  onVerified,
  onCancel,
}: {
  emailEnabled: boolean;
  onVerified: () => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation(["auth", "common"]);
  const [state, setState] = useState<ChallengeState>(initialState);
  const codeRef = useRef<HTMLInputElement | null>(null);
  // Set by a mode switch: the backup field is a different element, so focus
  // moves when it mounts (the ref callback below), not at the click.
  const focusNext = useRef(false);
  const attachCode = (el: HTMLInputElement | null) => {
    codeRef.current = el;
    if (el && focusNext.current) {
      focusNext.current = false;
      el.focus();
    }
  };
  const complete = codeIsComplete(state.mode, state.code);

  const switchMode = (mode: ChallengeMode) => {
    setState((s) => ({ ...s, mode, code: "", error: null }));
    focusNext.current = true;
    codeRef.current?.focus();
  };

  const fail = (message: string) => {
    setState((s) => ({ ...s, error: message }));
    codeRef.current?.focus();
  };

  const verify = async () => {
    if (!complete || state.verifying) return;
    setState((s) => ({ ...s, verifying: true, error: null }));
    try {
      const result =
        state.mode === "backup"
          ? await authClient.twoFactor.verifyBackupCode({ code: normalizeBackupCode(state.code) })
          : state.mode === "email"
            ? await authClient.twoFactor.verifyOtp({ code: state.code.trim() })
            : await authClient.twoFactor.verifyTotp({ code: state.code.trim() });
      if (result.error) {
        console.error("[login.twoFactor.verify]", state.mode, result.error);
        fail(
          isRateLimit(result.error)
            ? friendly(result.error)
            : state.mode === "backup"
              ? t("auth:errors.invalidBackupCode")
              : state.mode === "email"
                ? t("auth:errors.invalidEmailCode")
                : t("auth:errors.invalidTotp"),
        );
        return;
      }
      onVerified();
    } catch (error) {
      console.error("[login.twoFactor.verify]", state.mode, error);
      fail(friendly(error));
    } finally {
      setState((s) => ({ ...s, verifying: false }));
    }
  };

  const sendEmailOtp = async () => {
    setState((s) => ({ ...s, sendingOtp: true }));
    try {
      // Delivery-aware preflight: Better-Auth's send-otp endpoint reports
      // success even when SMTP delivery fails, so verify the transport is
      // actually reachable before telling the user a code is on the way.
      const preflight = await orpc.auth.verifyEmailTransport.call().catch((err) => {
        console.error("[login.twoFactor.verifyEmailTransport]", err);
        return { ok: false };
      });
      if (!preflight.ok) {
        toast.error(t("auth:twoFactor.couldNotSendCode"));
        return;
      }
      const result = await authClient.twoFactor.sendOtp();
      if (result.error) {
        console.error("[login.twoFactor.sendOtp]", result.error);
        toast.error(
          isRateLimit(result.error) ? friendly(result.error) : t("auth:twoFactor.couldNotSendCode"),
        );
        return;
      }
      switchMode("email");
      toast.success(t("auth:twoFactor.codeSent"));
    } finally {
      setState((s) => ({ ...s, sendingOtp: false }));
    }
  };

  const backup = state.mode === "backup";
  const description =
    state.mode === "email"
      ? t("auth:twoFactor.emailCodeDescription")
      : backup
        ? t("auth:twoFactor.backupCodeDescription")
        : t("auth:twoFactor.description");

  return (
    <AuthCard title={t("auth:twoFactor.title")} description={description}>
      <form
        className="space-y-4"
        data-challenge-mode={state.mode}
        onSubmit={(event) => {
          event.preventDefault();
          void verify();
        }}
      >
        {backup ? (
          <InlineInputField
            // A different key per mode: the browser must not offer one-time-code
            // autofill or a numeric keyboard to the backup field.
            key="backup"
            id="backup-code"
            label={t("auth:fields.backupCode")}
            description={t("auth:twoFactor.backupCodeHint")}
            error={state.error}
            inputRef={attachCode}
            placeholder="xxxxx-xxxxx"
            value={state.code}
            onChange={(e) => setState((s) => ({ ...s, code: e.target.value, error: null }))}
            inputMode="text"
            autoComplete="off"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            maxLength={24}
            className="text-center font-mono text-lg tracking-wider"
          />
        ) : (
          <InlineInputField
            key="code"
            id="totp-code"
            label={t("auth:fields.verificationCode")}
            error={state.error}
            inputRef={attachCode}
            placeholder="000000"
            value={state.code}
            onChange={(e) => setState((s) => ({ ...s, code: e.target.value, error: null }))}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            className="text-center text-lg tracking-widest"
          />
        )}
        <Button
          type="submit"
          className="min-h-[44px] w-full"
          disabled={!complete || state.verifying}
        >
          {state.verifying ? t("auth:twoFactor.verifying") : t("auth:twoFactor.verify")}
        </Button>
      </form>
      {state.mode !== "totp" ? (
        <Button
          variant="outline"
          className="min-h-[44px] w-full"
          onClick={() => switchMode("totp")}
        >
          {t("auth:twoFactor.useAuthenticator")}
        </Button>
      ) : null}
      {emailEnabled ? (
        <Button
          variant="outline"
          className="min-h-[44px] w-full"
          onClick={sendEmailOtp}
          disabled={state.sendingOtp}
        >
          {state.sendingOtp
            ? t("auth:twoFactor.sendingCode")
            : state.mode === "email"
              ? t("auth:twoFactor.resendEmailCode")
              : t("auth:twoFactor.emailMeCode")}
        </Button>
      ) : null}
      {!backup ? (
        <Button
          variant="outline"
          className="min-h-[44px] w-full"
          onClick={() => switchMode("backup")}
        >
          {t("auth:twoFactor.useBackupCode")}
        </Button>
      ) : null}
      {/* Cancel: back to the sign-in form with nothing carried over (the
          page unmounts this step, so no code, mode or error survives). */}
      <Button
        variant="ghost"
        className="min-h-[44px] w-full"
        disabled={state.verifying}
        onClick={onCancel}
      >
        {t("common:actions.cancel")}
      </Button>
    </AuthCard>
  );
}
