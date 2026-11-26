import { Button } from "@wssp/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import { toast } from "@wssp/ui/components/sileo";
import { type ReactNode, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { InlineInputField } from "@/components/auth/inline-input-field";
import { TwoFactorSetupDetails } from "@/components/two-factor-setup-details";
import { authClient } from "@/lib/auth-client";
import { twoFactorCodeError, twoFactorPasswordError } from "@/lib/two-factor-errors";
import {
  type ForcedTwoFactorSettings,
  type TwoFactorPolicySessionUser,
  twoFactorEnrollmentState,
} from "@/utils/two-factor-policy";

/**
 * The `_auth` layout's forced-2FA takeover. Decided synchronously from the
 * session and the force-2FA settings the route guard resolved in the same
 * server round trip (`getProtectedRouteSession`), so protected content never
 * renders — not even for a frame — before the decision, and the page's own
 * queries start without waiting on a separate settings request.
 *
 * Forced 2FA is on by default for admins, so an unenrolled admin gets an
 * enrollment grace window (`@wssp/auth/two-factor-policy`) before this guard
 * blocks them — otherwise the first admin to sign up would be walled off from
 * the app before ever reaching the enrollment screen. Only the post-grace
 * `blocked` state takes over the layout, and the takeover IS the enrollment
 * flow, so nobody is stranded behind it.
 *
 * UX, not the security boundary: the procedures re-check independently.
 */
export function ForcedTwoFactorGate({
  user,
  forcedTwoFactorSettings,
  children,
}: {
  user: TwoFactorPolicySessionUser;
  forcedTwoFactorSettings: ForcedTwoFactorSettings;
  children: ReactNode;
}) {
  if (twoFactorEnrollmentState(forcedTwoFactorSettings, user).status === "blocked") {
    return <TwoFactorSetupRequired />;
  }
  return children;
}

function TwoFactorSetupRequired() {
  const [step, setStep] = useState<"intro" | "setup" | "verify">("intro");
  const [totpURI, setTotpURI] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [verifyCode, setVerifyCode] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  // Errors sit under the field they are about; focus moves there.
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [codeError, setCodeError] = useState<string | null>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const codeRef = useRef<HTMLInputElement>(null);
  const { t } = useTranslation(["auth", "common"]);

  /** Cancel on the password and code steps: back to the start, nothing kept. */
  const backToIntro = () => {
    setStep("intro");
    setPassword("");
    setPasswordError(null);
    setVerifyCode("");
    setCodeError(null);
    // The secret shown on the code step was never confirmed; starting again
    // asks for a new one, so it must not linger on screen.
    setTotpURI("");
    setBackupCodes([]);
  };

  const failPassword = (error: unknown) => {
    setPasswordError(twoFactorPasswordError(error, t, "auth:twoFactor.couldNotStartSetup"));
    passwordRef.current?.focus();
  };

  const handleEnable = async () => {
    // Enter and the button both call this; a second call mid-flight would
    // start a second enrollment and replace the secret being shown.
    if (isLoading) return;
    setIsLoading(true);
    setPasswordError(null);
    try {
      const result = await authClient.twoFactor.enable({
        password,
        method: "totp",
      });
      if (result.error) {
        console.error("[_auth.twoFactor.enable]", result.error);
        failPassword(result.error);
        return;
      }
      if (result.data?.method !== "totp") {
        failPassword(null);
        return;
      }
      setTotpURI(result.data.totpURI || "");
      setBackupCodes(result.data.backupCodes || []);
      setStep("verify");
    } catch (err) {
      console.error("[_auth.twoFactor.enable]", err);
      failPassword(err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerify = async () => {
    if (isLoading) return;
    setIsLoading(true);
    setCodeError(null);
    try {
      const result = await authClient.twoFactor.verifyTotp({
        code: verifyCode,
      });
      if (result.error) {
        console.error("[_auth.twoFactor.verifyTotp]", result.error);
        setCodeError(twoFactorCodeError(result.error, t));
        codeRef.current?.focus();
        return;
      }
      toast.success(t("twoFactor.enabledSuccess"));
      window.location.reload();
    } catch (err) {
      console.error("[_auth.twoFactor.verifyTotp]", err);
      setCodeError(twoFactorCodeError(err, t));
      codeRef.current?.focus();
    } finally {
      setIsLoading(false);
    }
  };

  const cancelButton = (
    <Button
      variant="ghost"
      className="min-h-[44px] w-full"
      disabled={isLoading}
      onClick={backToIntro}
    >
      {t("common:actions.cancel")}
    </Button>
  );

  return (
    <div className="flex min-h-[80vh] items-center justify-center px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          {/* It replaces the page, so its title is the page's one h1. */}
          <CardTitle className="text-2xl">
            <h1>{t("twoFactor.requiredTitle")}</h1>
          </CardTitle>
          <CardDescription>{t("twoFactor.requiredDescription")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {step === "intro" && (
            <>
              <p className="text-sm text-muted-foreground">{t("twoFactor.introText")}</p>
              <Button className="min-h-[44px] w-full" onClick={() => setStep("setup")}>
                {t("twoFactor.setUp")}
              </Button>
            </>
          )}

          {step === "setup" && (
            <>
              <p className="text-sm text-muted-foreground">{t("twoFactor.passwordPrompt")}</p>
              <InlineInputField
                id="2fa-password"
                label={t("fields.password")}
                error={passwordError}
                inputRef={passwordRef}
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setPasswordError(null);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleEnable();
                }}
              />
              <Button className="min-h-[44px] w-full" onClick={handleEnable} disabled={isLoading}>
                {isLoading ? t("twoFactor.settingUp") : t("twoFactor.continue")}
              </Button>
              {cancelButton}
            </>
          )}

          {step === "verify" && (
            <>
              <TwoFactorSetupDetails
                backupCodes={backupCodes}
                backupCodesLabel={t("twoFactor.backupCodesLabel")}
                manualPrompt={t("twoFactor.addKeyToApp")}
                qrPrompt={t("twoFactor.scanQrPrompt")}
                totpURI={totpURI}
              />

              <InlineInputField
                id="verify-code"
                label={t("fields.verificationCode")}
                error={codeError}
                inputRef={codeRef}
                placeholder="000000"
                value={verifyCode}
                onChange={(e) => {
                  setVerifyCode(e.target.value);
                  setCodeError(null);
                }}
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                className="text-center text-lg tracking-widest"
                onKeyDown={(e) => {
                  if (e.key === "Enter" && verifyCode.length === 6) handleVerify();
                }}
              />
              <Button
                className="min-h-[44px] w-full"
                onClick={handleVerify}
                disabled={verifyCode.length !== 6 || isLoading}
              >
                {isLoading ? t("twoFactor.verifying") : t("twoFactor.verifyAndEnable")}
              </Button>
              {cancelButton}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
