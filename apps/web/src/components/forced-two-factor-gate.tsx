import { Button } from "@wssp/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import { Input } from "@wssp/ui/components/input";
import { Label } from "@wssp/ui/components/label";
import { toast } from "@wssp/ui/components/sileo";
import { type ReactNode, useState } from "react";
import { useTranslation } from "react-i18next";

import { TwoFactorSetupDetails } from "@/components/two-factor-setup-details";
import { authClient } from "@/lib/auth-client";
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
  const { t } = useTranslation("auth");

  const handleEnable = async () => {
    setIsLoading(true);
    try {
      const result = await authClient.twoFactor.enable({
        password,
        method: "totp",
      });
      if (result.error) {
        console.error("[_auth.twoFactor.enable]", result.error);
        toast.error(t("twoFactor.couldNotStartSetup"));
        return;
      }
      if (result.data?.method !== "totp") {
        toast.error(t("twoFactor.couldNotStartSetup"));
        return;
      }
      setTotpURI(result.data.totpURI || "");
      setBackupCodes(result.data.backupCodes || []);
      setStep("verify");
    } catch (err) {
      console.error("[_auth.twoFactor.enable]", err);
      toast.error(t("twoFactor.couldNotStartSetup"));
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerify = async () => {
    setIsLoading(true);
    try {
      const result = await authClient.twoFactor.verifyTotp({
        code: verifyCode,
      });
      if (result.error) {
        console.error("[_auth.twoFactor.verifyTotp]", result.error);
        toast.error(t("errors.invalidTotp"));
        return;
      }
      toast.success(t("twoFactor.enabledSuccess"));
      window.location.reload();
    } catch (err) {
      console.error("[_auth.twoFactor.verifyTotp]", err);
      toast.error(t("errors.invalidTotp"));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-[80vh] items-center justify-center px-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl">{t("twoFactor.requiredTitle")}</CardTitle>
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
              <div className="space-y-2">
                <Label htmlFor="2fa-password">{t("fields.password")}</Label>
                <Input
                  id="2fa-password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleEnable();
                  }}
                />
              </div>
              <Button className="min-h-[44px] w-full" onClick={handleEnable} disabled={isLoading}>
                {isLoading ? t("twoFactor.settingUp") : t("twoFactor.continue")}
              </Button>
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

              <div className="space-y-2">
                <Label htmlFor="verify-code">{t("fields.verificationCode")}</Label>
                <Input
                  id="verify-code"
                  placeholder="000000"
                  value={verifyCode}
                  onChange={(e) => setVerifyCode(e.target.value)}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  className="text-center text-lg tracking-widest"
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && verifyCode.length === 6) handleVerify();
                  }}
                />
              </div>
              <Button
                className="min-h-[44px] w-full"
                onClick={handleVerify}
                disabled={verifyCode.length !== 6 || isLoading}
              >
                {isLoading ? t("twoFactor.verifying") : t("twoFactor.verifyAndEnable")}
              </Button>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
