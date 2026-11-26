import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
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
import { ShieldCheck, ShieldOff } from "lucide-react";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { InlineInputField } from "@/components/auth/inline-input-field";
import { AccountSettingsLayout } from "@/components/settings/account-settings-layout";
import { ChangePasswordCard } from "@/components/settings/change-password-card";
import { TwoFactorSetupDetails } from "@/components/two-factor-setup-details";
import { authClient } from "@/lib/auth-client";
import { twoFactorCodeError, twoFactorPasswordError } from "@/lib/two-factor-errors";
import { orpc } from "@/utils/orpc";

export const Route = createFileRoute("/$lang/_app/_auth/settings/security")({
  staticData: { pendingShape: "detail" },
  component: SecuritySettings,
});

function SecuritySettings() {
  const { session } = Route.useRouteContext();
  const has2FA = session.user.twoFactorEnabled === true;
  const { t } = useTranslation("settings");
  const { lang } = Route.useParams();

  return (
    <AccountSettingsLayout lang={lang}>
      <PasswordSection />
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {has2FA ? (
              <ShieldCheck className="size-5 text-green-500" />
            ) : (
              <ShieldOff className="size-5 text-muted-foreground" />
            )}
            {t("security.twoFactorTitle")}
          </CardTitle>
          <CardDescription>
            {has2FA ? t("security.enabledDescription") : t("security.disabledDescription")}
          </CardDescription>
        </CardHeader>
        <CardContent>{has2FA ? <Disable2FASection /> : <Enable2FASection />}</CardContent>
      </Card>
    </AccountSettingsLayout>
  );
}

function PasswordSection() {
  const { t } = useTranslation(["settings", "common"]);
  const {
    data: capabilities,
    isPending,
    isError,
    refetch,
  } = useQuery(orpc.auth.passwordCapabilities.queryOptions());

  if (isPending) {
    return <PasswordCardSkeleton />;
  }

  if (isError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>{t("settings:security.passwordTitle")}</CardTitle>
          <CardDescription>{t("settings:security.passwordLoadError")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button variant="outline" className="min-h-[44px]" onClick={() => refetch()}>
            {t("common:actions.tryAgain")}
          </Button>
        </CardContent>
      </Card>
    );
  }

  if (!capabilities.canChangePassword) {
    return null;
  }

  return <ChangePasswordCard />;
}

function PasswordCardSkeleton() {
  return (
    <Card>
      <CardHeader>
        <Skeleton className="h-5 w-40" />
        <Skeleton className="h-4 w-full max-w-md" />
      </CardHeader>
      <CardContent className="max-w-lg space-y-4">
        {["current", "new", "confirm"].map((field) => (
          <div key={field} className="space-y-2">
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-8 max-md:min-h-11 w-full" />
          </div>
        ))}
        <Skeleton className="h-8 max-md:min-h-11 w-36" />
      </CardContent>
    </Card>
  );
}

function Enable2FASection() {
  const [step, setStep] = useState<"idle" | "password" | "setup" | "verify">("idle");
  const [password, setPassword] = useState("");
  const [totpURI, setTotpURI] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [verifyCode, setVerifyCode] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  // Errors sit under the field they are about; focus moves there.
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [codeError, setCodeError] = useState<string | null>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const codeRef = useRef<HTMLInputElement>(null);
  const { t } = useTranslation(["settings", "auth", "common"]);

  const failPassword = (error: unknown) => {
    setPasswordError(twoFactorPasswordError(error, t, "settings:security.couldNotStartSetup"));
    passwordRef.current?.focus();
  };

  const failCode = (error: unknown) => {
    setCodeError(twoFactorCodeError(error, t));
    codeRef.current?.focus();
  };

  const handleEnable = async () => {
    setIsLoading(true);
    setPasswordError(null);
    try {
      const result = await authClient.twoFactor.enable({
        password,
        method: "totp",
      });
      if (result.error) {
        console.error("[settings.security.twoFactor.enable]", result.error);
        failPassword(result.error);
        return;
      }
      if (result.data?.method !== "totp") {
        failPassword(null);
        return;
      }
      setTotpURI(result.data.totpURI || "");
      setBackupCodes(result.data.backupCodes || []);
      setStep("setup");
    } catch (err) {
      console.error("[settings.security.twoFactor.enable]", err);
      failPassword(err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerify = async () => {
    setIsLoading(true);
    setCodeError(null);
    try {
      const result = await authClient.twoFactor.verifyTotp({
        code: verifyCode,
      });
      if (result.error) {
        console.error("[settings.security.twoFactor.verifyTotp]", result.error);
        failCode(result.error);
        return;
      }
      toast.success(t("settings:security.enabledSuccess"));
      window.location.reload();
    } catch (err) {
      console.error("[settings.security.twoFactor.verifyTotp]", err);
      failCode(err);
    } finally {
      setIsLoading(false);
    }
  };

  if (step === "idle") {
    return (
      <Button className="min-h-[44px]" onClick={() => setStep("password")}>
        {t("settings:security.enable2FA")}
      </Button>
    );
  }

  if (step === "password") {
    return (
      <div className="space-y-4 max-w-sm">
        <p className="text-sm text-muted-foreground">
          {t("settings:security.confirmPasswordPrompt")}
        </p>
        <InlineInputField
          id="confirm-password"
          label={t("auth:fields.password")}
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
        <div className="flex gap-2">
          <Button className="min-h-[44px]" onClick={handleEnable} disabled={isLoading}>
            {isLoading ? t("auth:twoFactor.settingUp") : t("auth:twoFactor.continue")}
          </Button>
          <Button className="min-h-[44px]" variant="ghost" onClick={() => setStep("idle")}>
            {t("common:actions.cancel")}
          </Button>
        </div>
      </div>
    );
  }

  if (step === "setup") {
    return (
      <div className="space-y-4 max-w-sm">
        <TwoFactorSetupDetails
          backupCodes={backupCodes}
          backupCodesLabel={t("settings:security.saveBackupCodes")}
          manualPrompt={t("settings:security.addKeyToApp")}
          qrPrompt={t("settings:security.scanQrPrompt")}
          totpURI={totpURI}
        />

        <Button className="min-h-[44px]" onClick={() => setStep("verify")}>
          {t("settings:security.savedBackupCodes")}
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4 max-w-sm">
      <p className="text-sm text-muted-foreground">{t("settings:security.verifyPrompt")}</p>
      <InlineInputField
        id="setup-verify-code"
        label={t("auth:fields.verificationCode")}
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
        className="min-h-[44px]"
        onClick={handleVerify}
        disabled={verifyCode.length !== 6 || isLoading}
      >
        {isLoading ? t("auth:twoFactor.verifying") : t("settings:security.verifyAndEnable")}
      </Button>
    </div>
  );
}

function Disable2FASection() {
  const [showConfirm, setShowConfirm] = useState(false);
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const { t } = useTranslation(["settings", "auth", "common"]);

  const handleDisable = async () => {
    setIsLoading(true);
    setPasswordError(null);
    try {
      const result = await authClient.twoFactor.disable({
        password,
      });
      if (result.error) {
        console.error("[settings.security.twoFactor.disable]", result.error);
        setPasswordError(
          twoFactorPasswordError(result.error, t, "settings:security.couldNotDisable"),
        );
        passwordRef.current?.focus();
        return;
      }
      toast.success(t("settings:security.disabledSuccess"));
      window.location.reload();
    } catch (err) {
      console.error("[settings.security.twoFactor.disable]", err);
      setPasswordError(twoFactorPasswordError(err, t, "settings:security.couldNotDisable"));
      passwordRef.current?.focus();
    } finally {
      setIsLoading(false);
    }
  };

  if (!showConfirm) {
    return (
      <Button className="min-h-[44px]" variant="outline" onClick={() => setShowConfirm(true)}>
        {t("settings:security.disable2FA")}
      </Button>
    );
  }

  return (
    <div className="space-y-4 max-w-sm">
      <p className="text-sm text-muted-foreground">{t("settings:security.disablePrompt")}</p>
      <InlineInputField
        id="disable-password"
        label={t("auth:fields.password")}
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
          if (e.key === "Enter") handleDisable();
        }}
      />
      <div className="flex gap-2">
        <Button
          className="min-h-[44px]"
          variant="destructive"
          onClick={handleDisable}
          disabled={!password || isLoading}
        >
          {isLoading ? t("settings:security.disabling") : t("settings:security.disable")}
        </Button>
        <Button className="min-h-[44px]" variant="ghost" onClick={() => setShowConfirm(false)}>
          {t("common:actions.cancel")}
        </Button>
      </div>
    </div>
  );
}
