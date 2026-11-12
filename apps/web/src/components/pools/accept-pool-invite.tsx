import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@wssp/ui/components/button";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuthSession } from "@/hooks/use-auth-session";
import { clearPoolInviteToken, poolInviteToken } from "@/lib/pool-invite";
import { orpc } from "@/utils/orpc";
import { SharingNotice } from "./pool-sharing";
export function AcceptPoolInvite() {
  const { t } = useTranslation("hosts");
  const session = useAuthSession();
  const client = useQueryClient();
  const [mode, setMode] = useState<"bearer" | "email">("email");
  const [status, setStatus] = useState<"idle" | "pending" | "done" | "failed">("idle");
  const [failure, setFailure] = useState("failed");
  const token = poolInviteToken();
  const identity = session.state.status === "authenticated" ? session.state.session.user.email : "";
  return (
    <section className="flex min-w-0 flex-col gap-4">
      <h1>{t("hosts:sharing.accept")}</h1>
      <p>{t("hosts:sharing.acceptingAs", { email: identity })}</p>
      <SharingNotice />
      <p>{t("hosts:sharing.forwarding")}</p>
      <p>{t("hosts:sharing.reopen")}</p>
      {status === "done" ? (
        <p role="status">{t("hosts:sharing.accepted")}</p>
      ) : (
        <>
          <fieldset>
            <legend>{t("hosts:sharing.acceptMode")}</legend>
            {(["email", "bearer"] as const).map((value) => (
              <label key={value} className="flex min-h-11 items-center gap-3">
                <input
                  type="radio"
                  name="acceptMode"
                  autoComplete="off"
                  checked={mode === value}
                  onChange={() => setMode(value)}
                />
                {t(`hosts:sharing.${value === "email" ? "emailMode" : value}`)}
              </label>
            ))}
          </fieldset>
          <Button
            size="touch"
            disabled={!token || !identity || status === "pending"}
            onClick={async () => {
              if (!token) return;
              setStatus("pending");
              try {
                await orpc.sandboxPools.acceptInvite.call({ token, mode });
                clearPoolInviteToken();
                setStatus("done");
                await client.invalidateQueries({ queryKey: orpc.sandboxPools.key() });
              } catch (error) {
                const code =
                  error && typeof error === "object" && "code" in error ? error.code : null;
                setFailure(
                  code === "TOO_MANY_REQUESTS"
                    ? "acceptRateLimited"
                    : code === "UNAUTHORIZED"
                      ? "acceptSignedOut"
                      : code === "FORBIDDEN"
                        ? "acceptForbidden"
                        : code === "NOT_FOUND"
                          ? "acceptUnavailable"
                          : code === "CONFLICT"
                            ? "acceptConflict"
                            : "failed",
                );
                setStatus("failed");
              }
            }}
          >
            {t("hosts:sharing.accept")}
          </Button>
          {status === "failed" ? <p role="alert">{t(`hosts:sharing.${failure}`)}</p> : null}
        </>
      )}
    </section>
  );
}
