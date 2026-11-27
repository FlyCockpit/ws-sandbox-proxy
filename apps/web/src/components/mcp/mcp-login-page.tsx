import { Link } from "@tanstack/react-router";
import { Button } from "@wssp/ui/components/button";
import { useTranslation } from "react-i18next";
import { InlineRetry } from "@/components/inline-retry";
import { SkeletonList } from "@/components/skeleton-list";
import { useAuthSession } from "@/hooks/use-auth-session";
import { useMcpContinue } from "@/hooks/use-mcp-continue";
import { useMcpReauthenticate } from "@/hooks/use-mcp-reauthenticate";
import { parseMcpRequest } from "@/lib/mcp-oauth";
export function McpLoginPage({ lang, search }: { lang: string; search: Record<string, unknown> }) {
  return <LoginTransaction key={JSON.stringify(search)} lang={lang} search={search} />;
}
function LoginTransaction({ lang, search }: { lang: string; search: Record<string, unknown> }) {
  const { t } = useTranslation("agents");
  const { state, actions } = useAuthSession();
  const { status, proceed } = useMcpContinue();
  const reauth = useMcpReauthenticate(lang);
  const info = parseMcpRequest(search);
  if (!info.usable) return <p role="alert">{t("consent.invalid")}</p>;
  if (state.status === "pending" || status === "pending" || reauth.status === "pending")
    return <SkeletonList count={2} />;
  // The asynchronous failure is announced (InlineRetry has no live region).
  if (state.status === "error")
    return (
      <div role="alert">
        <InlineRetry
          variant="destructive"
          message={t("login.sessionCheckFailed")}
          onRetry={() => void actions.refetch()}
        />
      </div>
    );
  return (
    <section className="mx-auto my-6 flex w-[calc(100%-2rem)] min-w-0 max-w-xl flex-col gap-4 rounded-xl border p-4">
      <h1>{t("login.title")}</h1>
      {status === "failed" ? <p role="alert">{t("consent.invalid")}</p> : null}
      <p className="break-all">{t("login.description", { client: info.clientId })}</p>
      {state.status === "authenticated" ? (
        <>
          <Button size="touch" onClick={() => void proceed()}>
            {t("login.continue")}
          </Button>
          <p>{t("login.reauthHint")}</p>
          <Button size="touch" variant="outline" onClick={() => void reauth.reauthenticate()}>
            {t("login.reauthenticate")}
          </Button>
          {reauth.status === "failed" ? <p role="alert">{t("login.reauthFailed")}</p> : null}
        </>
      ) : (
        <Link
          className="inline-flex min-h-11 items-center underline"
          to="/$lang/login"
          params={{ lang }}
          search={{
            redirectTo:
              typeof window === "undefined"
                ? undefined
                : `/${lang}/mcp-login${window.location.search}`,
          }}
        >
          {t("login.signIn")}
        </Link>
      )}
    </section>
  );
}
