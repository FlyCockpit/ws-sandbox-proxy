import { useQuery } from "@tanstack/react-query";
import { Checkbox } from "@wssp/ui/components/checkbox";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { CredentialGrantEditor } from "@/components/credentials/sdk-keys-page";
import { SkeletonList } from "@/components/skeleton-list";
import { useMcpSubmit } from "@/hooks/use-mcp-submit";
import { authClient } from "@/lib/auth-client";
import { parseMcpRequest } from "@/lib/mcp-oauth";

export function McpConsentPage({
  lang,
  search,
}: {
  lang: string;
  search: Record<string, unknown>;
}) {
  // A new transaction discards selection and pending navigation authority.
  return <ConsentTransaction key={JSON.stringify(search)} lang={lang} search={search} />;
}
function ConsentTransaction({ lang, search }: { lang: string; search: Record<string, unknown> }) {
  const { t } = useTranslation("agents");
  const info = parseMcpRequest(search);
  const [offline, setOffline] = useState(info.scopes.includes("offline_access"));
  const { phase, submit } = useMcpSubmit();
  const client = useQuery({
    queryKey: ["mcp-client", JSON.stringify(search)],
    enabled: info.usable,
    retry: false,
    meta: { skipGlobalErrorToast: true },
    gcTime: 0,
    queryFn: async () => {
      const result = await authClient.oauth2.publicClient({ query: { client_id: info.clientId } });
      if (result.error) throw result.error;
      return result.data;
    },
  });
  if (!info.usable || client.isError || phase === "failed")
    return <p role="alert">{t("consent.invalid")}</p>;
  if (client.isPending || phase === "pending") return <SkeletonList count={3} />;
  if (phase === "denied") return <p role="status">{t("consent.denied")}</p>;
  const name = client.data?.client_name || info.clientId;
  let destination = "";
  try {
    if (typeof search.redirect_uri === "string") destination = new URL(search.redirect_uri).host;
  } catch {
    /* Invalid transactions are refused by the server. */
  }
  return (
    <section className="mx-auto my-6 flex w-[calc(100%-2rem)] min-w-0 max-w-xl flex-col gap-4 rounded-xl border p-4">
      <h1 className="text-xl font-semibold">{t("consent.title")}</h1>
      <p className="break-words">{t("consent.description", { client: name })}</p>
      <p className="break-all font-mono">{info.clientId}</p>
      {destination ? (
        <p className="break-all">{t("consent.destination", { host: destination })}</p>
      ) : null}
      <p>{t("consent.subset")}</p>
      <p
        role="note"
        className="rounded-lg border border-amber-500/50 p-3 text-sm text-amber-800 dark:text-amber-300"
      >
        {t("consent.hostWarning")}
      </p>
      {info.scopes.includes("offline_access") ? (
        <label className="flex min-h-11 items-center gap-3">
          <Checkbox checked={offline} onCheckedChange={(checked) => setOffline(checked === true)} />
          {t("consent.offline")}
        </label>
      ) : null}
      <CredentialGrantEditor
        lang={lang}
        mode="consent"
        requestedScopes={info.serviceScopes}
        consentName={name.slice(0, 120)}
        onClose={() => void submit(false)}
        onConsent={(input) => submit(true, input, offline)}
      />
    </section>
  );
}
