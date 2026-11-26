import { env } from "@wssp/env/web";
import { CopyField } from "@wssp/ui/components/copy-field";
import { useTranslation } from "react-i18next";
import { type DocPage, docsUrl } from "@/lib/docs-links";
import { shellWord } from "@/lib/host-status";

/** The example port in the forward command (the hint says to replace it). */
const EXAMPLE_PORT = 8080;

/** A link into the product guide. */
export function SandboxDocLink({ page, label }: { page: DocPage; label: string }) {
  return (
    <a
      href={docsUrl(env.VITE_DOCS_URL, page)}
      target="_blank"
      rel="noreferrer"
      data-docs-link={page}
      className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
    >
      {label}
    </a>
  );
}

/**
 * "Ports & previews" (design review #4, the minimum): the CLI port forward
 * that reaches an app in the sandbox from your computer, and, for a sandbox
 * created with preview ports, the CLI command that mints a share link. The
 * dashboard cannot share a preview itself yet, and says so plainly.
 */
export function SandboxPorts({
  sandbox,
}: {
  sandbox: { id: string; name: string; tunnelEnabled?: boolean; tunnelPorts?: number[] };
}) {
  const { t, i18n } = useTranslation(["sandboxes"]);
  const target = shellWord(sandbox.name);
  const ports = sandbox.tunnelPorts ?? [];
  return (
    <section
      aria-labelledby="sandbox-ports"
      data-sandbox-ports=""
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <h2 id="sandbox-ports" className="font-heading text-sm font-semibold">
        {t("sandboxes:ports.title")}
      </h2>
      <p className="text-sm text-muted-foreground">{t("sandboxes:ports.description")}</p>
      <div className="flex min-w-0 flex-col gap-1">
        <p className="text-sm font-medium">{t("sandboxes:ports.forwardLabel")}</p>
        <CopyField
          data-forward-command=""
          value={`wssp sandbox forward ${target} ${EXAMPLE_PORT}`}
          copyLabel={t("sandboxes:ports.copyForward")}
        />
        <p className="text-xs text-muted-foreground">{t("sandboxes:ports.forwardHint")}</p>
      </div>
      {sandbox.tunnelEnabled ? (
        <div data-tunnel-ports="" className="flex min-w-0 flex-col gap-2">
          {ports.length > 0 ? (
            <>
              <p className="text-sm">
                {t("sandboxes:ports.declared", {
                  ports: new Intl.ListFormat(i18n.language, {
                    type: "unit",
                    style: "short",
                  }).format(ports.map(String)),
                })}
              </p>
              {ports.map((port) => (
                <div key={port} className="flex min-w-0 flex-col gap-1">
                  <p className="text-xs text-muted-foreground">
                    {t("sandboxes:ports.linkLabel", { port })}
                  </p>
                  <CopyField
                    value={`wssp sandbox ports link ${sandbox.id} ${port}`}
                    copyLabel={t("sandboxes:ports.copyLink", { port })}
                  />
                </div>
              ))}
            </>
          ) : null}
        </div>
      ) : (
        <p data-no-tunnel="" className="text-sm text-muted-foreground">
          {t("sandboxes:ports.noTunnel")}
        </p>
      )}
      <p data-preview-cli-only="" className="text-sm">
        {t("sandboxes:ports.cliOnly")}
      </p>
      <div className="flex min-w-0 flex-wrap gap-x-4 text-sm">
        <SandboxDocLink page="tunnels" label={t("sandboxes:ports.guide")} />
        <SandboxDocLink page="connect" label={t("sandboxes:ports.guideCli")} />
      </div>
    </section>
  );
}
