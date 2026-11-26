import { Link } from "@tanstack/react-router";
import { env } from "@wssp/env/web";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { CodeSnippet } from "@wssp/ui/components/code-snippet";
import { CopyField } from "@wssp/ui/components/copy-field";
import { Input } from "@wssp/ui/components/input";
import { Label } from "@wssp/ui/components/label";
import { cn } from "@wssp/ui/lib/utils";
import { CheckCircle2, ExternalLink, Loader2 } from "lucide-react";
import { type ReactNode, useId, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { AdvancedDetails } from "@/components/advanced-details";
import { PageHeader } from "@/components/page-shell";
import { useHostEnrolmentWatch } from "@/hooks/use-host-enrolment-watch";
import { type DocPage, docsRepoPath, docsUrl } from "@/lib/docs-links";
import { GUARD_INSTALL_COMMAND, hostCommands } from "@/lib/host-status";
import { HostsBackLink } from "./hosts-back-link";

/** A host slug as the CLI accepts it: lowercase letters, digits and dashes. */
export function hostSlugFromName(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63)
    .replace(/-+$/g, "");
  return slug || "my-host";
}

/** Add host: a page of its own, so the steps, the commands and the live status fit. */
export function AddHostPage({ lang }: { lang: string }) {
  const { t } = useTranslation("hosts");
  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        back={<HostsBackLink lang={lang} />}
        title={t("enroll.pageTitle")}
        description={t("enroll.description")}
      />
      <EnrollHost lang={lang} />
    </div>
  );
}

/**
 * Enrolling a machine, in the order a new node owner does it: install, enroll
 * with a device code (approved on the link the CLI prints), install the
 * root-owned egress guard (without it the host connects but takes no
 * sandboxes), then start the daemon. Beside the steps a live row says when
 * the new host shows up and connects, and what to do next.
 */
export function EnrollHost({ lang }: { lang: string }) {
  const { t } = useTranslation("hosts");
  const nameId = useId();
  const [name, setName] = useState("");
  const slug = hostSlugFromName(name);
  const commands = hostCommands(env.VITE_SERVER_URL, { id: "", slug });
  return (
    <div
      data-host-enroll=""
      className="grid min-w-0 gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)] lg:items-start"
    >
      <div className="flex min-w-0 flex-col gap-6">
        <ol className="flex min-w-0 flex-col gap-6 text-sm">
          <Step n={1} id="install" title={t("enroll.stepTitles.install")}>
            <p className="text-muted-foreground">{t("enroll.steps.install")}</p>
            <Command value={commands.install} />
            <GuideLink page="hostsQuickStart" label={t("enroll.guideLink")} />
          </Step>
          <Step n={2} id="enroll" title={t("enroll.stepTitles.enroll")}>
            <div className="flex min-w-0 flex-col gap-2">
              <Label htmlFor={nameId}>{t("enroll.nameLabel")}</Label>
              <Input
                id={nameId}
                value={name}
                placeholder={t("enroll.namePlaceholder")}
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                maxLength={63}
                className="min-h-11 sm:max-w-xs"
                aria-describedby={`${nameId}-hint`}
                onChange={(event) => setName(event.target.value)}
              />
              <p id={`${nameId}-hint`} className="text-xs text-muted-foreground">
                {t("enroll.nameHint")}
              </p>
            </div>
            <p className="text-muted-foreground">{t("enroll.steps.enroll")}</p>
            <Command value={commands.deviceLogin} />
          </Step>
          <Step n={3} id="guard" title={t("enroll.stepTitles.guard")}>
            <p className="text-muted-foreground">{t("enroll.steps.guard")}</p>
            <Command value={GUARD_INSTALL_COMMAND} />
          </Step>
          <Step n={4} id="run" title={t("enroll.stepTitles.run")}>
            <p className="text-muted-foreground">{t("enroll.steps.run")}</p>
            <Command value={commands.connect} />
            <GuideLink page="hostsService" label={t("enroll.serviceLink")} />
          </Step>
        </ol>
        <AdvancedDetails summary={t("enroll.advanced")}>
          <p className="text-sm text-muted-foreground">
            <Trans
              t={t}
              i18nKey="connect.caHint"
              shouldUnescape
              components={{ code: <code className="whitespace-nowrap" /> }}
            />
          </p>
          <p className="text-sm text-muted-foreground">
            <Trans
              t={t}
              i18nKey="connect.vmCapacityHint"
              components={{ code: <code className="whitespace-nowrap" /> }}
            />
          </p>
        </AdvancedDetails>
      </div>
      <EnrolmentStatus lang={lang} />
    </div>
  );
}

function Step({
  n,
  id,
  title,
  children,
}: {
  n: number;
  id: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <li data-enroll-step={id} className="flex min-w-0 gap-3">
      <span
        aria-hidden="true"
        className="flex size-7 shrink-0 items-center justify-center rounded-full border bg-muted text-xs font-semibold tabular-nums"
      >
        {n}
      </span>
      <div className="flex min-w-0 flex-1 flex-col gap-2">
        <h2 className="pt-1 text-sm font-medium">{title}</h2>
        {children}
      </div>
    </li>
  );
}

function Command({ value }: { value: string }) {
  const { t } = useTranslation("hosts");
  return (
    <CodeSnippet data-enroll-command="" code={value} copyLabel={t("enroll.copyCommand")} wrap />
  );
}

/** A link into the host guide, or its copyable repository path when no docs base is configured. */
function GuideLink({ page, label }: { page: DocPage; label: string }) {
  const { t } = useTranslation("hosts");
  const href = docsUrl(env.VITE_DOCS_URL, page);
  return href ? (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      data-docs-link=""
      className="inline-flex min-h-11 items-center gap-1 self-start font-medium underline underline-offset-4"
    >
      {label}
      <ExternalLink aria-hidden="true" className="size-3.5" />
    </a>
  ) : (
    <div data-docs-path="" className="flex min-w-0 flex-col gap-1">
      <span className="text-xs text-muted-foreground">{t("enroll.guidePath", { label })}</span>
      <CopyField value={docsRepoPath(page)} copyLabel={t("enroll.copyGuidePath")} />
    </div>
  );
}

/** The live "Waiting for your host… → Connected" row, with the next step after it connects. */
function EnrolmentStatus({ lang }: { lang: string }) {
  const { t } = useTranslation("hosts");
  const watch = useHostEnrolmentWatch();
  const connected = watch.phase === "connected";
  const failed = watch.phase === "failed";
  const expired =
    watch.phase !== "connected" && watch.phase !== "loading" && !failed && watch.expired;
  return (
    <aside
      aria-labelledby="enroll-status-title"
      data-enroll-status={watch.phase}
      className={cn(
        "flex min-w-0 flex-col gap-3 rounded-xl border p-4 lg:sticky lg:top-4",
        connected ? "border-emerald-600/40 bg-emerald-600/5" : "bg-card",
      )}
    >
      <h2 id="enroll-status-title" className="text-sm font-medium">
        {t("enroll.status.title")}
      </h2>
      <div role="status" aria-live="polite" className="flex min-w-0 items-start gap-2 text-sm">
        {connected ? (
          <CheckCircle2
            aria-hidden="true"
            className="mt-0.5 size-4 shrink-0 text-emerald-700 dark:text-emerald-400"
          />
        ) : expired || failed ? null : (
          <Loader2
            aria-hidden="true"
            className="mt-0.5 size-4 shrink-0 text-muted-foreground motion-safe:animate-spin"
          />
        )}
        <p className="min-w-0 [overflow-wrap:anywhere]">
          {watch.phase === "connected"
            ? t("enroll.status.connected", { label: watch.host.label })
            : watch.phase === "enrolled"
              ? t("enroll.status.enrolled", { label: watch.host.label })
              : t(
                  failed
                    ? "enroll.status.failed"
                    : expired
                      ? "enroll.status.expired"
                      : "enroll.status.waiting",
                )}
        </p>
      </div>
      {watch.phase === "connected" ? (
        <div className="flex min-w-0 flex-wrap gap-2">
          <Link
            to="/$lang/dashboard/sandboxes/new"
            params={{ lang }}
            search={{ host: watch.host.id }}
            data-enroll-next=""
            className={cn(buttonVariants({ size: "touch" }))}
          >
            {t("enroll.status.createSandbox")}
          </Link>
          <Link
            to="/$lang/settings/hosts/$hostId"
            params={{ lang, hostId: watch.host.id }}
            className={cn(buttonVariants({ size: "touch", variant: "outline" }))}
          >
            {t("enroll.status.openHost")}
          </Link>
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">
          {t(watch.phase === "enrolled" ? "enroll.status.enrolledHint" : "enroll.status.hint")}
        </p>
      )}
      {expired || failed ? (
        <Button
          type="button"
          size="touch"
          variant="outline"
          className="self-start"
          onClick={watch.restart}
        >
          {t(failed ? "enroll.status.retry" : "enroll.status.checkAgain")}
        </Button>
      ) : null}
    </aside>
  );
}
