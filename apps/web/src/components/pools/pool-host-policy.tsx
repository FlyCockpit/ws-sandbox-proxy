import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { env } from "@wssp/env/web";
import { CodeSnippet } from "@wssp/ui/components/code-snippet";
import { useTranslation } from "react-i18next";
import { InlineRetry } from "@/components/inline-retry";
import { docsUrl } from "@/lib/docs-links";
import { orpc } from "@/utils/orpc";

/**
 * What a pool's hosts allow other accounts (their node-local settings, as the
 * daemons last reported them) and the next step in every state. The pool
 * owner reads it in the share sheet; a person the pool is shared with reads it
 * on the pool card and the create page. The server stays the authority: this
 * only explains, it never changes or gates placement.
 */
export type PoolHostPolicy = Awaited<ReturnType<AppRouterClient["sandboxPools"]["hostPolicy"]>>;
type Capability = "images" | "builds" | "openEgress" | "guestSudo";
const CAPABILITIES: readonly Capability[] = ["images", "builds", "openEgress", "guestSudo"];

/** The host-side commands, run by the host's owner at the host (never by the server). */
export const ACCEPT_FOREIGN_BUILDS_COMMAND = "wssp host config set-accept-foreign-builds on";
const STEP_COMMANDS: Record<Exclude<Capability, "images">, string> = {
  builds: ACCEPT_FOREIGN_BUILDS_COMMAND,
  openEgress: "wssp host config set-open-egress-for-others on",
  guestSudo: "wssp host config set-allow-guest-sudo-for-others on",
};

export function usePoolHostPolicy(poolId: string) {
  return useQuery({
    ...orpc.sandboxPools.hostPolicy.queryOptions({ input: { id: poolId } }),
    enabled: poolId !== "",
    staleTime: 30_000,
    meta: { skipGlobalErrorToast: true },
  });
}

/**
 * The capabilities whose host-side step is worth naming: a member is told
 * only what blocks running its own work (images, builds); the owner, who
 * decides, sees every restricted setting.
 */
function restricted(policy: PoolHostPolicy): Capability[] {
  const named: readonly Capability[] =
    policy.viewer === "owner" ? CAPABILITIES : ["images", "builds"];
  return named.filter((capability) => policy[capability] !== "all");
}

export function PoolHostPolicyNotice({
  poolId,
  lang,
  ownerName,
}: {
  poolId: string;
  lang: string;
  /** A shared pool's owner, named in a member's next step. */
  ownerName?: string;
}) {
  const { t } = useTranslation("hosts");
  const query = usePoolHostPolicy(poolId);
  if (query.isPending)
    return (
      <p role="status" className="text-sm text-muted-foreground" data-pool-host-policy="loading">
        {t("hosts:hostPolicy.loading")}
      </p>
    );
  if (query.isError)
    return (
      <InlineRetry message={t("hosts:hostPolicy.failed")} onRetry={() => void query.refetch()} />
    );
  return (
    <PoolHostPolicyView
      policy={query.data}
      lang={lang}
      ownerName={ownerName || t("hosts:hostPolicy.theOwner")}
    />
  );
}

/** Pure view of one policy read; exported for its tests. */
export function PoolHostPolicyView({
  policy,
  lang,
  ownerName,
}: {
  policy: PoolHostPolicy;
  lang: string;
  ownerName: string;
}) {
  const { t } = useTranslation("hosts");
  const owner = policy.viewer === "owner";
  const blocked = policy.images === "none" || policy.builds === "none";
  const steps = restricted(policy);
  return (
    <section
      data-pool-host-policy={policy.viewer}
      aria-label={t(owner ? "hosts:hostPolicy.titleOwner" : "hosts:hostPolicy.titleMember")}
      className={
        blocked && policy.ownHosts === 0
          ? "flex min-w-0 flex-col gap-2 rounded-md border border-amber-600/40 bg-amber-600/10 p-3 text-sm text-amber-900 dark:text-amber-200"
          : "flex min-w-0 flex-col gap-2 rounded-md border p-3 text-sm"
      }
    >
      <h3 className="font-medium">
        {t(owner ? "hosts:hostPolicy.titleOwner" : "hosts:hostPolicy.titleMember")}
      </h3>
      {policy.hosts === 0 && (owner || policy.ownHosts === 0) ? (
        <p data-host-policy-state="no-hosts">
          {t(owner ? "hosts:hostPolicy.noHostsOwner" : "hosts:hostPolicy.noHostsMember", {
            owner: ownerName,
          })}
        </p>
      ) : (
        <>
          {policy.hosts > 0 ? (
            <ul className="flex min-w-0 list-disc flex-col gap-1 pl-5">
              {CAPABILITIES.map((capability) => (
                <li key={capability} data-host-policy={capability} data-level={policy[capability]}>
                  {t(`hosts:hostPolicy.${policy.viewer}.${capability}.${policy[capability]}`)}
                </li>
              ))}
            </ul>
          ) : null}
          {!owner && policy.ownHosts > 0 ? (
            <p data-host-policy-own="">
              {t("hosts:hostPolicy.ownHosts", { count: policy.ownHosts })}
            </p>
          ) : null}
          {/* Work can run somewhere: say what to do next; what is refused
              gets its host-side step as well. */}
          {policy.images !== "none" || policy.ownHosts > 0 ? <ReadyStep owner={owner} /> : null}
          {policy.hosts > 0 && steps.length > 0 ? (
            <HostSteps steps={steps} owner={owner} ownerName={ownerName} />
          ) : null}
          {!owner &&
          policy.allowForeignBuilds === false &&
          policy.builds !== "none" &&
          policy.hosts > 0 ? (
            <div
              data-host-policy-foreign-builds-off=""
              className="flex min-w-0 flex-col items-start"
            >
              <p>{t("hosts:hostPolicy.foreignBuildsOff")}</p>
              <Link
                to="/$lang/settings/images"
                params={{ lang }}
                className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
              >
                {t("hosts:hostPolicy.openImageSettings")}
              </Link>
            </div>
          ) : null}
        </>
      )}
      <a
        href={docsUrl(env.VITE_DOCS_URL, "poolHostPolicy")}
        target="_blank"
        rel="noreferrer"
        data-docs-link="poolHostPolicy"
        className="inline-flex min-h-11 items-center self-start font-medium underline underline-offset-4"
      >
        {t("hosts:hostPolicy.guide")}
      </a>
    </section>
  );
}

function HostSteps({
  steps,
  owner,
  ownerName,
}: {
  steps: Capability[];
  owner: boolean;
  ownerName: string;
}) {
  const { t } = useTranslation("hosts");
  const restart = steps.includes("images") || steps.includes("builds");
  return (
    <div data-host-policy-steps="" className="flex min-w-0 flex-col gap-2">
      <p>
        {t(owner ? "hosts:hostPolicy.nextOwner" : "hosts:hostPolicy.nextMember", {
          owner: ownerName,
        })}
      </p>
      {steps.map((step) =>
        step === "images" ? (
          <p key={step} data-host-policy-step={step}>
            {t("hosts:hostPolicy.imagesStep")}
          </p>
        ) : (
          <div key={step} data-host-policy-step={step} className="flex min-w-0 flex-col gap-1">
            <p>{t(`hosts:hostPolicy.${step}Step`)}</p>
            <CodeSnippet
              code={STEP_COMMANDS[step]}
              copyLabel={t("hosts:hostPolicy.copyCommand")}
              wrap
            />
          </div>
        ),
      )}
      {restart ? <p>{t("hosts:hostPolicy.restartStep")}</p> : null}
    </div>
  );
}

/** The Shared tab and the create page already link to Templates; this only says what's next. */
function ReadyStep({ owner }: { owner: boolean }) {
  const { t } = useTranslation("hosts");
  return (
    <p data-host-policy-state="ready">
      {t(owner ? "hosts:hostPolicy.readyOwner" : "hosts:hostPolicy.readyMember")}
    </p>
  );
}
