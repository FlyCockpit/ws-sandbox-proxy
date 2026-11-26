import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";

import { GettingStarted, type GettingStartedStep } from "@/components/home/getting-started";
import { useGettingStartedHidden } from "@/hooks/use-getting-started-hidden";
import { hostConnectionState, hostGuardState } from "@/lib/host-status";
import { orpc } from "@/utils/orpc";

/** Hosts read for the first step: enough for a personal fleet, still bounded. */
const HOSTS_CHECKED = 20;
const HOSTS_REFETCH_MS = 15_000;

/**
 * Sandboxes' getting-started checklist (the generic `GettingStarted`): the
 * three steps to a first sandbox, above the list whatever the status filter
 * shows, until they are done or the user hides it. Every done state comes
 * from one bounded owner-scoped read:
 *
 * 1. Somewhere to run: a connected host with a healthy egress guard, or a
 *    usable shared pool (a user who only joined someone else's pool is not
 *    told to enroll a host). An enrolled host that cannot take sandboxes is
 *    not a finished step: the step points at Hosts instead.
 * 2. A template (`listTemplates({ status: "active" })`).
 * 3. A sandbox, ever: `hasSandboxRows` (the list on screen has rows) or
 *    `sandboxes.list({ status: "all", limit: 1 })`, which counts deleted ones.
 *
 * The first sandbox proves the path worked, so once one exists the checklist
 * is done for good, and an established user's home pays for no step reads:
 * the first two are asked only while no sandbox exists. That also keeps a
 * host blipping offline later from bringing the checklist back.
 *
 * A positive answer survives filter changes: once the list shows a row, a
 * cached "none" from the "any sandbox?" read is dropped, so switching to an
 * empty filter (Deleted) asks again (rendering nothing meanwhile) instead of
 * bringing the checklist and its host polling back from the stale answer.
 *
 * `hasSandboxRows` is `undefined` while the page's list is loading; nothing
 * renders (and nothing is read) until it and every step read have answered,
 * so the checklist mounts once, already right. A failed step read counts as
 * "not done yet" (the step's link still works); a failed "any sandbox?" read
 * shows nothing.
 */
export function OnboardingChecklist({
  lang,
  scope,
  hasSandboxRows,
}: {
  lang: string;
  /** The user id: whose "hidden" flag this is. */
  scope: string;
  hasSandboxRows: boolean | undefined;
}) {
  const { t } = useTranslation("sandboxes");
  const hidden = useGettingStartedHidden(scope);
  const queryClient = useQueryClient();
  const anySandboxOptions = orpc.sandboxes.list.queryOptions({
    input: { limit: 1, status: "all" },
  });
  const anySandbox = useQuery({
    ...anySandboxOptions,
    enabled: !hidden && hasSandboxRows === false,
    // While it says "none", keep asking at the host step's pace: the first
    // sandbox may come from the CLI while a filter (Deleted) shows no rows,
    // and the checklist must not keep offering a step that is already done.
    refetchInterval: (query) => (query.state.data?.items.length === 0 ? HOSTS_REFETCH_MS : false),
    meta: { skipGlobalErrorToast: true },
  });
  const anySandboxKey = anySandboxOptions.queryKey;
  const cachedNone = anySandbox.data?.items.length === 0;
  // effect:audited — syncs the query cache with rows the list just rendered (an external store), no state set here.
  useEffect(() => {
    // Rows on screen disprove a cached "none": drop it (the query is disabled
    // right now, so this does not fetch; the next enabled render re-asks).
    if (hasSandboxRows === true && cachedNone)
      void queryClient.resetQueries({ queryKey: anySandboxKey, exact: true });
  }, [hasSandboxRows, cachedNone, queryClient, anySandboxKey]);
  const sandboxExists =
    hasSandboxRows === true || (anySandbox.data ? anySandbox.data.items.length > 0 : undefined);
  // Unknown (a failed read) is not "none": an established user must not get
  // the checklist back from a transient error.
  const firstRun = !hidden && sandboxExists === false;
  const hosts = useQuery({
    ...orpc.sandboxHosts.listHosts.queryOptions({ input: { limit: HOSTS_CHECKED } }),
    enabled: firstRun,
    // Connection state depends on a fresh heartbeat: never judge from a cached
    // page, and follow the host while the checklist is shown (as Hosts does).
    refetchOnMount: "always",
    refetchInterval: firstRun ? HOSTS_REFETCH_MS : false,
    meta: { skipGlobalErrorToast: true },
  });
  const pools = useQuery({
    ...orpc.sandboxPools.listUsable.queryOptions({ input: { limit: 1 } }),
    enabled: firstRun,
    meta: { skipGlobalErrorToast: true },
  });
  const templates = useQuery({
    ...orpc.sandboxTemplates.listTemplates.queryOptions({
      input: { limit: 1, status: "active" },
    }),
    enabled: firstRun,
    meta: { skipGlobalErrorToast: true },
  });

  if (!firstRun || hosts.isPending || pools.isPending || templates.isPending) return null;

  const now = Date.now();
  const hostItems = hosts.data?.items ?? [];
  const readyHost = hostItems.some(
    (host) => hostConnectionState(host, now) === "ready" && hostGuardState(host) === "running",
  );
  const hasPlace = readyHost || (pools.data?.items.length ?? 0) > 0;
  // Enrolled but not usable yet: point at the host, not at enrolling another.
  const hostNotReady = !hasPlace && hostItems.length > 0;
  const hasTemplate = (templates.data?.items.length ?? 0) > 0;
  const ready = hasPlace && hasTemplate;

  const steps: GettingStartedStep[] = [
    {
      id: "host",
      title: t("onboarding.host.title"),
      description: t(hostNotReady ? "onboarding.host.notReady" : "onboarding.host.description"),
      done: hasPlace,
      actions: [
        {
          label: t(hostNotReady ? "onboarding.host.openHosts" : "onboarding.host.action"),
          link: { to: "/$lang/settings/hosts", params: { lang } },
        },
        {
          label: t("onboarding.host.poolsAction"),
          link: { to: "/$lang/settings/pools", params: { lang }, search: { tab: "shared" } },
        },
      ],
    },
    {
      id: "template",
      title: t("onboarding.template.title"),
      description: t("onboarding.template.description"),
      done: hasTemplate,
      actions: [
        {
          label: t("onboarding.template.action"),
          link: { to: "/$lang/dashboard/templates", params: { lang } },
        },
      ],
    },
    {
      id: "sandbox",
      title: t("onboarding.sandbox.title"),
      // Waiting on an earlier step: say so instead of offering a page that
      // cannot create anything yet; the earlier step's action is the next one.
      description: t(ready ? "onboarding.sandbox.description" : "onboarding.sandbox.waiting"),
      done: false,
      actions: ready
        ? [
            {
              label: t("onboarding.sandbox.action"),
              link: { to: "/$lang/dashboard/sandboxes/new", params: { lang } },
              primary: true,
            },
          ]
        : [],
    },
  ];

  return (
    <GettingStarted
      steps={steps}
      scope={scope}
      title={t("onboarding.title")}
      description={t("onboarding.description")}
    />
  );
}
