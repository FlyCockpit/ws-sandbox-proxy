import { useQuery } from "@tanstack/react-query";
import { Button } from "@wssp/ui/components/button";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { InlineRetry } from "@/components/inline-retry";
import {
  type LifecycleDialog,
  SandboxLifecycleDialogs,
  useSandboxLifecycle,
} from "@/components/sandboxes/sandbox-lifecycle";
import type { SandboxListItem, SandboxView } from "@/components/sandboxes/sandbox-parts";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { translateText } from "@/i18n/translate-text";
import { isQueryAccessError } from "@/lib/query-access-error";
import { sandboxActions } from "@/lib/sandbox-rules";
import { sandboxDisplayOverride } from "@/lib/sandbox-status";
import { orpc } from "@/utils/orpc";

/**
 * Start or Stop beside Open on the Sandboxes list (design review #13). The
 * row offers what the detail page's header offers for the same state (Start,
 * or Restore for a stored disk, else Stop), through the same confirmation
 * dialogs and lifecycle requests. The first click reads the sandbox's full
 * view for the two facts the list does not carry (its lease limit and
 * remembered lifetime), and every later click reads it again before its
 * dialog opens; everything else, the state above all, comes from the list
 * row, which polls. Nothing here decides more than the detail page; the server
 * re-checks it all.
 */
type QuickDialog = Extract<LifecycleDialog, "startCold" | "stop">;

/** How often a loaded full view is read again while its row is on screen. */
const FULL_VIEW_REFRESH_MS = 15_000;

function quickDialog(sandbox: {
  state: SandboxListItem["state"];
  lastLifecycleOperation: SandboxListItem["lastLifecycleOperation"];
}): QuickDialog | null {
  const actions = sandboxActions(sandbox.state, sandbox.lastLifecycleOperation);
  // A start already in flight reads "Starting": Start again would only replay it.
  if (actions.has("startCold") && sandboxDisplayOverride(sandbox) === null) return "startCold";
  if (actions.has("stop")) return "stop";
  return null;
}

function quickLabel(dialog: QuickDialog, state: SandboxListItem["state"]): string {
  if (dialog === "stop") return "sandboxes:stop.action";
  return state === "OFFLOADED" ? "sandboxes:start.restoreAction" : "sandboxes:start.action";
}

function QuickButton({
  dialog,
  sandbox,
  disabled,
  onClick,
}: {
  dialog: QuickDialog;
  sandbox: SandboxListItem;
  disabled: boolean;
  onClick: () => void;
}) {
  const { t } = useTranslation(["sandboxes"]);
  return (
    <Button
      type="button"
      size="touch"
      variant="outline"
      data-quick-action={dialog}
      aria-label={translateText(t, `${quickLabel(dialog, sandbox.state)}Named`, {
        name: sandbox.name,
      })}
      disabled={disabled}
      onClick={onClick}
    >
      {t(quickLabel(dialog, sandbox.state))}
    </Button>
  );
}

export function SandboxQuickAction({ sandbox, lang }: { sandbox: SandboxListItem; lang: string }) {
  const { t } = useTranslation(["sandboxes"]);
  // The dialog of the first click, set only once a fresh read succeeded: a
  // cached view (the detail page's, say) may hold an older lease limit or
  // remembered lifetime, so it never opens a dialog on its own.
  const [first, setFirst] = useState<QuickDialog | null>(null);
  const detail = useQuery({
    ...orpc.sandboxes.getSandbox.queryOptions({ input: { id: sandbox.id } }),
    enabled: first !== null,
    staleTime: FULL_VIEW_REFRESH_MS,
    refetchInterval: first !== null ? FULL_VIEW_REFRESH_MS : false,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [detail.error]);
  // Gone or no longer ours: no controls, exactly as the detail page hides them.
  if (detail.isError && isQueryAccessError(detail.error)) return null;
  if (first !== null && detail.data)
    return (
      <LoadedQuickAction
        item={sandbox}
        sandbox={{ ...detail.data, ...sandbox }}
        lang={lang}
        first={first}
        transientError={detail.isError}
        refreshing={detail.isFetching}
        refresh={async () => {
          const next = await detail.refetch();
          return !next.isError;
        }}
      />
    );
  const dialog = quickDialog(sandbox);
  if (dialog === null) return null;
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <QuickButton
        dialog={dialog}
        sandbox={sandbox}
        disabled={detail.isFetching}
        onClick={() =>
          void detail.refetch().then((next) => {
            if (!next.isError && next.data) setFirst(dialog);
          })
        }
      />
      {detail.isError ? (
        <p role="alert" data-quick-action-problem="" className="text-xs text-destructive">
          {t("sandboxes:detail.loadFailed")}
        </p>
      ) : null}
    </div>
  );
}

/**
 * Mounted once the full view is read and kept mounted, so a retry after an
 * uncertain outcome replays the same request (the lifecycle hook's intent
 * keys live here, exactly as on the detail page). `sandbox` is the full view
 * with the polled list row laid over it.
 */
function LoadedQuickAction({
  item,
  sandbox,
  lang,
  first,
  transientError,
  refreshing,
  refresh,
}: {
  item: SandboxListItem;
  sandbox: SandboxView;
  lang: string;
  first: QuickDialog;
  transientError: boolean;
  refreshing: boolean;
  /** Reads the full view again; false when that read failed. */
  refresh: () => Promise<boolean>;
}) {
  const { t } = useTranslation(["sandboxes"]);
  const dialog = quickDialog(item);
  // Open the first dialog only if the row still offers it.
  const lifecycle = useSandboxLifecycle(sandbox, lang, dialog === first ? first : null);
  const { setOpen, problem, pending } = lifecycle;
  return (
    <div className="flex min-w-0 flex-col gap-1">
      {dialog ? (
        <QuickButton
          dialog={dialog}
          sandbox={item}
          disabled={pending || refreshing}
          // The lease limit and remembered lifetime may have changed since the
          // last read: open the dialog only on a fresh one.
          onClick={() =>
            void refresh().then((fresh) => {
              if (fresh) setOpen(dialog);
            })
          }
        />
      ) : null}
      {problem ? (
        <p role="alert" data-action-problem={problem} className="text-xs text-destructive">
          {t(`sandboxes:problem.${problem}`)}
        </p>
      ) : transientError ? (
        <div data-quick-action-problem="">
          <InlineRetry message={t("sandboxes:detail.loadFailed")} onRetry={() => void refresh()} />
        </div>
      ) : null}
      <SandboxLifecycleDialogs
        sandbox={sandbox}
        lang={lang}
        lifecycle={lifecycle}
        waiting={sandbox.state === "WAITING_FOR_CAPACITY"}
      />
    </div>
  );
}
