import { Link, type LinkProps } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { toast } from "@wssp/ui/components/sileo";
import { cn } from "@wssp/ui/lib/utils";
import { ChevronRight, Circle, CircleCheck } from "lucide-react";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { useGettingStartedHidden } from "@/hooks/use-getting-started-hidden";
import {
  defaultGettingStartedExpanded,
  gettingStartedProgress,
  hideGettingStarted,
} from "@/lib/getting-started";

/**
 * What a step's button does: go somewhere. `primary` fills it (the one step
 * the checklist leads to); the rest are outlined.
 */
type GettingStartedAction = { label: string; link: LinkProps; primary?: boolean };

export type GettingStartedStep = {
  id: string;
  title: string;
  description?: string;
  /**
   * Detected from real data, never ticked by the user: a host is ready, a
   * template exists, a sandbox exists. The list can only say what is true.
   */
  done: boolean;
  /**
   * The next actions, shown while the step is not done. Empty when the step
   * waits on an earlier one (its description says so): the earlier step's
   * action is the next thing to do.
   */
  actions: readonly GettingStartedAction[];
};

/**
 * The getting-started checklist of the signed-in home. Generic: the caller
 * passes its steps (lib/getting-started.ts holds the logic; Sandboxes' steps
 * are in components/sandboxes/onboarding-checklist.tsx).
 * docs/design/shell-rules.md § The signed-in home.
 *
 * - "n of m done", and every open step shows its next action.
 * - Gone once every step is done, and hideable before that ("Hide", with an
 *   Undo toast). The hidden flag is per user (`scope` = the user id).
 * - A disclosure (`aria-expanded`): collapsed below `sm` to the title and the
 *   progress, so on a phone the main list stays on screen; expanded from
 *   `sm` up.
 *
 * Render it only once the data behind the steps has loaded: it has no
 * skeleton, so mounting it with guesses would show wrong ticks and then move
 * the page.
 */
export function GettingStarted({
  steps,
  scope,
  title,
  description,
}: {
  steps: readonly GettingStartedStep[];
  /** Whose checklist this is (the user id): the key of the hidden flag. */
  scope: string;
  /** Defaults to "Get started". */
  title?: string;
  /** One line under the title, shown while expanded. */
  description?: string;
}) {
  const { t } = useTranslation("common");
  const hidden = useGettingStartedHidden(scope);
  const [expanded, setExpanded] = useState(defaultGettingStartedExpanded);
  const listId = useId();
  const progress = gettingStartedProgress(steps);

  if (hidden || progress.allDone) return null;

  const heading = title ?? t("gettingStarted.title");
  const hide = () =>
    hideGettingStarted(scope, (undo) => {
      toast.message(t("gettingStarted.hidden"), {
        action: { label: t("gettingStarted.undo"), onClick: undo },
      });
    });

  return (
    <section
      data-getting-started=""
      aria-label={heading}
      className="min-w-0 rounded-xl border bg-card text-sm text-card-foreground"
    >
      <div className="flex min-w-0 items-center gap-2 px-2 py-1">
        {/* The accordion pattern: the heading holds the disclosure button. */}
        <h2 className="min-w-0 flex-1">
          <button
            type="button"
            aria-expanded={expanded}
            aria-controls={listId}
            onClick={() => setExpanded((open) => !open)}
            className="flex min-h-11 w-full min-w-0 items-center gap-2 rounded-md px-2 py-1 text-left outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <ChevronRight
              aria-hidden="true"
              className={cn(
                "size-4 shrink-0 text-muted-foreground motion-safe:transition-transform",
                expanded && "rotate-90",
              )}
            />
            <span className="min-w-0">
              <span className="block truncate text-base font-medium">{heading}</span>
              <span className="block text-xs text-muted-foreground">
                {t("gettingStarted.progress", { done: progress.done, total: progress.total })}
              </span>
            </span>
          </button>
        </h2>
        <Button
          type="button"
          variant="ghost"
          size="touch"
          className="shrink-0"
          aria-label={t("gettingStarted.hideAriaLabel")}
          onClick={hide}
        >
          {t("gettingStarted.hide")}
        </Button>
      </div>
      <div aria-hidden="true" className="mx-4 mb-3 h-1 overflow-hidden rounded-full bg-muted">
        <div
          className="h-full rounded-full bg-primary"
          style={{ width: `${(progress.done / Math.max(progress.total, 1)) * 100}%` }}
        />
      </div>
      <div id={listId} hidden={!expanded} className="border-t">
        {description ? (
          <p className="px-4 pt-3 text-xs text-muted-foreground">{description}</p>
        ) : null}
        <ol className="divide-y">
          {steps.map((step) => (
            <li
              key={step.id}
              data-step={step.id}
              data-done={step.done ? "" : undefined}
              className="flex min-w-0 flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center"
            >
              <div className="flex min-w-0 flex-1 gap-3">
                {step.done ? (
                  <CircleCheck
                    aria-hidden="true"
                    className="mt-0.5 size-4 shrink-0 text-state-success"
                  />
                ) : (
                  <Circle
                    aria-hidden="true"
                    className="mt-0.5 size-4 shrink-0 text-muted-foreground"
                  />
                )}
                <div className="min-w-0">
                  <p className={cn("font-medium", step.done && "text-muted-foreground")}>
                    {step.title}
                    <span className="sr-only">
                      {" "}
                      ({step.done ? t("gettingStarted.stepDone") : t("gettingStarted.stepToDo")})
                    </span>
                  </p>
                  {step.description && !step.done ? (
                    <p className="mt-0.5 text-xs text-muted-foreground">{step.description}</p>
                  ) : null}
                </div>
              </div>
              {step.done ? (
                <span aria-hidden="true" className="text-xs text-muted-foreground sm:shrink-0">
                  {t("gettingStarted.stepDone")}
                </span>
              ) : step.actions.length > 0 ? (
                <div className="flex flex-wrap gap-2 sm:shrink-0">
                  {step.actions.map((action) => (
                    <Link
                      key={action.label}
                      {...action.link}
                      className={buttonVariants({
                        variant: action.primary ? "default" : "outline",
                        size: "touch",
                      })}
                    >
                      {action.label}
                    </Link>
                  ))}
                </div>
              ) : null}
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
