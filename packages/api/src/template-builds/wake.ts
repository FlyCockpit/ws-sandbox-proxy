/**
 * Post-commit wakes of the build orchestrator (
 * cancel, capture finalization, staged context changes, operation results).
 * A wake carries no data and no authority; a missed wake only delays the
 * work to the next 15 s sweep. Bound by the server that runs the tick.
 */
import { wakeOperationWatchers } from "../sandbox/operation-waiters";

let listener: (() => void) | null = null;

/** The long-poll key of one build's progress (`GET /v1/template-builds/{id}?waitMs`). */
export function templateBuildWatchKey(buildId: string): string {
  return `template-build:${buildId}`;
}

/** Post-commit: answer held reads of this build (no data, no authority). */
export function notifyTemplateBuildProgress(buildId: string): void {
  try {
    wakeOperationWatchers([templateBuildWatchKey(buildId)]);
  } catch {
    // Held reads re-read on their recheck timer.
  }
}

export function bindTemplateBuildWake(next: (() => void) | null): void {
  listener = next;
}

export function notifyTemplateBuildsChanged(): void {
  try {
    listener?.();
  } catch {
    // The change is durable; the sweep picks it up.
  }
}
