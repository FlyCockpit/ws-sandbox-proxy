import { VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
import {
  createTemplateInput,
  TEMPLATE_ARCHITECTURES,
  TEMPLATE_GUEST_VERSION_MAX,
  TEMPLATE_LABEL_MAX,
} from "@wssp/api/sandbox/template-input";

import {
  type HostConnectionFields,
  hostConnectionState,
  nextHostStateChangeAt,
} from "@/lib/host-status";

/**
 * Pure rules for the Templates dashboard (C46). The registration form parses
 * with the server's own `createTemplateInput`, so a draft the server would
 * refuse on shape never leaves the browser. Whether the image exists on the
 * host (and its fingerprint and architecture) is decided only by the host,
 * through the server; nothing here predicts it.
 */

export { TEMPLATE_ARCHITECTURES, TEMPLATE_GUEST_VERSION_MAX, TEMPLATE_LABEL_MAX };

export type TemplateHost = HostConnectionFields & {
  id: string;
  slug: string;
  label: string;
  draining: boolean;
};

/**
 * Why a template can or cannot start a sandbox right now. Only `usable` means
 * the template is active on a host that is connected, heartbeating and
 * admitting work; guest readiness (agent, declared user, tools) is still
 * checked by the host at every sandbox boot.
 */
export type TemplateUsability =
  | "usable"
  | "archived"
  | "hostDeleting"
  | "hostRevoked"
  | "hostDraining"
  | "hostStale"
  | "hostOffline";

export function templateUsability(
  template: { retiredAt: Date | string | null; host: TemplateHost | null },
  now: number,
): TemplateUsability {
  if (template.retiredAt != null || template.host == null) return "archived";
  const state = hostConnectionState(template.host, now);
  if (state === "deleting") return "hostDeleting";
  if (state === "revoked") return "hostRevoked";
  if (template.host.draining) return "hostDraining";
  if (state === "stale") return "hostStale";
  if (state === "ready") return "usable";
  return "hostOffline";
}

/** When the first usable template's host turns stale (so the page re-renders then). */
export function nextTemplateStateChangeAt(
  templates: readonly { host: TemplateHost | null }[],
  now: number,
): number | null {
  return nextHostStateChangeAt(
    templates.flatMap((template) => (template.host ? [template.host] : [])),
    now,
  );
}

/** Where a new template may be registered: the host must answer the image check now. */
export type RegistrationHostState = "ready" | "draining" | "unavailable";

export function registrationHostState(host: TemplateHost, now: number): RegistrationHostState {
  const state = hostConnectionState(host, now);
  if (state !== "ready") return "unavailable";
  return host.draining ? "draining" : "ready";
}

/** Hosts the form lists at all: owned and not pending deletion. */
export function registrableHosts<H extends TemplateHost>(hosts: readonly H[]): H[] {
  return hosts.filter((host) => host.deletionRequestedAt == null);
}

export type TemplateDraft = {
  poolId?: string;
  memberId?: string;
  hostId: string;
  slug: string;
  label: string;
  imageRef: string;
  envs: string;
  architecture: string;
  guestUid: string;
  guestGid: string;
  guestHome: string;
  guestShell: string;
  guestVersion: string;
  cpuCount: string;
  memoryMiB: string;
  defaultDiskGiB: string;
  /** Blank: the default is the floor. */
  minDiskGiB: string;
};

export const DEFAULT_TEMPLATE_DRAFT: TemplateDraft = {
  hostId: "",
  slug: "",
  label: "",
  imageRef: "",
  envs: "",
  architecture: "x86_64",
  guestUid: "1000",
  guestGid: "1000",
  guestHome: "/home/user",
  guestShell: "/bin/bash",
  guestVersion: "",
  cpuCount: String(VM_SIZE_LIMITS.cpuCountDefault),
  memoryMiB: String(VM_SIZE_LIMITS.memoryMiBDefault),
  defaultDiskGiB: String(VM_SIZE_LIMITS.diskGiBDefault),
  minDiskGiB: "",
};

export type TemplateDraftProblem =
  | "noHost"
  | "unknownHost"
  | "hostUnavailable"
  | "hostDraining"
  | "slug"
  | "label"
  | "imageRef"
  | "envs"
  | "architecture"
  | "guestUid"
  | "guestGid"
  | "guestHome"
  | "guestShell"
  | "guestVersion"
  | "cpuCount"
  | "memoryMiB"
  | "defaultDiskGiB"
  | "minDiskGiB";

const FIELD_PROBLEMS = [
  "slug",
  "label",
  "imageRef",
  "envs",
  "architecture",
  "guestUid",
  "guestGid",
  "guestHome",
  "guestShell",
  "guestVersion",
  "cpuCount",
  "memoryMiB",
  "defaultDiskGiB",
  "minDiskGiB",
] as const satisfies readonly TemplateDraftProblem[];

function integerOrNaN(value: string): number {
  const trimmed = value.trim();
  return /^\d{1,10}$/.test(trimmed) ? Number(trimmed) : Number.NaN;
}

function parseDefaults(text: string) {
  try {
    const parsed = createTemplateInput.shape.envs.safeParse(text.trim() ? JSON.parse(text) : {});
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}
/** The exact candidate input for `createTemplate` (before the server schema parses it). */
export function templateDraftInput(draft: TemplateDraft) {
  const guestVersion = draft.guestVersion.trim();
  return {
    ...(draft.poolId
      ? { poolId: draft.poolId, memberId: draft.memberId }
      : { hostId: draft.hostId }),
    cpuCount: integerOrNaN(draft.cpuCount),
    memoryMiB: integerOrNaN(draft.memoryMiB),
    defaultDiskGiB: integerOrNaN(draft.defaultDiskGiB),
    ...(draft.minDiskGiB.trim() ? { minDiskGiB: integerOrNaN(draft.minDiskGiB) } : {}),
    slug: draft.slug.trim(),
    label: draft.label.trim(),
    imageRef: draft.imageRef.trim(),
    envs: parseDefaults(draft.envs) ?? {},
    architecture: draft.architecture,
    guestUid: integerOrNaN(draft.guestUid),
    guestGid: integerOrNaN(draft.guestGid),
    guestHome: draft.guestHome.trim(),
    guestShell: draft.guestShell.trim(),
    ...(guestVersion ? { guestVersion } : {}),
  };
}

/**
 * Every reason the draft cannot be sent: the server schema's own verdict per
 * field, plus the chosen host's current state (a host that cannot answer the
 * image check now would only be refused).
 */
export function templateDraftProblems(
  draft: TemplateDraft,
  hosts: readonly TemplateHost[],
  now: number,
): TemplateDraftProblem[] {
  const problems = new Set<TemplateDraftProblem>();
  if (parseDefaults(draft.envs) === null) problems.add("envs");
  const host = registrableHosts(hosts).find((candidate) => candidate.id === draft.hostId);
  if (draft.poolId) {
    if (!draft.memberId) problems.add("noHost");
  } else if (!draft.hostId) problems.add("noHost");
  else if (!host) problems.add("unknownHost");
  else {
    const state = registrationHostState(host, now);
    if (state === "unavailable") problems.add("hostUnavailable");
    if (state === "draining") problems.add("hostDraining");
  }
  const input = templateDraftInput(draft);
  const parsed = createTemplateInput.safeParse(input);
  // The floor never exceeds the default (the server refuses it as a size).
  if (
    input.minDiskGiB !== undefined &&
    Number.isInteger(input.defaultDiskGiB) &&
    input.minDiskGiB > input.defaultDiskGiB
  )
    problems.add("minDiskGiB");
  if (!parsed.success) {
    for (const issue of parsed.error.issues) {
      const field = issue.path[0];
      const problem = FIELD_PROBLEMS.find((name) => name === field);
      if (problem) problems.add(problem);
    }
  }
  return [...problems];
}

export function parseTemplateDraft(draft: TemplateDraft) {
  return createTemplateInput.parse(templateDraftInput(draft));
}

type ErrorShape = { code?: unknown; status?: unknown; data?: unknown; message?: unknown };

function shapeOf(error: unknown): ErrorShape {
  return (error && typeof error === "object" ? error : {}) as ErrorShape;
}

function domainCode(error: unknown): string | null {
  const data = shapeOf(error).data;
  if (data && typeof data === "object" && "code" in data) {
    const code = (data as { code?: unknown }).code;
    return typeof code === "string" ? code : null;
  }
  return null;
}

export type TemplateProblem =
  | "imageRejected"
  | "hostUnavailable"
  | "hostDraining"
  | "hostDeleting"
  | "revisionExists"
  | "inUse"
  | "notFound"
  | "changed"
  | "invalid"
  | "forbidden"
  | "imageMissing"
  | "generic";

/**
 * Map a failed register/archive to the explanation shown next to it. Every
 * problem except `generic` and `invalid` also means the page's data is stale,
 * so the caller refetches.
 */
export function templateProblem(error: unknown): TemplateProblem {
  switch (domainCode(error)) {
    case "sandbox.template_image_missing":
      return "imageMissing";
    case "sandbox.template_image_rejected":
      return "imageRejected";
    case "sandbox.host_unavailable":
      return "hostUnavailable";
    case "sandbox.host_draining":
      return "hostDraining";
    case "sandbox.host_delete_conflict":
      return "hostDeleting";
    case "sandbox.template_revision_exists":
      return "revisionExists";
    case "sandbox.template_in_use":
      return "inUse";
    case "sandbox.host_not_found":
    case "sandbox.template_not_found":
      return "notFound";
  }
  const shape = shapeOf(error);
  if (shape.code === "NOT_FOUND" || shape.status === 404) return "notFound";
  if (shape.code === "CONFLICT" || shape.status === 409) return "changed";
  if (shape.code === "BAD_REQUEST" || shape.status === 400) return "invalid";
  if (shape.code === "FORBIDDEN" || shape.status === 403) return "forbidden";
  return "generic";
}

/**
 * Search of the New template pages: `template` adds a version to that template
 * instead of creating one; `from` (register only) prefills the default size
 * of that version. Anything that is not a plain id is dropped.
 */
export type NewTemplateSearch = { template?: string; from?: string };
const SEARCH_ID = /^[A-Za-z0-9_-]{1,64}$/;
export function parseNewTemplateSearch(search: Record<string, unknown>): NewTemplateSearch {
  const pick = (value: unknown) =>
    typeof value === "string" && SEARCH_ID.test(value) ? value : undefined;
  const template = pick(search.template);
  const from = template ? pick(search.from) : undefined;
  return { ...(template ? { template } : {}), ...(from ? { from } : {}) };
}

/** `/templates?new=true` opens the New template chooser (a deep link from Create sandbox). */
export type TemplatesSearch = { new?: true };
export function parseTemplatesSearch(search: Record<string, unknown>): TemplatesSearch {
  return search.new === true || search.new === "true" ? { new: true } : {};
}

/** Lowercase, hyphenated slug from a display name (the register page's default slug). */
export function slugFromName(name: string): string {
  return name
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63)
    .replace(/-+$/g, "");
}

/** Key/value rows ↔ the draft's JSON env text (the API keeps a JSON string map). */
export function envRowsToDraft(record: Record<string, string>): string {
  return Object.keys(record).length === 0 ? "" : JSON.stringify(record);
}

/** Env keys the server refuses on stored defaults. */
export const RESERVED_DEFAULT_ENV = ["HOME", "SHELL", "TERM"] as const;

/**
 * A template revision as people read it: `slug vN` (the revision's per-template
 * number). Its cuid stays behind a copy button where it is needed at all.
 */
export function revisionLabel({ slug, revision }: { slug: string; revision: number }): string {
  return `${slug} v${revision}`;
}
