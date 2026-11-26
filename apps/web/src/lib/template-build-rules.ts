import {
  compileDockerfile,
  parseRecipe,
  RECIPE_ERROR_CODES,
  RecipeError,
  TEMPLATE_BUILD_CAPTURE_DETAIL_ERROR_CODES,
  TEMPLATE_BUILD_ERROR_CODES,
  TEMPLATE_BUILD_STATES,
  TEMPLATE_BUILD_TERMINAL_STATES,
  type TemplateBuildErrorCode,
  type TemplateBuildStateDto,
} from "@wssp/api/sandbox/contracts";

/**
 * Pure rules of the template-build dashboard: the
 * builds list filter, state tones, the build dialog's source composition
 * (egress choice, build args) and the typed-error mapping. The server stays
 * the authority: the editor check here only explains a refusal earlier.
 */

export type BuildState = TemplateBuildStateDto;
export { TEMPLATE_BUILD_STATES };

const TERMINAL: ReadonlySet<string> = new Set(TEMPLATE_BUILD_TERMINAL_STATES);
const STATES: ReadonlySet<string> = new Set(TEMPLATE_BUILD_STATES);
const ERROR_CODES: ReadonlySet<string> = new Set(TEMPLATE_BUILD_ERROR_CODES);
const RECIPE_CODES: ReadonlySet<string> = new Set(RECIPE_ERROR_CODES);
const RESOURCE_ID = /^[A-Za-z0-9_-]{1,64}$/;

/** Live builds poll their detail and step logs; terminal builds stop. */
export const BUILD_ACTIVE_REFETCH_MS = 2_000;
export const BUILD_LIST_REFETCH_MS = 5_000;

export function isBuildActive(state: BuildState): boolean {
  return !TERMINAL.has(state);
}

/** A build can be cancelled until it is terminal; CANCELLING repeats idempotently. */
export function canCancelBuild(state: BuildState): boolean {
  return isBuildActive(state) && state !== "CANCELLING";
}

export type BuildTone = "pending" | "cancelling" | "succeeded" | "failed" | "cancelled";
export function buildTone(state: BuildState): BuildTone {
  if (state === "SUCCEEDED") return "succeeded";
  if (state === "FAILED") return "failed";
  if (state === "CANCELLED") return "cancelled";
  if (state === "CANCELLING") return "cancelling";
  return "pending";
}

/** The progress phase's label key (`capturing:<capture phase>` → `capturing`). */
const BUILD_PHASES = [
  "awaiting_context",
  "queued",
  "placing",
  "waiting_for_capacity",
  "context_import",
  "context_commit",
  "step",
  "lease",
  "stopping",
  "capturing",
  "capture_waiting_capacity",
  "storing",
  "verifying",
] as const;
export type BuildPhase = (typeof BUILD_PHASES)[number] | "other";
const PHASES: ReadonlySet<string> = new Set(BUILD_PHASES);
export function buildPhase(phase: string | null): BuildPhase | null {
  if (phase === null) return null;
  const head = phase.split(":")[0] ?? "";
  return PHASES.has(head) ? (head as BuildPhase) : "other";
}

export function buildErrorCode(code: string | null): TemplateBuildErrorCode | null {
  return code !== null && ERROR_CODES.has(code) ? (code as TemplateBuildErrorCode) : null;
}

const CAPTURE_DETAIL_CODES: ReadonlySet<string> = new Set(
  TEMPLATE_BUILD_CAPTURE_DETAIL_ERROR_CODES,
);

/** A build failure whose detail can be a capture's storage or export cause
 * (the server's own list), so a known detail is explained as a sentence. */
export function carriesCaptureDetail(code: string | null): boolean {
  return code !== null && CAPTURE_DETAIL_CODES.has(code);
}

/**
 * Failure details with a sentence and a next step of their own, so a raw
 * code ("template.build_no_builder") is never the primary text. Values are
 * the server's typed causes (`errorDetail`), code-shaped, never message text.
 */
const FAILURE_DETAIL_KEYS: Readonly<Record<string, string>> = {
  "template.build_no_builder": "noBuilder",
  "sandbox.host_capacity": "hostCapacity",
  placement_timeout: "placementTimeout",
  "sandbox.host_unavailable": "hostUnavailable",
};
export type FailureDetailKey =
  | "noBuilder"
  | "hostCapacity"
  | "placementTimeout"
  | "hostUnavailable";

/** The sentence key of a known failure detail, or null (shown raw, as secondary text). */
export function failureDetailKey(detail: string | null): FailureDetailKey | null {
  if (detail === null) return null;
  return (FAILURE_DETAIL_KEYS[detail] as FailureDetailKey | undefined) ?? null;
}

/**
 * A step's shown state: in a finished build a step still "pending" never
 * ran (the build failed or was cancelled before it), so it says so.
 */
export function shownStepState(
  buildState: BuildState,
  stepState: "pending" | "running" | "succeeded" | "failed",
): "pending" | "running" | "succeeded" | "failed" | "notRun" {
  return stepState === "pending" && !isBuildActive(buildState) ? "notRun" : stepState;
}

/** Storage failure details with a sentence of their own (`build_store_failed`). */
const STORE_DETAIL_KEYS = [
  "upload_stalled",
  "upload_timeout",
  "upload_reset",
  "upload_connect",
  "upload_tls",
  "upload_url_expired",
  "upload_local_io",
  "upload_export",
  "upload_no_grant",
  "upload_protocol",
  "upload_lost",
  "upload_invalid",
  "upload_stale",
  "store_verify_failed",
  "store_verify_timeout",
  "store_complete_failed",
  "store_list_failed",
  "store_unavailable",
  "store_failed",
  "store_deadline",
] as const;
export type StoreDetailKey = (typeof STORE_DETAIL_KEYS)[number];
const STORE_DETAILS: ReadonlySet<string> = new Set(STORE_DETAIL_KEYS);

/**
 * The translated sentence a storage detail maps to, or null for an unknown
 * one (shown raw). HTTP statuses and server refusals carry their value.
 */
export function storeDetailMessage(
  detail: string,
):
  | { key: StoreDetailKey | "upload_quota" }
  | { key: "upload_http"; status: string }
  | { key: "upload_refused"; reason: string }
  | null {
  if (STORE_DETAILS.has(detail)) return { key: detail as StoreDetailKey };
  const http = /^upload_http_(\d{3})$/.exec(detail);
  if (http?.[1]) return { key: "upload_http", status: http[1] };
  if (detail === "upload_refused.image_quota_exceeded") return { key: "upload_quota" };
  const refused = /^upload_refused\.([a-z_.]{1,64})$/.exec(detail);
  if (refused?.[1]) return { key: "upload_refused", reason: refused[1] };
  return null;
}

// ---------------------------------------------------------------------------
// Builds list filter (URL search)

export type TemplateBuildsSearch = { templateId?: string; state?: BuildState };

export function parseTemplateBuildsSearch(search: Record<string, unknown>): TemplateBuildsSearch {
  const out: TemplateBuildsSearch = {};
  if (typeof search.templateId === "string" && RESOURCE_ID.test(search.templateId))
    out.templateId = search.templateId;
  if (typeof search.state === "string" && STATES.has(search.state))
    out.state = search.state as BuildState;
  return out;
}

export function buildsListInput(search: TemplateBuildsSearch, limit: number, cursor?: string) {
  return {
    limit,
    ...(cursor === undefined ? {} : { cursor }),
    ...(search.templateId === undefined ? {} : { templateId: search.templateId }),
    ...(search.state === undefined ? {} : { state: search.state }),
  };
}

// ---------------------------------------------------------------------------
// Build dialog: build args, egress and the recipe source

const BUILD_ARGS_MAX = 64;
const ARG_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
/** Names that look like secrets: build args and ENV are stored in plain text (§6.2). */
const SECRET_NAME = /(TOKEN|SECRET|PASSWORD|API_?KEY)/i;

export type ParsedArgs = { args: Record<string, string>; invalidId: string | null };

/**
 * Build-arg rows as the API's map, values exactly as typed (a newline stays a
 * newline: the API and recipe accept any string up to 4096 characters). Blank
 * rows are skipped; the first row with a bad name, an over-long value or past
 * the 64-arg limit is reported by id, and then nothing is returned.
 */
export function buildArgsFromRows(
  rows: readonly { id: string; key: string; value: string }[],
): ParsedArgs {
  // Null prototype: a `__proto__` name stays an own key.
  const args = Object.create(null) as Record<string, string>;
  for (const row of rows) {
    const name = row.key.trim();
    if (name === "" && row.value === "") continue;
    if (
      !ARG_NAME.test(name) ||
      row.value.length > 4096 ||
      (!Object.hasOwn(args, name) && Object.keys(args).length >= BUILD_ARGS_MAX)
    )
      return { args: {}, invalidId: row.id };
    args[name] = row.value;
  }
  return { args, invalidId: null };
}

/** Build-arg and ENV names that look like secrets (warned, never refused). */
export function secretLikeNames(names: Iterable<string>): string[] {
  return [...new Set([...names].filter((name) => SECRET_NAME.test(name)))].sort();
}

/** ENV names declared in a Dockerfile (`ENV k=v …` and legacy `ENV k v`). */
export function dockerfileEnvNames(text: string): string[] {
  const names: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*(?:ENV|ARG)\s+(.+)$/i.exec(line);
    if (!match?.[1]) continue;
    for (const token of match[1].split(/\s+/)) {
      const name = token.split("=")[0] ?? "";
      if (ARG_NAME.test(name)) names.push(name);
      if (!token.includes("=")) break;
    }
  }
  return names;
}

export type SourceFormat = "dockerfile" | "recipe";
/** `asWritten`: the recipe's own egress (absent → a plain sandbox create's default). */
export type EgressChoice = "asWritten" | "allowlist" | "open";
export type EgressDraft = { mode: EgressChoice; presets: string[]; domains: string };

export function egressDomains(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((domain) => domain.trim().toLowerCase())
    .filter((domain) => domain.length > 0);
}

/** A recipe refusal; `names` lists the build args no ARG declares (recipe_arg_undeclared). */
type RecipeProblem = {
  kind: "recipe";
  code: string;
  line?: number;
  column?: number;
  stepIndex?: number;
  names?: string[];
};

export type SourceProblem =
  | { kind: "empty" }
  | { kind: "json" }
  | { kind: "egressConflict" }
  | RecipeProblem;

export type ComposedSource =
  | { ok: true; body: { recipe: Record<string, unknown> } | { dockerfile: string } }
  | { ok: false; problem: SourceProblem };

/**
 * The create body's recipe source with the dialog's egress choice applied.
 * A Dockerfile gets `# wssp:` extension lines appended (line numbers of the
 * user's text are unchanged); a recipe gets its `egress` replaced. A
 * Dockerfile that already declares egress keeps it unless the dialog asks
 * otherwise, which is a conflict to resolve in the text.
 */
export function composeBuildSource(
  format: SourceFormat,
  text: string,
  egress: EgressDraft,
): ComposedSource {
  if (text.trim() === "") return { ok: false, problem: { kind: "empty" } };
  const domains = egressDomains(egress.domains);
  if (format === "recipe") {
    let recipe: unknown;
    try {
      recipe = JSON.parse(text);
    } catch {
      return { ok: false, problem: { kind: "json" } };
    }
    if (!recipe || typeof recipe !== "object" || Array.isArray(recipe))
      return { ok: false, problem: { kind: "json" } };
    const record = { ...(recipe as Record<string, unknown>) };
    if (egress.mode !== "asWritten")
      record.egress = {
        mode: egress.mode,
        ...(egress.presets.length ? { presets: [...egress.presets] } : {}),
        ...(domains.length ? { domains } : {}),
      };
    return { ok: true, body: { recipe: record } };
  }
  if (egress.mode === "asWritten") return { ok: true, body: { dockerfile: text } };
  if (/^\s*#\s*wssp:egress/m.test(text)) return { ok: false, problem: { kind: "egressConflict" } };
  const lines = [`# wssp:egress-mode ${egress.mode}`];
  if (egress.presets.length) lines.push(`# wssp:egress-preset ${egress.presets.join(" ")}`);
  if (domains.length) lines.push(`# wssp:egress domain ${domains.join(" ")}`);
  const base = text.endsWith("\n") ? text : `${text}\n`;
  return { ok: true, body: { dockerfile: `${base}${lines.join("\n")}\n` } };
}

/** The FROM base as written: a template slug (with its tag) or a revision id. */
export type BuildBase = { template: string; tag?: string } | { revisionId: string };

export type SourceCheck = {
  problem: SourceProblem | null;
  hasCopy: boolean;
  /** The parsed FROM, when the source parsed. */
  from?: BuildBase;
};

function compileSource(
  body: { recipe: Record<string, unknown> } | { dockerfile: string },
  buildArgs: Record<string, string>,
) {
  return "dockerfile" in body
    ? compileDockerfile(body.dockerfile, { buildArgs })
    : parseRecipe(body.recipe, { buildArgs });
}

/** The build args the source's ARG steps do not declare (for the refusal's text). */
function undeclaredArgs(
  body: { recipe: Record<string, unknown> } | { dockerfile: string },
  buildArgs: Record<string, string>,
): string[] {
  try {
    const declared = new Set(
      compileSource(body, {}).recipe.steps.flatMap((step) =>
        step.type === "arg" ? [step.name] : [],
      ),
    );
    return Object.keys(buildArgs).filter((name) => !declared.has(name));
  } catch {
    return [];
  }
}

/**
 * Parse the composed source with the server's own recipe package, so a
 * refusal is shown inline (line and column) before anything is sent. The
 * server parses again and decides.
 */
export function checkBuildSource(
  body: { recipe: Record<string, unknown> } | { dockerfile: string },
  buildArgs: Record<string, string>,
): SourceCheck {
  try {
    const parsed = compileSource(body, buildArgs);
    return { problem: null, hasCopy: parsed.plan.hasCopy, from: parsed.recipe.from };
  } catch (error) {
    if (error instanceof RecipeError) {
      const names = error.code === "recipe_arg_undeclared" ? undeclaredArgs(body, buildArgs) : [];
      return {
        problem: {
          kind: "recipe",
          code: error.code,
          ...(error.line === undefined ? {} : { line: error.line }),
          ...(error.column === undefined ? {} : { column: error.column }),
          ...(error.stepIndex === undefined ? {} : { stepIndex: error.stepIndex }),
          ...(names.length > 0 ? { names } : {}),
        },
        hasCopy: false,
      };
    }
    return { problem: { kind: "recipe", code: "recipe_invalid" }, hasCopy: false };
  }
}

/** FROM as the person wrote it (`slug`, `slug:tag` or `revision/<id>`). */
export function baseSelector(from: BuildBase): string {
  if ("revisionId" in from) return `revision/${from.revisionId}`;
  return from.tag === undefined ? from.template : `${from.template}:${from.tag}`;
}

/** What the build form knows about the caller's templates (active, first page). */
export type KnownTemplate = { id: string; slug: string; versions: { count: number } };

/**
 * A FROM that cannot resolve: not one of your templates, one with no ready
 * version (both known before submit), or refused by the server (`fromNotFound`).
 */
export type BaseProblem = {
  kind: "fromUnknown" | "fromNoVersion" | "fromNotFound";
  from: string;
  /** A few slugs that would work (templates with a ready version). */
  examples: string[];
};

/** How many of the caller's template slugs a FROM error suggests. */
const BASE_EXAMPLES = 2;

/** Ready templates to suggest after "FROM must name one of your templates". */
export function baseExamples(templates: readonly KnownTemplate[]): string[] {
  return templates
    .filter((template) => template.versions.count > 0)
    .slice(0, BASE_EXAMPLES)
    .map((template) => template.slug);
}

/**
 * FROM checked against the caller's templates before submit. The server
 * resolves FROM to one of the owner's own templates (by slug or id) with a
 * ready version; `ubuntu:24.04` is a registry image, not a template, and was
 * refused only after submit as "not found". Null when it is fine or the list
 * is incomplete (`templates` null: not loaded, or more pages than read); the
 * server stays the authority (a tag that does not exist is its to refuse).
 */
export function checkBuildBase(
  from: BuildBase | undefined,
  templates: readonly KnownTemplate[] | null,
): BaseProblem | null {
  if (from === undefined || templates === null || "revisionId" in from) return null;
  const match = templates.find(
    (template) => template.slug === from.template || template.id === from.template,
  );
  if (match && match.versions.count > 0) return null;
  return {
    kind: match ? "fromNoVersion" : "fromUnknown",
    from: baseSelector(from),
    examples: baseExamples(templates),
  };
}

/** The label key of a recipe refusal code (server-only codes included). */
const SERVER_RECIPE_CODES = new Set([
  "context_without_copy",
  "tag_invalid",
  "tag_not_latest",
  "target_invalid",
  "template_slug_invalid",
  "timeout_exceeds_lease_ceiling",
  "timeout_exceeds_max",
  "timeout_invalid",
  "wait_needs_pool",
]);
export function recipeCodeKey(code: string): string {
  return RECIPE_CODES.has(code) || SERVER_RECIPE_CODES.has(code) ? code : "other";
}

// ---------------------------------------------------------------------------
// Typed refusals of the build routes

export type BuildProblem =
  | RecipeProblem
  /** FROM did not resolve to a template version you can build from (create only). */
  | { kind: "baseNotFound" }
  | { kind: "disabled"; reason: string }
  | { kind: "noBuilder" }
  | { kind: "concurrency"; max: number | null }
  | { kind: "minutes"; max: number | null }
  | { kind: "contextRequired" }
  | { kind: "contextTooLarge" }
  | { kind: "contextBusy" }
  | { kind: "contextMismatch" }
  | { kind: "notCancellable" }
  | { kind: "egressModeUnavailable" }
  | { kind: "communityKeyScope" }
  | { kind: "communityUnavailable"; reason: "index_unreachable" | "no_tested_version" }
  | { kind: "communityManaged" }
  | { kind: "notFound" }
  | { kind: "forbidden" }
  | { kind: "rateLimited" }
  | { kind: "invalid" }
  | { kind: "generic" };

type ErrorShape = { code?: unknown; status?: unknown; data?: unknown };

function shapeOf(error: unknown): ErrorShape {
  return (error && typeof error === "object" ? error : {}) as ErrorShape;
}

function dataOf(error: unknown): Record<string, unknown> {
  const data = shapeOf(error).data;
  return data && typeof data === "object" ? (data as Record<string, unknown>) : {};
}

const num = (value: unknown) => (typeof value === "number" ? value : undefined);

/**
 * A build route's refusal as a typed problem. `createBuild` marks the build
 * create call, where a template miss is the FROM base (see below).
 */
export function buildProblem(error: unknown, route?: "createBuild"): BuildProblem {
  const data = dataOf(error);
  // Build create resolves FROM before anything else it looks up by template,
  // so a template miss there is the base (the target template was already
  // loaded by the page, or is created from its slug).
  if (route === "createBuild" && data.code === "sandbox.template_not_found")
    return { kind: "baseNotFound" };
  switch (data.code) {
    case "template.build_recipe_invalid": {
      const line = num(data.line);
      const column = num(data.column);
      const stepIndex = num(data.stepIndex);
      return {
        kind: "recipe",
        code: typeof data.recipeCode === "string" ? data.recipeCode : "recipe_invalid",
        ...(line === undefined ? {} : { line }),
        ...(column === undefined ? {} : { column }),
        ...(stepIndex === undefined ? {} : { stepIndex }),
      };
    }
    case "template.build_disabled":
      return { kind: "disabled", reason: typeof data.reason === "string" ? data.reason : "off" };
    case "template.build_no_builder":
      return { kind: "noBuilder" };
    case "template.build_concurrency":
      return { kind: "concurrency", max: num(data.maxConcurrent) ?? null };
    case "template.build_minutes_exhausted":
      return { kind: "minutes", max: num(data.minutesPerMonth) ?? null };
    case "template.build_context_required":
      return { kind: "contextRequired" };
    case "template.build_context_too_large":
      return { kind: "contextTooLarge" };
    case "template.build_context_busy":
      return { kind: "contextBusy" };
    case "template.build_context_mismatch":
      return { kind: "contextMismatch" };
    case "template.build_not_cancellable":
      return { kind: "notCancellable" };
    case "template.build_egress_mode_unavailable":
      return { kind: "egressModeUnavailable" };
    case "template.community_key_scope":
      return { kind: "communityKeyScope" };
    case "template.community_unavailable":
      return {
        kind: "communityUnavailable",
        reason: data.reason === "no_tested_version" ? "no_tested_version" : "index_unreachable",
      };
    case "template.community_managed":
      return { kind: "communityManaged" };
  }
  const shape = shapeOf(error);
  if (shape.code === "NOT_FOUND" || shape.status === 404) return { kind: "notFound" };
  if (shape.code === "FORBIDDEN" || shape.status === 403) return { kind: "forbidden" };
  if (shape.code === "TOO_MANY_REQUESTS" || shape.status === 429) return { kind: "rateLimited" };
  if (shape.code === "BAD_REQUEST" || shape.status === 400) return { kind: "invalid" };
  return { kind: "generic" };
}

/** Disabled reasons with their own label; anything newer reads as "off". */
const DISABLED_REASONS = new Set([
  "off",
  "image_distribution_off",
  "no_builder",
  "lease_ceiling",
  "storage_unavailable",
  "community_timeout_exceeds_max",
]);
export function disabledReasonKey(reason: string | null | undefined): string {
  return reason && DISABLED_REASONS.has(reason) ? reason : "off";
}

/**
 * The output tail as plain text: control characters (terminal escapes
 * included) are dropped except newline and tab; React renders it as text.
 */
export function plainTail(text: string): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control bytes are removed, not matched for meaning
  return text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "");
}

// ---------------------------------------------------------------------------
// Community bases (community-base S12)

/**
 * A revision a sandbox may launch from: never a community base's UPSTREAM
 * pin and never a build output still awaiting its verify VM. The server
 * enforces this (`launchableRevisionWhere`); the page only hides the
 * launch-shaped actions (tag, publish, associate) that it would refuse.
 */
export function isLaunchableRevision(revision: {
  sourceKind: string;
  pendingVerifyBuildId?: string | null;
}): boolean {
  return revision.sourceKind !== "UPSTREAM" && !revision.pendingVerifyBuildId;
}

const COMMUNITY_REFRESH_SKIPS = [
  "no_latest",
  "archived",
  "owner_inactive",
  "refresh_off",
  "builds_disabled",
  "timeout_misfit",
  "unchanged",
  "too_recent",
  "quota",
  "no_target",
] as const;
export type CommunityRefreshSkip = (typeof COMMUNITY_REFRESH_SKIPS)[number] | "other";
const REFRESH_SKIPS: ReadonlySet<string> = new Set(COMMUNITY_REFRESH_SKIPS);
export function communityRefreshSkip(reason: string): CommunityRefreshSkip {
  return REFRESH_SKIPS.has(reason) ? (reason as CommunityRefreshSkip) : "other";
}

/** "Try again" is offered once the latest community build ended without a revision. */
export function canRetryCommunity(latest: { state: BuildState } | undefined): boolean {
  return latest?.state === "FAILED" || latest?.state === "CANCELLED";
}
