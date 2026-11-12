/**
 * Blocked-name hints (template-builds B12, §6.3, r3 N24). The node daemon
 * reports names its allowlist-mode resolver refused (`egress.refused`); for a
 * build VM the relay appends them to the build, and the step log read renders
 * them as synthetic lines.
 *
 * Names are untrusted operator input on every host: only DNS-grammar names
 * (`validHintDnsName`, ≤ 253 bytes, lowercase, no control characters)
 * outside the bridge's internal `.incus` domain are stored, and they are
 * re-checked before display. On a foreign builder (a
 * node the build owner does not own) the line only says the node reported
 * the name: no grant suggestion and no preset match (T16).
 */
import prisma from "@wssp/db";
import {
  EGRESS_REFUSED_NAMES_MAX,
  TEMPLATE_BUILD_HINTS_MAX,
  type TemplateBuildHintDto,
  validHintDnsName,
} from "@wssp/sandbox-contracts";
import { EGRESS_PRESETS } from "@wssp/template-recipe";
import { wakeOperationWatchers } from "../sandbox/operation-waiters";
import { type BuildStepRecord, parseStepRecords } from "./exec-plan";
import { notifyTemplateBuildProgress } from "./wake";

/** Re-attributions of one report when the steps change under it. */
const HINT_ATTRIBUTION_ATTEMPTS = 3;

/** One stored hint: the executed step it belongs to and the refused name. */
export type StoredBuildHint = { n: number; name: string; at: string };

const presetByDomain = new Map<string, string>();
for (const preset of EGRESS_PRESETS)
  for (const domain of preset.domains)
    if (!presetByDomain.has(domain)) presetByDomain.set(domain, preset.name);

/**
 * The build VM bridge's own DNS domain (Incus `dns.domain`, default `incus`).
 * The guest resolver appends it as a search suffix, so every lookup also
 * yields `<name>.incus` (`archive.ubuntu.com.incus`, even for a granted
 * name) — never a name to grant (E2-A-02). The daemon's in-memory DNS stub
 * already drops them (`crates/sandbox-runtime/src/refused_names.rs`); every
 * report still reaches hints only through this filter.
 */
const INTERNAL_DNS_DOMAIN = "incus";

/** A name under the bridge's internal domain: a search-suffix expansion. */
export function internalDnsName(name: string): boolean {
  return name === INTERNAL_DNS_DOMAIN || name.endsWith(`.${INTERNAL_DNS_DOMAIN}`);
}

/**
 * A name no egress grant can name: the grant grammar has no `_`, so a service
 * lookup such as apt's `_http._tcp.archive.ubuntu.com` SRV query is never
 * something to "add to egress" (E3-A-05). The daemon already drops them
 * (`refused_names.rs`); this also covers older daemons and stored hints.
 */
export function ungrantableDnsName(name: string): boolean {
  return name.includes("_");
}

/** The reported names worth storing: grammar-valid, not internal, grantable, unique, at most 16. */
export function sanitizeHintNames(names: readonly unknown[]): string[] {
  const out: string[] = [];
  for (const name of names.slice(0, EGRESS_REFUSED_NAMES_MAX))
    if (
      typeof name === "string" &&
      validHintDnsName(name) &&
      !internalDnsName(name) &&
      !ungrantableDnsName(name) &&
      !out.includes(name)
    )
      out.push(name);
  return out;
}

/** Stored hints, re-validated (a malformed entry is dropped, never shown). */
export function parseStoredHints(value: unknown): StoredBuildHint[] {
  if (!Array.isArray(value)) return [];
  const out: StoredBuildHint[] = [];
  for (const entry of value.slice(0, TEMPLATE_BUILD_HINTS_MAX)) {
    if (typeof entry !== "object" || entry === null) continue;
    const { n, name, at } = entry as Record<string, unknown>;
    if (
      typeof n === "number" &&
      Number.isInteger(n) &&
      n >= 0 &&
      n <= 255 &&
      typeof name === "string" &&
      validHintDnsName(name) &&
      // Hints stored before the internal-domain and service-name filters
      // are never shown.
      !internalDnsName(name) &&
      !ungrantableDnsName(name) &&
      typeof at === "string" &&
      !Number.isNaN(Date.parse(at))
    )
      out.push({ n, name, at: new Date(at).toISOString() });
  }
  return out;
}

/** The step a refusal belongs to: the running step, else the latest started one. */
export function hintStep(steps: readonly BuildStepRecord[]): BuildStepRecord | null {
  const running = steps.find((step) => step.state === "running");
  if (running) return running;
  const started = steps.filter((step) => step.state !== "pending");
  return started.length > 0 ? (started[started.length - 1] ?? null) : null;
}

/** New hints to append: not already stored for that step, within the build cap. */
export function planHintAppend(
  existing: readonly StoredBuildHint[],
  step: number,
  names: readonly string[],
  at: Date,
): StoredBuildHint[] {
  const room = TEMPLATE_BUILD_HINTS_MAX - existing.length;
  if (room <= 0) return [];
  const seen = new Set(existing.filter((hint) => hint.n === step).map((hint) => hint.name));
  return names
    .filter((name) => !seen.has(name))
    .slice(0, room)
    .map((name) => ({ n: step, name, at: at.toISOString() }));
}

/**
 * The display form. `foreign` is true exactly when the build ran on a node
 * its owner does not own: such a hint names no preset, suggests no grant, and
 * carries no host identity (grantees never see a foreign host's identity).
 */
export function renderBuildHint(hint: StoredBuildHint, foreign: boolean): TemplateBuildHintDto {
  if (foreign) {
    return {
      type: "blocked_name",
      step: hint.n,
      name: hint.name,
      source: "foreign_node",
      preset: null,
      message: `the build node reported a blocked name: \`${hint.name}\``,
      at: hint.at,
    };
  }
  const preset = presetByDomain.get(hint.name) ?? null;
  return {
    type: "blocked_name",
    step: hint.n,
    name: hint.name,
    source: "own_node",
    preset,
    message: preset
      ? `blocked: \`${hint.name}\` — add it to egress or use preset \`${preset}\``
      : `blocked: \`${hint.name}\` — add it to egress`,
    at: hint.at,
  };
}

/** The hints of one step, in display form. */
export function stepHints(
  row: { egressHints: unknown; foreignHost: boolean },
  step: number,
): TemplateBuildHintDto[] {
  return parseStoredHints(row.egressHints)
    .filter((hint) => hint.n === step)
    .map((hint) => renderBuildHint(hint, row.foreignHost));
}

/**
 * Relay entry: `hostId` (the authenticated session's host) reported refused
 * names for `sandboxId`. Only a RUNNING build whose build VM is that sandbox
 * on that host takes them; anything else is ignored. Returns whether hints
 * were appended.
 */
export async function recordBuildEgressHints(input: {
  hostId: string;
  sandboxId: string;
  names: readonly string[];
  now?: Date;
}): Promise<boolean> {
  const names = sanitizeHintNames(input.names);
  if (names.length === 0) return false;
  const now = input.now ?? new Date();
  // E2-A-03: the step attribution is atomic with the append. The write
  // re-checks that the steps are exactly the ones the attribution read, so a
  // hint never lands on a step after a later step started (a follower that
  // saw the later step treats the earlier one's hints as final); a step
  // change in between re-attributes.
  for (let attempt = 0; attempt < HINT_ATTRIBUTION_ATTEMPTS; attempt++) {
    const build = await prisma.sandboxTemplateBuild.findFirst({
      where: { buildSandboxId: input.sandboxId, hostId: input.hostId, state: "RUNNING" },
      select: { id: true, steps: true, egressHints: true },
    });
    if (!build) return false;
    const step = hintStep(parseStepRecords(build.steps));
    if (!step) return false;
    const existing = parseStoredHints(build.egressHints);
    const append = planHintAppend(existing, step.n, names, now);
    if (append.length === 0) return false;
    // One atomic append that touches only the hints (never the orchestrator's
    // columns) and re-checks the binding, the steps and the cap at write time.
    const written = await prisma.$executeRaw`
      UPDATE "sandbox_template_build"
      SET "egressHints" = "egressHints" || ${JSON.stringify(append)}::jsonb, "updatedAt" = now()
      WHERE "id" = ${build.id}
        AND "buildSandboxId" = ${input.sandboxId}
        AND "hostId" = ${input.hostId}
        AND "state"::text = 'RUNNING'
        AND "steps" = ${JSON.stringify(build.steps)}::jsonb
        AND jsonb_array_length("egressHints") + ${append.length} <= ${TEMPLATE_BUILD_HINTS_MAX}`;
    if (written === 0) continue;
    notifyHintAppended(build.id, step.operationId);
    return true;
  }
  return false;
}

function notifyHintAppended(buildId: string, operationId: string | null) {
  notifyTemplateBuildProgress(buildId);
  if (operationId) {
    try {
      wakeOperationWatchers([operationId]);
    } catch {
      // Held log reads re-read on their recheck timer.
    }
  }
}
