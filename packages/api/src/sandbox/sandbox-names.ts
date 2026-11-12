/**
 * Sandbox names (UI launch chunk B). App creates always store a name: the
 * caller's, checked free, or a generated adjective-noun one. Both are picked
 * in create's `work`, under the exclusive per-owner `lockOwnerPlacement`
 * (lock 31, taken by `resolvePlacement`) and after authorization, and rename
 * takes the same lock, so an owner's name writes serialize. The partial
 * unique index `sandbox_instance_owner_live_name` (live WORKLOAD rows only)
 * is the backstop; `isSandboxNameViolation` maps its P2002 to `name_taken`.
 *
 * The word lists are English-only lowercase ASCII and are not translated.
 */
import { randomInt } from "node:crypto";
import type { Prisma } from "@wssp/db";
import { isValidSandboxName } from "@wssp/sandbox-contracts";
import { isPrismaUniqueViolation } from "../lib/prisma-errors";
import { sandboxNameInvalid, sandboxNameTaken } from "./errors";

const SANDBOX_NAME_INDEX = "sandbox_instance_owner_live_name";

export const SANDBOX_NAME_ADJECTIVES = [
  "able",
  "agile",
  "airy",
  "amber",
  "ample",
  "apt",
  "aqua",
  "arctic",
  "azure",
  "balmy",
  "bold",
  "brave",
  "breezy",
  "bright",
  "brisk",
  "bubbly",
  "calm",
  "candid",
  "cheery",
  "clever",
  "cobalt",
  "comfy",
  "cosmic",
  "cozy",
  "crisp",
  "curious",
  "daring",
  "dapper",
  "deft",
  "dewy",
  "eager",
  "early",
  "easy",
  "elated",
  "electric",
  "epic",
  "fair",
  "fancy",
  "fast",
  "fearless",
  "fine",
  "fleet",
  "fluent",
  "fond",
  "frank",
  "fresh",
  "frosty",
  "gentle",
  "giant",
  "glad",
  "gleaming",
  "golden",
  "grand",
  "green",
  "happy",
  "hardy",
  "hazel",
  "hearty",
  "helpful",
  "honest",
  "humble",
  "ivory",
  "jade",
  "jolly",
  "jovial",
  "keen",
  "kind",
  "lively",
  "lucid",
  "lucky",
  "lunar",
  "mellow",
  "merry",
  "mighty",
  "mint",
  "modest",
  "neat",
  "nimble",
  "noble",
  "novel",
  "oaken",
  "opal",
  "patient",
  "peppy",
  "placid",
  "plucky",
  "polished",
  "proud",
  "quick",
  "quiet",
  "radiant",
  "rapid",
  "ready",
  "regal",
  "robust",
  "rosy",
  "royal",
  "rustic",
  "sage",
  "serene",
  "sharp",
  "shiny",
  "silver",
  "sleek",
  "smart",
  "snowy",
  "solar",
  "sonic",
  "spry",
  "steady",
  "stellar",
  "sterling",
  "sturdy",
  "sunny",
  "super",
  "swift",
  "tidy",
  "tranquil",
  "trusty",
  "upbeat",
  "valiant",
  "velvet",
  "vivid",
  "warm",
  "wise",
  "witty",
  "zesty",
  "zippy",
] as const;

export const SANDBOX_NAME_NOUNS = [
  "acorn",
  "albatross",
  "alpaca",
  "anchor",
  "antelope",
  "apricot",
  "aspen",
  "aurora",
  "badger",
  "bamboo",
  "basil",
  "beacon",
  "beaver",
  "birch",
  "bison",
  "bobcat",
  "breeze",
  "brook",
  "cactus",
  "canyon",
  "cedar",
  "cheetah",
  "chipmunk",
  "cloud",
  "clover",
  "comet",
  "condor",
  "coral",
  "cougar",
  "crane",
  "creek",
  "cricket",
  "cypress",
  "daisy",
  "dolphin",
  "dove",
  "eagle",
  "elm",
  "ember",
  "falcon",
  "fern",
  "finch",
  "firefly",
  "fjord",
  "flamingo",
  "forest",
  "fox",
  "gazelle",
  "gecko",
  "geyser",
  "glacier",
  "grove",
  "gull",
  "harbor",
  "harrier",
  "hawk",
  "hazelnut",
  "heron",
  "hill",
  "ibis",
  "iris",
  "island",
  "jaguar",
  "juniper",
  "kestrel",
  "kiwi",
  "koala",
  "lagoon",
  "lantern",
  "lark",
  "laurel",
  "lemur",
  "lily",
  "lotus",
  "lynx",
  "magpie",
  "maple",
  "marmot",
  "meadow",
  "meerkat",
  "mesa",
  "moose",
  "moth",
  "narwhal",
  "nebula",
  "newt",
  "oak",
  "ocelot",
  "orca",
  "orchid",
  "osprey",
  "otter",
  "owl",
  "panda",
  "panther",
  "pebble",
  "pelican",
  "penguin",
  "pine",
  "plover",
  "pond",
  "puffin",
  "quail",
  "quartz",
  "rabbit",
  "raven",
  "reef",
  "river",
  "robin",
  "sequoia",
  "sparrow",
  "spruce",
  "squirrel",
  "stork",
  "summit",
  "swan",
  "thistle",
  "tiger",
  "toucan",
  "trout",
  "tulip",
  "tundra",
  "valley",
  "walrus",
  "willow",
  "wren",
  "yak",
  "zebra",
] as const;

/** Candidates per lookup round. */
const CANDIDATES = 8;
/** Rounds with a `-xxxx` suffix after the plain round. */
const SUFFIX_ROUNDS = 3;
const SUFFIX_SPACE = 36 ** 4;

/** Uniform integer in [0, max). Tests replace `int` to force collisions. */
export const sandboxNameRandom = {
  int(max: number): number {
    return randomInt(max);
  },
};

function candidate(suffix: boolean): string {
  const adjective = SANDBOX_NAME_ADJECTIVES[sandboxNameRandom.int(SANDBOX_NAME_ADJECTIVES.length)];
  const noun = SANDBOX_NAME_NOUNS[sandboxNameRandom.int(SANDBOX_NAME_NOUNS.length)];
  const base = `${adjective}-${noun}`;
  return suffix
    ? `${base}-${sandboxNameRandom.int(SUFFIX_SPACE).toString(36).padStart(4, "0")}`
    : base;
}

/** Names among the owner's live workload sandboxes (the index predicate). */
async function takenNames(
  tx: Prisma.TransactionClient,
  ownerId: string,
  names: readonly string[],
  exceptId?: string,
): Promise<Set<string>> {
  const rows = await tx.sandbox.findMany({
    where: {
      userId: ownerId,
      name: { in: [...names] },
      state: { not: "DELETED" },
      purpose: "WORKLOAD",
      ...(exceptId ? { id: { not: exceptId } } : {}),
    },
    select: { name: true },
    take: names.length,
  });
  return new Set(rows.map((row) => row.name));
}

/**
 * A free generated name: 8 candidates and one lookup per round, the first
 * free one wins; then up to 3 rounds with a `-xxxx` (base36) suffix; then
 * `sandbox.name_taken`. The caller holds `lockOwnerPlacement`.
 */
export async function pickFreeSandboxName(
  tx: Prisma.TransactionClient,
  ownerId: string,
): Promise<string> {
  for (let round = 0; round <= SUFFIX_ROUNDS; round++) {
    const names = [...new Set(Array.from({ length: CANDIDATES }, () => candidate(round > 0)))];
    const taken = await takenNames(tx, ownerId, names);
    const free = names.find((name) => !taken.has(name));
    if (free) return free;
  }
  throw sandboxNameTaken();
}

/**
 * Refuse an invalid name (`sandbox.name_invalid`) or one another live
 * workload sandbox of the owner uses (`sandbox.name_taken`). `exceptId` is
 * the sandbox being renamed. The caller holds `lockOwnerPlacement`.
 */
export async function assertSandboxNameFree(
  tx: Prisma.TransactionClient,
  ownerId: string,
  name: string,
  exceptId?: string,
): Promise<void> {
  if (!isValidSandboxName(name)) throw sandboxNameInvalid();
  if ((await takenNames(tx, ownerId, [name], exceptId)).size > 0) throw sandboxNameTaken();
}

/** The name a fresh insert stores: the explicit one checked free, or a generated one. */
export async function resolveCreateSandboxName(
  tx: Prisma.TransactionClient,
  ownerId: string,
  explicit: string | undefined,
): Promise<string> {
  if (explicit === undefined) return pickFreeSandboxName(tx, ownerId);
  await assertSandboxNameFree(tx, ownerId, explicit);
  return explicit;
}

function namesNameIndex(value: unknown): boolean {
  if (value === SANDBOX_NAME_INDEX) return true;
  if (!Array.isArray(value) || value.length !== 2) return false;
  // The driver adapter reports quoted identifiers (`"userId"`), Prisma bare ones.
  const fields = value.map((field) => (typeof field === "string" ? field.replaceAll('"', "") : ""));
  return fields.includes("userId") && fields.includes("name");
}

/**
 * A P2002 on `sandbox_instance_owner_live_name` (shape of
 * `isHostSlugConflict`): `meta.target` is the constraint name or exactly
 * `[userId, name]`; the Prisma 7 driver adapter reports the same under
 * `meta.driverAdapterError.cause.constraint` (`index`, or `fields` with
 * quoted identifiers; pinned by sandbox-name.pg.test.ts). A P2002
 * on any other unique (buildId, currentPlacementId, idempotency) is not one.
 */
export function isSandboxNameViolation(error: unknown): boolean {
  if (!isPrismaUniqueViolation(error) || !error || typeof error !== "object" || !("meta" in error))
    return false;
  const meta = error.meta;
  if (!meta || typeof meta !== "object") return false;
  if ("target" in meta && namesNameIndex(meta.target)) return true;
  const adapter = "driverAdapterError" in meta ? meta.driverAdapterError : undefined;
  const cause =
    adapter && typeof adapter === "object" && "cause" in adapter ? adapter.cause : undefined;
  const constraint =
    cause && typeof cause === "object" && "constraint" in cause ? cause.constraint : undefined;
  if (!constraint || typeof constraint !== "object") return false;
  return (
    ("index" in constraint && constraint.index === SANDBOX_NAME_INDEX) ||
    ("fields" in constraint && namesNameIndex(constraint.fields))
  );
}
