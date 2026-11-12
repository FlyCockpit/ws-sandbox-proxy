import { z } from "zod";
import { CanonicalJsonError, canonicalDigestHex, canonicalJsonBytes } from "./canonical-json";
import { LOGIN_DEFINITION_LIMITS as L } from "./limits";
import { dnsNameProblem, formatProblem, headerNameProblem, parseUpstream } from "./net";
import { pathBelow, pathProblem, pathsOverlap } from "./paths";
import { codePointLength, hasAsciiControl, utf8Length } from "./text";

// --- Building blocks --------------------------------------------------------

/** `x-` followed by at least one character, at any schema object level. */
export function isExtensionKey(key: string): boolean {
  return key.length > 2 && key.startsWith("x-");
}

/** Objects that accept `x-*` keys and refuse every other unknown key. */
const extensibleObjects = new WeakSet<z.ZodType>();

/**
 * Unknown keys are checked on the input object, before Zod builds its output:
 * Zod never copies an own `__proto__` key into the output, so a check on the
 * output would accept it silently while Rust refuses it.
 */
function extensibleObject<S extends z.ZodRawShape>(shape: S) {
  const known = new Set(Object.keys(shape));
  const object = z.object(shape).catchall(z.unknown());
  extensibleObjects.add(object);
  return z.preprocess((input: z.input<typeof object>, ctx) => {
    if (typeof input === "object" && input !== null && !Array.isArray(input)) {
      for (const key of Object.keys(input)) {
        if (!known.has(key) && !isExtensionKey(key)) {
          ctx.addIssue({
            code: "custom",
            path: [key],
            message: "unknown key (only x-* extensions may be added)",
            input,
          });
        }
      }
    }
    return input;
  }, object);
}

/** At most `max` UTF-8 bytes. `.max(max)` is a sound relaxation for JSON Schema. */
const bytes = (max: number) =>
  z
    .string()
    .max(max)
    .refine((s) => utf8Length(s) <= max, { message: `must be at most ${max} UTF-8 bytes` });

/** At most `max` Unicode scalar values (JSON Schema `maxLength` semantics). */
const chars = (max: number) =>
  z
    .string()
    .refine((s) => codePointLength(s) <= max, { message: `must be at most ${max} characters` })
    .meta({ maxLength: max });

const command = bytes(L.commandMaxBytes)
  .min(1)
  .refine((s) => !s.includes("\0"), { message: "must not contain NUL" });

const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const RESERVED_ENV_NAMES = new Set(["HOME", "SHELL", "TERM", "PATH"]);

export function envNameProblem(name: string): string | null {
  if (!ENV_NAME_PATTERN.test(name)) return "must be a POSIX environment variable name";
  if (name.length > L.envNameMaxBytes) return `must be at most ${L.envNameMaxBytes} bytes`;
  if (RESERVED_ENV_NAMES.has(name) || name.startsWith("LD_")) return "is reserved";
  return null;
}

const refineWith =
  (check: (value: string) => string | null) => (value: string, ctx: z.RefinementCtx) => {
    const problem = check(value);
    if (problem) ctx.addIssue({ code: "custom", message: problem });
  };

const envName = z
  .string()
  .max(L.envNameMaxBytes)
  .regex(ENV_NAME_PATTERN)
  .superRefine(refineWith(envNameProblem));

const definitionPath = bytes(L.definitionPathMaxBytes).superRefine(
  refineWith((p) => pathProblem(p, L.definitionPathMaxBytes)),
);

const dnsName = z.string().max(L.dnsNameMaxBytes).superRefine(refineWith(dnsNameProblem));

// --- Schema -----------------------------------------------------------------

export const LOGIN_METHODS = ["device-code", "paste", "interactive", "browser-callback"] as const;
export const CREDENTIAL_SHARING = ["exclusive", "shareable"] as const;
export const CREDENTIAL_ROTATES = ["yes", "no", "unknown"] as const;

const proxySchema = extensibleObject({
  upstream: z
    .string()
    .max(L.proxyUpstreamMaxBytes)
    .superRefine(
      refineWith((u) => {
        const parsed = parseUpstream(u);
        return typeof parsed === "string" ? parsed : null;
      }),
    ),
  header: z.string().max(L.proxyHeaderMaxBytes).superRefine(refineWith(headerNameProblem)),
  format: z.string().max(L.proxyFormatMaxBytes).superRefine(refineWith(formatProblem)),
  baseUrlEnv: envName,
  placeholderEnv: envName.optional(),
});

const envEntrySchema = extensibleObject({
  name: envName,
  description: chars(L.envDescriptionMaxChars).optional(),
  required: z.boolean(),
  proxy: proxySchema.optional(),
});

const filesSchema = extensibleObject({
  required: z.array(definitionPath).max(L.filePathsMax).default([]),
  optional: z.array(definitionPath).max(L.filePathsMax).default([]),
  exclude: z.array(definitionPath).max(L.filePathsMax).default([]),
});

const credentialsSchema = extensibleObject({
  files: filesSchema.optional(),
  env: z.array(envEntrySchema).max(L.envEntriesMax).optional(),
  sharing: z.enum(CREDENTIAL_SHARING).default("exclusive"),
  rotates: z.enum(CREDENTIAL_ROTATES).default("unknown"),
  maxBytes: z.number().int().min(L.maxBytesMin).max(L.maxBytesMax).default(L.maxBytesDefault),
});

const loginSchema = extensibleObject({
  command,
  method: z.enum(LOGIN_METHODS),
  doneWhenCommandExits: z.boolean().default(true),
  verifyCommand: command.optional(),
  egress: extensibleObject({ domains: z.array(dnsName).max(L.egressDomainsMax) }).optional(),
});

const installSchema = extensibleObject({
  checkCommand: command.optional(),
  command: command.optional(),
  needsRoot: z.boolean().optional(),
  notes: chars(L.installNotesMaxChars).optional(),
});

const structuralSchema = extensibleObject({
  schemaVersion: z.literal(L.schemaVersion),
  id: z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/),
  displayName: chars(L.displayNameMaxChars)
    .min(1)
    .refine((s) => !hasAsciiControl(s), { message: "must not contain control characters" }),
  description: chars(L.descriptionMaxChars).optional(),
  install: installSchema.optional(),
  login: loginSchema,
  credentials: credentialsSchema,
});

type Structural = z.output<typeof structuralSchema>;

/** Cross-field rules (identical to `validate_semantics` in the Rust crate). */
function semanticIssues(def: Structural): DefinitionIssue[] {
  const issues: DefinitionIssue[] = [];
  const add = (path: string, message: string) => issues.push({ path, message });
  const files = def.credentials.files;
  const required = files?.required ?? [];
  const optional = files?.optional ?? [];
  const exclude = files?.exclude ?? [];
  const env = def.credentials.env ?? [];

  if (required.length + optional.length + exclude.length > L.filePathsMax) {
    add("credentials.files", `at most ${L.filePathsMax} paths in total`);
  }
  const included = [...required, ...optional];
  for (let i = 0; i < included.length; i++) {
    for (let j = i + 1; j < included.length; j++) {
      if (pathsOverlap(included[i] ?? "", included[j] ?? "")) {
        add("credentials.files", `included paths overlap: ${included[i]} and ${included[j]}`);
      }
    }
  }
  for (let i = 0; i < exclude.length; i++) {
    const path = exclude[i] ?? "";
    if (!included.some((dir) => pathBelow(path, dir))) {
      add(`credentials.files.exclude[${i}]`, "must lie below an included path");
    }
    for (let j = i + 1; j < exclude.length; j++) {
      if (pathsOverlap(path, exclude[j] ?? "")) {
        add("credentials.files.exclude", `excluded paths overlap: ${path} and ${exclude[j]}`);
      }
    }
  }
  if (included.length === 0 && env.length === 0) {
    add("credentials", "declare at least one file path or env entry");
  }

  const names = new Set<string>();
  env.forEach((entry, i) => {
    if (names.has(entry.name)) add(`credentials.env[${i}].name`, "duplicate env name");
    names.add(entry.name);
  });

  const proxied = env.filter((entry) => entry.proxy !== undefined);
  if (proxied.length > 0) {
    if (proxied.length !== env.length) {
      add("credentials.env", "a proxied definition must proxy every env entry");
    }
    if (required.length + optional.length + exclude.length > 0) {
      add("credentials.files", "a proxied definition must not declare files");
    }
    // Guest-visible names: each baseUrlEnv is unique and distinct from every
    // entry name; a placeholderEnv may reuse its own entry's name only.
    const taken = new Map<string, string>();
    env.forEach((entry, i) => {
      if (!entry.proxy) return;
      const claims: [string, string][] = [[entry.proxy.baseUrlEnv, "baseUrlEnv"]];
      if (entry.proxy.placeholderEnv) claims.push([entry.proxy.placeholderEnv, "placeholderEnv"]);
      for (const [name, field] of claims) {
        const ownName = field === "placeholderEnv" && name === entry.name;
        if ((names.has(name) && !ownName) || taken.has(name)) {
          add(`credentials.env[${i}].proxy.${field}`, `${name} is already used`);
        }
        taken.set(name, field);
      }
    });
  }

  const domains = def.login.egress?.domains ?? [];
  if (new Set(domains).size !== domains.length) add("login.egress.domains", "duplicate domain");
  return issues;
}

export const loginDefinitionSchema = structuralSchema.superRefine((def, ctx) => {
  for (const issue of semanticIssues(def)) {
    ctx.addIssue({ code: "custom", path: [issue.path], message: issue.message });
  }
});

export type LoginDefinition = z.output<typeof loginDefinitionSchema>;
export type LoginDefinitionInput = z.input<typeof loginDefinitionSchema>;

/** Every extensible object in the schema, so JSON Schema can close it to known keys plus `x-*`. */
export function isExtensibleObjectSchema(schema: unknown): boolean {
  return (
    typeof schema === "object" && schema !== null && extensibleObjects.has(schema as z.ZodType)
  );
}

// --- Parsing ----------------------------------------------------------------

export const DEFINITION_ERROR_CODES = [
  "definition.invalid",
  "definition.schema_version_unsupported",
] as const;
export type DefinitionErrorCode = (typeof DEFINITION_ERROR_CODES)[number];
export type DefinitionIssue = { path: string; message: string };
export type DefinitionError = { code: DefinitionErrorCode; issues: DefinitionIssue[] };

/** Accepted, but wssp cannot run the flow yet. */
export const DEFINITION_WARNINGS = ["login.method.browser_callback_unsupported"] as const;
export type DefinitionWarning = (typeof DEFINITION_WARNINGS)[number];

export type ParsedDefinition = {
  success: true;
  definition: LoginDefinition;
  warnings: DefinitionWarning[];
  /** The bounded canonical JSON; `canonicalDigestHex(canonical)` is the definition digest. */
  canonical: Uint8Array;
};
export type ParseDefinitionResult = ParsedDefinition | { success: false; error: DefinitionError };

const invalid = (issues: DefinitionIssue[]): { success: false; error: DefinitionError } => ({
  success: false,
  error: { code: "definition.invalid", issues },
});

/** Object check and the typed `schemaVersion > 1` refusal, which precede everything else. */
function precheck(document: unknown): { success: false; error: DefinitionError } | null {
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    return invalid([{ path: "", message: "definition must be a JSON object" }]);
  }
  const version = (document as Record<string, unknown>).schemaVersion;
  if (typeof version === "number" && Number.isInteger(version) && version > L.schemaVersion) {
    return {
      success: false,
      error: {
        code: "definition.schema_version_unsupported",
        issues: [{ path: "schemaVersion", message: `schemaVersion ${version} is not supported` }],
      },
    };
  }
  return null;
}

/** Schema and cross-field rules, given the document's bounded canonical JSON. */
function validate(document: unknown, canonical: Uint8Array): ParseDefinitionResult {
  const result = loginDefinitionSchema.safeParse(document);
  if (!result.success) {
    return invalid(
      result.error.issues.map((issue) => ({
        path: issue.path.map(String).join("."),
        message: issue.message,
      })),
    );
  }
  const warnings: DefinitionWarning[] = [];
  if (result.data.login.method === "browser-callback") {
    warnings.push("login.method.browser_callback_unsupported");
  }
  return { success: true, definition: result.data, warnings, canonical };
}

/**
 * Validates a login definition document. Order (shared with Rust): object
 * check, `schemaVersion > 1` typed refusal, canonical JSON constraints and the
 * document size bound (enforced while canonicalizing), then schema and
 * cross-field rules.
 */
export function parseLoginDefinition(document: unknown): ParseDefinitionResult {
  const refused = precheck(document);
  if (refused) return refused;
  let canonical: Uint8Array;
  try {
    canonical = canonicalJsonBytes(document);
  } catch (error) {
    if (error instanceof CanonicalJsonError) {
      return invalid([{ path: error.path, message: error.detail }]);
    }
    throw error;
  }
  return validate(document, canonical);
}

export type ParseDefinitionTextResult =
  | (ParsedDefinition & { document: Record<string, unknown> })
  | { success: false; error: DefinitionError };

/**
 * Parses definition text (at most `documentTextMaxBytes` UTF-8 bytes, checked
 * before `JSON.parse`), then `parseLoginDefinition`. Unparseable text is
 * `definition.invalid`. Same rules as `parse_definition_str` in Rust.
 */
export function parseLoginDefinitionText(text: string): ParseDefinitionTextResult {
  // UTF-8 bytes >= UTF-16 units, so the cheap length check is sound.
  if (text.length > L.documentTextMaxBytes || utf8Length(text) > L.documentTextMaxBytes) {
    return invalid([
      { path: "", message: `definition text exceeds ${L.documentTextMaxBytes} bytes` },
    ]);
  }
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    return invalid([{ path: "", message: "definition is not valid JSON" }]);
  }
  const result = parseLoginDefinition(document);
  return result.success ? { ...result, document: document as Record<string, unknown> } : result;
}

export type VerifiedDefinitionResult =
  | ParseDefinitionResult
  | { success: false; error: { code: "credential.definition_corrupt"; issues: DefinitionIssue[] } };

/**
 * Loads a stored definition for use: the digest is recomputed from the stored
 * document's bounded canonical JSON and must equal the pinned digest before
 * anything derives from it. The same canonical bytes are then validated.
 */
export async function loadVerifiedDefinition(
  document: unknown,
  expectedDigestHex: string,
): Promise<VerifiedDefinitionResult> {
  let canonical: Uint8Array | null;
  try {
    canonical = canonicalJsonBytes(document);
  } catch {
    canonical = null;
  }
  if (canonical === null || (await canonicalDigestHex(canonical)) !== expectedDigestHex) {
    return {
      success: false,
      error: {
        code: "credential.definition_corrupt",
        issues: [{ path: "", message: "stored definition does not match its digest" }],
      },
    };
  }
  return precheck(document) ?? validate(document, canonical);
}
