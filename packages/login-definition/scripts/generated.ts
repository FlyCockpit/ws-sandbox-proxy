/**
 * Deterministic generator for every committed derived artifact of this
 * package: the JSON Schema, `vectors/digests.json`, `vectors/max-inputs/*`
 * and `vectors/bundles/*`. `src/vectors.test.ts` regenerates them in memory
 * and byte-compares; `pnpm --filter @wssp/login-definition generate` rewrites
 * them. The Rust crate checks the same files independently.
 */
import { readdirSync, readFileSync } from "node:fs";
import { canonicalJson } from "../src/canonical-json";
import {
  type Bundle,
  type BundleFile,
  definitionDigestHex,
  encodeBundle,
  fromHex,
  LOGIN_DEFINITION_LIMITS as L,
  type LoginDefinition,
  parseLoginDefinition,
  renderLoginDefinitionJsonSchema,
  serializeBundleUnchecked,
  toHex,
} from "../src/index";
import { compareBytes, utf8 } from "../src/text";

export const PACKAGE_ROOT = new URL("../", import.meta.url);

const json = (value: unknown) => utf8(`${JSON.stringify(value, null, 2)}\n`);
const readJson = (rel: string): unknown =>
  JSON.parse(readFileSync(new URL(rel, PACKAGE_ROOT), "utf8"));

export function validVectorNames(): string[] {
  return readdirSync(new URL("vectors/valid/", PACKAGE_ROOT))
    .filter((name) => name.endsWith(".json"))
    .sort();
}

function mustParse(document: unknown): LoginDefinition {
  const result = parseLoginDefinition(document);
  if (!result.success) throw new Error(`generator input invalid: ${JSON.stringify(result.error)}`);
  return result.definition;
}

// --- Definition max-input vectors (R3-5) ----------------------------------------

const repeat = (s: string, n: number) => s.repeat(n);

function filesBase(): Record<string, unknown> {
  return {
    schemaVersion: 1,
    id: "max",
    displayName: "Max",
    login: { command: "true", method: "paste" },
    credentials: { files: { required: [".tool/auth.json"] } },
  };
}

function proxyEntry(i: number, overrides: Record<string, unknown> = {}) {
  return {
    name: `K${i}`,
    required: true,
    proxy: {
      upstream: "https://api.example.com",
      header: "Authorization",
      format: "Bearer {value}",
      baseUrlEnv: `K${i}_BASE_URL`,
      ...overrides,
    },
  };
}

function proxyBase(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: 1,
    id: "max-proxy",
    displayName: "Max proxy",
    login: { command: "true", method: "paste" },
    credentials: { env: [proxyEntry(0, overrides)] },
  };
}

/** A DNS name of exactly `bytes` bytes made of 63-byte labels of `a`. */
function dnsName(bytes: number): string {
  const labels: string[] = [];
  let left = bytes;
  while (left > 63) {
    labels.push(repeat("a", 63));
    left -= 64;
  }
  if (left === 0) throw new Error(`no DNS name of ${bytes} bytes with this layout`);
  labels.push(repeat("a", left));
  return labels.join(".");
}

/** Exact canonical size, measured without the document byte budget. */
function canonicalSize(document: unknown): number {
  return utf8(canonicalJson(document, { maxBytes: Number.POSITIVE_INFINITY })).length;
}

function padTo(document: Record<string, unknown>, size: number): Record<string, unknown> {
  const padded = { ...document, "x-pad": "" };
  const missing = size - canonicalSize(padded);
  if (missing < 0) throw new Error("document already too large");
  return { ...document, "x-pad": repeat("p", missing) };
}

function nested(depth: number): Record<string, unknown> {
  // The document object itself is depth 1; each `x-n` object adds one level.
  let inner: Record<string, unknown> = {};
  for (let level = 2; level < depth; level++) inner = { "x-n": inner };
  return { ...filesBase(), "x-n": inner };
}

/**
 * `textPadding`: parse `canonical(document)` followed by that many spaces as
 * text. `firstIssue`: the refusal's first issue, exactly.
 */
type MaxCase = {
  name: string;
  ok: boolean;
  document: unknown;
  textPadding?: number;
  firstIssue?: { path: string; message: string };
};

function definitionMaxCases(): MaxCase[] {
  const cases: MaxCase[] = [];
  const pair = (name: string, at: unknown, over: unknown) => {
    cases.push({ name: `${name}-at-bound`, ok: true, document: at });
    cases.push({ name: `${name}-over-bound`, ok: false, document: over });
  };
  type Draft = {
    login: Record<string, unknown>;
    credentials: Record<string, unknown> & { files: Record<string, unknown> };
  };
  const withField = (edit: (d: Draft) => void) => {
    const d = filesBase();
    edit(d as unknown as Draft);
    return d;
  };
  pair(
    "id",
    { ...filesBase(), id: `a${repeat("-", 62)}` },
    { ...filesBase(), id: `a${repeat("-", 63)}` },
  );
  pair(
    "display-name-astral",
    { ...filesBase(), displayName: repeat("😀", L.displayNameMaxChars) },
    { ...filesBase(), displayName: repeat("😀", L.displayNameMaxChars + 1) },
  );
  pair(
    "description-escapes",
    { ...filesBase(), description: repeat('"', L.descriptionMaxChars) },
    { ...filesBase(), description: repeat('"', L.descriptionMaxChars + 1) },
  );
  pair(
    "install-notes",
    { ...filesBase(), install: { notes: repeat("\n", L.installNotesMaxChars) } },
    { ...filesBase(), install: { notes: repeat("\n", L.installNotesMaxChars + 1) } },
  );
  pair(
    "login-command-escapes",
    withField((d) => {
      d.login.command = repeat('"', L.commandMaxBytes);
    }),
    withField((d) => {
      d.login.command = repeat('"', L.commandMaxBytes + 1);
    }),
  );
  pair(
    "login-command-multibyte",
    withField((d) => {
      d.login.command = repeat("é", L.commandMaxBytes / 2);
    }),
    withField((d) => {
      d.login.command = `${repeat("é", L.commandMaxBytes / 2)}a`;
    }),
  );
  const domains = (n: number) => Array.from({ length: n }, (_, i) => `d${i}.example.com`);
  pair(
    "egress-domains",
    withField((d) => {
      d.login.egress = { domains: domains(L.egressDomainsMax) };
    }),
    withField((d) => {
      d.login.egress = { domains: domains(L.egressDomainsMax + 1) };
    }),
  );
  pair(
    "egress-domain-length",
    withField((d) => {
      d.login.egress = { domains: [dnsName(L.dnsNameMaxBytes)] };
    }),
    withField((d) => {
      d.login.egress = { domains: [dnsName(L.dnsNameMaxBytes + 1)] };
    }),
  );
  const paths = (n: number) =>
    Array.from({ length: n }, (_, i) => `p${String(i).padStart(3, "0")}`);
  pair(
    "file-paths-total",
    withField((d) => {
      d.credentials.files = {
        required: paths(L.filePathsMax - 2),
        exclude: ["p000/a", "p001/b"],
      };
    }),
    withField((d) => {
      d.credentials.files = {
        required: paths(L.filePathsMax - 1),
        exclude: ["p000/a", "p001/b"],
      };
    }),
  );
  const escapePath = (bytes: number) => `a${repeat('"', bytes - 1)}`;
  pair(
    "path-escapes",
    withField((d) => {
      d.credentials.files.required = [escapePath(L.definitionPathMaxBytes)];
    }),
    withField((d) => {
      d.credentials.files.required = [escapePath(L.definitionPathMaxBytes + 1)];
    }),
  );
  const envs = (n: number) =>
    Array.from({ length: n }, (_, i) => ({ name: `E${i}`, required: false }));
  pair(
    "env-entries",
    withField((d) => {
      d.credentials.env = envs(L.envEntriesMax);
    }),
    withField((d) => {
      d.credentials.env = envs(L.envEntriesMax + 1);
    }),
  );
  pair(
    "env-name",
    withField((d) => {
      d.credentials.env = [{ name: `E${repeat("_", L.envNameMaxBytes - 1)}`, required: true }];
    }),
    withField((d) => {
      d.credentials.env = [{ name: `E${repeat("_", L.envNameMaxBytes)}`, required: true }];
    }),
  );
  pair(
    "env-description-escapes",
    withField((d) => {
      d.credentials.env = [
        { name: "E", required: true, description: repeat("\\", L.envDescriptionMaxChars) },
      ];
    }),
    withField((d) => {
      d.credentials.env = [
        { name: "E", required: true, description: repeat("\\", L.envDescriptionMaxChars + 1) },
      ];
    }),
  );
  pair(
    "proxy-upstream-host",
    proxyBase({ upstream: `https://${dnsName(L.dnsNameMaxBytes)}` }),
    proxyBase({ upstream: `https://${dnsName(L.dnsNameMaxBytes + 1)}` }),
  );
  pair(
    "proxy-upstream-basepath",
    proxyBase({ upstream: `https://api.example.com/${repeat("a", L.proxyBasepathMaxBytes - 1)}` }),
    proxyBase({ upstream: `https://api.example.com/${repeat("a", L.proxyBasepathMaxBytes)}` }),
  );
  pair(
    "proxy-upstream-port",
    proxyBase({ upstream: "https://api.example.com:65535" }),
    proxyBase({ upstream: "https://api.example.com:65536" }),
  );
  // Longest upstream the component bounds allow: 8 + 253 + 6 + 240 = 507 bytes.
  cases.push({
    name: "proxy-upstream-longest",
    ok: true,
    document: proxyBase({
      upstream: `https://${dnsName(L.dnsNameMaxBytes)}:65535/${repeat("%C3", 79)}ab`,
    }),
  });
  pair(
    "proxy-header",
    proxyBase({ header: `X${repeat("-", L.proxyHeaderMaxBytes - 1)}` }),
    proxyBase({ header: `X${repeat("-", L.proxyHeaderMaxBytes)}` }),
  );
  pair(
    "proxy-format-escapes",
    proxyBase({ format: `${repeat('"', L.proxyFormatMaxBytes - 7)}{value}` }),
    proxyBase({ format: `${repeat('"', L.proxyFormatMaxBytes - 6)}{value}` }),
  );
  pair(
    "proxy-base-url-env",
    proxyBase({ baseUrlEnv: `B${repeat("_", L.envNameMaxBytes - 1)}` }),
    proxyBase({ baseUrlEnv: `B${repeat("_", L.envNameMaxBytes)}` }),
  );
  pair(
    "proxy-placeholder-env",
    proxyBase({ placeholderEnv: `P${repeat("_", L.envNameMaxBytes - 1)}` }),
    proxyBase({ placeholderEnv: `P${repeat("_", L.envNameMaxBytes)}` }),
  );
  pair(
    "proxy-entries",
    {
      ...proxyBase(),
      credentials: { env: Array.from({ length: L.envEntriesMax }, (_, i) => proxyEntry(i)) },
    },
    {
      ...proxyBase(),
      credentials: { env: Array.from({ length: L.envEntriesMax + 1 }, (_, i) => proxyEntry(i)) },
    },
  );
  pair(
    "max-bytes",
    withField((d) => {
      d.credentials.maxBytes = L.maxBytesMax;
    }),
    withField((d) => {
      d.credentials.maxBytes = L.maxBytesMax + 1;
    }),
  );
  pair(
    "document-size",
    padTo(filesBase(), L.documentMaxBytes),
    padTo(filesBase(), L.documentMaxBytes + 1),
  );
  pair("document-depth", nested(L.documentMaxDepth), nested(L.documentMaxDepth + 1));

  const tooLarge = { path: "", message: `canonical JSON exceeds ${L.documentMaxBytes} bytes` };
  const over = cases.find((c) => c.name === "document-size-over-bound");
  if (over) over.firstIssue = tooLarge;
  // The budget is enforced while writing: `x-z` sorts after `x-pad`, so the
  // fraction it holds is never reached once the padding fills the budget.
  cases.push({
    name: "document-size-refused-before-later-keys",
    ok: false,
    document: { ...padTo(filesBase(), L.documentMaxBytes + 1), "x-z": 1.5 },
    firstIssue: tooLarge,
  });
  // Raw text is bounded before JSON parsing: whitespace counts.
  const textPadding = L.documentTextMaxBytes - canonicalSize(filesBase());
  cases.push({ name: "document-text-at-bound", ok: true, document: filesBase(), textPadding });
  cases.push({
    name: "document-text-over-bound",
    ok: false,
    document: filesBase(),
    textPadding: textPadding + 1,
    firstIssue: { path: "", message: `definition text exceeds ${L.documentTextMaxBytes} bytes` },
  });
  return cases;
}

// --- Bundle max-input recipe (R2-9) ---------------------------------------------

/**
 * The exact-maximum bundle, built identically by both test suites:
 * `fileCount` files `d/<index padded to 6>` padded with `x` to `pathBytes`
 * bytes, all mode 0600; file 0 holds `maxBytes` bytes of `a`, the rest are
 * empty; `envCount` entries `E<index padded to 2>` padded with `_` to
 * `envNameBytes`, each holding `envValueBytes` bytes of `v`.
 */
export const MAX_BUNDLE_RECIPE = {
  fileCount: L.bundleFileCountMax,
  pathBytes: L.bundlePathTotalMaxBytes / L.bundleFileCountMax,
  envCount: L.bundleEnvCountMax,
  envNameBytes: L.envNameMaxBytes,
  envValueBytes: L.envValueMaxBytes,
  maxBytes: L.maxBytesMax,
  expectedBytes: L.bundleFixedMaxBytes + L.maxBytesMax,
  variants: [
    { name: "file-count-plus-one", expect: "file_count" },
    { name: "path-length-plus-one", expect: "path_length" },
    { name: "path-total-plus-one", expect: "path_total" },
    { name: "data-total-plus-one", expect: "data_total" },
    { name: "env-count-plus-one", expect: "env_count" },
    { name: "env-name-length-plus-one", expect: "env_name_length" },
    { name: "env-value-length-plus-one", expect: "env_value_length" },
  ],
};

export function maxBundleDefinition(): Record<string, unknown> {
  const env = Array.from({ length: MAX_BUNDLE_RECIPE.envCount }, (_, i) => ({
    name: maxEnvName(i, MAX_BUNDLE_RECIPE.envNameBytes),
    required: false,
  }));
  return {
    schemaVersion: 1,
    id: "max-bundle",
    displayName: "Max bundle",
    login: { command: "true", method: "paste" },
    credentials: { files: { required: ["d"] }, env, maxBytes: MAX_BUNDLE_RECIPE.maxBytes },
  };
}

const maxPath = (i: number, bytes: number) => {
  const head = `d/${String(i).padStart(6, "0")}`;
  return head + repeat("x", bytes - head.length);
};
const maxEnvName = (i: number, bytes: number) => {
  const head = `E${String(i).padStart(2, "0")}`;
  return head + repeat("_", bytes - head.length);
};

/** Builds the exact-max bundle or one of its +1 variants (unvalidated). */
export function buildMaxBundle(digest: Uint8Array, variant: string | null): Bundle {
  const r = MAX_BUNDLE_RECIPE;
  const fileCount = r.fileCount + (variant === "file-count-plus-one" ? 1 : 0);
  const files: BundleFile[] = Array.from({ length: fileCount }, (_, i) => {
    let path = maxPath(i, r.pathBytes);
    if (variant === "path-length-plus-one" && i === 0) {
      path = maxPath(0, L.bundlePathMaxBytes + 1);
    }
    if (variant === "path-total-plus-one" && i === r.fileCount - 1) {
      path = maxPath(i, r.pathBytes + 1);
    }
    const size = i === 0 ? r.maxBytes + (variant === "data-total-plus-one" ? 1 : 0) : 0;
    return { kind: "file", path, mode: 0o600, data: new Uint8Array(size).fill(0x61) };
  });
  const envCount = r.envCount + (variant === "env-count-plus-one" ? 1 : 0);
  const env = Array.from({ length: envCount }, (_, i) => {
    const name =
      variant === "env-name-length-plus-one" && i === r.envCount - 1
        ? maxEnvName(i, r.envNameBytes + 1)
        : maxEnvName(i, r.envNameBytes);
    const size = r.envValueBytes + (variant === "env-value-length-plus-one" && i === 0 ? 1 : 0);
    return { name, value: new Uint8Array(size).fill(0x76) };
  });
  return { definitionDigest: digest, files, env };
}

// --- Small binary bundle vectors --------------------------------------------------

type BundleCase = {
  file: string;
  definition: string;
  expect: string;
  decoded?: {
    files: { kind: string; path: string; mode: number; dataHex?: string }[];
    env: { name: string; valueHex: string }[];
  };
};

const text = (s: string) => utf8(s);

async function bundleVectors(): Promise<Map<string, Uint8Array>> {
  const out = new Map<string, Uint8Array>();
  const cases: BundleCase[] = [];
  const load = async (name: string) => {
    const document = readJson(`vectors/valid/${name}`);
    return {
      definition: mustParse(document),
      digest: fromHex(await definitionDigestHex(document)),
    };
  };
  const codex = await load("codex-cli.json");
  const tool = await load("files-exclude.json");

  const ok = (file: string, definition: string, def: LoginDefinition, bundle: Bundle) => {
    const bytes = encodeBundle(bundle, def);
    out.set(`vectors/bundles/${file}`, bytes);
    cases.push({ file, definition, expect: "ok", decoded: summarize(bundle) });
  };
  const bad = (file: string, definition: string, expect: string, bytes: Uint8Array) => {
    out.set(`vectors/bundles/${file}`, bytes);
    cases.push({ file, definition, expect });
  };
  const summarize = (bundle: Bundle) => {
    const sorted = [...bundle.files].sort((a, b) => compareBytes(utf8(a.path), utf8(b.path)));
    return {
      files: sorted.map((f) =>
        f.kind === "file"
          ? {
              kind: f.kind,
              path: f.path,
              mode: f.mode & 0o100 ? 0o700 : 0o600,
              dataHex: toHex(f.data),
            }
          : { kind: f.kind, path: f.path, mode: 0o700 },
      ),
      env: [...bundle.env]
        .sort((a, b) => compareBytes(utf8(a.name), utf8(b.name)))
        .map((e) => ({ name: e.name, valueHex: toHex(e.value) })),
    };
  };

  const codexBundle: Bundle = {
    definitionDigest: codex.digest,
    files: [
      {
        kind: "file",
        path: ".codex/auth.json",
        mode: 0o644,
        data: text('{"token":"test-only"}\n'),
      },
    ],
    env: [],
  };
  ok("codex-auth.bin", "codex-cli.json", codex.definition, codexBundle);
  const toolBundle: Bundle = {
    definitionDigest: tool.digest,
    files: [
      { kind: "file", path: ".config/tool/run.sh", mode: 0o755, data: text("#!/bin/sh\n") },
      { kind: "dir", path: ".config/tool", mode: 0o755 },
      { kind: "dir", path: ".config/tool/empty", mode: 0o700 },
      {
        kind: "file",
        path: ".local/share/tool/session",
        mode: 0o600,
        data: new Uint8Array([0, 255, 1]),
      },
      {
        kind: "file",
        path: 'dir with "quotes" and spaces/ünïcödé/x',
        mode: 0o600,
        data: new Uint8Array(),
      },
    ],
    env: [{ name: "TOOL_PROFILE", value: text("work") }],
  };
  ok("tool-mixed.bin", "files-exclude.json", tool.definition, toolBundle);

  const valid = encodeBundle(codexBundle, codex.definition);
  const raw = (bundle: Partial<Bundle>, digest = codex.digest) =>
    serializeBundleUnchecked({ definitionDigest: digest, files: [], env: [], ...bundle });
  const file = (path: string, data = text("x"), mode = 0o600): BundleFile => ({
    kind: "file",
    path,
    mode,
    data,
  });
  const patched = (mutate: (b: Uint8Array) => void) => {
    const copy = valid.slice();
    mutate(copy);
    return copy;
  };
  bad("empty.bin", "codex-cli.json", "truncated", new Uint8Array());
  bad("truncated-header.bin", "codex-cli.json", "truncated", valid.slice(0, 40));
  bad("truncated-data.bin", "codex-cli.json", "truncated", valid.slice(0, valid.length - 1));
  bad("trailing-byte.bin", "codex-cli.json", "trailing_bytes", new Uint8Array([...valid, 0]));
  bad(
    "bad-magic.bin",
    "codex-cli.json",
    "bad_magic",
    patched((b) => {
      b[0] = 0x58;
    }),
  );
  bad(
    "version-2.bin",
    "codex-cli.json",
    "unsupported_version",
    patched((b) => {
      b[4] = 2;
    }),
  );
  bad("digest-mismatch.bin", "codex-cli.json", "digest_mismatch", raw({}, new Uint8Array(32)));
  bad(
    "bad-kind.bin",
    "codex-cli.json",
    "bad_kind",
    patched((b) => {
      b[41] = 3;
    }),
  );
  bad(
    "mode-0644.bin",
    "codex-cli.json",
    "bad_mode",
    raw({ files: [file(".codex/auth.json", text("x"), 0o644)] }),
  );
  bad(
    "dir-mode-0755.bin",
    "files-exclude.json",
    "bad_mode",
    raw({ files: [{ kind: "dir", path: ".config/tool", mode: 0o755 }] }, tool.digest),
  );
  bad(
    "undeclared-path.bin",
    "codex-cli.json",
    "undeclared_path",
    raw({ files: [file(".codex/config.toml")] }),
  );
  bad(
    "excluded-path.bin",
    "files-exclude.json",
    "excluded_path",
    raw({ files: [file(".config/tool/cache/blob")] }, tool.digest),
  );
  bad(
    "under-file.bin",
    "files-exclude.json",
    "under_file",
    raw({ files: [file(".config/tool/a"), file(".config/tool/a/b")] }, tool.digest),
  );
  bad(
    "unsorted.bin",
    "files-exclude.json",
    "unsorted_path",
    raw({ files: [file(".config/tool/b"), file(".config/tool/a")] }, tool.digest),
  );
  bad(
    "duplicate.bin",
    "files-exclude.json",
    "duplicate_path",
    raw({ files: [file(".config/tool/a"), file(".config/tool/a")] }, tool.digest),
  );
  bad(
    "dir-with-data.bin",
    "files-exclude.json",
    "dir_has_data",
    (() => {
      const b = raw({ files: [file(".config/tool", text("z"), 0o700)] }, tool.digest);
      b[41] = 2; // kind = dir, data still present
      return b;
    })(),
  );
  bad(
    "dot-dot.bin",
    "files-exclude.json",
    "invalid_path",
    raw({ files: [file(".config/tool/../../.ssh/id")] }, tool.digest),
  );
  bad(
    "absolute.bin",
    "files-exclude.json",
    "invalid_path",
    raw({ files: [file("/etc/passwd")] }, tool.digest),
  );
  bad(
    "empty-path.bin",
    "files-exclude.json",
    "invalid_path",
    raw({ files: [file("")] }, tool.digest),
  );
  bad(
    "non-utf8-path.bin",
    "files-exclude.json",
    "invalid_path",
    (() => {
      const b = raw({ files: [file(".config/tool/zz")] }, tool.digest);
      b[41 + 5 + ".config/tool/".length] = 0xff;
      return b;
    })(),
  );
  bad(
    "data-over-max-bytes.bin",
    "codex-cli.json",
    "data_total",
    raw({ files: [file(".codex/auth.json", new Uint8Array(65537))] }),
  );
  bad(
    "undeclared-env.bin",
    "files-exclude.json",
    "undeclared_env",
    raw({ env: [{ name: "OTHER", value: text("x") }] }, tool.digest),
  );
  bad(
    "env-nul.bin",
    "files-exclude.json",
    "env_value_nul",
    raw({ env: [{ name: "TOOL_PROFILE", value: new Uint8Array([0x61, 0]) }] }, tool.digest),
  );
  bad(
    "env-duplicate.bin",
    "files-exclude.json",
    "duplicate_env",
    raw(
      {
        env: [
          { name: "TOOL_PROFILE", value: text("a") },
          { name: "TOOL_PROFILE", value: text("b") },
        ],
      },
      tool.digest,
    ),
  );
  out.set("vectors/bundles/cases.json", json({ cases }));
  return out;
}

export async function generatedFiles(): Promise<Map<string, Uint8Array>> {
  const files = new Map<string, Uint8Array>();
  files.set("schema/login-definition.v1.schema.json", utf8(renderLoginDefinitionJsonSchema()));

  const digests: Record<string, unknown> = {};
  for (const name of validVectorNames()) {
    const document = readJson(`vectors/valid/${name}`);
    const parsed = parseLoginDefinition(document);
    if (!parsed.success) throw new Error(`valid vector ${name} is invalid`);
    digests[name] = {
      digest: await definitionDigestHex(document),
      canonical: canonicalJson(document),
      warnings: parsed.warnings,
    };
  }
  files.set("vectors/digests.json", json(digests));

  const maxCases = definitionMaxCases();
  files.set(
    "vectors/max-inputs/definitions.json",
    json({
      description:
        "R3-5 max-input definitions: every bound at its limit is accepted and one past it is refused with definition.invalid. A case with textPadding is parsed as text: its canonical JSON followed by that many spaces. A case with firstIssue must report exactly that first issue.",
      cases: maxCases,
    }),
  );
  const maxDefinition = maxBundleDefinition();
  files.set(
    "vectors/max-inputs/bundle.json",
    json({
      description:
        "R2-9 exact-maximum bundle recipe (see MAX_BUNDLE_RECIPE in scripts/generated.ts). Both languages build it, must encode it to exactly expectedBytes and accept it, and must refuse each +1 variant with the named reason.",
      definition: maxDefinition,
      definitionDigest: await definitionDigestHex(maxDefinition),
      ...MAX_BUNDLE_RECIPE,
    }),
  );
  for (const [path, bytes] of await bundleVectors()) files.set(path, bytes);
  return files;
}
