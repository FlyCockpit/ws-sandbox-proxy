import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  OPERATION_KINDS,
  OPERATION_STATES,
  SANDBOX_OFFLOAD_PINS,
  SANDBOX_STATES,
  SDK_ERRORS,
  WEBHOOK_EVENT_TYPES,
} from "@wssp/sandbox-contracts";
import { describe, expect, it } from "vitest";

/**
 * C56: the SDK documentation shows only compiled code. Every `ts` fence in the
 * README must be preceded by `<!-- example: examples/<file>.ts -->` and equal
 * that file byte for byte; `examples/` is type-checked against the real
 * exports by `pnpm check-types` (`tsc -p examples`). Error codes named in the
 * SDK and guide docs must exist in the `SDK_ERRORS` catalog.
 */

const root = fileURLToPath(new URL("..", import.meta.url));
const repo = fileURLToPath(new URL("../../..", import.meta.url));
const MARKER = /^<!-- example: (examples\/[\w-]+\.ts) -->$/;

type Fence = { line: number; info: string; body: string; marker: string | null };

function fences(markdown: string): Fence[] {
  const lines = markdown.split("\n");
  const found: Fence[] = [];
  for (let i = 0; i < lines.length; i++) {
    const open = /^```(\S*)\s*$/.exec(lines[i] ?? "");
    if (!open) continue;
    const start = i;
    const body: string[] = [];
    for (i++; i < lines.length && lines[i] !== "```"; i++) body.push(lines[i] ?? "");
    let previous = start - 1;
    while (previous >= 0 && (lines[previous] ?? "").trim() === "") previous--;
    const marker = MARKER.exec((lines[previous] ?? "").trim())?.[1] ?? null;
    found.push({ line: start + 1, info: open[1] ?? "", body: `${body.join("\n")}\n`, marker });
  }
  return found;
}

/** Problems with the README's TypeScript fences; empty when all are compiled examples. */
function exampleProblems(markdown: string, read: (path: string) => string): string[] {
  const problems: string[] = [];
  for (const fence of fences(markdown)) {
    if (!["ts", "typescript", "js", "mjs"].includes(fence.info)) continue;
    if (!fence.marker) {
      problems.push(`README.md:${fence.line}: code fence is not a compiled example`);
      continue;
    }
    if (read(fence.marker) !== fence.body) {
      problems.push(`README.md:${fence.line}: differs from ${fence.marker}`);
    }
  }
  return problems;
}

const readme = readFileSync(`${root}README.md`, "utf8");

/** The SDK README plus every docs/guide page. */
function guideDocs(): { name: string; text: string }[] {
  const guide = `${repo}docs/guide/`;
  return [
    { name: "packages/sdk/README.md", text: readme },
    ...readdirSync(guide)
      .filter((name) => name.endsWith(".md"))
      .map((name) => ({ name: `docs/guide/${name}`, text: readFileSync(guide + name, "utf8") })),
  ];
}

/**
 * `WSSP_*` variables the CLI and node daemon actually read (C56-F7): every
 * `var("WSSP_…")` / `var_os("WSSP_…")` call and `&str` constant in non-test
 * Rust source under `apps/cli/src` and `crates/`. A doc naming an invented
 * daemon variable then fails instead of riding a blanket `WSSP_` exemption.
 */
function rustEnvKeys(): string[] {
  const keys: string[] = [];
  for (const dir of ["apps/cli/src", "crates"]) {
    for (const entry of readdirSync(`${repo}${dir}`, { recursive: true, encoding: "utf8" })) {
      const path = entry.replaceAll("\\", "/");
      if (
        !path.endsWith(".rs") ||
        /(^|\/)(tests?|target)\/|(^|[/_])tests?(_[a-z_]*)?\.rs$/.test(path)
      )
        continue;
      const text = readFileSync(`${repo}${dir}/${path}`, "utf8");
      for (const match of text.matchAll(/(?:\bvar(?:_os)?\(\s*|: &str = )"(WSSP_[A-Z0-9_]+)"/g))
        keys.push(match[1] ?? "");
    }
  }
  return keys;
}

/**
 * Uppercase tokens the docs may name: the `/v1` error catalog, sandbox and
 * operation states, environment variables from the env manifest and the Rust
 * daemon, SDK exports, and a few named non-catalog identifiers (with their
 * sources).
 */
function uppercaseAllowlist(): Set<string> {
  const manifest = readFileSync(`${repo}scripts/lib/env-manifest.ts`, "utf8");
  const envKeys = [...manifest.matchAll(/key: "([A-Z0-9_]+)"/g)].map((m) => m[1] ?? "");
  const sdkExports = [
    ...readFileSync(`${root}src/index.ts`, "utf8").matchAll(/\b([A-Z][A-Z0-9_]{2,})\b/g),
  ].map((m) => m[1] ?? "");
  return new Set<string>([
    ...Object.keys(SDK_ERRORS),
    ...SANDBOX_STATES,
    ...SANDBOX_OFFLOAD_PINS, // disk.offloadPin (ANY, OWN_HOSTS)
    ...OPERATION_STATES,
    ...OPERATION_KINDS, // webhook operation.completed kind filters
    ...envKeys,
    ...rustEnvKeys(),
    ...sdkExports,
    "CREDENTIAL_PLANE", // terminal upgrade refusal, apps/server/src/sandbox-relay/browser-terminal-upgrade.ts
    "FORCE_2FA_DEFAULTS", // packages/auth/src/two-factor-policy.ts
    "HOME",
    "SHELL",
    "TERM", // reserved guest identity/default names, sandbox-contracts/src/env.ts
    "O_NOFOLLOW", // open(2) flag named in the aarch64 release note
    "SO_PEERCRED", // socket(7) option the egress guard authenticates with (hosts.md)
    "INCUS_DIR", // Incus client directory the build resolver's pid file lives under (template-builds.md)
    "XDG_RUNTIME_DIR", // the node's tmpfs runtime directory preview-tunnel clients keep state in (tunnels.md)
    // iptables/firewalld chain, target and protocol names in the host
    // firewall setup steps (hosts.md)
    ...["FORWARD", "ACCEPT", "ANY"],
    "GET", // HTTP method (network.md)
    "SPECIAL_PURPOSE_V4", // packages/sandbox-contracts/src/special-ranges.ts
    "ALL_OWNED",
    "ALLOWLIST",
    "ALL_USABLE",
    "SELECTED", // createSdkKeyInput enums, packages/api/src/sandbox/services/sdk-keys.ts
    // Dockerfile instructions (the template-build subset and the refused ones),
    // packages/template-recipe/src/dockerfile.ts
    ...["FROM", "RUN", "COPY", "ADD", "ARG", "ENV", "WORKDIR", "USER", "EXPOSE", "LABEL"],
    ...["ENTRYPOINT", "CMD", "VOLUME", "HEALTHCHECK", "ONBUILD", "STOPSIGNAL"],
    // CLI-login delivery and instance states, packages/db/prisma/schema/credential.prisma
    ...["GUEST", "PROXY", "EMPTY", "READY", "NEEDS_LOGIN"],
    // HTTP methods the credential proxy forwards or refuses,
    // apps/cli/src/sandbox_relay/credentials/proxy/
    ...["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "TRACK", "CONNECT"],
  ]);
}
const readExample = (path: string) => readFileSync(`${root}${path}`, "utf8");

describe("SDK documentation examples", () => {
  it("embeds only compiled example files, verbatim", () => {
    expect(exampleProblems(readme, readExample)).toEqual([]);
  });

  it("embeds every example file", () => {
    const embedded = new Set(fences(readme).map((fence) => fence.marker));
    const files = readdirSync(`${root}examples`).filter((name) => name.endsWith(".ts"));
    expect(files.length).toBeGreaterThanOrEqual(4);
    for (const file of files) expect(embedded, file).toContain(`examples/${file}`);
  });

  it("rejects a fence that is not a compiled example or has drifted", () => {
    const read = () => "const a = 1;\n";
    expect(exampleProblems("```ts\nconst a = 1;\n```\n", read)).toHaveLength(1);
    expect(
      exampleProblems("<!-- example: examples/a.ts -->\n\n```ts\nconst a = 2;\n```\n", read),
    ).toHaveLength(1);
    expect(
      exampleProblems("<!-- example: examples/a.ts -->\n```ts\nconst a = 1;\n```\n", read),
    ).toEqual([]);
  });

  it("names only known uppercase codes, states and identifiers", () => {
    const known = uppercaseAllowlist();
    const unknown: string[] = [];
    for (const doc of guideDocs()) {
      for (const match of doc.text.matchAll(/`([A-Z][A-Z0-9_]{2,})`/g)) {
        const token = match[1] ?? "";
        if (!known.has(token)) unknown.push(`${doc.name}: ${token}`);
      }
    }
    expect(unknown).toEqual([]);
  });

  it("rejects an uppercase code outside the catalog", () => {
    const known = uppercaseAllowlist();
    expect(known.has("UNSUPPORTED_CAPABILITY")).toBe(true);
    expect(known.has("READY")).toBe(true);
    expect(known.has("TRANSFER_MAX_BYTES")).toBe(true);
    expect(known.has("TRANSFER_TOO_BIG")).toBe(false);
  });

  it("allows only WSSP_ variables the Rust daemon reads", () => {
    const known = uppercaseAllowlist();
    expect(known.has("WSSP_DATA_DIR")).toBe(true);
    expect(known.has("WSSP_INCUS_PROJECT")).toBe(true);
    expect(known.has("WSSP_LOG")).toBe(true);
    expect(known.has("WSSP_DISABLE_EGRESS_CHECKS")).toBe(false);
  });

  it("names only catalogued sandbox error codes", () => {
    const docs = guideDocs();
    const unknown: string[] = [];
    for (const doc of docs) {
      for (const match of doc.text.matchAll(/`(sandbox\.[a-z_]+)`/g)) {
        const code = match[1] ?? "";
        // Webhook event types share the `sandbox.` prefix; they are a closed set too.
        if (
          !Object.hasOwn(SDK_ERRORS, code) &&
          !(WEBHOOK_EVENT_TYPES as readonly string[]).includes(code)
        )
          unknown.push(`${doc.name}: ${code}`);
      }
    }
    expect(docs.length).toBeGreaterThan(1);
    expect(unknown).toEqual([]);
  });
});
