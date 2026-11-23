/**
 * `/install.sh` rendering and behaviour. The rendered script runs under `sh` (and dash, busybox
 * where installed) with stub `curl`, `uname` and `id` commands against a local fixture release,
 * so nothing touches the network.
 */

import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono } from "hono";
import { afterAll, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_URL: "https://wssp.example.com/ignored-path" },
}));

const {
  CLI_MIN_RUST,
  CLI_RELEASE_TARGETS,
  CLI_REPOSITORY,
  cliReleaseBaseUrl,
  defaultCliReleaseBaseUrl,
  installCommand,
  installScript,
  registerInstallRoutes,
  windowsExplainer,
} = await import("./install-script.js");
const { SERVER_VERSION } = await import("./version.js");

const ORIGIN = "https://wssp.example.com";
const RELEASE = "https://mirror.example.com/wssp/v1";
const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const repoRoot = join(import.meta.dirname, "../../..");

function has(command: string): boolean {
  return spawnSync("sh", ["-c", `command -v ${command}`]).status === 0;
}

describe("install.sh rendering", () => {
  it("defaults to this version's GitHub Release and strips a trailing slash", () => {
    expect(defaultCliReleaseBaseUrl()).toBe(
      `${CLI_REPOSITORY}/releases/download/v${SERVER_VERSION}`,
    );
    expect(cliReleaseBaseUrl(undefined)).toBe(defaultCliReleaseBaseUrl());
    expect(cliReleaseBaseUrl(`${RELEASE}//`)).toBe(RELEASE);
    const text = installScript(ORIGIN, `${RELEASE}/`);
    expect(text).toContain(`WSSP_RELEASE_URL='${RELEASE}'`);
    expect(text).toContain(`WSSP_VERSION='${SERVER_VERSION}'`);
    expect(text).toContain(`WSSP_ORIGIN='${ORIGIN}'`);
  });

  it("embeds the server's commit only when it is a full hash", () => {
    expect(installScript(ORIGIN, RELEASE, COMMIT)).toContain(`WSSP_SOURCE_REV='${COMMIT}'`);
    for (const commit of [null, "abc123", `${COMMIT}0`, COMMIT.toUpperCase()]) {
      expect(installScript(ORIGIN, RELEASE, commit)).toContain("WSSP_SOURCE_REV=''");
    }
  });

  it("refuses to embed a value that could leave its quotes", () => {
    for (const bad of ["https://x.example/'; id; '", "https://x.example/$(id)", "a b", "`id`"]) {
      expect(() => installScript(ORIGIN, bad)).toThrow(/refusing/);
      expect(() => installScript(bad, RELEASE)).toThrow(/refusing/);
    }
    // An IPv6 origin stays inside its quotes.
    expect(installScript("http://[::1]:3000", RELEASE)).toContain(
      "WSSP_ORIGIN='http://[::1]:3000'",
    );
  });

  it("parses as POSIX sh", () => {
    for (const [shell, ...args] of [["sh"], ["dash"], ["bash", "--posix"], ["busybox", "sh"]]) {
      if (shell && has(shell)) {
        execFileSync(shell, [...args, "-n"], { input: installScript(ORIGIN, RELEASE, COMMIT) });
      }
    }
  });

  it("matches the CLI version, Rust version and the targets cargo-dist builds", () => {
    const cargo = readFileSync(join(repoRoot, "apps/cli/Cargo.toml"), "utf8");
    expect(cargo).toMatch(
      new RegExp(`^version = "${SERVER_VERSION.replaceAll(".", "\\.")}"$`, "m"),
    );
    expect(cargo).toMatch(
      new RegExp(`^rust-version = "${CLI_MIN_RUST.replace(".", "\\.")}"$`, "m"),
    );
    const dist = readFileSync(join(repoRoot, "apps/cli/dist-workspace.toml"), "utf8");
    const targets = /^targets = \[(.*)\]$/m.exec(dist)?.[1] ?? "";
    expect(
      targets
        .split(",")
        .map((t) => t.trim().replaceAll('"', ""))
        .sort(),
    ).toEqual([...CLI_RELEASE_TARGETS].sort());
    expect(dist).not.toMatch(/unix-archive/); // the installer expects the default .tar.xz
    expect(dist).toMatch(/^installers = \[\]$/m); // one installer: this one
  });

  it("is gated by the release workflow: version, archive check and attestation", () => {
    const release = readFileSync(join(repoRoot, ".github/workflows/release.yml"), "utf8");
    expect(release).toContain("apps/server/src/version.ts");
    expect(release).toContain("scripts/release/check-cli-artifacts.sh");
    expect(release).toMatch(/uses: actions\/attest@[0-9a-f]{40} # v\d/);
    expect(release).toContain("apps/cli/artifacts/wssp-*.tar.xz");
    expect(release).toContain("apps/cli/artifacts/sha256.sum");
    expect(release).toMatch(/id-token: write/);
    expect(release).toMatch(/attestations: write/);
    // The workflow is hand-maintained: dist refuses to plan or build without --allow-dirty.
    const distCalls = release.match(/^\s*dist (?:host|build) .*$/gm) ?? [];
    expect(distCalls.length).toBe(4);
    for (const call of distCalls) expect(call).toContain("--allow-dirty");
    const check = readFileSync(join(repoRoot, "scripts/release/check-cli-artifacts.sh"), "utf8");
    for (const target of CLI_RELEASE_TARGETS) expect(check).toContain(target);
  });

  it("gives the install command for https and plain-http (loopback) origins", () => {
    expect(installCommand(`${ORIGIN}/`)).toBe(
      `curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 ${ORIGIN}/install.sh | sh`,
    );
    expect(installCommand("http://localhost:3000")).toBe(
      "curl -fsSL --max-time 120 http://localhost:3000/install.sh | sh",
    );
  });

  it("serves a Windows explainer that installs nothing and throws", () => {
    const text = windowsExplainer(ORIGIN);
    expect(text).toContain("Linux only");
    expect(text).toContain(`${ORIGIN}/install.sh`);
    expect(text).toMatch(/^throw '/m);
    expect(text).not.toMatch(/Invoke-WebRequest|iwr |irm |Start-Process|Expand-Archive/);
    // The single-quoted PowerShell string doubles every embedded quote.
    const thrown = /^throw '(.*)'$/m.exec(text)?.[1] ?? "";
    expect(thrown.replaceAll("''", "")).not.toContain("'");
  });
});

describe("install routes", () => {
  it("serves the script from the canonical origin, not request headers, uncached", async () => {
    const app = new Hono();
    registerInstallRoutes(app, { releaseBaseUrl: RELEASE, commit: COMMIT });
    const response = await app.request("/install.sh", {
      headers: { host: "evil.example", "x-forwarded-host": "evil.example" },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/x-shellscript; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
    const text = await response.text();
    expect(text).toBe(installScript(ORIGIN, RELEASE, COMMIT));
    expect(text).not.toContain("evil.example");

    const ps1 = await app.request("/install.ps1", { headers: { host: "evil.example" } });
    expect(ps1.status).toBe(200);
    expect(ps1.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(await ps1.text()).toBe(windowsExplainer(ORIGIN));
  });

  it("defaults to this version's GitHub Release", async () => {
    const app = new Hono();
    registerInstallRoutes(app);
    const text = await (await app.request("/install.sh")).text();
    expect(text).toContain(`WSSP_RELEASE_URL='${defaultCliReleaseBaseUrl()}'`);
    expect(text).toContain("WSSP_SOURCE_REV=''");
  });
});

// ── Behaviour ────────────────────────────────────────────────────────────────

type Fixture = {
  /** Rewrite sha256.sum (null: no sha256.sum). */
  sums?: (lines: string[], digest: string, archive: string) => string | null;
  /** Replace the archive after its checksum was taken. */
  corrupt?: boolean;
  /** Build the archive's tree in `root` (default: wssp-<target>/wssp + README). */
  tree?: (root: string, target: string) => void;
  /** What the binary prints for --version (default "wssp <SERVER_VERSION>"). */
  version?: string;
  /** Exit status of the binary (default 0). */
  binaryStatus?: number;
};
/** `rootOwns`: with `uid: 0`, a stub `ls` reports root as the owner of the real user's files. */
type Machine = { os?: string; arch?: string; uid?: number; rootOwns?: boolean };
type Run = {
  machine?: Machine;
  fixture?: Fixture;
  shell?: string[];
  args?: string[];
  /** Directories on PATH before the stubs and the system (e.g. a stale wssp). */
  pathBefore?: (dir: string) => string[];
  /** Prepare HOME (e.g. an existing install). */
  prepare?: (home: string) => void;
  /** Replace the default PATH tail (/usr/bin:/bin), e.g. to hide tools. */
  systemPath?: (dir: string) => string;
  script?: string;
  env?: Record<string, string>;
  /** Run with no USER in the environment at all. */
  unsetUser?: boolean;
};

const work = mkdtempSync(join(tmpdir(), "wssp-install-test-"));
afterAll(() => {
  execFileSync("rm", ["-rf", work]);
});

function binaryScript(version: string, status = 0) {
  return `#!/bin/sh\necho '${version}'\nexit ${status}\n`;
}

let runs = 0;
function run(opts: Run = {}) {
  const { machine = {}, fixture = {} } = opts;
  const dir = join(work, `run-${++runs}`);
  const home = join(dir, "home");
  const stubs = join(dir, "stubs");
  const release = join(dir, "release");
  const log = join(dir, "log");
  for (const d of [home, stubs, release]) mkdirSync(d, { recursive: true });
  // Node's umask may leave these group-writable, which the installer refuses for any parent.
  for (const d of [dir, home]) chmodSync(d, 0o755);
  writeFileSync(log, "");
  opts.prepare?.(home);

  const arch = machine.arch ?? "x86_64";
  const target = /^(aarch64|arm64)$/.test(arch)
    ? "aarch64-unknown-linux-musl"
    : "x86_64-unknown-linux-musl";
  const archive = `wssp-${target}.tar.xz`;
  const tree = join(release, "tree");
  mkdirSync(tree);
  const build =
    fixture.tree ??
    ((root: string, t: string) => {
      mkdirSync(join(root, `wssp-${t}`));
      writeFileSync(
        join(root, `wssp-${t}/wssp`),
        binaryScript(fixture.version ?? `wssp ${SERVER_VERSION}`, fixture.binaryStatus),
        { mode: 0o755 },
      );
      writeFileSync(join(root, `wssp-${t}/README.md`), "readme\n");
    });
  build(tree, target);
  const members = readdirSync(tree);
  execFileSync("tar", ["-cJf", join(release, archive), ...members], { cwd: tree });
  const digest = createHash("sha256")
    .update(readFileSync(join(release, archive)))
    .digest("hex");
  if (fixture.corrupt) writeFileSync(join(release, archive), "tampered");
  const lines = [`${"1".repeat(64)}  source.tar.gz`, `${digest}  ${archive}`];
  const sums = fixture.sums ? fixture.sums(lines, digest, archive) : `${lines.join("\n")}\n`;
  if (sums !== null) writeFileSync(join(release, "sha256.sum"), sums);

  const stub = (name: string, body: string) =>
    writeFileSync(join(stubs, name), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  // curl ... -o DEST URL: serve RELEASE/<name> from the fixture directory, 22 when missing.
  stub(
    "curl",
    `echo "curl $*" >> '${log}'
dest=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in -o) dest=$2; shift ;; *) url=$1 ;; esac
  shift
done
case "$url" in '${RELEASE}/'*) ;; *) exit 22 ;; esac
src='${release}'/\${url##*/}
[ -f "$src" ] || exit 22
cp "$src" "$dest"`,
  );
  stub("uname", `case "$1" in -s) echo '${machine.os ?? "Linux"}' ;; -m) echo '${arch}' ;; esac`);
  if (machine.uid !== undefined) {
    const real = execFileSync("sh", ["-c", "command -v id"], { encoding: "utf8" }).trim();
    stub("id", `if [ "$1" = -u ]; then echo ${machine.uid}; else exec '${real}' "$@"; fi`);
  }
  if (machine.rootOwns) {
    const ls = execFileSync("sh", ["-c", "command -v ls"], { encoding: "utf8" }).trim();
    const uid = execFileSync("id", ["-u"], { encoding: "utf8" }).trim();
    stub("ls", `'${ls}' "$@" | awk '$3 == "${uid}" { $3 = 0 } { print }'`);
  }

  const before = opts.pathBefore?.(dir) ?? [];
  const tail = opts.systemPath?.(dir) ?? "/usr/bin:/bin";
  const result = spawnSync(
    opts.shell?.[0] ?? "sh",
    [...(opts.shell?.slice(1) ?? []), "-s", "--", ...(opts.args ?? [])],
    {
      input: opts.script ?? installScript(ORIGIN, RELEASE),
      encoding: "utf8",
      env: Object.fromEntries(
        Object.entries({
          HOME: home,
          PATH: [...before, stubs, tail].join(":"),
          USER: "tester",
          ...opts.env,
        }).filter(([k]) => !(opts.unsetUser && k === "USER")),
      ),
    },
  );
  const installed = join(home, ".local/bin/wssp");
  const binDir = join(home, ".local/bin");
  return {
    home,
    status: result.status,
    stdout: result.stdout,
    output: `${result.stdout}${result.stderr}`,
    calls: readFileSync(log, "utf8"),
    installed: existsSync(installed) ? installed : null,
    leftovers: existsSync(binDir) ? readdirSync(binDir).filter((f) => f.startsWith(".wssp-")) : [],
  };
}

function refused(out: ReturnType<typeof run>, message: RegExp) {
  expect(out.status).not.toBe(0);
  expect(out.output).toMatch(message);
  expect(out.installed).toBeNull();
  expect(out.leftovers).toEqual([]);
}

const canRun = has("xz") && has("tar") && has("awk") && has("sha256sum");

describe.skipIf(!canRun)("install.sh behaviour", () => {
  it("installs the verified binary into ~/.local/bin and prints the next steps", () => {
    for (const shell of [["sh"], ["dash"], ["busybox", "sh"]].filter(([s]) => s && has(s))) {
      const out = run({ shell });
      expect(out.output).toContain("checksum verified");
      expect(out.status).toBe(0);
      expect(out.installed).not.toBeNull();
      expect(execFileSync(out.installed ?? "", ["--version"], { encoding: "utf8" })).toBe(
        `wssp ${SERVER_VERSION}\n`,
      );
      expect(out.leftovers).toEqual([]);
      expect(out.calls).toContain(`${RELEASE}/sha256.sum`);
      expect(out.calls).toContain("curl --proto =https --tlsv1.2 ");
      // Every download is bounded: a stalled mirror fails instead of hanging the install.
      for (const flag of [
        "--connect-timeout 30",
        "--speed-limit 1024 --speed-time 60",
        "--max-time 900",
      ])
        expect(out.calls).toContain(flag);
      // Not on PATH: the steps say how to add it and use the full path.
      const bin = join(out.home, ".local/bin");
      expect(out.stdout).toContain(`export PATH='${bin}':"$PATH"`);
      expect(out.stdout).toContain(`'${bin}/wssp' login --server '${ORIGIN}'`);
      expect(out.stdout).toContain(`'${bin}/wssp' host enroll --slug my-host --server '${ORIGIN}'`);
      expect(out.stdout).toMatch(
        new RegExp(`sudo '${bin}/wssp' host guard install --daemon-user '[^']+'`),
      );
      expect(out.stdout).toContain(`'${bin}/wssp' host run`);
    }
  });

  it("picks the archive for the machine's architecture", () => {
    for (const [arch, target] of [
      ["x86_64", "x86_64-unknown-linux-musl"],
      ["amd64", "x86_64-unknown-linux-musl"],
      ["aarch64", "aarch64-unknown-linux-musl"],
      ["arm64", "aarch64-unknown-linux-musl"],
    ]) {
      const out = run({ machine: { arch } });
      expect(out.status).toBe(0);
      expect(out.calls).toContain(`${RELEASE}/wssp-${target}.tar.xz`);
    }
  });

  it("uses bare wssp when the install directory is on PATH, and replaces an old binary", () => {
    const out = run({
      prepare: (home) => {
        mkdirSync(join(home, ".local/bin"), { recursive: true, mode: 0o755 });
        writeFileSync(join(home, ".local/bin/wssp"), binaryScript("wssp 0.0.1"), { mode: 0o755 });
      },
      pathBefore: (dir) => [join(dir, "home/.local/bin")],
    });
    expect(out.status).toBe(0);
    expect(execFileSync(out.installed ?? "", ["--version"], { encoding: "utf8" })).toBe(
      `wssp ${SERVER_VERSION}\n`,
    );
    expect(out.stdout).not.toContain("export PATH");
    expect(out.stdout).toContain(`  wssp login --server '${ORIGIN}'`);
  });

  it("warns about another wssp earlier on PATH", () => {
    const out = run({
      pathBefore: (dir) => {
        mkdirSync(join(dir, "old"));
        writeFileSync(join(dir, "old/wssp"), binaryScript("wssp 0.0.1"), { mode: 0o755 });
        return [join(dir, "old"), join(dir, "home/.local/bin")];
      },
    });
    expect(out.status).toBe(0);
    expect(out.output).toMatch(/warning: .*\/old\/wssp comes first on your PATH/);
    expect(out.stdout).toContain(`'${join(out.home, ".local/bin/wssp")}' login`);
  });

  it("replaces a symlink at the install path with the binary itself", () => {
    const out = run({
      prepare: (home) => {
        mkdirSync(join(home, ".local/bin"), { recursive: true, mode: 0o755 });
        writeFileSync(join(home, "elsewhere"), "keep\n");
        symlinkSync(join(home, "elsewhere"), join(home, ".local/bin/wssp"));
      },
    });
    expect(out.status).toBe(0);
    expect(readFileSync(join(out.home, "elsewhere"), "utf8")).toBe("keep\n");
    expect(execFileSync(out.installed ?? "", ["--version"], { encoding: "utf8" })).toContain(
      SERVER_VERSION,
    );
  });

  it("refuses root without --install-dir, and installs for root into an explicit one", () => {
    refused(run({ machine: { uid: 0 } }), /not as root/);
    const out = run({ machine: { uid: 0 }, args: ["--install-dir", join(work, `root-${runs}`)] });
    // The guard refuses --daemon-user root: a root install names the daemon's user instead.
    const rootDir = join(work, `rootok-${runs}`);
    const rootOk = run({ machine: { uid: 0, rootOwns: true }, args: ["--install-dir", rootDir] });
    expect(rootOk.status).toBe(0);
    expect(existsSync(join(rootDir, "wssp"))).toBe(true);
    expect(rootOk.stdout).toContain(
      `sudo '${rootDir}/wssp' host guard install --daemon-user "$USER"`,
    );
    expect(rootOk.stdout).toContain("not root");
    // Minimal containers run as root without USER: the hint still prints, under `set -u`.
    const noUserDir = join(work, `rootnouser-${runs}`);
    const noUser = run({
      machine: { uid: 0, rootOwns: true },
      args: ["--install-dir", noUserDir],
      env: { USER: "" },
      unsetUser: true,
    });
    expect(noUser.status).toBe(0);
    expect(noUser.stdout).toContain("the shell fills in $USER");
    expect(noUser.stdout).toContain("host run");
    // The stub says uid 0, but the directory belongs to the real user: the owner check refuses.
    expect(out.status).not.toBe(0);
    expect(out.output).toMatch(/belongs to another user/);
    const dir = join(work, `own-${runs}`);
    const ok = run({ args: [`--install-dir=${dir}`] });
    expect(ok.status).toBe(0);
    expect(existsSync(join(dir, "wssp"))).toBe(true);
    expect(ok.stdout).toContain(`sudo '${dir}/wssp' host guard install`);
  });

  it("refuses an install directory under a parent other users can change, not under sticky /tmp", () => {
    // `work` is a private directory in the sticky, world-writable /tmp: allowed.
    const fine = join(work, `fine-${runs}/bin`);
    expect(run({ args: ["--install-dir", fine] }).status).toBe(0);
    const open = join(work, `open-${runs}`);
    mkdirSync(join(open, "bin"), { recursive: true });
    chmodSync(open, 0o777);
    const out = run({ args: ["--install-dir", join(open, "bin")] });
    expect(out.status).not.toBe(0);
    expect(out.output).toMatch(/other users can write to .*open-/);
    expect(existsSync(join(open, "bin/wssp"))).toBe(false);
  });

  it("installs into a directory whose name holds a backslash or spaces", () => {
    const odd = join(work, `odd-${runs}/a\\b c`);
    const out = run({ args: ["--install-dir", odd] });
    expect(out.output).toContain("checksum verified");
    expect(out.status).toBe(0);
    expect(existsSync(join(odd, "wssp"))).toBe(true);
    expect(out.stdout).toContain(`sudo '${odd}/wssp' host guard install`);
  });

  it("refuses an install directory that is relative, quoted or writable by others", () => {
    refused(run({ args: ["--install-dir", "relative/bin"] }), /must be an absolute path/);
    refused(run({ args: ["--install-dir", join(work, "it's")] }), /must not contain quotes/);
    const shared = join(work, `shared-${runs}`);
    mkdirSync(shared);
    chmodSync(shared, 0o777);
    const out = run({ args: ["--install-dir", shared] });
    expect(out.status).not.toBe(0);
    expect(out.output).toMatch(/other users can write/);
    expect(existsSync(join(shared, "wssp"))).toBe(false);
    refused(run({ args: ["--bogus"] }), /unknown option --bogus/);
    refused(run({ env: { HOME: "" } }), /set HOME/);
  });

  it("refuses a checksum mismatch, and leaves nothing behind", () => {
    refused(run({ fixture: { corrupt: true } }), /checksum mismatch/);
  });

  it("refuses a missing, ambiguous or malformed sha256.sum entry", () => {
    refused(run({ fixture: { sums: () => null } }), /could not download .*sha256\.sum.*published/);
    refused(run({ fixture: { sums: (lines) => `${lines[0]}\n` } }), /no single valid checksum/);
    refused(
      run({ fixture: { sums: (lines) => `${lines.join("\n")}\n${lines[1]}\n` } }),
      /no single valid checksum/,
    );
    refused(
      run({ fixture: { sums: (_l, d, a) => `${d.slice(0, 63)}g  ${a}\n` } }),
      /no single valid checksum/,
    );
    refused(
      run({ fixture: { sums: (_l, d, a) => `${d.slice(0, 60)}  ${a}\n` } }),
      /no single valid checksum/,
    );
    refused(
      run({ fixture: { sums: (_l, d, a) => `${d}  ${a} extra\n` } }),
      /no single valid checksum/,
    );
  });

  it("accepts binary-mode, CRLF and upper-case entries", () => {
    expect(run({ fixture: { sums: (_l, d, a) => `${d} *${a}\n` } }).status).toBe(0);
    expect(run({ fixture: { sums: (_l, d, a) => `${d.toUpperCase()}  ${a}\r\n` } }).status).toBe(0);
  });

  it("refuses an archive with the wrong layout, links or a wrong version", () => {
    refused(
      run({
        fixture: {
          tree: (root, t) => {
            mkdirSync(join(root, `wssp-${t}`));
            writeFileSync(join(root, `wssp-${t}/README.md`), "no binary\n");
          },
        },
      }),
      /layout of a wssp release/,
    );
    refused(
      run({
        fixture: {
          tree: (root, t) => {
            mkdirSync(join(root, `wssp-${t}`));
            writeFileSync(join(root, `wssp-${t}/wssp`), binaryScript(`wssp ${SERVER_VERSION}`), {
              mode: 0o755,
            });
            writeFileSync(join(root, "evil"), "outside\n");
          },
        },
      }),
      /layout of a wssp release/,
    );
    refused(
      run({
        fixture: {
          tree: (root, t) => {
            mkdirSync(join(root, `wssp-${t}`));
            writeFileSync(join(root, "real"), binaryScript(`wssp ${SERVER_VERSION}`), {
              mode: 0o755,
            });
            symlinkSync("../real", join(root, `wssp-${t}/wssp`));
          },
        },
      }),
      /layout of a wssp release|does not contain the wssp binary/,
    );
    refused(run({ fixture: { version: "wssp 0.0.1" } }), /reports "wssp 0\.0\.1", not wssp/);
    refused(run({ fixture: { binaryStatus: 1 } }), /does not run on this machine/);
    // A binary that never stops printing is cut off by the output bound, not waited on.
    refused(
      run({
        fixture: {
          tree: (root, t) => {
            mkdirSync(join(root, `wssp-${t}`));
            writeFileSync(
              join(root, `wssp-${t}/wssp`),
              `#!/bin/sh\nwhile :; do echo "wssp ${SERVER_VERSION}"; done\n`,
              { mode: 0o755 },
            );
          },
        },
      }),
      /does not run on this machine/,
    );
  });

  it("refuses non-Linux systems and unknown architectures, naming the source build", () => {
    refused(run({ machine: { os: "Darwin" } }), /Linux only.*WSL 2/);
    refused(run({ machine: { arch: "riscv64" } }), /no wssp release binary for riscv64.*apps\/cli/);
    const pinned = run({
      machine: { arch: "riscv64" },
      script: installScript(ORIGIN, RELEASE, COMMIT),
    });
    refused(
      pinned,
      new RegExp(`cargo install --git ${CLI_REPOSITORY} --rev ${COMMIT} --locked wssp`),
    );
  });

  it("refuses a directory at the install path", () => {
    const out = run({
      prepare: (home) => mkdirSync(join(home, ".local/bin/wssp"), { recursive: true, mode: 0o755 }),
    });
    expect(out.status).not.toBe(0);
    expect(out.output).toMatch(/is a directory/);
    expect(readdirSync(join(out.home, ".local/bin/wssp"))).toEqual([]);
    expect(out.leftovers).toEqual([]);
  });

  it("refuses to run without a SHA-256 tool or xz, before downloading", () => {
    const minimal = (missing: string[]) => (dir: string) => {
      const bin = join(dir, "minbin");
      mkdirSync(bin, { recursive: true });
      for (const tool of [
        "awk",
        "cat",
        "chmod",
        "cp",
        "cut",
        "id",
        "ls",
        "mkdir",
        "mktemp",
        "mv",
        "rm",
        "sed",
        "tar",
        "xz",
        "sha256sum",
        "env",
      ]) {
        if (missing.includes(tool)) continue;
        const real = execFileSync("sh", ["-c", `command -v ${tool}`], { encoding: "utf8" }).trim();
        symlinkSync(real, join(bin, tool));
      }
      return bin;
    };
    const noHash = run({ systemPath: minimal(["sha256sum"]), shell: ["/bin/sh"] });
    refused(noHash, /no SHA-256 tool/);
    expect(noHash.calls).toBe("");
    const noXz = run({ systemPath: minimal(["xz"]), shell: ["/bin/sh"] });
    refused(noXz, /xz is needed/);
    expect(noXz.calls).toBe("");
  });

  it("runs nothing when the download is cut short", () => {
    const full = installScript(ORIGIN, RELEASE);
    const cuts = [0.3, 0.6, 0.9].map((f) => Math.floor(full.length * f));
    cuts.push(full.lastIndexOf('main "$@"') + 'main "$@"'.length, full.lastIndexOf("}"));
    for (const cut of cuts) {
      const out = run({ script: full.slice(0, cut) });
      expect(out.status).not.toBe(0);
      expect(out.calls).toBe("");
      expect(out.installed).toBeNull();
    }
  });
});

// ── The release gate (scripts/release/check-cli-artifacts.sh) ───────────────

describe.skipIf(!canRun)("check-cli-artifacts.sh", () => {
  const checker = join(repoRoot, "scripts/release/check-cli-artifacts.sh");
  let n = 0;
  function release(
    edit: (lines: string[], dir: string) => string | null = (l) => `${l.join("\n")}\n\n`,
    extra = false,
  ) {
    const dir = join(work, `gate-${++n}`);
    mkdirSync(dir, { recursive: true });
    const lines: string[] = [];
    for (const target of CLI_RELEASE_TARGETS) {
      const tree = join(dir, `tree-${target}`);
      mkdirSync(join(tree, `wssp-${target}`), { recursive: true });
      writeFileSync(join(tree, `wssp-${target}/wssp`), binaryScript(`wssp ${SERVER_VERSION}`), {
        mode: 0o755,
      });
      const archive = `wssp-${target}.tar.xz`;
      const members = [`wssp-${target}`];
      if (extra) {
        writeFileSync(join(tree, "outside"), "x\n");
        members.push("outside");
      }
      execFileSync("tar", ["-cJf", join(dir, archive), ...members], { cwd: tree });
      execFileSync("rm", ["-rf", tree]);
      const digest = createHash("sha256")
        .update(readFileSync(join(dir, archive)))
        .digest("hex");
      lines.push(`${digest}  ${archive}`);
    }
    const sums = edit(lines, dir);
    if (sums !== null) writeFileSync(join(dir, "sha256.sum"), sums);
    const result = spawnSync("sh", [checker, dir], { encoding: "utf8" });
    return { dir, status: result.status, output: `${result.stdout}${result.stderr}` };
  }

  it("passes a complete release and strips cargo-dist's trailing blank line", () => {
    const out = release();
    expect(out.status).toBe(0);
    expect(readFileSync(join(out.dir, "sha256.sum"), "utf8")).not.toMatch(/\n\n/);
  });

  it("refuses a missing, duplicated, malformed or wrong checksum, or a missing archive", () => {
    expect(release(() => null).output).toMatch(/sha256\.sum is missing/);
    expect(release((l) => `${l[0]}\n`).output).toMatch(/exactly one/);
    expect(release((l) => `${l.join("\n")}\n${l[0]}\n`).output).toMatch(/exactly one/);
    expect(release((l) => `${l[0]}\n${l[1]?.replace(/^./, "z")}\n`).output).toMatch(/exactly one/);
    const wrong = release((l) => `${l[0]}\n${"0".repeat(64)}  ${l[1]?.split("  ")[1]}\n`);
    expect(wrong.status).not.toBe(0);
    const missing = release((l, dir) => {
      execFileSync("rm", [join(dir, `wssp-${CLI_RELEASE_TARGETS[1]}.tar.xz`)]);
      return `${l.join("\n")}\n`;
    });
    expect(missing.output).toMatch(/is missing from the release artifacts/);
    expect(release(undefined, true).output).toMatch(/must hold only wssp-/);
  });
});
