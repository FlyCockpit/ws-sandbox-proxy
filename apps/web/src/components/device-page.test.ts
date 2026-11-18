import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { build } from "vite";
import { it } from "vitest";

/** Uses installed Chrome/Chromium (including Playwright's existing cache), never downloads. */
function chromium() {
  const cache = join(homedir(), ".cache/ms-playwright");
  const candidates = [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ];
  if (existsSync(cache))
    for (const dir of readdirSync(cache).sort().reverse()) {
      candidates.push(join(cache, dir, "chrome-headless-shell-linux64/chrome-headless-shell"));
      candidates.push(join(cache, dir, "chrome-linux64/chrome"));
    }
  const found = candidates.find(existsSync);
  if (!found) throw new Error("DevicePage DOM test requires an installed Chrome/Chromium browser.");
  return found;
}
/**
 * The bundle is the same for every mode (the mode is set in the page), so it is
 * built once and shared by every case.
 */
let deviceBundle: Promise<string> | undefined;
function deviceBundleCode(): Promise<string> {
  deviceBundle ??= buildDeviceBundle();
  return deviceBundle;
}

async function buildDeviceBundle(): Promise<string> {
  const stubs: Record<string, string> = {
    "@wssp/env/web": 'export const env = { VITE_SERVER_URL: "https://api.example.test" };',
    "@/utils/orpc": `export const orpc = { hostCredentials: { deviceLoginRequest: { queryOptions: ({input}) => ({ queryKey: ["device-login-request", "owner-1", globalThis.deviceTestSummary?.requestId ?? "pending", { userCode: input.userCode }], queryFn: async () => { globalThis.deviceTestQueries++; if (globalThis.deviceTestSummaryDelayMs) await new Promise((resolve) => setTimeout(resolve, globalThis.deviceTestSummaryDelayMs)); if (globalThis.deviceTestSummaryError) throw globalThis.deviceTestSummaryError; return globalThis.deviceTestSummary; } }) } }, sandboxHosts: { key: () => ["hosts"] }, sdkKeys: { list: { key: () => ["sdk-keys"] } }, sandboxPools: { listUsable: { key: () => ["pools"], infiniteOptions: ({ input, initialPageParam, getNextPageParam }) => ({ queryKey: ["pools", "infinite"], initialPageParam, getNextPageParam, queryFn: async ({ pageParam }) => { input(pageParam); globalThis.deviceTestPoolQueries++; if (globalThis.deviceTestPoolError) throw globalThis.deviceTestPoolError; return { items: globalThis.deviceTestPools ?? [], nextCursor: null }; } }) } } };`,
    "@/utils/friendly-error": "export const friendly = (_error, fallback) => fallback;",
    "@wssp/ui/components/sileo":
      "export const toast = { success() { globalThis.deviceTestToasts = (globalThis.deviceTestToasts ?? 0) + 1; }, error(message) { globalThis.deviceTestToasts = (globalThis.deviceTestToasts ?? 0) + 1; (globalThis.deviceTestToastErrors ??= []).push(message); } };",
    "@tanstack/react-router":
      'import { createElement } from "react"; export const Link = ({ children, to, params, className }) => createElement("a", { "data-to": to, "data-params": JSON.stringify(params), className }, children);',
  };
  const bundle = await build({
    configFile: false,
    logLevel: "silent",
    resolve: {
      alias: [
        ...Object.keys(stubs).map((id) => ({ find: id, replacement: `\0device-test:${id}` })),
        { find: "@", replacement: fileURLToPath(new URL("../", import.meta.url)) },
      ],
    },
    plugins: [
      {
        name: "device-test-boundaries",
        enforce: "pre",
        resolveId(id) {
          return id in stubs ? `\0device-test:${id}` : null;
        },
        load(id) {
          return id.startsWith("\0device-test:") ? stubs[id.slice(13)] : null;
        },
      },
    ],
    define: { "process.env.NODE_ENV": '"development"' },
    build: {
      write: false,
      minify: false,
      lib: {
        entry: fileURLToPath(new URL("./device-page.browser.tsx", import.meta.url)),
        name: "DeviceDOM",
        formats: ["iife"],
      },
    },
  });
  const outputs = Array.isArray(bundle) ? bundle : [bundle];
  return outputs
    .flatMap((result) => ("output" in result ? result.output : []))
    .filter((output) => output.type === "chunk")
    .map((output) => output.code)
    .join("\n");
}

// Each case has its own temp directory and Chrome profile, so cases run concurrently.
it.concurrent.for([
  "empty",
  "create",
  "replace",
  "claim-failure",
  "deny",
  "reentry-approved",
  "reentry-denied",
  "late-approve",
  "late-deny",
  "late-error",
  "recycled-user-code",
  "host-limit",
  "user-default",
  "user-selected",
  "user-invalid",
  "user-deny",
  "user-refetch-error",
])("DevicePage DOM: %s", { timeout: 30_000 }, async (mode, { expect }) => {
  const directory = mkdtempSync(join(tmpdir(), "wssp-device-dom-"));
  try {
    const code = await deviceBundleCode();
    const html = join(directory, "index.html");
    writeFileSync(
      html,
      `<html><body><script>globalThis.deviceTestMode = ${JSON.stringify(mode)};${code.replaceAll("</script", "<\\/script")}</script></body></html>`,
    );
    const { stdout } = await promisify(execFile)(
      chromium(),
      [
        "--headless",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-background-networking",
        "--disable-dev-shm-usage",
        `--user-data-dir=${join(directory, "profile")}`,
        "--virtual-time-budget=5000",
        "--dump-dom",
        `file://${html}`,
      ],
      { timeout: 20_000, maxBuffer: 5_000_000 },
    );
    expect(stdout).toContain(`DEVICE_DOM_PASS:${mode}`);
    expect(stdout).not.toContain("DEVICE_DOM_FAIL:");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
