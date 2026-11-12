import { createWsspClient } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
  polling: { waitTimeoutMs: 10 * 60_000 },
});
const hostId = "<owned-host-id>";
const revisionId = "<verified-agent-browser-revision-id>";

const sandbox = await wssp.sandboxes.create({
  cpuCount: 2,
  memoryMiB: 2048,
  sandboxHostId: hostId,
  template: `revision/${revisionId}`,
  // Allowlist mode: only these names (host-resolved IPv4 addresses) are reachable.
  allowInternetAccess: false,
  egress: { domains: ["example.com", "en.wikipedia.org", "upload.wikimedia.org"] },
  timeoutMs: 30 * 60_000,
  lifecycle: { onTimeout: "kill" },
});
try {
  // Sandbox on. Other mode: agent-browser --args --no-sandbox open <url>
  const result = await wssp.commands.script(
    sandbox.id,
    "agent-browser open https://example.com && agent-browser screenshot /home/user/shot.png",
    { timeoutMs: 120_000 },
  );
  const png = Buffer.from(
    await (await wssp.files.download(sandbox.id, "/home/user/shot.png")).bytes(),
  );
  console.log(result.exitCode, png.byteLength);
} finally {
  await wssp.sandboxes.destroy(sandbox.id);
}
