import { createWsspClient } from "@wssp/sdk";

// The SDK never reads the environment: your program passes the key in.
const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "", // a `wssp_sdk_…` key from the dashboard
});

// Create pins the sandbox to one of your hosts and one of its templates. It
// resolves only once the operation succeeded and the sandbox reads READY.
const sandbox = await wssp.sandboxes.create({
  name: "ci-runner", // optional; omitted, the server picks a free one like "quiet-otter"
  cpuCount: 2,
  diskGiB: 32,
  memoryMiB: 2048,
  sandboxHostId: "host_…",
  template: "revision/" + "tpl_…",
  metadata: { purpose: "ci" },
  envs: { APP_MODE: "ci" }, // private defaults for commands and terminals
  // Open IPv4 internet by default. `allowInternetAccess: false` switches to
  // an allowlist of `egress.domains` / `egress.cidrs` (see the agent-browser
  // example); private and metadata ranges are always blocked.
  // Default: the guest user may run `sudo` inside the VM (`guestSudo: false`
  // turns it off). Commands, files and terminals still run as the guest user.
  guestSudo: true,
  lifecycle: { onTimeout: "kill" }, // default; the default lifetime is five minutes
});

console.log(sandbox.name, sandbox.id);

const result = await sandbox.commands.script("uname -a && id");
console.log(result.exitCode, result.stdout);
console.log((await sandbox.files.list("/home/user", { limit: 100 })).items);

await sandbox.destroy(); // resolves at confirmed deletion
