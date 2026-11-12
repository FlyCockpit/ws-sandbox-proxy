import { createWsspClient, isWsspError } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});

const sandboxId = "sbx_…";

// Natural nonzero completion throws CommandExitError; check:false returns it.
const build = await wssp.commands.run(
  sandboxId,
  {
    argv: ["make", "test"],
    cwd: "/home/user/repo",
    envs: { BUILD_MODE: "test" },
    timeoutMs: 15 * 60_000,
  },
  {
    onOutput: (event) => {
      if (event.kind === "data") process.stdout.write(event.text);
      else if (event.kind === "gap") console.warn(`[output gap ${event.start}..${event.end}]`);
      else console.warn(`[output reset to attempt ${event.attempt}]`);
    },
  },
);
console.log("exit", build.exitCode, "truncated", build.truncated);

// Convenience helpers keep the guest budget separate from the local wait.
await wssp.commands.script(sandboxId, "make bootstrap", {
  timeoutMs: 15 * 60_000,
  waitTimeoutMs: 16 * 60_000,
});
await wssp.commands.argv(sandboxId, ["sleep", "5"], {
  timeoutMs: 10_000,
  waitTimeoutMs: 60_000,
});

// Start waits for a guest-attested identity, then returns without following.
const server = await wssp.commands.start(sandboxId, { script: "./serve --port 8080" });
await server.writeStdin("ready\n");
console.log(await server.stat());

// Aborting detaches this observer; the command keeps running.
const controller = new AbortController();
setTimeout(() => controller.abort(), 30_000);
try {
  await wssp.commands.script(sandboxId, "sleep 600", { signal: controller.signal });
} catch (error) {
  if (!isWsspError(error)) throw error;
  // `aborted`: observation stopped. An uncertain submission is `unknown`.
  console.warn(error.kind, error.operationId);
}

// A fresh client can attach to the exact tracked incarnation. Output emitted
// between this committed snapshot and wait() is included; prior output is skipped.
const attached = await wssp.commands.connect(server.process);
try {
  await attached.wait({ check: false, waitTimeoutMs: 30_000 });
} catch (error) {
  if (!isWsspError(error) || !["timeout", "aborted"].includes(error.kind)) throw error;
  console.warn("observer stopped", error.kind);
} finally {
  attached.disconnect(); // subscriber only; server.kill() explicitly cancels
}
await server.closeStdin(); // EOF; disconnect never closes guest stdin

// Check the effective capability before requesting no command timer.
// When the host supports it, zero removes only the command timer.
const capabilities = await wssp.sandboxes.capabilities(sandboxId);
if (capabilities.limits.commandTimeoutZero) {
  const reader = await wssp.commands.start(
    sandboxId,
    { argv: ["cat"], timeoutMs: 0 },
    {
      waitTimeoutMs: 30_000,
    },
  );
  await reader.writeStdin("bounded observation, independent execution\n");
  await reader.closeStdin(); // read-until-EOF otherwise stays open
  await reader.wait({ waitTimeoutMs: 60_000 }); // finite; expiry detaches, never kills
}
