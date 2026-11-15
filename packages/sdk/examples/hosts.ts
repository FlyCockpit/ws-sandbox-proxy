import { createWsspClient } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});
const hostId = "host_1";
const host = await wssp.hosts.get(hostId); // hosts:read

// hosts:execute requires your own host, a host grant, and agent commands
// enabled at the node. Commands run as the node daemon user (which may be an
// Incus admin) and can reach other users' sandboxes; ownSandboxesOnly does not
// limit them.
if (host.agentAccess.owned && host.agentAccess.hostCommands) {
  const result = await wssp.hosts.commands.run(
    hostId,
    { argv: ["uname", "-a"], timeoutMs: 10_000 },
    { idempotencyKey: "host-uname-1", waitTimeoutMs: 30_000 },
  );
  console.log(result.commandId, result.state, result.stdoutText, result.truncated);
}

// Queueing only asks a person to run it. It works even while agent commands
// are disabled; the SDK cannot approve, run or dismiss a queued command.
const queued = await wssp.hosts.queueCommand(hostId, {
  command: "incus list",
  reason: "Please inspect the node's current instances",
  expiresInHours: 24,
});
console.log(await wssp.hosts.getQueuedCommand(hostId, queued.id));

// hosts:files: paths must be inside roots the node owner configured. Reads
// mask secrets. Write a new file, or use the read etag to replace/edit one.
if (host.agentAccess.owned && host.agentAccess.hostFiles) {
  const file = await wssp.hosts.files.read(hostId, { path: "/srv/agent-work/note.txt" });
  await wssp.hosts.files.edit(hostId, {
    path: "/srv/agent-work/note.txt",
    expectedEtag: file.etag,
    edits: [{ oldText: "pending", newText: "reviewed" }],
  });
}
