import { readFile } from "node:fs/promises";
import { createWsspClient } from "@wssp/sdk";

// A key with `credentials:write` (and `credentials:read` to list). Values are
// write-only: nothing below ever reads one back.
const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});

// 1. Store your own login definition (see docs/guide/cli-logins.md).
const definition = await wssp.credentials.definitions.create({
  text: await readFile("tool-login.json", "utf8"),
});

// 2. A login pinned to that version, one account, one instance.
const login = await wssp.credentials.create({ name: "tool", definitionId: definition.id });
const account = await wssp.credentials.accounts.create(login.id, { name: "work" });
const instance = await wssp.credentials.instances.create(login.id, account.id);

// 3. Upload the token files (base64) and env; the response is metadata only.
const written = await wssp.credentials.instances.writeValue(login.id, instance.id, {
  files: [
    { path: ".config/tool", kind: "dir" },
    {
      path: ".config/tool/token.json",
      contentBase64: (await readFile("token.json")).toString("base64"),
    },
  ],
});
console.log(`instance ${written.instanceId} is ${written.state} at seq ${written.storageSeq}`);

// 4. With `credentials:use` and `sandboxes:manage`: attach the login to a
//    running sandbox (new commands and terminals see it), then free it: the
//    env leaves at once, terminals opened with it close, and the files are
//    copied back and scrubbed. A stopped sandbox claims an attached login at
//    its next start; `connect({ credentials })` pins an account or instance.
const sandbox = await wssp.sandboxes.connect(process.env.WSSP_SANDBOX_ID ?? "");
await sandbox.credentials.attach({ credentialId: login.id, accountId: account.id });
await sandbox.commands.run({ argv: ["tool", "whoami"] });
await sandbox.credentials.free(login.id);

// 5. Pause the account: new sandboxes stop using it, running ones keep it.
await wssp.credentials.accounts.update(login.id, account.id, { paused: true });

// 6. Recover a stuck holder (`credentials:read` + `credentials:write`): list
//    the instance's live leases, then force-release one, keeping the newest
//    value its guest checkpointed.
const leases = await wssp.credentials.leases.list(login.id, instance.id);
const held = leases.items.find((lease) => lease.sandboxId === sandbox.id);
if (held)
  await wssp.credentials.leases.forceRelease(login.id, instance.id, held.id, {
    promoteCheckpoint: held.checkpoint !== null,
  });
