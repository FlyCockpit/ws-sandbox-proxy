import { createWsspClient, isWsspError } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
  polling: { waitTimeoutMs: 10 * 60_000 }, // default bound of every wait
});

const sandboxId = "sbx_…";

// Rename. Names are unique among your live sandboxes (`sandbox.name_taken`,
// kind `conflict`) and free again once a sandbox is deleted. `update` returns
// a fresh read; a bound `Sandbox` handle's own fields stay its snapshot.
const renamed = await wssp.sandboxes.update(sandboxId, { name: "nightly-build" });
console.log(renamed.name);

// Set the relative lifetime, at most the advertised deployment maximum. `effective` is the
// lease the HOST acknowledged, not merely the one requested.
const { effective } = await wssp.sandboxes.setTimeout(sandboxId, {
  timeoutMs: 2 * 60 * 60_000,
});
console.log("host enforces", effective.expiresAt, effective.onExpire);

// Stop can interrupt boot. A retained disk ends STOPPED; cold connect reuses it.
// If boot never made an instance, Stop succeeds with DELETED and releases capacity.
const stopped = await wssp.sandboxes.stop(sandboxId);
if (stopped.state === "STOPPED") {
  const sandbox = await wssp.sandboxes.connect(sandboxId, { mode: "cold" });
  console.log(
    sandbox.state,
    sandbox.generation,
    sandbox.sandbox.cpuCount,
    sandbox.sandbox.memoryMiB,
  );
}

// One idempotency key per intent. An `unknown` outcome means the request may
// have taken effect: the SAME key replays the original receipt. Teardown
// recovery allows a new key only for current-generation UNKNOWN teardown;
// the SDK does not retry UNKNOWN automatically.
const idempotencyKey = `nightly-stop:${sandboxId}:2026-10-24`;
try {
  await wssp.sandboxes.stop(sandboxId, { idempotencyKey });
} catch (error) {
  if (!isWsspError(error) || error.kind !== "unknown") throw error;
  console.warn("outcome unknown for operation", error.operationId);
  await wssp.sandboxes.stop(sandboxId, { idempotencyKey });
}

// Liveness asks the host to probe the guest; it awaits that answer.
console.log("alive:", await wssp.sandboxes.isAlive(sandboxId));

// Discovery defaults to READY. Filters are exact-match AND in SQL before pagination.
const filters = {
  metadata: { purpose: "ci", team: "infra" },
  states: ["READY", "STOPPED"] as const,
};
const first = await wssp.sandboxes.list({
  metadata: filters.metadata,
  states: [...filters.states],
  templateId: "tpl_…",
  startedAfter: "2026-09-26T00:00:00.000Z",
  order: "desc",
  limit: 10, // numeric; the low-level HTTP transport still uses wire strings
});
if (first.nextCursor) {
  const next = await wssp.sandboxes.list({
    metadata: filters.metadata,
    states: [...filters.states],
    templateId: "tpl_…",
    startedAfter: "2026-09-26T00:00:00.000Z",
    order: "desc",
    limit: 10,
    cursor: first.nextCursor, // reuse with the same owner, filters and order
  });
  console.log(next.items.map((item) => item.id));
}
