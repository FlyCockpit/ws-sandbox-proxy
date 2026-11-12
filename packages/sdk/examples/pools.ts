import { createWsspClient, isWsspError } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});
const page = await wssp.pools.list({ limit: 20 });
const pool = page.items[0];
if (pool) {
  // Pool use trusts foreign host operators and their network/egress policy.
  // Shared members expose opaque IDs; owner metadata includes host labels.
  const members = await wssp.pools.members(pool.id, { limit: 20 });
  console.log(members.items.map((member) => ("host" in member ? member.host.label : member.id)));
  try {
    const sandbox = await wssp.sandboxes.create({
      template: "my-template:latest",
      poolId: pool.id, // exactly one of poolId or sandboxHostId
      memoryMiB: 2048, // CPU independently uses the selected revision default
      // Open internet on your own hosts and on hosts whose owner allows it.
      // Another user's host may allow only listed destinations: these
      // fallback grants then become the allowlist (`egressModeReason`).
      allowInternetAccess: true,
      egress: { domains: ["registry.npmjs.org"] },
    });
    console.log(sandbox.egress.mode, sandbox.egressModeReason);
    await sandbox.destroy();
  } catch (error) {
    if (
      isWsspError(error) &&
      (error.code === "sandbox.vm_size_unsupported" ||
        error.code === "sandbox.pool_full" ||
        error.code === "sandbox.pool_unavailable" ||
        error.code === "sandbox.host_capacity" ||
        // No member's network guard is running (retryable later).
        (error.code === "UNSUPPORTED_CAPABILITY" && error.reason === "egress_guard_unavailable"))
    ) {
      // A definitive refusal made no allocation; a provider fallback is safe.
      console.log(error.code);
    } else {
      // Preserve the idempotency key / operation ID for an uncertain outcome.
      throw error;
    }
  }
}
