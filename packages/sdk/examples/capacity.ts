import { createWsspClient, isCapacityWaitTimeout, isWsspError } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});
const poolId = "pool_id";
// What fits now (aggregates over hosts you can schedule on; your own hosts in
// detail with hosts:read), the lease limits and the queue.
const capacity = await wssp.pools.capacity(poolId, { template: "my-template:latest" });
console.log(capacity.fits, capacity.queue.waiting, capacity.queue.limits.maxWaitMs);
try {
  // Wait up to 30 minutes in the pool's FIFO queue if no host fits now. The
  // lease (timeoutMs) starts only when the create is placed.
  const sandbox = await wssp.sandboxes.create({
    template: "my-template:latest",
    poolId,
    waitForCapacityMs: 30 * 60_000,
  });
  await sandbox.destroy();
} catch (error) {
  if (isCapacityWaitTimeout(error)) {
    // The wait ended on the server: nothing was allocated.
    console.log("no capacity within 30 minutes");
  } else if (isWsspError(error) && error.sandboxId) {
    // The local wait ended but the queued create remains: destroy cancels it.
    await wssp.sandboxes.destroy(error.sandboxId);
  } else if (isWsspError(error) && error.code === "capacity_wait_exceeds_policy") {
    console.log("largest allowed wait", error.maxWaitMs);
  } else {
    throw error;
  }
}
