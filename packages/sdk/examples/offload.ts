import { createWsspClient, isWsspError } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});

const sandboxId = "sbx_…";

// A stopped disk may be copied to the image store in the background
// (`disk.location`: host → host_and_store) and later evicted from its host
// (state OFFLOADED, `disk.location: "store"`). Stop resolves on any of
// STOPPED, OFFLOADED or DELETED.
const stopped = await wssp.sandboxes.stop(sandboxId);
console.log(stopped.state, stopped.disk?.location, stopped.disk?.offloadState);
if (stopped.disk?.offloadState === "failed") {
  // The disk stays on its host; `quota_exceeded` means the stored quota is used.
  console.log("not offloaded:", stopped.disk.offloadFailure);
}

// Offload policy: when a stopped disk is exported. `on_stop` (the default)
// exports at once; `after` waits `afterMs` of being stopped; `on_pressure`
// keeps it on its host until the host needs the space. Host pressure and
// `wssp drain --offload` export early whatever the policy. Set it at create
// (`offload`), with a stop (`stop(id, { offload })`), or later with `update`.
const parked = await wssp.sandboxes.update(sandboxId, { offload: { mode: "on_pressure" } });
console.log(parked.disk?.offloadPolicy, parked.disk?.offloadDueAt); // null: not due
// Export it once it has been stopped for two hours, unless resumed first.
const later = await wssp.sandboxes.update(sandboxId, {
  offload: { mode: "after", afterMs: 2 * 60 * 60_000 },
});
console.log(later.disk?.offloadDueAt);

// Starting an OFFLOADED sandbox restores its disk onto an eligible host
// (progress phases fetching_disk, importing_disk). `disk.eligibility`
// says whether other users' hosts may take it (`any_host`) or only yours.
try {
  const sandbox = await wssp.sandboxes.connect(sandboxId, {
    mode: "cold",
    // Wait up to 10 minutes for a host this restore may use to have room.
    waitForCapacityMs: 10 * 60_000,
  });
  console.log(sandbox.state, sandbox.sandbox.disk?.location);
} catch (error) {
  if (isWsspError(error) && error.code === "restore_no_allowed_host") {
    // No allowed host had room before the wait ended; the stored copy is kept.
    console.log("add capacity or widen the key's allowlists, then start again");
  } else if (isWsspError(error) && error.code === "sandbox.disk_unavailable") {
    console.log("the image store or data key is not configured on this deployment");
  } else {
    throw error;
  }
}
