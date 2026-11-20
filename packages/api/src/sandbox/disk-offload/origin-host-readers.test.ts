import { readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Sweep S19 with the plan's alternation
 * (`originHostId` over packages/api/src and apps/server/src). A restore
 * moves a sandbox to another host while `Sandbox.originHostId` stays the
 * first host's, so every non-comment occurrence is classified:
 * - authorization: the CURRENT host (§5a) — a current/latest placement's
 *   host, a bound `sandboxHostId` first, or a legacy context that
 *   `currentCustodyAllowed` re-resolves at request and dispatch time;
 * - remnant: the host of the latest retained placement (§8.10 item 2);
 * - history: provenance writes and copies, digest snapshots, per-placement
 *   accounting — never read as "where it is now".
 * A new occurrence fails until it is classified here.
 */
const ROOT = resolve(import.meta.dirname, "../../../../..");
const SCAN = ["packages/api/src", "apps/server/src"];

type ReaderClass = "authorization" | "remnant" | "history";

const CLASSIFIED: Record<string, Partial<Record<ReaderClass, number>>> = {
  // requireRelayWorkload: the current placement's host (DELETED included).
  // requireRelayReceiptWorkload: a hostless sandbox's terminal receipt, the
  // retained placement the operation ran under (§8.10).
  "packages/api/src/sandbox/relay-fence.ts": { authorization: 2, remnant: 2 },
  // Action-receipt replay context; custody re-resolved by the access check.
  "packages/api/src/sandbox/action-receipts.ts": { authorization: 2 },
  // Current-placement host lock check.
  "packages/api/src/sandbox/host-admission.ts": { authorization: 2 },
  // Process controls: the transport is the bound (current) host.
  "packages/api/src/sandbox/process-controls.ts": { authorization: 8 },
  // Per-placement image-fetch byte accounting.
  "packages/api/src/sandbox/image-placement.ts": { history: 2 },
  // Current placement vs bound host (guest access, host custody).
  "packages/api/src/sandbox/sharing-access.ts": { authorization: 4 },
  // Placement provenance writes (create).
  "packages/api/src/sandbox/placement-materialize.ts": { history: 2 },
  // The restore's target placement write.
  "packages/api/src/sandbox/disk-offload/restore-admit.ts": { history: 1 },
  // Current placement host check of a pool binding.
  "packages/api/src/sandbox/sharing-authority.ts": { authorization: 2 },
  // Cold reconnect: copies the previous placement; reserves on the bound host.
  "packages/api/src/sandbox/services/sandboxes.ts": { history: 1, authorization: 1 },
  // `readSandboxCustody` / the request context (current host, §5a).
  "packages/api/src/lib/sdk-key-access.ts": { authorization: 4 },
  // A restore fetch grant names its own placement's host.
  "apps/server/src/sandbox-relay/image-authority.ts": { authorization: 2 },
  // Dispatch revalidation contexts (custody re-resolved).
  "apps/server/src/sandbox-relay/outbox-processor.ts": { authorization: 2 },
  "apps/server/src/sandbox-relay/dispatch-gates.ts": { authorization: 2 },
  "apps/server/src/sandbox-relay/session-manager.ts": { authorization: 2 },
  "apps/server/src/sandbox-relay/operation-handlers.ts": { authorization: 2 },
  // "Last ran here": the latest retained placement.
  "apps/server/src/sandbox-relay/inventory-reconcile.ts": { remnant: 2 },
  // Digest snapshot of the acceptance transport (replay never re-derives).
  // A terminal ticket's binding against its placement's host.
  "packages/api/src/sandbox/terminal-tickets.ts": { authorization: 2 },
  // A CLI connection's binding against its placement's host (like a terminal ticket).
  "packages/api/src/sandbox/connect-binding.ts": { authorization: 2 },
  // Request transport identity: current placement first.
  "packages/api/src/sandbox/idempotency.ts": { authorization: 4 },
  // Config pin against the current placement's host.
  "packages/api/src/sandbox/execution-config.ts": { authorization: 2 },
};

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!["node_modules", "testing", "generated"].includes(entry.name))
        out.push(...sources(path));
    } else if (
      entry.name.endsWith(".ts") &&
      !entry.name.endsWith(".d.ts") &&
      !/\.(test|pg\.test|s3\.test)\.ts$/.test(entry.name) &&
      !entry.name.includes("harness")
    )
      out.push(path);
  }
  return out;
}

describe("S19: every originHostId reader is classified (§8.10, U2)", () => {
  it("counts per file match the classification", () => {
    const counts: Record<string, number> = {};
    for (const file of SCAN.flatMap((dir) => sources(resolve(ROOT, dir))))
      for (const line of readFileSync(file, "utf8").split("\n")) {
        const text = line.trim();
        if (!text.includes("originHostId") || /^(\/\/|\*|\/\*)/.test(text)) continue;
        const key = relative(ROOT, file);
        counts[key] = (counts[key] ?? 0) + 1;
      }
    const expected = Object.fromEntries(
      Object.entries(CLASSIFIED).map(([file, classes]) => [
        file,
        Object.values(classes).reduce((n, c) => n + (c ?? 0), 0),
      ]),
    );
    expect(counts).toEqual(expected);
  });
});
