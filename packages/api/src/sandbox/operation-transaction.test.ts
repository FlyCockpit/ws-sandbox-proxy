import { readdirSync, readFileSync } from "node:fs";
import { parse } from "@babel/parser";
import { expect, it } from "vitest";

it("every service operation insert is inside the shared idempotency transaction", () => {
  let inserts = 0;
  let boundaries = 0;
  const directory = new URL("./services/", import.meta.url);
  for (const file of readdirSync(directory).filter(
    (name) => name.endsWith(".ts") && !name.endsWith(".test.ts"),
  )) {
    const source = readFileSync(new URL(file, directory), "utf8");
    function visit(value: unknown, within = false) {
      if (Array.isArray(value)) {
        for (const child of value) visit(child, within);
        return;
      }
      if (!value || typeof value !== "object") return;
      const node = value as Record<string, unknown>;
      if (node.type === "CallExpression" && node.callee && typeof node.callee === "object") {
        const callee = node.callee as { start: number; end: number; name?: string };
        if (callee.name === "operationTransaction") {
          boundaries++;
          within = true;
        }
        // Inserts delegated to the placement/queue helpers count at their
        // service call site, which must itself be inside the boundary.
        if (
          /\.sandboxOperation\.create$|^(?:materializePlacement|enqueueCapacityWait|recordWaitingTeardown)$/.test(
            source.slice(callee.start, callee.end),
          )
        ) {
          inserts++;
          expect(within, `${file}: operation insert bypassed the owner/key replay boundary`).toBe(
            true,
          );
        }
      }
      for (const child of Object.values(node)) visit(child, within);
    }
    visit(parse(source, { sourceType: "module", plugins: ["typescript"] }));
  }
  // enqueue + kill inline (plus kill's server-completed OFFLOADED destroy,
  // offload §8.9); create (materialize/enqueue), kill (waiting and
  // already-DELETED teardown) and stop (waiting teardown) through helpers.
  expect(inserts).toBe(8);
  expect(boundaries).toBe(4); // shared enqueue, create, kill, lease renewal
});
