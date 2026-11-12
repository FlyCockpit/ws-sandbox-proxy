// Rewrites every generated artifact (schema, digests, max-input and bundle
// vectors). `src/vectors.test.ts` fails until the committed bytes match.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generatedFiles, PACKAGE_ROOT } from "./generated";

for (const [path, bytes] of await generatedFiles()) {
  const target = fileURLToPath(new URL(path, PACKAGE_ROOT));
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, bytes);
  console.log(`wrote ${path}`);
}
