// Regenerates the committed static OpenAPI snapshot. `src/openapi.test.ts`
// fails until the snapshot matches the registry and DTO schemas.
import { writeFileSync } from "node:fs";
import { buildSdkOpenApiDocument } from "../src/openapi";

const target = new URL("../openapi.json", import.meta.url);
writeFileSync(target, `${JSON.stringify(buildSdkOpenApiDocument(), null, 2)}\n`);
console.log(`wrote ${target.pathname}`);
