import { describe, expect, it } from "vitest";
import { localServiceConfiguration } from "../../../scripts/setup.js";
import { parseEnvContents } from "./root-env.js";

const local =
  "DATABASE_URL=postgresql://postgres:password@localhost:5432/wssp\nREDIS_URL=redis://localhost:6379\n";

describe("local setup datastore ports", () => {
  it("propagates selected Compose ports into both URLs and the persisted configuration", () => {
    const configured = localServiceConfiguration(local, {
      DEV_POSTGRES_PORT: "15432",
      DEV_REDIS_PORT: "16379",
    });
    const parsed = parseEnvContents(configured.contents);
    expect(new URL(parsed.DATABASE_URL!).port).toBe("15432");
    expect(new URL(parsed.REDIS_URL!).port).toBe("16379");
    expect(parsed.DEV_POSTGRES_PORT).toBe("15432");
    expect(parsed.DEV_REDIS_PORT).toBe("16379");
    expect(new URL(parsed.DATABASE_URL!).password).toBe("password");
  });

  it("uses dotenv last-wins semantics and preserves already selected local ports", () => {
    const contents = local + "export DEV_POSTGRES_PORT=15433\nDEV_POSTGRES_PORT=15434\n";
    expect(localServiceConfiguration(contents).ports).toEqual({
      DEV_POSTGRES_PORT: "15434",
      DEV_REDIS_PORT: "6379",
    });
  });

  it("rejects invalid ports and remote URLs before starting local services", () => {
    for (const port of ["0", "65536", "x", "12.5"]) {
      expect(() => localServiceConfiguration(local, { DEV_POSTGRES_PORT: port })).toThrow(
        "DEV_POSTGRES_PORT must be an integer",
      );
    }
    expect(() =>
      localServiceConfiguration(local, { DATABASE_URL: "postgresql://remote.invalid/wssp" }),
    ).toThrow("loopback");
  });
});
