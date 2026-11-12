import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";

const zeroPolicy = vi.hoisted(() => ({ enabled: false }));
vi.mock("../../../sandbox-contracts/src/command-timeout-policy", () => ({
  get commandTimeoutZeroEnabled() {
    return zeroPolicy.enabled;
  },
}));
afterEach(() => {
  zeroPolicy.enabled = false;
});

vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
}));

import {
  commandPayloadWithinLimit,
  SANDBOX_COMMAND_PAYLOAD_MAX_BYTES,
  serializedCommandPayloadBytes,
} from "./command-payload";
import {
  effectiveCommandTimeoutMs,
  encodeCommandTimeoutMs,
  listDirInput,
  mkdirInput,
  movePathInput,
  readFileInput,
  removePathInput,
  runCommandInput,
  SANDBOX_COMMAND_TIMEOUT_DEFAULT_MS,
  SANDBOX_COMMAND_TIMEOUT_MAX_MS,
  statPathInput,
} from "./contracts";
import { hashRequestBody } from "./idempotency";

const base = {
  id: "sandbox-1",
  idempotencyKey: "cmd-1",
  argv: ["true"],
};

describe("runCommandInput timeoutMs", () => {
  it("defaults omitted timeoutMs to 120s", () => {
    expect(runCommandInput.parse(base).timeoutMs).toBe(SANDBOX_COMMAND_TIMEOUT_DEFAULT_MS);
  });

  it("keeps an explicit in-range timeout", () => {
    expect(runCommandInput.parse({ ...base, timeoutMs: 5_000 }).timeoutMs).toBe(5_000);
    expect(
      runCommandInput.parse({ ...base, timeoutMs: SANDBOX_COMMAND_TIMEOUT_MAX_MS }).timeoutMs,
    ).toBe(SANDBOX_COMMAND_TIMEOUT_MAX_MS);
  });

  it("rejects zero and values above 1800s", () => {
    expect(runCommandInput.safeParse({ ...base, timeoutMs: 0 }).success).toBe(false);
    expect(
      runCommandInput.safeParse({ ...base, timeoutMs: SANDBOX_COMMAND_TIMEOUT_MAX_MS + 1 }).success,
    ).toBe(false);
  });
});

describe("effectiveCommandTimeoutMs", () => {
  it("distinguishes zero/default and refuses malformed persisted values", () => {
    for (const value of [undefined, 1, 80, 120000, 1800000]) {
      expect(effectiveCommandTimeoutMs(value)).toEqual({ kind: "deadline", ms: value ?? 120000 });
      expect(encodeCommandTimeoutMs(effectiveCommandTimeoutMs(value))).toBe(value ?? 120000);
    }
    expect(effectiveCommandTimeoutMs(0)).toEqual({ kind: "none" });
    expect(encodeCommandTimeoutMs(effectiveCommandTimeoutMs(0))).toBe(0);
    for (const value of [null, "0", -1, 0.5, NaN, Infinity, 1800001])
      expect(() => effectiveCommandTimeoutMs(value)).toThrow("Invalid stored command timeout.");
  });
});

describe("runCommandInput script/argv contract (C15)", () => {
  const goldenScript: string = JSON.parse(
    readFileSync(
      new URL(
        "../../../../crates/sandbox-protocol/fixtures/control_operation_dispatch_script.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ).script;

  it("accepts a multiline script longer than 512 bytes", () => {
    const parsed = runCommandInput.parse({
      id: "sandbox-1",
      idempotencyKey: "script-1",
      script: goldenScript,
    });
    expect(parsed.script).toBe(goldenScript);
    expect(parsed.argv).toBeUndefined();
  });

  it("rejects both argv and script and neither mode", () => {
    expect(runCommandInput.safeParse({ ...base, argv: ["true"], script: "echo" }).success).toBe(
      false,
    );
    expect(runCommandInput.safeParse({ ...base, argv: undefined, script: undefined }).success).toBe(
      false,
    );
  });

  it("preserves argv empty-string entries without trimming", () => {
    expect(runCommandInput.parse({ ...base, argv: ["", "echo"] }).argv).toEqual(["", "echo"]);
  });

  it("rejects oversized serialized command payload before enqueue", () => {
    const script = "x".repeat(SANDBOX_COMMAND_PAYLOAD_MAX_BYTES);
    expect(runCommandInput.safeParse({ ...base, argv: undefined, script }).success).toBe(false);
    expect(
      commandPayloadWithinLimit({
        argv: ["y".repeat(SANDBOX_COMMAND_PAYLOAD_MAX_BYTES)],
      }),
    ).toBe(false);
  });

  it("shares UTF-8 encoded payload boundaries with Rust", () => {
    const cases: Array<{
      name: string;
      scriptUnit: string;
      repeat: number;
      envCount: number;
      envValueBytes: number;
      expectedBytes: number;
      valid: boolean;
    }> = JSON.parse(
      readFileSync(
        new URL(
          "../../../../crates/sandbox-protocol/fixtures/command_payload_cases.json",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    for (const fixture of cases) {
      const env: Array<[string, string]> = Array.from({ length: fixture.envCount }, (_, i) => [
        `KEY${i}`,
        "z".repeat(fixture.envValueBytes),
      ]);
      const parts = { script: fixture.scriptUnit.repeat(fixture.repeat), env };
      const envs = Object.fromEntries(env);
      expect(serializedCommandPayloadBytes(parts), fixture.name).toBe(fixture.expectedBytes);
      expect(commandPayloadWithinLimit(parts), fixture.name).toBe(fixture.valid);
      expect(
        runCommandInput.safeParse({ ...base, argv: undefined, script: parts.script, envs }).success,
        fixture.name,
      ).toBe(fixture.valid);
      if (!env.length)
        expect(serializedCommandPayloadBytes({ ...parts, env: undefined })).toBe(
          fixture.expectedBytes,
        );
    }
  });

  it("rejects NUL in script, argv, env values, and cwd", () => {
    expect(
      runCommandInput.safeParse({ ...base, script: undefined, argv: ["echo\0"] }).success,
    ).toBe(false);
    expect(runCommandInput.safeParse({ ...base, argv: undefined, script: "echo\0" }).success).toBe(
      false,
    );
    expect(
      runCommandInput.safeParse({
        ...base,
        argv: undefined,
        script: "true",
        cwd: "/tmp\0",
      }).success,
    ).toBe(false);
    expect(
      runCommandInput.safeParse({
        ...base,
        argv: undefined,
        script: "true",
        envs: { OK: "fine\0" },
      }).success,
    ).toBe(false);
  });

  it.each(["\ud800", "\udfff", "\ud800x", "x\udfff", "\udfff\ud800"])(
    "rejects unpaired UTF-16 surrogates %j in all command strings",
    (invalid) => {
      for (const fields of [
        { argv: ["echo", invalid] },
        { argv: undefined, script: `echo ${invalid}` },
        { cwd: `/tmp/${invalid}` },
        { envs: { KEY: invalid } },
        { envs: { [invalid]: "value" } },
      ]) {
        expect(runCommandInput.safeParse({ ...base, ...fields }).success).toBe(false);
      }
    },
  );

  it("preserves valid surrogate pairs in script, argv, cwd and env values", () => {
    const value = "a\ud83d\ude00z";
    for (const fields of [
      { argv: ["echo", value] },
      { argv: undefined, script: `echo ${value}` },
      { cwd: `/tmp/${value}` },
      { envs: { KEY: value } },
    ]) {
      expect(runCommandInput.safeParse({ ...base, ...fields }).success).toBe(true);
    }
  });

  it("shares argv count and per-argument UTF-16 limits with Rust", () => {
    const cases: Array<{
      name: string;
      argvCount: number;
      segment?: string;
      segmentCount?: number;
      argvValue?: string;
      valid: boolean;
    }> = JSON.parse(
      readFileSync(
        new URL(
          "../../../../crates/sandbox-protocol/fixtures/command_argv_cases.json",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    for (const fixture of cases) {
      const unit =
        fixture.argvValue ??
        (fixture.segment != null && fixture.segmentCount != null
          ? fixture.segment.repeat(fixture.segmentCount)
          : undefined);
      if (unit == null) throw new Error(`invalid argv fixture ${fixture.name}`);
      const argv = Array.from({ length: fixture.argvCount }, () => unit);
      expect(
        runCommandInput.safeParse({ ...base, argv, script: undefined }).success,
        fixture.name,
      ).toBe(fixture.valid);
    }
  });

  it("hashes exact script bytes for idempotency replay", () => {
    const body = {
      id: "sandbox-1",
      idempotencyKey: "script-hash",
      script: goldenScript,
    };
    const a = hashRequestBody(body);
    const b = hashRequestBody({ ...body, script: `${goldenScript} ` });
    expect(a).not.toBe(b);
    expect(hashRequestBody(body)).toBe(a);
  });
});

it("bounds caller idempotency keys to the ASCII receipt charset", () => {
  expect(runCommandInput.safeParse({ ...base, idempotencyKey: "a".repeat(128) }).success).toBe(
    true,
  );
  expect(runCommandInput.safeParse({ ...base, idempotencyKey: "a".repeat(129) }).success).toBe(
    false,
  );
  expect(runCommandInput.safeParse({ ...base, idempotencyKey: "é" }).success).toBe(false);
  expect(runCommandInput.safeParse({ ...base, idempotencyKey: "界".repeat(86) }).success).toBe(
    false,
  );
});

describe("file-operation guest paths (G4R1-1, G4R1-2)", () => {
  const at = { id: "sandbox-1", idempotencyKey: "op-1" };
  const inputs = {
    stat: (path: string) => statPathInput.safeParse({ ...at, path }),
    list: (path: string) => listDirInput.safeParse({ ...at, path }),
    read: (path: string) => readFileInput.safeParse({ ...at, path }),
    mkdir: (path: string) => mkdirInput.safeParse({ ...at, path }),
    remove: (path: string) => removePathInput.safeParse({ ...at, path }),
    moveFrom: (path: string) => movePathInput.safeParse({ ...at, path, destPath: "/tmp/b" }),
    moveTo: (path: string) => movePathInput.safeParse({ ...at, path: "/tmp/a", destPath: path }),
  };
  it("refuses surrounding whitespace everywhere instead of trimming it", () => {
    for (const path of [
      "/data/report ",
      " /data/report",
      "\t/data/report",
      "\n/data/report",
      "/data/report\n",
    ])
      for (const [name, parse] of Object.entries(inputs))
        expect(parse(path).success, `${name} ${JSON.stringify(path)}`).toBe(false);
  });
  it("keeps internal spaces, and the path exactly as sent", () => {
    for (const [name, parse] of Object.entries(inputs)) {
      const parsed = parse("/data/my report.txt");
      expect(parsed.success, name).toBe(true);
      const data = parsed.data as { path: string; destPath?: string };
      expect(name === "moveTo" ? data.destPath : data.path).toBe(
        name === "moveTo" ? "/data/my report.txt" : "/data/my report.txt",
      );
    }
  });
  it("refuses `/` as a mutation target but not for stat or list", () => {
    for (const name of ["read", "mkdir", "remove", "moveFrom", "moveTo"] as const)
      expect(inputs[name]("/").success, name).toBe(false);
    for (const name of ["stat", "list"] as const)
      expect(inputs[name]("/").success, name).toBe(true);
  });
});

describe("D-20 command duration landing switch", () => {
  it.each([false, true])(
    "shares public, oRPC and private-default validation (enabled=%s)",
    async (enabled) => {
      zeroPolicy.enabled = enabled;
      const { commandBodySchema, FS_PROCESS_LIMITS } = await import("@wssp/sandbox-contracts");
      const { validateCommandEnvironmentUnion } = await import("./execution-config");
      expect(FS_PROCESS_LIMITS.commandTimeoutZero).toBe(enabled);
      for (const value of [
        undefined,
        0,
        1,
        120000,
        1800000,
        -1,
        0.5,
        NaN,
        Infinity,
        1800001,
        null,
        "0",
      ]) {
        const valid =
          value === undefined ||
          (typeof value === "number" &&
            Number.isInteger(value) &&
            value >= (enabled ? 0 : 1) &&
            value <= 1800000);
        expect(commandBodySchema.safeParse({ argv: ["true"], timeoutMs: value }).success).toBe(
          valid,
        );
        expect(runCommandInput.safeParse({ ...base, timeoutMs: value }).success).toBe(valid);
        const validate = () =>
          validateCommandEnvironmentUnion({ argv: ["true"], timeoutMs: value }, [
            ["DEFAULT", "present"],
          ]);
        if (valid) expect(validate()).toEqual([["DEFAULT", "present"]]);
        else expect(validate).toThrow();
      }
    },
  );
  it("preserves zero and legacy omission in dispatch builders and sizing", async () => {
    const {
      commandRunDispatchBuildInputFromOutboxPayload: fromPayload,
      buildCommandRunOperationDispatchMessage: build,
      commandRunDispatchBuildInputForEnqueueGuard: guard,
    } = await import("./dispatch-control-envelope");
    for (const timeoutMs of [undefined, 0, 1, 120000, 1800000]) {
      const payload = { operationId: "op", argv: ["true"], timeoutMs };
      const input = fromPayload(payload, "sbx", {
        attempt: 1,
        bodyHash: "a".repeat(64),
        stdinSequence: 0,
      });
      expect(input.timeoutMs).toBe(timeoutMs ?? 120000);
      expect(JSON.parse(JSON.stringify(build(input))).timeoutMs).toBe(timeoutMs ?? 120000);
      expect(guard(payload, "sbx").timeoutMs).toBe(timeoutMs ?? 120000);
    }
    for (const timeoutMs of [null, "0", -1, 0.5, NaN, Infinity, 1800001])
      expect(() =>
        fromPayload({ timeoutMs }, "sbx", { attempt: 1, bodyHash: "", stdinSequence: 0 }),
      ).toThrow();
  });
});
