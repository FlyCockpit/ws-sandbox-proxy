import { afterEach, expect, it, vi } from "vitest";
import { FS_PROCESS_LIMITS, guestApiCapabilities } from "./dto";
import { commandOutputPageSchema } from "./output";
import { enabledSdkFeatures, SDK_ROUTE_IDS, SDK_ROUTES, sdkRouteErrorStatuses } from "./routes";

const zeroPolicy = vi.hoisted(() => ({ enabled: false }));
vi.mock("./command-timeout-policy", () => ({
  get commandTimeoutZeroEnabled() {
    return zeroPolicy.enabled;
  },
}));
afterEach(() => {
  zeroPolicy.enabled = false;
});
it.each([false, true])("reports command zero policy state %s", (enabled) => {
  zeroPolicy.enabled = enabled;
  expect(FS_PROCESS_LIMITS.commandTimeoutZero).toBe(enabled);
});

it("requires every endpoint for a feature, including status/result/output dependencies", () => {
  const dependencies = {
    "files.list": ["listDir", "getOperation", "getOperationResult"],
    "commands.background": ["startCommand", "getOperation", "getOperationResult"],
    "processes.connect": ["connectProcess", "getOperation", "getCommandOutput"],
    "processes.signal": ["signalProcess", "killProcess", "getOperation"],
  } as const;
  for (const [feature, required] of Object.entries(dependencies)) {
    for (const missing of required)
      expect(
        enabledSdkFeatures(SDK_ROUTE_IDS.filter((id) => id !== missing)),
        `${feature}: missing ${missing}`,
      ).not.toContain(feature);
    for (const only of required) expect(enabledSdkFeatures([only])).not.toContain(feature);
  }
  expect(enabledSdkFeatures()).toContain("processes.signal");
});

it("advertises kill only while process signals are unavailable", () => {
  expect(guestApiCapabilities(false).supportedSignals).toEqual(["SIGKILL"]);
  expect(guestApiCapabilities(true).supportedSignals).toEqual([
    "SIGTERM",
    "SIGINT",
    "SIGHUP",
    "SIGKILL",
  ]);
  expect(guestApiCapabilities(true).signalSupport).toBe("checked-at-call");
});

it("qualifies multi-parameter process routes explicitly and declares result/connect expiry", () => {
  for (const id of [
    "connectProcess",
    "signalProcess",
    "killProcess",
    "sendProcessStdin",
  ] as const) {
    const params = SDK_ROUTES[id].params;
    expect(params.safeParse({ id: "sandbox", pid: "42" }).success).toBe(true);
    for (const pid of ["1", "0", "-1", "42x", "2147483648"])
      expect(params.safeParse({ id: "sandbox", pid }).success).toBe(false);
    expect(params.safeParse({ id: "sandbox", pid: "42", private: "x" }).success).toBe(false);
  }
  expect(sdkRouteErrorStatuses(SDK_ROUTES.connectProcess)).toContain(410);
  expect(sdkRouteErrorStatuses(SDK_ROUTES.getOperationResult)).toContain(410);
  expect(SDK_ROUTES.getOperationResult.errors).toEqual([
    "OPERATION_RESULT_NOT_READY",
    "OPERATION_RESULT_UNSUPPORTED",
    "OPERATION_RESULT_EXPIRED",
  ]);
});

it("keeps the exact output-page structure, with identity supplied only by start/connect", () => {
  expect(Object.keys(commandOutputPageSchema.shape).sort()).toEqual(
    [
      "operationId",
      "attempt",
      "state",
      "exitCode",
      "offset",
      "nextCursor",
      "reset",
      "chunks",
      "gaps",
      "totalBytes",
      "hasMore",
      "receivedBytes",
      "retainedBytes",
      "truncated",
      "complete",
      "expiresAt",
    ].sort(),
  );
});
