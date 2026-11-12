import assert from "node:assert/strict";
import { test } from "node:test";
import { parseOffloadLiveConfig, unitBinary, unitSharesIncus } from "./offload-live.ts";

const base = {
  OFFLOAD_LIVE: "1",
  WSSP_OFFLOAD_API_URL: "http://127.0.0.1:4310",
  WSSP_OFFLOAD_SDK_KEY: "wssp_sdk_test",
  WSSP_OFFLOAD_TEMPLATE: "revision/abc",
  WSSP_OFFLOAD_HOST_A: "host-a",
  WSSP_OFFLOAD_HOST_A_TOKEN: "wssp_host_a",
  WSSP_OFFLOAD_UNIT_A: "wssp-chaos-c9a",
  WSSP_OFFLOAD_PROJECT_A: "wssp-chaos",
  WSSP_OFFLOAD_HOST_B: "host-b",
  WSSP_OFFLOAD_HOST_B_TOKEN: "wssp_host_b",
  WSSP_OFFLOAD_UNIT_B: "wssp-chaos-c9b",
  WSSP_OFFLOAD_PROJECT_B: "wssp-chaos-b",
};
const parse = (over: Record<string, string | undefined>) =>
  parseOffloadLiveConfig({ ...base, ...over }, () => "run123abc");

test("a complete dedicated two-host config parses", () => {
  const parsed = parse({});
  assert.equal(parsed.ok, true);
  if (parsed.ok) assert.equal(parsed.config.runId, "run123abc");
});

test("refuses without opt-in, off loopback, production unit or shared projects", () => {
  for (const over of [
    { OFFLOAD_LIVE: undefined },
    { WSSP_OFFLOAD_API_URL: "https://wssp.example.com" },
    { WSSP_OFFLOAD_UNIT_A: "wssp-host" },
    { WSSP_OFFLOAD_PROJECT_B: "wssp" },
    { WSSP_OFFLOAD_PROJECT_A: "default" },
    { WSSP_OFFLOAD_PROJECT_B: "wssp-chaos" },
    { WSSP_OFFLOAD_HOST_B_TOKEN: "nope" },
    { WSSP_OFFLOAD_SDK_KEY: "" },
  ])
    assert.equal(parse(over).ok, false, JSON.stringify(over));
});

test("each chaos unit must carry the test-only shared-Incus override", () => {
  assert.equal(unitSharesIncus("WSSP_DATA_DIR=/d WSSP_TEST_SHARED_INCUS=1"), true);
  assert.equal(unitSharesIncus("WSSP_TEST_SHARED_INCUS=1\n"), true);
  assert.equal(unitSharesIncus("WSSP_DATA_DIR=/d"), false);
  assert.equal(unitSharesIncus("WSSP_TEST_SHARED_INCUS=0"), false);
  assert.equal(unitSharesIncus("XWSSP_TEST_SHARED_INCUS=1"), false);
  assert.equal(unitSharesIncus(""), false);
});

test("the unit's daemon binary comes from its ExecStart path", () => {
  assert.equal(
    unitBinary("{ path=/repo/target/debug/wssp ; argv[]=/repo/target/debug/wssp connect ; }"),
    "/repo/target/debug/wssp",
  );
  assert.equal(unitBinary(""), null);
});
