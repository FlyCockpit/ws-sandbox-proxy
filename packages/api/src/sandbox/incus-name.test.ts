import { describe, expect, it } from "vitest";

import {
  defaultIncusInstanceName,
  INCUS_INSTANCE_NAME_PREFIX,
  isManagedIncusInstanceName,
} from "./incus-name";

/** Keep in lockstep with `crates/sandbox-runtime/src/trait.rs` naming fixtures. */
const FIXTURES: ReadonlyArray<{ sandboxId: string; instanceName: string }> = [
  { sandboxId: "sbx-1", instanceName: "wssp-sbx-sbx-1" },
  { sandboxId: "sbx-2", instanceName: "wssp-sbx-sbx-2" },
  { sandboxId: "sbx-3", instanceName: "wssp-sbx-sbx-3" },
  { sandboxId: "ckabcdefghijklmnopqrstuv", instanceName: "wssp-sbx-ckabcdefghijklmnopqrstuv" },
];

const REJECTED = [
  "-wssp-sbx-1",
  "wssp-sbx-/etc/passwd",
  "wssp-sbx-foo/bar",
  "wssp-sbx-foo%2Fbar",
  "wssp-sbx-foo%00",
  "default",
  "ubuntu",
  "wssp-sbx-",
  "wssp-sbx-.",
  "wssp-sbx- foo",
  "fc-sbx-1",
];

describe("default Incus instance names", () => {
  it("uses the product prefix for every fixture", () => {
    expect(INCUS_INSTANCE_NAME_PREFIX).toBe("wssp-sbx-");
    for (const { sandboxId, instanceName } of FIXTURES) {
      expect(defaultIncusInstanceName(sandboxId)).toBe(instanceName);
      expect(instanceName.startsWith(INCUS_INSTANCE_NAME_PREFIX)).toBe(true);
      expect(isManagedIncusInstanceName(instanceName)).toBe(true);
    }
  });

  it("rejects malicious and unprefixed instance names", () => {
    for (const name of REJECTED) {
      expect(isManagedIncusInstanceName(name), name).toBe(false);
    }
  });
});
