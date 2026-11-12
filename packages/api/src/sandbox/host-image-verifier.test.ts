import { afterEach, describe, expect, it, vi } from "vitest";

import {
  bindHostSandboxProbe,
  type HostSandboxProbeInput,
  probeHostSandbox,
} from "./host-image-verifier";

const input: HostSandboxProbeInput = {
  incusFingerprint: "a".repeat(64),
  ownerId: "user-1",
  hostId: "host-1",
  sandboxId: "sbx-1",
  generation: 3,
  architecture: "x86_64",
  guestUid: 1000,
  guestGid: 1000,
  guestHome: "/home/user",
  guestShell: "/bin/bash",
};

afterEach(() => bindHostSandboxProbe(null));

describe("probeHostSandbox", () => {
  it("forwards only the probe wire fields, dropping launch-only extras", async () => {
    const probe = vi.fn(async () => "guest_ready" as const);
    bindHostSandboxProbe(probe);
    // A pinned launch source also carries the VM size; the daemon rejects the
    // probe (and drops the relay session) on any unknown field.
    const withExtras = { diskGiB: 32, ...input, cpuCount: 2, memoryMiB: 4096 };
    await expect(probeHostSandbox(withExtras)).resolves.toBe("guest_ready");
    expect(probe).toHaveBeenCalledWith(input);
    expect(Object.keys(probe.mock.calls[0]![0]).sort()).toEqual(Object.keys(input).sort());
  });

  it("reports unreachable when no probe is bound or the probe throws", async () => {
    await expect(probeHostSandbox(input)).resolves.toBe("unreachable");
    bindHostSandboxProbe(async () => {
      throw new Error("socket closed");
    });
    await expect(probeHostSandbox(input)).resolves.toBe("unreachable");
  });
});
