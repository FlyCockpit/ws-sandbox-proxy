import { parseRecipe, sha256Hex } from "@wssp/template-recipe";
import { describe, expect, it } from "vitest";
import {
  COMMUNITY_IMAGES,
  UBUNTU_CLOUD_PREP_V1,
  UBUNTU_CLOUD_PREP_V1_DIGEST,
  UBUNTU_CLOUD_SMOKE_V1,
} from "./catalog";

describe("community catalog (community-base S5)", () => {
  it("ships Ubuntu 26.04 only, tested, with the planned size and bounds", () => {
    expect(COMMUNITY_IMAGES.map((e) => e.id)).toEqual(["ubuntu-26.04"]);
    expect(COMMUNITY_IMAGES[0]).toMatchObject({
      product: "ubuntu:resolute:amd64:cloud",
      architecture: "x86_64",
      tested: true,
      // A small floor (the published base's minDiskGiB, inherited by every
      // derived template) and the unchanged 32 GiB create default.
      resources: { cpuCount: 2, memoryMiB: 2048, diskGiB: 8, defaultDiskGiB: 32 },
      maxDiskBytes: 4 * 1024 ** 3,
      recipeTimeoutMinutes: 30,
    });
  });

  it("hands root growth to wssp: cloud-init growpart off, grow tools asserted", () => {
    const scripts = UBUNTU_CLOUD_PREP_V1.steps.map((step) =>
      step.type === "run" ? step.script : "",
    );
    expect(scripts.join("\n")).toContain(
      "printf 'growpart:\\n  mode: \"off\"\\nresize_rootfs: false\\n' > /etc/cloud/cloud.cfg.d/99-wssp-root-growth.cfg",
    );
    expect(scripts[2]).toContain("cloud-guest-utils e2fsprogs");
    expect(scripts[2]).toContain("command -v growpart >/dev/null");
    expect(scripts[2]).toContain("command -v resize2fs >/dev/null");
  });

  it("pins the prep recipe digest (the template_build_origin CHECK carries the same literal)", async () => {
    const parsed = parseRecipe(UBUNTU_CLOUD_PREP_V1, {});
    expect(await sha256Hex(parsed.canonical)).toBe(UBUNTU_CLOUD_PREP_V1_DIGEST);
    const { readFileSync } = await import("node:fs");
    const schema = readFileSync(
      new URL("../../../../db/prisma/schema/build.prisma", import.meta.url),
      "utf8",
    );
    expect(schema).toContain(`"recipeDigest" = '${UBUNTU_CLOUD_PREP_V1_DIGEST}'`);
  });

  it("runs steps 1–4 as root and the fast-fail asserts as the guest user", () => {
    const users = UBUNTU_CLOUD_PREP_V1.steps.map((step) => ("user" in step ? step.user : null));
    expect(users).toEqual(["root", "root", "root", "root", "user"]);
    const script = (n: number) => {
      const step = UBUNTU_CLOUD_PREP_V1.steps[n];
      return step?.type === "run" ? step.script : "";
    };
    expect(script(1)).toContain("rm -f /etc/sudoers.d/90-cloud-init-users");
    expect(script(1)).toContain("org.freedesktop.login1.set-self-linger");
    expect(script(1)).toContain("org.freedesktop.login1.set-user-linger");
    expect(script(1)).toContain("useradd -m -u 1000 -g 1000 -d /home/user -s /bin/bash user");
    expect(script(1)).not.toMatch(/useradd[^\n]* -G/);
    expect(script(3)).toContain("cloud-init clean --logs --seed");
    expect(script(3)).toContain("NOPASSWD|!authenticate");
    expect(script(3)).toContain("rm -f /var/lib/systemd/linger/*");
    expect(UBUNTU_CLOUD_PREP_V1.egress).toEqual({ mode: "open", presets: ["ubuntu-apt"] });
  });

  it("never relies on `set -e` for a negated assert, and the linger check needs an access denial (U5)", () => {
    for (const text of [
      ...UBUNTU_CLOUD_PREP_V1.steps.map((s) => (s.type === "run" ? s.script : "")),
      UBUNTU_CLOUD_SMOKE_V1,
    ])
      expect(text).not.toMatch(/^\s*!\s/m);
    expect(UBUNTU_CLOUD_SMOKE_V1).toContain("KillUserProcesses");
    expect(UBUNTU_CLOUD_SMOKE_V1).toContain('*AccessDenied*|*"Access denied"*');
    for (const check of [
      "-n true",
      "-n -l",
      'id -Gn)" = user',
      "getent passwd ubuntu",
      "test -s /etc/machine-id",
      "ssh_host_ed25519_key.pub",
      "setsid -w true",
      "python3 -c 0",
      'test -w "$HOME"',
    ])
      expect(UBUNTU_CLOUD_SMOKE_V1).toContain(check);
  });
});
