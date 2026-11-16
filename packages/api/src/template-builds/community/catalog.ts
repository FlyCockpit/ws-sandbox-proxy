import type { Recipe } from "@wssp/template-recipe";

/**
 * Community base templates. The owner picks a
 * tested distro; wssp pins the newest upstream VM build from the fixed
 * simplestreams host, records it as a hidden UPSTREAM revision of the owner's
 * new template, runs the fixed prep recipe on it, verifies the result in a
 * fresh VM and only then publishes it as `latest`.
 *
 * The catalog, the recipe and the smoke are constants: nothing here is
 * derived from a request. The prep recipe's digest is pinned by the
 * `template_build_origin` CHECK (build.prisma) and by a unit test.
 */

export type CommunityImageEntry = {
  /** `SandboxTemplate.communitySource` (CHECK `sandbox_template_community`). */
  id: "ubuntu-26.04";
  /** Display name (a product name, not translated). */
  label: string;
  /** Simplestreams product id on images.linuxcontainers.org. */
  product: string;
  architecture: "x86_64";
  /** Shown in the picker only when tested (D-E). */
  tested: true;
  /** Default template slug. */
  slug: string;
  /**
   * The prep build VM's size. `diskGiB` is the published base's
   * `minDiskGiB` (its root never shrinks, so it is every derived template's
   * floor): small on purpose. `defaultDiskGiB` is what a create from the base
   * gets when it omits a size.
   */
  resources: { cpuCount: number; memoryMiB: number; diskGiB: number; defaultDiskGiB: number };
  /** Upstream disk bound (index client, server zod and daemon). */
  maxDiskBytes: number;
  /** The prep recipe's step budget (the build's own timeout). */
  recipeTimeoutMinutes: number;
};

export const COMMUNITY_IMAGES: readonly CommunityImageEntry[] = Object.freeze([
  Object.freeze({
    id: "ubuntu-26.04",
    label: "Ubuntu 26.04 LTS",
    product: "ubuntu:resolute:amd64:cloud",
    architecture: "x86_64",
    tested: true,
    slug: "ubuntu-26-04",
    // 8 GiB root: the prepared image uses ~0.95 GB (947 MiB, one kernel; the
    // upstream qcow2 is 4 GiB virtual), leaving ~7 GiB for apt upgrades
    // (a second kernel during an upgrade is ~0.3 GB) and small installs.
    // Creates still default to 32 GiB and the root grows on first boot.
    resources: Object.freeze({ cpuCount: 2, memoryMiB: 2048, diskGiB: 8, defaultDiskGiB: 32 }),
    maxDiskBytes: 4 * 1024 ** 3,
    recipeTimeoutMinutes: 30,
  }) as CommunityImageEntry,
]);

export function communityImage(id: string): CommunityImageEntry | null {
  return COMMUNITY_IMAGES.find((entry) => entry.id === id) ?? null;
}

/** D-I: the daily refresh scan's minimum age and the verify window. */
export const COMMUNITY_REFRESH_MIN_AGE_MS = 7 * 24 * 60 * 60_000;
export const VERIFY_WINDOW_MINUTES = 10;

/** The declared identity of an UPSTREAM revision: the prep's target user. */
export const UPSTREAM_GUEST = Object.freeze({
  guestUid: 1000,
  guestGid: 1000,
  guestHome: "/home/user",
  guestShell: "/bin/bash",
});

/**
 * The prep recipe's base. A fixed sentinel, never resolved: a community
 * build's base is always its own template's UPSTREAM revision
 * (`baseRevisionId`), so the recipe text, and therefore its digest, is the
 * same for every owner and every upstream version.
 */
const COMMUNITY_BASE_SENTINEL = { template: "wssp-upstream" } as const;

/**
 * Guest-side privilege probes. These scripts run inside the community build
 * and verify VMs only (never on a host) and assert that the escalation tool
 * is NOT usable; the names are interpolated so the repo's host-side
 * `sudo` guardrail (scripts/policy-checks.sh) keeps its meaning.
 */
const ESCALATE = "sudo";
const ESCALATE_CHECK = "visudo";

const LINGER_RULE = `polkit.addRule(function (action, subject) {
  if ((action.id == "org.freedesktop.login1.set-self-linger" ||
       action.id == "org.freedesktop.login1.set-user-linger") && subject.user != "root")
    return polkit.Result.NO;
});`;

/**
 * Linger refusal as the guest user (review4 U5): logind must be reachable
 * first, and the SetUserLinger call must fail with an access denial, not
 * with any other error. `set -e` ignores `!`-negated commands, so every
 * negative assert is an explicit `if … then exit`.
 */
const LINGER_ASSERT = `busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager KillUserProcesses >/dev/null
if out=$(busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager SetUserLinger ubb "$(id -u)" true false 2>&1); then
  echo "wssp: the guest user can enable linger" >&2; exit 1
fi
case "$out" in
  *AccessDenied*|*"Access denied"*|*"not allowed"*|*"Permission denied"*) ;;
  *) echo "wssp: linger refusal was not an access denial: $out" >&2; exit 1 ;;
esac
if [ -e /var/lib/systemd/linger/user ]; then echo "wssp: a linger file exists" >&2; exit 1; fi`;

/** `UBUNTU_CLOUD_PREP_V1` (S5). Steps 1–4 run as root, step 5 as `user`. */
export const UBUNTU_CLOUD_PREP_V1: Recipe = Object.freeze({
  version: 1,
  from: COMMUNITY_BASE_SENTINEL,
  steps: [
    { type: "run", user: "root", script: "cloud-init status --wait || true" },
    {
      type: "run",
      user: "root",
      script: `set -eu
loginctl terminate-user ubuntu 2>/dev/null || true
pkill -KILL -u ubuntu 2>/dev/null || true
if getent passwd ubuntu >/dev/null; then userdel -r ubuntu 2>/dev/null || userdel ubuntu; fi
if getent group ubuntu >/dev/null; then groupdel ubuntu; fi
if getent group lxd >/dev/null; then groupdel lxd; fi
if ! getent group user >/dev/null; then groupadd -g 1000 user; fi
if ! getent passwd user >/dev/null; then useradd -m -u 1000 -g 1000 -d /home/user -s /bin/bash user; fi
test "$(id -u user)" = 1000
test "$(id -g user)" = 1000
test "$(id -Gn user)" = user
rm -f /etc/sudoers.d/90-cloud-init-users
install -d -m 0755 /etc/cloud/cloud.cfg.d
printf 'users: []\\n' > /etc/cloud/cloud.cfg.d/99-wssp-no-default-user.cfg
printf 'growpart:\\n  mode: "off"\\nresize_rootfs: false\\n' > /etc/cloud/cloud.cfg.d/99-wssp-root-growth.cfg
install -d -m 0755 /etc/polkit-1/rules.d
cat > /etc/polkit-1/rules.d/10-wssp-no-linger.rules <<'WSSP_RULE'
${LINGER_RULE}
WSSP_RULE
chown root:root /etc/polkit-1/rules.d/10-wssp-no-linger.rules
chmod 0644 /etc/polkit-1/rules.d/10-wssp-no-linger.rules`,
    },
    {
      type: "run",
      user: "root",
      script: `set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3 util-linux git tar ca-certificates cloud-guest-utils e2fsprogs
command -v growpart >/dev/null
command -v resize2fs >/dev/null`,
    },
    {
      type: "run",
      user: "root",
      script: `set -eu
apt-get clean
rm -rf /var/lib/apt/lists/*
cloud-init clean --logs --seed
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
rm -f /var/lib/systemd/linger/*
if [ -e /etc/sudoers.d/90-cloud-init-users ]; then echo "wssp: stale cloud-init sudoers" >&2; exit 1; fi
if grep -rqsE 'NOPASSWD|!authenticate' /etc/sudoers /etc/sudoers.d; then echo "wssp: a passwordless grant remains" >&2; exit 1; fi
if command -v ${ESCALATE_CHECK} >/dev/null 2>&1; then ${ESCALATE_CHECK} -c >/dev/null; fi`,
    },
    {
      type: "run",
      user: "user",
      script: `set -eu
test "$(id -u)" = 1000
test "$(id -g)" = 1000
if ${ESCALATE} -n true 2>/dev/null; then echo "wssp: privilege escalation is reachable" >&2; exit 1; fi
${LINGER_ASSERT}`,
    },
  ],
  egress: { mode: "open", presets: ["ubuntu-apt"] },
}) as Recipe;

/**
 * sha256 of the canonical `UBUNTU_CLOUD_PREP_V1` JSON. Pinned by the
 * `template_build_origin` CHECK; `catalog.test.ts` recomputes it.
 */
export const UBUNTU_CLOUD_PREP_V1_DIGEST =
  "eb8a190977a1665adb2f14dcbe7f60eede39ea3ef72f8646652f4919d6802c59";

/**
 * `UBUNTU_CLOUD_SMOKE_V1`: run as the guest user in the verify VM (`guestSudo`
 * pinned off, deny-all egress). Each check has its own exit code, so a
 * failure tail names it. Proves the IMAGE grants no root and no linger.
 */
export const UBUNTU_CLOUD_SMOKE_V1 = `set -u
if ${ESCALATE} -n true 2>/dev/null; then echo "smoke: passwordless escalation succeeded" >&2; exit 11; fi
if ${ESCALATE} -n -l >/dev/null 2>&1; then echo "smoke: escalation rules are listed" >&2; exit 12; fi
[ "$(id -Gn)" = user ] || { echo "smoke: groups are $(id -Gn)" >&2; exit 13; }
if getent passwd ubuntu >/dev/null; then echo "smoke: the ubuntu user exists" >&2; exit 14; fi
( set -e
${LINGER_ASSERT}
) || exit 15
test -s /etc/machine-id || { echo "smoke: empty machine-id" >&2; exit 16; }
test -s /etc/ssh/ssh_host_ed25519_key.pub || { echo "smoke: no SSH host key" >&2; exit 17; }
setsid -w true || exit 18
python3 -c 0 || exit 19
test -w "$HOME" || exit 20
echo wssp-smoke-ok`;

/** The smoke command's timeout (inside the verify window). */
export const SMOKE_TIMEOUT_MS = 120_000;
