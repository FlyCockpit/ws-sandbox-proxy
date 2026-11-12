# agent-browser in a sandbox

Template authors can run agent-browser in a WS Sandbox Proxy sandbox. This is a supported
workload; WS Sandbox Proxy ships no browser image. Prepare and publish your own Incus VM
image, then register it on an enrolled Linux host. This recipe was tested
with the Ubuntu 26.04 cloud image, Node.js v24.22.1, agent-browser 0.39.2 and
Chrome for Testing 156.0.8078.73 on x86_64.

## Prepare the VM

Run on the host, in the same Incus project used by its `wssp` node daemon:

```sh
incus launch images:ubuntu/26.04/cloud wssp-abtest-prep --vm
incus exec wssp-abtest-prep -- cloud-init status --wait
```

Run the following inside that preparation VM as root. The stock `ubuntu`
user occupies UID 1000 and `lxd` occupies GID 1000. Replace them with the
non-root template user; disable cloud-init's default user so it does not
recreate an extra sudoer in every sandbox:

```sh
set -eux
userdel -r ubuntu
groupdel lxd                       # frees GID 1000
groupadd -g 1000 user
useradd -m -u 1000 -g 1000 -d /home/user -s /bin/bash user
printf 'users: []\n' > /etc/cloud/cloud.cfg.d/99-wssp-no-default-user.cfg
```

The resulting identity is 1000:1000, home `/home/user`, shell `/bin/bash`.
The tested home mode was 750. The image already contains the Incus guest
agent; the packages below provide the other readiness tools and browser
libraries. uutils coreutils on 26.04 are fine.

## Install Node and agent-browser

Run as root inside the VM. Ubuntu's Node 22 does not satisfy this
agent-browser version's Node ≥24 requirement. These commands install the
checksum-verified official x86_64 tarball and pinned agent-browser globally
so the guest user has them on its PATH:

```sh
set -eux
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3 git tar ca-certificates curl xz-utils
NODE_VER=v24.22.1
cd /tmp
curl -fsSLO https://nodejs.org/dist/$NODE_VER/node-$NODE_VER-linux-x64.tar.xz
curl -fsSLO https://nodejs.org/dist/$NODE_VER/SHASUMS256.txt
grep " node-$NODE_VER-linux-x64.tar.xz\$" SHASUMS256.txt | sha256sum -c -
tar -xJf node-$NODE_VER-linux-x64.tar.xz -C /usr/local --strip-components=1 --no-same-owner
rm -f node-$NODE_VER-linux-x64.tar.xz SHASUMS256.txt
npm install -g agent-browser@0.39.2
agent-browser install --with-deps   # apt system libs; also drops a Chrome copy in /root (removed below)
```

npm 11 skipped the package's postinstall during the test; the npm tarball
already includes the native binaries and the wrapper selected the correct
one. `agent-browser install --with-deps` installs the Chrome system libraries
as root and also downloads a root-owned browser cache. Remove that cache and
pre-download Chrome as the guest user, so runtime egress need only cover the
pages the workload visits:

```sh
rm -rf /root/.agent-browser
su - user -c 'agent-browser install'   # → /home/user/.agent-browser/browsers/chrome-156.0.8078.73
```

The tested Chrome cache was
`/home/user/.agent-browser/browsers/chrome-156.0.8078.73`.

## Choose the Chrome sandbox mode

**Sandbox on** works on the stock 26.04 cloud image. The tested image had no
`apparmor` userspace package and
`kernel.apparmor_restrict_unprivileged_userns=0`. Chrome's renderers ran in
separate user and PID namespaces. Keep this additional browser isolation
when your template supports it.

Installing the `apparmor` package enables the unprivileged-user-namespace
restriction through `/usr/lib/sysctl.d/10-apparmor.conf`. Without a profile,
sandbox-on Chrome then fails with `Permission denied (13)` in
`credentials.cc`. For that image configuration, save this exact minimal
profile as `chrome-for-testing` inside the preparation VM:

```text
# /etc/apparmor.d/chrome-for-testing
# Lets Chrome for Testing (installed by agent-browser under the guest user's HOME)
# create unprivileged user namespaces for its sandbox when
# kernel.apparmor_restrict_unprivileged_userns=1. Same shape as Ubuntu's chrome profile.
abi <abi/4.0>,
include <tunables/global>

profile chrome-for-testing /home/user/.agent-browser/browsers/chrome-*/chrome flags=(unconfined) {
  userns,
  include if exists <local/chrome-for-testing>
}
```

Run as root inside the VM to install and load it:

```sh
apt-get install -y --no-install-recommends apparmor
install -m 0644 chrome-for-testing /etc/apparmor.d/chrome-for-testing
apparmor_parser -r /etc/apparmor.d/chrome-for-testing
```

The profile attaches to a path in the guest user's own writable home, so
that user can effectively create user namespaces by placing an executable
there. This matches the stock image's behavior; it does not add a narrower
restriction for that user. The WS Sandbox Proxy KVM boundary is unchanged. The profile
was tested with the restriction set to 1. The published test image used the
stock configuration instead, without the apparmor package.

**`--no-sandbox`** also worked. The exact tested command was
`agent-browser --args --no-sandbox open <url>` on the first open for that
browser daemon. This removes Chrome's
renderer sandbox: renderers shared the browser's namespaces in the test.
The Incus KVM boundary and WS Sandbox Proxy egress policy remain (the guest user is
non-root, but [`guestSudo`](../sandboxes.md#root-in-the-guest), on by default,
gives it root inside the VM),
but the browser loses an internal defense against hostile pages. Choose this
mode deliberately for your template's workloads.

## Publish and register

Clean inside the VM, then stop and publish on the host:

```sh
# in the VM
cloud-init clean --logs; truncate -s 0 /etc/machine-id; apt-get clean; rm -rf /var/lib/apt/lists/*
# on the host
incus stop wssp-abtest-prep
incus publish wssp-abtest-prep --alias wssp-abtest-browser
```

Registration was tested through `POST /v1/templates` with this body and an
SDK key with `templates:write`. Dashboard registration through **Templates →
Register template** should work the same way, but was not tested. Use the
prepared host and guest identity above:

```json
{
  "hostId": "<owned-host-id>",
  "slug": "agent-browser-test",
  "label": "agent-browser test",
  "imageRef": "wssp-abtest-browser",
  "cpuCount": 2,
  "memoryMiB": 2048
}
```

Registration returns an operation receipt; wait for success and select its
exact verified revision from the template's revision list. See
[template registration](../../operations/templates.md) and the
[HTTP contract](../../design/native-http-contract.md). The tested 1.34 GiB
image took 62.5 seconds cold and 48.3 seconds warm on a `dir` pool.

## Drive the browser through the SDK

Sandboxes deny egress by default. The basic test needed only `example.com`.
The full-page Wikipedia screenshot also needed `en.wikipedia.org` and
`upload.wikimedia.org`. Chrome's denied background Google-service calls did
not affect navigation or screenshots. An ungranted `www.google.com` failed
DNS and direct TCP connectivity in the test. Domain grants authorize
host-resolved IP destinations, not HTTP hostname or TLS identity isolation;
see [network egress](../network.md).

The compiled [SDK example](../../../packages/sdk/examples/agent-browser.ts)
uses these tested commands and downloads the screenshot:

```ts
const sandbox = await wssp.sandboxes.create({
  cpuCount: 2,
  memoryMiB: 2048,
  sandboxHostId: hostId,
  template: `revision/${revisionId}`,
  egress: { domains: ["example.com", "en.wikipedia.org", "upload.wikimedia.org"] },
  timeoutMs: 30 * 60_000,
  lifecycle: { onTimeout: "kill" },
});
// Sandbox on. Other mode: agent-browser --args --no-sandbox open <url>
const result = await wssp.commands.script(
  sandbox.id,
  "agent-browser open https://example.com && agent-browser screenshot /home/user/shot.png",
  { guestTimeoutMs: 120_000 },
);
const png = Buffer.from(
  await (await wssp.files.download(sandbox.id, "/home/user/shot.png")).bytes(),
);
```

The agent-browser daemon outlives a WS Sandbox Proxy command. A later SDK command can
reuse the browser session (`agent-browser get url` took about 0.3 seconds).
After `agent-browser close`, wait about two seconds before opening again:
an immediate reopen raced daemon shutdown and returned an EOF error in the
test.

## Capacity

For browser workloads, **2 GiB memory and 2 vCPUs are recommended**. The
measured default 1 GiB / 1 vCPU VM completed the tests without OOM, but a
full-page screenshot peaked near 93% of guest-visible memory (759 of 813 MiB,
with 53 MiB available and no swap). Light single-tab pages used about 530 MiB.
Multiple tabs and heavier pages need more headroom.

Register the revision with `cpuCount: 2, memoryMiB: 2048` or pass those
independent create overrides as above. The earlier measurements used 1/1024;
the recommended 2/2048 recipe is a policy choice, not new live-VM measurement.
Cold boot retains the accepted size. See [VM sizing](../sandboxes.md#vm-size).
