# Declarative template builds

**Status: implemented, route A** (template builds). A recipe or a Dockerfile
subset is applied inside a KVM **build VM** on one of the owner's builder
hosts; the stopped VM is then saved through the existing
[capture path](../operations/templates.md) as a new template revision. The
user guide is [template builds](../guide/template-builds.md).

**Non-goals:** byte-compatible templates with e2b.dev; `FROM <docker image>`
(route B: OCI image → VM image, later); Incus containers (WS Sandbox Proxy sandboxes are
`incus launch … --vm` only); per-step layer caching; RAM snapshots after a
start command.

## Constraints that stay true

| Topic           | Choice                                                                                          |
| --------------- | ----------------------------------------------------------------------------------------------- |
| Sandbox runtime | KVM VM via Incus (`IncusKvmRuntime`, `launch --vm`)                                             |
| Guest interface | Incus guest agent (`incus exec`, including the Python 3 helpers)                                |
| Control plane   | oRPC/`/v1` API + durable operations + outbox → node daemon; the control plane never calls Incus |
| Tenancy         | Per-user ownership; no organizations                                                            |
| Fleet           | Enrolled `SandboxHost` daemons on outbound WSS                                                  |

## Route A: a build is composed from existing operations

There is no `BUILD_TEMPLATE` operation and no daemon-side build job. The server
orchestrates ordinary operations under a dedicated, unforgeable build
principal:

```text
accept recipe ─▶ (stage COPY context) ─▶ create build VM (placement on a builder host)
   ─▶ for each RUN/COPY: command operation ─▶ stop ─▶ capture (STOPPED) ─▶ kill
```

1. **Accept.** The recipe is parsed and bounded by the shared package
   `packages/template-recipe` (canonical JSON, Dockerfile compiler,
   substitution, digests, egress presets). The base is a template revision the
   owner can use (`slug[:tag]` or `revision/<id>`); guest identity is inherited
   from it, so the readiness contract is unchanged.
2. **Context.** A recipe with COPY uploads a tar context **before** any VM
   exists, into a build-context store that is separate from file transfers. It
   becomes an ordinary transfer only after the build VM is READY.
3. **Build VM.** A managed sandbox (`purpose = TEMPLATE_BUILD`) placed by the
   normal placement rules plus a `builder` stage. It is hidden from sandbox
   lists and webhooks and refuses every user action; only its build may act on
   it.
4. **Steps.** ENV, ARG, WORKDIR and USER fold into build state. RUN and COPY
   are command operations; RUN may run as guest root **only** inside a build
   VM. A failing step fails the build with its index, exit code and an output
   tail.
5. **Capture.** On success the VM is stopped and captured exactly like a
   manual capture (scrub, publish, upload, availability, tag move,
   retention). The revision records `sourceKind = BUILD`, the base as parent,
   the recipe digest, final ENV as default envs and the final WORKDIR as the
   default cwd. The upload to an S3 image store (or from a foreign builder)
   runs on the build VM's dispatch authority, so the VM lives until the
   capture is finalized. Its lease is the build timeout plus a reserve of the
   capture window (`TEMPLATE_BUILD_CAPTURE_WINDOW_MINUTES`, 60 min default), a
   60-minute storage window and 15 minutes of slack, re-anchored to that
   reserve after the last step (135 min by default; the deployment lease
   ceiling must fit timeout + reserve). Storage gives up
   (`build_store_failed`) two hours after the capture was accepted or at the
   VM's lease (server or host-acknowledged, whichever is earlier), whichever
   comes first, and at once if the VM is gone.
6. **Cleanup** is a state invariant: any live sandbox whose build is missing,
   finished, or cancelled, or whose capture is finalized (its image stored),
   is killed. One exception: a capture whose host result was recorded before
   the cancel still publishes, so a cancelling build keeps its VM, and only
   that capture's upload keeps dispatch authority, until the capture is
   stored or fails. A community (`verifyRequired`) build never publishes
   after a cancel (it has not verified), so it gets no exception: its VM is
   killed, its upload loses authority, and the finalizer fails its capture
   before waiting for storage.

## Recipe

Canonical form `wssp.recipe/v1` (JSON) and a Dockerfile subset compiled to
it. Bounds: 64 KiB canonical recipe, 256 steps, 32 KiB merged command payload
per RUN step (script, cwd and effective envs), sandbox env limits, 16 extra
scrub paths, 16 egress presets, 64 COPY sources. The full format is in the
[guide](../guide/template-builds.md#recipe-format).

Digests: `recipeDigest` is the SHA-256 of the canonical JSON (sorted keys);
`buildDigest` adds the resolved base revision and fingerprint, effective args,
context SHA-256, the normalized egress request and the resolved VM size (the
cache lookup and the active-build join both key on it). A whole-recipe cache hit
returns the existing revision without building.

## Egress

The build stores only the egress **request**. Presets
(`packages/config/src/egress-presets.json`) expand into domains and CIDRs
before the sandbox egress normalizer validates them, so every preset grant
passes the same protected-range refusal as a written one. The effective
policy is decided when the build VM is materialized, like for any sandbox
([network egress](../guide/network.md)).

## Guest base

A build starts from the owner's registered base template. The documented guest
default is `images:ubuntu/26.04/cloud`; Ubuntu 24.04 remains supported. On
24.04 GA / kernel 6.8, approved group-pidfd non-kill signals refuse
`signal_unsupported_on_guest`. HWE (`linux-generic-hwe-24.04`) or another
verified ≥6.9 kernel is the remedy only after checking the booted kernel is
≥6.9 and the helper probe succeeds. See
[guest prerequisites](../operations/templates.md) and the
[filesystem and command behavior](../guide/sandboxes.md#filesystem-and-command-result-limits).

## Hosts

A capture-capable host is a builder unless its local config sets
`builder = false`. Builds on another owner's node need the requester's opt-in,
the node's `accept_foreign_builds` and `accept_foreign_images`, an S3 image
store, and a target template whose image placement allows any node.
