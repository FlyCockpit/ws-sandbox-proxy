# ssh, VS Code, rsync and sftp with `wssp ssh`

> Verified on 2026-11-21 with OpenSSH 10.2p1 (Ubuntu) and rsync 3.4.1 against
> sandboxes from the community Ubuntu 26.04 template, including the
> template's own rsync (`/usr/bin/rsync`) after the rebuild with this
> release's recipe.

These pages show how to reach a sandbox with the tools you already use:
`ssh`, `scp`, `sftp`, `rsync`, VS Code Remote-SSH and JetBrains Gateway. The
reference behind them (the generated config, what each ssh feature maps to,
exit codes, flow control) is [Shells, port forwards and ssh from the
CLI](../connect.md#ssh).

| Page                                | What it covers                                                                     |
| ----------------------------------- | ---------------------------------------------------------------------------------- |
| [Plain ssh](./ssh.md)               | Shells, commands, `-L`/`-D` forwards, ControlMaster, `wssp ssh` without a config   |
| [Copy files](./files.md)            | rsync, scp and sftp: typical commands, large transfers, ownership, troubleshooting |
| [VS Code Remote-SSH](./vscode.md)   | Connecting VS Code to a sandbox, forwarded ports, reconnecting, troubleshooting    |
| [JetBrains Gateway](./jetbrains.md) | Connecting a JetBrains IDE backend to a sandbox (not yet verified in the app)      |

## What `wssp ssh` is

`ssh <sandbox>.wssp` works without SSH keys or passwords. **Your wssp login is
the credential**: `wssp ssh-config --install` adds a `Host *.wssp` block to
your ssh config whose `ProxyCommand` is `wssp ssh --stdio`. When ssh connects,
that local `wssp` process opens one connection to the server with your login
and speaks SSH to your ssh client over a pipe. Nothing listens anywhere, not
on your machine, the server, the node or in the guest, and no `sshd` runs in
the sandbox. Every session runs as the template's guest user.

Two consequences, both explained in the reference:

- **It is not end-to-end SSH to the guest.** The SSH session ends in your
  local `wssp` process; from there the bytes travel over TLS to the server and
  the node, like the browser terminal. The server and the node (so a shared
  node's owner) can see them ([Not end-to-end](../connect.md#ssh)).
- **The tools trust the sandbox.** VS Code, Gateway, scp, sftp and rsync act on
  what the guest sends them. Use the editor integrations only with sandboxes
  whose contents you trust ([Trust toward your machine](../connect.md#ssh)).

## One-time setup

The `wssp` CLI runs on Linux (macOS and Windows are not supported CLI
platforms, see [what is not supported](../README.md#what-is-not-supported)).
Install it ([Using the CLI](../cli.md#install)), then:

```sh
wssp login --server https://wssp.example.com   # approve in the browser with write access
wssp ssh-config --install                      # writes ~/.ssh/config.d/wssp, asks to include it
ssh <sandbox>.wssp true                        # exits 0, no host-key prompt
```

- **The login needs write access.** A read-only login cannot open ssh sessions
  (``error: this login cannot open ssh sessions; log in again (`wssp login`)
  to get shell access: `FORBIDDEN`: the server answered HTTP 403``). A dashboard SDK key works only when it was given the
  `sandboxes:connect` scope ([Access](../connect.md#access)).
- **`--install`** writes the block to `~/.ssh/config.d/wssp` and, after
  asking, puts one `Include config.d/wssp` line at the top of `~/.ssh/config`
  (`--yes` skips the question). Nothing else in your ssh config changes. To
  look at the block first, run `wssp ssh-config` without `--install`: it
  prints the block and edits no ssh config (on first use it still creates
  wssp's own host key and `known_hosts`). The details (when `--install` refuses, backups, the local host
  key) are in [How it works](../connect.md#ssh).
- **Run `--install` again** after moving or reinstalling `wssp` to another
  path: the block names the `wssp` binary you ran it with.
- **No host-key prompt.** The block pins a host key that this install made
  for itself; it opens nothing. `wssp ssh-config --rotate-host-key` replaces
  it.

## Host names

A sandbox is `<sandbox>.wssp`, where `<sandbox>` is its id or its name:

```sh
ssh 76ec82c2-2ded-46d0-b53c-cca432318a38.wssp   # by id
ssh web.wssp                                     # by name (one of your live sandboxes)
```

`wssp sandbox list` shows ids and names. A name is looked up among your live
sandboxes. Names with `'` or `\` never match the block (see the reference for
why).

## What the sandbox needs

The sandbox must be `READY` on a connected host. Beyond that, each tool needs a
program in the guest:

| Tool                                  | Needs in the guest                              | Community template |
| ------------------------------------- | ----------------------------------------------- | ------------------ |
| `ssh`, commands, `-L`/`-D`, VS Code   | a shell (always there)                          | yes                |
| `scp` (default mode), `sftp`, Gateway | OpenSSH's `sftp-server` (`openssh-sftp-server`) | yes                |
| `scp -O` (legacy mode)                | `scp`                                           | yes                |
| `rsync`                               | `rsync`                                         | yes                |

The community templates install `openssh-sftp-server` and `rsync`. A
community template prepared before they did gets them with its next refresh
to a newer upstream image; on your own templates add them in a build step
([template builds](../template-builds.md)).
