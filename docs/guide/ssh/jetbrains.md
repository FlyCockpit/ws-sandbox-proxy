# JetBrains Gateway

> **Not yet verified in the JetBrains Gateway app.** What is verified (on
> 2026-11-21, OpenSSH 10.2p1, community Ubuntu 26.04 template): the pieces
> Gateway uses to install its backend each work through `<sandbox>.wssp` live:
> a command, an sftp upload and an `-L` forward, checked separately. The
> automated tests run them in sequence (an upload, then a forward to the
> uploaded stand-in program). The Gateway steps below follow JetBrains'
> documented SSH configuration and have not been clicked through.

JetBrains Gateway (and the remote development entry of IntelliJ IDEA, PyCharm
and the other JetBrains IDEs) runs the IDE backend in the sandbox and a thin
client on your machine. It connects over SSH, uploads and starts the
backend, and reaches it through a forwarded port, all of which `wssp ssh`
provides.

## Before you start

- The [one-time setup](./README.md#one-time-setup) is done on the machine
  that runs Gateway, and `ssh <sandbox>.wssp true` exits 0 in a terminal
  there.
- The sandbox has OpenSSH's `sftp-server` (the community templates do), and
  enough disk and memory for an IDE backend. Gateway downloads the backend;
  a sandbox in allowlist egress mode needs JetBrains' download hosts allowed
  ([network egress](../network.md)).
- You trust the sandbox's contents: Gateway runs code from the remote side
  and acts on what it sends ([Trust toward your
  machine](../connect.md#ssh)).

## Connect

1. In Gateway choose **SSH Connection → New Connection** and edit the SSH
   configurations (or **Settings → Tools → SSH Configurations** in an IDE).
2. Add a configuration: host `<sandbox>.wssp`, port 22, user name `wssp`,
   authentication type **OpenSSH config and authentication agent**. This
   type reads `~/.ssh/config` by itself; by JetBrains' documentation its
   default parser asks the system `ssh` (`ssh -G`), so the `ProxyCommand`,
   `HostKeyAlias` and known hosts file of the wssp block apply. The port is not used: no network
   connection is made to it.
3. **Test Connection**, then choose an IDE and a project directory in the
   sandbox (for example `/home/user`) and connect. Gateway uploads its
   backend over sftp, starts it as the guest user and connects the client
   through a forward to the sandbox's loopback.

The endpoint accepts every SSH authentication method (it is reached only by
your own ssh; your wssp login is the credential), so no key has to be loaded
in an agent and an empty password works too.

## Open questions

Two points only the Gateway app can answer:

- **Host key.** Whether Gateway's own known-hosts check uses the block's
  `HostKeyAlias wssp` and wssp's `known_hosts`. If Gateway shows a fingerprint
  question, compare it with `ssh-keygen -lf <wssp user dir>/ssh/known_hosts`
  (the wssp user directory is `~/.local/share/wssp/user` by default) and
  accept it when they match.
- **Agent mode without a key.** Whether "OpenSSH config and authentication
  agent" connects when the agent has no key loaded. If it refuses before
  connecting, choose the **Password** authentication type with an empty
  password, and turn on **Parse config file ~/.ssh/config** (that checkbox
  belongs to the Password and Key pair types), so the wssp block still applies.

## Reconnecting and troubleshooting

The connection ends when the sandbox stops, the login is revoked or the
connection drops, as for [VS Code](./vscode.md#reconnecting); start the
sandbox (`wssp sandbox start <id> --wait`) and connect again. The backend's
files stay on the sandbox's disk.

When Gateway cannot connect, run `ssh <sandbox>.wssp true` in a terminal: it
prints wssp's own error line and the fix. The messages are listed in the
[VS Code troubleshooting table](./vscode.md#troubleshooting). An upload that
fails with
`wssp: this sandbox has no sftp-server; add the openssh-sftp-server package to its template (scp -O and rsync work without it)`
needs `openssh-sftp-server` in the template ([Copy
files](./files.md#troubleshooting)).
