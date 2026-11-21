# VS Code Remote-SSH

> **Not yet verified in the VS Code app.** Verified on 2026-11-21 with OpenSSH
> 10.2p1 (Ubuntu) against the community Ubuntu 26.04 template: the connection
> pattern Remote-SSH uses (`ssh -T -D <port> <sandbox>.wssp bash` with a
> bootstrap script on stdin), with a script that downloaded and started VS
> Code Server (commit `8a14f0cc`). The server then answered HTTP and a
> WebSocket upgrade through that connection's SOCKS forward and, after the
> bootstrap connection closed, through a new `-L` forward. The automated tests
> run the same connection pattern with a stand-in service, not VS Code Server.
> The VS Code steps below follow VS Code's own Remote-SSH workflow and have
> not been clicked through.

VS Code Remote-SSH opens a folder in a sandbox as if it were on your machine:
the editor runs locally, while a VS Code Server in the sandbox runs
terminals, language servers, debuggers and extensions as the guest user.
Remote-SSH reaches the sandbox through your ssh config, so it works with
`<sandbox>.wssp` like plain `ssh`.

## Before you start

- The [one-time setup](./README.md#one-time-setup) is done on the machine
  that runs VS Code, and `ssh <sandbox>.wssp true` exits 0 in a terminal
  there. If it does not, fix that first: VS Code shows less detail.
- The sandbox is `READY` and can reach VS Code's download servers. In the
  verified run the guest downloaded VS Code Server itself, from
  `update.code.visualstudio.com`, with egress open (the default). A sandbox in
  allowlist mode needs VS Code's download hosts allowed (Microsoft's
  [connectivity requirements](https://code.visualstudio.com/docs/remote/faq#_what-are-the-connectivity-requirements-for-vs-code-server)
  list `update.code.visualstudio.com` and `vscode.download.prss.microsoft.com`)
  and whatever your extensions fetch ([network egress](../network.md)), or
  VS Code's setting to download the server on your machine and copy it over.
  Neither allowlist mode nor that setting has been verified with wssp.
- You trust the sandbox's contents. VS Code acts on what the remote side
  sends; a compromised sandbox can reach your workstation through it
  ([Trust toward your machine](../connect.md#ssh)).

## Connect

1. Install the **Remote - SSH** extension (`ms-vscode-remote.remote-ssh`).
2. Run **Remote-SSH: Connect to Host…** from the Command Palette and type the
   host name, `<sandbox>.wssp` (for example `web.wssp`). The `*.wssp` entry in
   your ssh config is a pattern, so the host list does not offer each sandbox:
   type the name.
3. If VS Code asks for the remote platform, choose **Linux**. There is no
   password or key prompt and no host-key question.
4. On the first connection to a sandbox VS Code installs its server in the
   guest user's home directory (under `~/.vscode-server`) and starts it. Later
   connections reuse it, also after the sandbox was stopped and started (the
   disk is kept).
5. **Open Folder** and pick a directory in the sandbox, for example
   `/home/user`.

The VS Code Server keeps running in the sandbox after you disconnect, like any
process a normal close leaves behind, until the sandbox stops.

## Forwarded ports

VS Code forwards ports through the same connection (**Ports** view, or
automatically when a program in the sandbox starts listening). A forward
reaches the sandbox's **own loopback** (`localhost`, `127.0.0.1`, `::1`): a
dev server listening on `localhost:3000` in the sandbox opens on
`localhost:3000` on your machine. A forward to any other host is refused, since
it would bypass the sandbox's egress policy ([What maps to
what](../connect.md#ssh)). The forwarded port listens on your machine's
loopback, where every local user can reach it while it is open.

Without VS Code, `wssp sandbox forward <sandbox> 3000` or
`ssh -L 3000:localhost:3000 <sandbox>.wssp` forward the same port
([Plain ssh](./ssh.md#port-forwards)).

## Reconnecting

The connection ends, and VS Code shows that it lost the remote, when:

- the sandbox stops (`wssp sandbox stop`, its lease ends, a shutdown);
- your login is revoked or expires (`wssp logout`, a dashboard revoke);
- the connection drops (a network change, a laptop going to sleep), the
  server or node restarts, or the 12-hour session limit is reached.

There is no session resume. VS Code reconnects by opening a new connection;
for a stopped sandbox start it first, then reload the window:

```sh
wssp sandbox start <id> --wait    # the sandbox's id, as `wssp sandbox list --state STOPPED` shows
```

Unsaved editor buffers stay in VS Code. Terminals and programs that ran in the
sandbox ended with the stop; files on the sandbox's disk are kept. For work
that must survive a disconnect, run it in `tmux` or `screen` in the sandbox.

## Settings

- **ssh config:** Remote-SSH uses your `~/.ssh/config`, which includes the
  wssp block after `wssp ssh-config --install`. If you set
  **Remote.SSH: Config File** to another file, that file has to include the
  block too (`Include ~/.ssh/config.d/wssp`).
- **Remote.SSH: Use Local Server:** the verified sequence is the one this
  mode runs, one `ssh -T -D` connection that VS Code keeps open and tunnels
  through. Other modes use plain commands and `-L` forwards, each of which
  works on its own, but they have not been run with VS Code.
- **ControlMaster** in your ssh config works: later sessions reuse the first
  connection. A shared connection keeps the login it started with: after
  `wssp logout --local` or a `wssp login` as another account, stop it with
  `ssh -O exit <sandbox>.wssp` ([ControlMaster](../connect.md#ssh)).

## Troubleshooting

First run the same connection in a terminal on the machine that runs VS Code:

```sh
ssh <sandbox>.wssp true
```

It prints wssp's own error line (lines that start with `error:`) and exits 255
when wssp refused or ended the connection. Exit 0 means ssh reaches the
sandbox; whether VS Code then installs and runs its server is a separate step
(see the last row below). For more detail run `WSSP_LOG=debug ssh <sandbox>.wssp true`
(wssp logs only until the SSH session starts) or `ssh -v <sandbox>.wssp true`
(ssh's own log).

Lines marked "…" continue with the server's error code, for example
``…: `sandbox.state_conflict`: the server answered HTTP 409``.

| In the terminal                                                                                                        | Meaning and fix                                                                                                                                                              |
| ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ``error: sandbox `web` is stopped; start it with `wssp sandbox start <id> --wait`…``                                   | Start the sandbox with the command shown, then reconnect.                                                                                                                    |
| ``error: sandbox `web` is still starting (`PROVISIONING`); connect again once `wssp sandbox get <id>` shows `READY`…`` | Wait until it is ready.                                                                                                                                                      |
| ``error: no sandbox `web` among yours (give its id, or the name of a live sandbox); `wssp sandbox list` shows them…``  | A typo, a destroyed sandbox, or one that belongs to another account.                                                                                                         |
| ``error: this login cannot open ssh sessions; log in again (`wssp login`) to get shell access…``                       | A read-only login. Run `wssp login` and choose write access.                                                                                                                 |
| ``error: the server refused this login (revoked or expired); log in again (`wssp login`)…``                            | The login was revoked or expired. Run `wssp login`.                                                                                                                          |
| ``error: not logged in; run `wssp login --server <url>` ``                                                             | No login on this machine. Run `wssp login --server <url>`.                                                                                                                   |
| `error: the sandbox's host is not connected to the server; try again once it is back…`                                 | The node running the sandbox is offline or reconnecting. Try again later.                                                                                                    |
| ``error: the session ended (`sandbox_stopped`): the sandbox stopped``                                                  | The sandbox stopped while VS Code was connected. Start it and reload the window.                                                                                             |
| ``error: the session ended (`revoked`): the login was revoked or expired, or access to the sandbox was withdrawn``     | The login was revoked while connected (for example `wssp logout`). Log in again (`wssp login --server <url>` after a `wssp logout`).                                         |
| `Host key verification failed.`                                                                                        | ssh runs `wssp` with another wssp user directory than `wssp ssh-config --install` used. Run `--install` again in the environment VS Code starts ssh from.                    |
| the terminal connects, VS Code does not                                                                                | Check that VS Code uses the same ssh config (Remote.SSH: Config File) and the same `ssh` binary (Remote.SSH: Path), and that the guest can download VS Code Server (egress). |

The full list of refusals and session ends is in the
[reference](../connect.md#exit-status).
