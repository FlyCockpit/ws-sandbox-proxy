# Plain ssh

> Verified on 2026-11-21 with OpenSSH 10.2p1 (Ubuntu) against sandboxes from
> the community Ubuntu 26.04 template: commands and their exit status, `-t`,
> `-L`, `-D`, ControlMaster and `wssp ssh <sandbox> -- …`; the rest of this
> page is covered by the automated tests.

After the [one-time setup](./README.md#one-time-setup) a sandbox is an ssh
host named `<sandbox>.wssp`.

## Shells and commands

```sh
ssh web.wssp                        # a login shell on a terminal
ssh web.wssp 'uname -a'             # a command, run by the guest user's shell
ssh -t web.wssp htop                # a command on a terminal
ssh web.wssp 'tar -C app -cf - .' > app.tar
ssh web.wssp 'exit 7'; echo $?      # 7: the remote exit status comes back
```

- A command runs as `$SHELL -c '<command>'` of the guest user, as with sshd,
  so quoting and shell syntax behave as you expect from ssh.
- Only `COLORTERM`, `LANG` and `LC_*` travel from your environment
  (`SendEnv`/`SetEnv`); other variables are ignored.
- Closing the session hangs up its processes, as with sshd; `tmux`, `nohup` or
  `setsid` keep work running. There is no resume after a lost connection.

`wssp sandbox shell <sandbox>` does the same without ssh
([Shell](../connect.md#shell)).

## Port forwards

```sh
ssh -L 8080:localhost:8080 web.wssp                 # local 8080 → the sandbox's localhost:8080
ssh -N -L 5432:localhost:5432 web.wssp              # only the forward, no shell
ssh -L ./pg.sock:/run/postgresql/.s.PGSQL.5432 web.wssp   # to a guest Unix socket
ssh -D 1080 web.wssp                                # a SOCKS proxy into the sandbox's loopback
```

A forward reaches only the sandbox's **own loopback** (`localhost`,
`127.0.0.1`, `::1`) or a guest Unix socket (absolute path). A forward to any
other host is refused with `administratively prohibited`: the sandbox's
egress policy decides what it may reach, and a forward cannot go around it.
`-R` (remote forwards), `-A` (agent forwarding) and `-X` are refused in this
release.

The listening side is your ssh, on your machine: with the default bind
address only local users can reach it; `-L 0.0.0.0:…`, `-D 0.0.0.0:…` or
`GatewayPorts yes` open it to your network.

`wssp sandbox forward <sandbox> 8080` forwards a port without ssh and can
listen on a private Unix socket ([Port forwards](../connect.md#port-forwards)).

## ControlMaster

To reuse one connection for many sessions (faster second connections, one
connection to the server), add to your ssh config, **after** the
`Include config.d/wssp` line:

```
Host *.wssp
  ControlMaster auto
  ControlPath ~/.ssh/cm-%C
  ControlPersist 60
```

Or per command: `ssh -o ControlMaster=auto -o ControlPath=~/.ssh/cm-%C -o
ControlPersist=60 web.wssp`. Stop a shared connection with
`ssh -O exit web.wssp` (with the config above), or
`ssh -o ControlPath=~/.ssh/cm-%C -O exit web.wssp` when you gave the options
on the command line.

A shared connection keeps the login it started with. A server-side revoke
(`wssp logout`, a dashboard revoke, the key's expiry) ends it, but
`wssp logout --local` or a `wssp login` as another account does not: run
`ssh -O exit <sandbox>.wssp` after switching accounts. Any process of your
local user can use the control socket while it exists
([ControlMaster](../connect.md#ssh)).

## Without an ssh config: `wssp ssh`

`wssp ssh` runs the system `ssh` with the same options the config block sets,
so it needs no `wssp ssh-config --install`:

```sh
wssp ssh web                         # a login shell
wssp ssh web -- 'uname -a'           # a command
wssp ssh web -- -t htop              # ssh options, then the command
wssp ssh web -- -L 8080:localhost:8080 -N
```

Everything after `--` goes to `ssh`: options first, then the remote command.
The exit status is ssh's. scp, sftp, rsync and the editors need the config
block (`wssp ssh-config --install`), since they start ssh themselves.

## Your ssh config

- `wssp ssh-config --install` adds the block in `~/.ssh/config.d/wssp` and one
  `Include config.d/wssp` line at the top of `~/.ssh/config`. Because ssh
  keeps the first value it reads for each option, the block wins over
  anything later in your config; put your own `Host *.wssp` additions (such as
  ControlMaster above) after the `Include`.
- `~` is your account's home directory as OpenSSH reads it; with a different
  `$HOME` (`sudo -E`, some containers) `--install` refuses and names both.
- To add the block yourself (for example to a config file a tool manages),
  save `wssp ssh-config` and include it. The block's options, and when
  `--install` refuses to edit, are in [How it works](../connect.md#ssh).
- The `wssp` CLI and its ProxyCommand run on Linux. macOS and Windows are not
  supported CLI platforms, so `wssp ssh` cannot be used from them directly.

## When it fails

`ssh` exits 255 and prints wssp's line starting with `error:`, for example
``error: sandbox `web` is stopped; start it with `wssp sandbox start <id> --wait`: `sandbox.state_conflict`: the server answered HTTP 409``.
The messages and their fixes are in the
[VS Code troubleshooting table](./vscode.md#troubleshooting); every refusal and
session end is in the [reference](../connect.md#exit-status).
