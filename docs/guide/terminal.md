# Sandbox terminal

The sandbox detail page has a browser terminal: an interactive shell **inside
the sandbox VM**, as the template's guest user. It is never a shell on the
Incus host. Browser terminals require your session. From your own terminal,
`wssp sandbox shell` opens a shell over `/v1/sandboxes/{id}/connect`: only
kind-`API` keys with `sandboxes:connect` (a write `wssp login`, or a dashboard
key given that scope) get one; see [shells from the CLI](./connect.md). MCP
(`/mcp`) credentials and agent tokens have no PTY; their separate host
command/file tools follow [ADR-006](../design/adr-006-agent-host-access.md).

## Attach model

- **Explicit attach.** Nothing connects when the page loads. Press **Attach terminal**
  and the page loads the terminal, mints a one-use ticket and opens a
  WebSocket. Only the sandbox's owner can attach, only while the sandbox is
  `READY`, and only with a session that satisfies the 2FA policy.
- **One attachment per sandbox.** Attaching from a second tab or device
  **replaces** the first: the old one ends with "replaced" and its shell is
  closed. Input from a replaced attachment reaches nothing.
- **A new shell every time, except a short reattach.** End session, closing the
  tab, the shell exiting, or any other end is final; **Attach again** starts a
  new shell process. The one exception: when the node daemon supports it
  (`terminalResume`), a sandbox terminal survives
  a relay reconnect or a server restart. The page shows "Reconnecting…", keeps
  your scrollback and reattaches to the **same** shell within the host's grace
  (120 s by default, at most 10 minutes; at most 3 attempts, one tab at a
  time). Typed input is never replayed, and if the host had to drop output
  while you were away the page says so. If it cannot reattach in time it shows
  **Attach again**. Host terminals never reattach. Long-running work still
  belongs in a command (`commands.start`) or a terminal multiplexer inside the
  guest.
- **Terminals page.** **Terminals** in the sidebar (phone: bottom tabs) lists
  your open browser terminals on your sandboxes and hosts: which browser
  opened each, when, its last keystroke or output, and whether it is attached.
  **Open here** goes to its sandbox or host page; attaching there replaces the
  other tab (a fresh shell). **End** closes it after a confirmation, and the
  other tab says it was ended from the Terminals page. It shows only your own
  terminals, for admins too. A terminal ends when its sandbox or host page
  is left or its tab closes, so the page lists live ones only.
- **How it ends.** Every end after the socket opened arrives as an explicit
  close notice (WebSocket close code 4401) with a reason the page shows:
  you detached, replaced, the sandbox stopped or was destroyed, its lease
  expired, a new generation started, your session was revoked, the node daemon
  stopped or disconnected, the host's credential stopped authorizing it, or
  the connection was too slow. The notice also
  carries a `requestId`: the one your detach sent, otherwise the upgrade's
  `X-Request-Id`, which is what to quote to an operator. Refusals before the
  socket opens are classified by one fresh ticket request and are not retried
  in a loop.

## Header and End session

- **End session** ends the shell (the CloseIntent above) and always asks
  first in a dialog. There is no "stop viewing" that leaves the shell
  running: every end is final, and **Attach again** starts a new shell.
- **Maximize / Restore** lets the terminal fill the screen (inside the
  phone's safe areas, above the phone's bottom navigation, and above the
  on-screen keyboard while it is open) and puts it back; the terminal
  refits, so the shell gets the new size.
- **On phones (640 px wide or less)** the actions become one fixed row once
  the terminal is shown: the **terminal picker**, **⋯**, and Maximize/Restore
  in the corner. Nothing moves into an overflow as the screen narrows.
  - The picker shows a status icon and the sandbox (or host) name. The icon
    is a **keyboard** when what you type reaches the shell and an **eye**
    while it is view only (reconnecting: the scrollback stays, input stops).
    Its colour is green when connected, amber while opening or reconnecting,
    red when the terminal was refused and grey when it ended. The list shows
    this page's terminal and **New terminal…**, which goes to Sandboxes (or
    Hosts), where terminals are attached; leaving the page ends this terminal.
  - **⋯** has two groups. **Type & view**: Show/Hide keys, Paste…, Photo /
    camera…, text size, **Select text**, Copy selection and (on a CLI login)
    Type it for me. **Session**: End session… (red, asks first), or on an
    ended terminal Attach again and **Close terminal** (clears the ended view).
  - There is no status line: the reason a terminal ended (with Attach again)
    and warnings appear inside the terminal area, and copy/paste results as
    a toast.
- **Select text** shows the terminal's text as of now in a box where it can
  be selected by touch. Copy stays an explicit button there too (native copy
  is cancelled, as on the terminal), and nothing in the box is sent.

## Utilities (phones and touch screens)

The **Utilities** button in the terminal actions (in **⋯ › Type & view** on
phones) opens:

- **Show keys / Hide keys**: a key row under the terminal with Esc, Tab, Ctrl,
  Alt and a swipe pad. It is hidden until you show it, and the choice is
  remembered on this device (this browser), not on your account. The keys
  never take focus from the terminal, so the phone keyboard stays open, and
  the row sits above the on-screen keyboard while it is open.
  - **Swipe pad**: one arrow key per 20 px of swipe; arrows follow the
    program's application cursor mode (`ESC O A` instead of `ESC [ A`).
  - **Ctrl / Alt**: tap to apply it to the next key you type on the phone
    keyboard (tap twice quickly to lock it); hold for about 0.4 s to open a
    letter grid, slide to a key and lift to send that combination
    (Ctrl+C, Ctrl+R, Alt+B, …). Alt is sent as an ESC prefix.
- **Paste…**: a box to check text before it is sent, with **Paste from
  clipboard** (when the browser allows reading it; otherwise long-press the
  box and choose Paste) and **Press Enter after sending**. It takes the same
  path as the Paste button: bracketed when the program asked for it, markers
  stripped, at most 64 KiB.
- **Photo / camera…** (sandbox terminals whose files can be written):
  **Choose photo** or **Take photo**. The image (PNG, JPEG, WebP or GIF, at
  most 16 MiB) is uploaded through the same transfer path as the Files card
  into `<guest home>/.uploads/paste-<time>-<id>.<ext>`; once the sandbox has
  written it, its path and a space are typed as a paste, which is how coding
  agents such as Claude Code and Codex take images in a terminal.
- **Text size**: A− / A+ in 1 px steps (1–20 px) and Reset, remembered on
  this device. Pinching the terminal with two fingers changes it too (the
  page itself does not zoom there; one finger still scrolls and selects);
  spreading the fingers to twice their distance adds about 5 px, closing
  them takes off up to 5 px. A size change refits the terminal, so the shell
  gets the new columns and rows like a window resize. At very small sizes
  the columns and rows are capped at the relay contract's PTY bounds
  (1024 columns × 512 rows); a screen that would fit more leaves the rest
  of the box empty.

## Security properties

- **Ticket.** 32 random bytes, valid for 30 seconds, usable once, bound to your
  auth session, the sandbox, its host and generation. It travels only in the
  `Sec-WebSocket-Protocol` header, never in a URL, and the database stores only
  its digest. Any refusal after it was presented burns it.
- **Plane separation.** The upgrade refuses an `Authorization` header and any
  subprotocol carrying a `wssp_sdk_`, `wssp_agent_`, `wssp_host_` or `wssp_device_`
  credential. The `Origin` must exactly match the configured public origin.
- **Continuous authorization.** After the upgrade the server re-reads your
  session, account and the sandbox before opening the shell, then every 15
  seconds and on every relevant change (sign-out, session revocation, ban,
  2FA policy change, sandbox stop, destroy, lease expiry or new generation).
  A failed or unreadable check closes the terminal.
- **No transcripts.** The server and host relay bytes and record none of them.
  Output lives only in the page's bounded scrollback (2,000 lines) and is gone
  when the terminal is disposed.
- **No end-to-end encryption.** Each hop is TLS (browser to your proxy, the
  host's outbound WSS), but the server and the node daemon see terminal bytes
  in clear while relaying them. Anyone who controls the server or the host can
  observe a session. Do not type secrets you would not give the operator of
  both.
- **Untrusted output stays inert.** Escape sequences that could write your
  clipboard (OSC 52), create links (OSC 8) or transfer files (iTerm2, kitty)
  are swallowed. Copy only through the **Copy selection** button. Paste (button or
  Ctrl/Cmd+V) is all-or-nothing: bracketed-paste markers inside the text are
  stripped, and a paste over the 64 KiB input queue is refused whole.
- The shell gets no control-plane credentials; it is the same guest user that
  commands and file transfers run as.

## Operational limits

| Limit                        | Value                                                                                                                                                                                                                                                                                             |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Active terminals per sandbox | 1 (a new attach replaces it; one more may still be closing)                                                                                                                                                                                                                                       |
| Terminals per host           | 8, counted until the host confirms the shell was reaped                                                                                                                                                                                                                                           |
| Terminal opens per host      | 30 per rolling minute                                                                                                                                                                                                                                                                             |
| Ticket requests              | 20 per minute per user; upgrades 30 per minute (each reattach attempt costs one of each)                                                                                                                                                                                                          |
| Session lifetime             | Sandbox terminals: 4 hours from the first open, then the daemon closes the shell; a shell started with private env or CLI-login credentials also ends at the sandbox lease. Reattaching never extends it. Host terminals: 1 hour (and 10 minutes without input). Not configurable in this release |
| Reattach grace               | The host's `terminal_resume_grace` (default 120 s, at most 10 minutes), only on hosts that negotiate `terminalResume`                                                                                                                                                                             |
| Idle browser                 | A browser that sends nothing and answers no ping for 60 s is detached (the server pings every 20 s)                                                                                                                                                                                               |
| Input                        | Frames of at most 16 KiB; at most 64 KiB queued per session                                                                                                                                                                                                                                       |
| Size                         | 1–512 rows, 1–1024 columns                                                                                                                                                                                                                                                                        |
| Slow browser                 | Output the browser cannot keep up with detaches it ("too slow") instead of buffering without bound                                                                                                                                                                                                |

Stopping, destroying or expiring a sandbox closes its terminal. Stopping the
node daemon (`systemctl stop`, Ctrl-C) closes every terminal on that host
gracefully first; SIGKILL does not. Reverse proxies must pass WebSocket
upgrades for the terminal path: see
[deployment](../operations/deployment.md#reverse-proxy-browser-terminals).

Wire contracts: [terminal relay](../design/terminal-relay-contract.md) and
[browser terminal authentication](../design/browser-terminal-auth.md).

Retained sandbox authority names the exact
revision and the sandbox's current host (or, while offloaded, the host it last
ran on); cold reconnect and restore keep the pinned configuration.

A terminal uses the sandbox's snapshotted revision defaults plus its create
`envs`; it has no readback of those values. Stop/reconnect preserves that
snapshot. A later template tag move, revision append or pool membership change
does not alter it. Deliberately printing a value in the guest makes it visible
to that terminal's authorized viewer. See [private defaults](./sandboxes.md#private-environment-defaults).
Pool grants belong to SDK access; browser attachment always uses the owner's
cookie session and one-use ticket, including on a sandbox created by an SDK key.

Tracked pipe commands are a separate surface from this PTY. Closing a browser
terminal closes its shell; disconnecting a tracked command's SDK/output observer
only detaches that observer and sends neither EOF nor cancel. No SDK PTY or
all-guest process census is added. See [tracked commands](./sandboxes.md#files-and-tracked-command-dashboard)
and the [filesystem and command behavior](sandboxes.md#filesystem-and-command-result-limits).

## Owner host terminal

Hosts → Details and terminal opens an explicit owner-only host shell, separate
from the guest terminal. It runs fixed `/bin/sh -i` with the daemon user's local
UID/GID/groups and trusted NSS home, using a cleared fixed environment. No
browser command, cwd, user or env is accepted. An incus-admin host user can
reach every VM, including foreign guests. API restrictions and disabling host
terminals do not isolate guests from local administrators.

Local default is off with TOTP required. Enabling requires stdin and stderr
TTYs, no `WSSP_HOST_COMMAND` or `WSSP_HOST_TERMINAL` marker, no daemon ancestry,
and typing `on` in a local login session on the node. Enable with
`wssp host config set-host-terminal on`; local off is observed within two seconds,
closes host PTYs and preserves guest work. Optional mode is local-only via
`wssp host config set-host-terminal-totp optional`. The dashboard can raise the
requirement on a connected host; only a persisted ACK confirms it. Offline
TOTP-raise requests are not stored; timeout/disconnect needs an explicit retry.
There is no dashboard enable control. You can choose **Turn off** for
**People may open a host terminal** on the host detail's **Agent access** card. This
immediately refuses new tickets and attachments, sets a durable server-side
veto and asks the daemon to persist off and close host PTYs. The node cannot
undo the veto, even by reporting off. Every hello/report that says on while
vetoed receives another turn-off request. Only a live owner browser session
can choose **Allow again** to lift the dashboard block only when the node is
online and its live report at the current epoch says host terminals are off.
If it reports on, run `wssp host config set-host-terminal off` at the node first and
wait for the off report. Lifting the block does not turn on the node setting. See
[ADR-006](../design/adr-006-agent-host-access.md).
Turning off **Agents may run host commands** separately interrupts agent host
commands and pending file work. Guest terminals are a separate target.

Agent host commands and host file tools run as the daemon user, an Incus
admin: an agent with host access can do what that user can do, including
editing its settings and reading its credential. Access is off until a person
enables it at the node. The node-local raise gate and process-tree cleanup are
best effort against that uid. See
[node settings](./hosts.md#node-settings-for-agents-and-terminals) for the
dashboard emergency veto.

Run the daemon as a service (a system or user unit) and raise settings from a
separate local login. A daemon started in the same terminal session or scope
as your shell makes the cgroup check refuse the raise. The marker, ancestry
and cgroup checks refuse the direct dashboard host-terminal/host-command case,
but are best effort against the daemon's own uid. A person
or agent with host execution can escape the process tree with `systemd-run --user`, `setsid`
followed by killing the supervisor, or cron, or edit `config.toml` directly.
These checks are not a kernel-enforced sandbox.

Required mode needs enrolled verified TOTP, a ten-minute first/changed-factor
observation cooldown, and a fresh unused code on every attach/retry. Five proof
attempts/minute and twenty/day apply across hosts/sessions; ten failures or
budget exhaustion locks for at least fifteen minutes. Login/factor changes do
not reset budgets or locks. Recovery/email codes, passwords and trusted-device
cookies cannot substitute. The enrollment link goes to Security settings.
Optional mode still requires a live verified non-impersonated owner session.

Codes clear after submission/refusal/close and are never put in Query caches,
URLs, storage, logs or toasts. Host pre-upgrade refusal ends that attempt;
manual retry needs a new proof/ticket. Guest pre-upgrade classification keeps
its existing one additional mint behavior. Both use lazy xterm/CSS, safe native
paste/copy, OSC/link/clipboard defenses and bounded disposable scrollback.

One active attachment per typed target may have a second closing PTY. Eight
host slots include two reserved host slots and six guest slots, with three per
guest creator. Thirty host opens/minute reserve two for host opens and cap one
guest creator at fourteen. Closing slots remain charged until confirmed reap.
Host input idle expires after ten minutes and total lifetime after one hour,
enforced by the daemon; output/ping/resize never reset idle. Detach starts no
background/resumable terminal, and host terminals never reattach after a relay
drop. Session/credential/policy changes recheck durable
authority for both target kinds, with about twenty seconds fallback for missed
hints. Host-owner custody, pool ownership and admin metadata confer no guest IO.

## Queued host commands

An agent with `hosts:execute` can queue a command for a node you own even when
agent host commands are off. Open **Queued commands** in the host detail to
review its command text, reason, credential and expiry. **Dismiss** declines
it. **Run** records your decision and prepares a wrapper in your host terminal;
it does not execute it. You still attach explicitly, with a fresh TOTP code
when required. **Pressing Enter is your decision.**

The panel pre-types only a printable ASCII command on one line, without a
trailing newline. If it cannot safely pre-type, or a host terminal is unavailable,
it shows the wrapper to copy. Review the whole wrapper before running it:

```sh
env -u SUDO_ASKPASS -u BASH_ENV -u ENV /bin/sh -c 'if command -v sudo >/dev/null 2>&1; then sudo -k >/dev/null 2>&1; fi; /bin/sh -c "$1"; s=$?; if command -v sudo >/dev/null 2>&1; then sudo -k >/dev/null 2>&1; fi; exit $s' wssp-queued '<quoted command>'
```

The application shell-quotes the final command argument, escaping each single
quote. The wrapper clears askpass/shell-startup variables and invalidates cached
sudo authentication before and after the command while preserving its exit
status. It does not automatically run as root; any sudo prompt is for you to
decide. Queue state **RUN** records the handoff, not proof that you pressed
Enter or that the command succeeded. The agent can inspect its queue item's
state but cannot run or dismiss it. Default expiry is 24 hours.

The daemon user is an Incus admin: a human host shell or agent host command can reach every
sandbox on the node, including other users' sandboxes. **Own sandboxes only**
does not limit that power. See [node settings](./hosts.md#node-settings-for-agents-and-terminals).
