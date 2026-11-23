# Copy files with rsync, scp and sftp

> Verified on 2026-11-21 with OpenSSH 10.2p1 (Ubuntu) and rsync 3.4.1 against
> sandboxes from the community Ubuntu 26.04 template: scp (both modes) and
> sftp with 100 MiB files, rsync with a 216-file tree of 64 MiB and of 1 GiB,
> each byte-exact in both directions (rsync installed in the guest by hand).
> After the community template was rebuilt with this release's recipe, its own
> rsync was verified the same day: `--checksum`, `--delete`, `--exclude`,
> `--partial` resuming an interrupted 300 MiB upload, kept modes and guest
> ownership, plus scp in both modes, an sftp batch (and one that fails), and
> the stopped-sandbox line quoted below.

After the [one-time setup](./README.md#one-time-setup) every sandbox is an
ssh host named `<sandbox>.wssp`, so the usual copy tools work unchanged. Paths
on the sandbox side are paths in the VM's own filesystem; a relative path is
relative to the guest user's home directory.

Which one to use:

- **rsync** for directories you copy more than once: it sends only what
  changed, can delete, exclude and resume.
- **scp** for a file or two.
- **sftp** to browse and move files interactively, or for a scripted batch.

## rsync

```sh
rsync -a ./src/ web.wssp:src/                    # upload a directory's contents into ~/src
rsync -a web.wssp:src/ ./src-copy/               # download it again
rsync -a --checksum ./src/ web.wssp:src/         # compare contents, not size and time
rsync -a --delete ./src/ web.wssp:src/           # also delete files that are gone locally
rsync -a --exclude node_modules --exclude .git ./app/ web.wssp:app/
rsync -a --partial --info=progress2 ./big/ web.wssp:big/   # keep partial files, show progress
```

- `-a` keeps the tree as it is: directories, symlinks, permissions and
  modification times. A trailing `/` on the source means "the contents of";
  without it rsync creates `src` inside the target.
- `--checksum` compares file contents instead of size and modification time.
  It reads every file on both sides, so it is slower on large trees.
- `--delete` removes files in the target that are not in the source. Try it
  with `--dry-run` (`-n`) first.
- `--exclude` takes a pattern, and can repeat; `--exclude-from=FILE` reads
  them from a file.
- **Resuming a large tree:** run the same command again. rsync skips the files
  that already arrived. `--partial` keeps a file that was cut off halfway, so
  the next run continues from it instead of from zero.

rsync runs the guest's own `rsync` binary over ssh (`rsync --server …` as a
command). The community templates include it; a custom template needs it
installed ([What the sandbox needs](./README.md#what-the-sandbox-needs)).

**Speed.** A transfer moves at most about 1 MiB per round trip between your
machine and the sandbox's node, in each direction, so the round trip sets the
speed more than the tool: about 10 MB/s at 100 ms. rsync and scp, uploads and
downloads, all run close to that.

## scp

```sh
scp ./data.tar web.wssp:                         # into the guest user's home
scp ./data.tar web.wssp:/home/user/backups/      # an absolute path
scp web.wssp:results.json .                      # download
scp -r ./site web.wssp:                          # a directory
scp -O ./data.tar web.wssp:                      # legacy scp protocol
```

OpenSSH's `scp` uses the **sftp protocol** by default, which needs the guest's
`sftp-server`. `scp -O` uses the legacy scp protocol instead, which runs the
guest's `scp` binary as a command and works without `sftp-server`. Both modes
copy byte-exact; use `-O` only for a template without `sftp-server`.

## sftp

Interactive:

```sh
sftp web.wssp
sftp> ls -l
sftp> put ./report.pdf
sftp> get results.json
sftp> bye
```

In a script, put the commands in a batch file; `-b` stops at the first command
that fails and exits non-zero:

```sh
printf 'put ./build.tar\nls -l build.tar\nget logs/app.log\n' > batch.txt
sftp -b batch.txt web.wssp
```

sftp, like default-mode scp and JetBrains Gateway, runs the guest's
`sftp-server`.

## Large transfers

- **Where to put large files.** The guest's `/tmp` can be a small memory
  file system (on a 2 GiB community sandbox it held about 900 MB). Copy large
  files into the home directory, which is on the sandbox's disk, or check with
  `ssh web.wssp 'df -h /tmp ~'` first.
- **Disk size.** A sandbox's disk is sized when it is created (`diskGiB`, by
  default the template's default: 32 GiB for the community base, see
  [root disk](../sandboxes.md#root-disk-minimum-and-default)) and cannot grow
  afterwards. A full disk fails the copy (see below).
- **Long copies and the 12-hour limit.** Every ssh connection is a connect
  session, which ends after 12 hours at the latest, and when the sandbox
  stops, the login is revoked or the connection drops. Split very long copies
  into rsync runs you can repeat.
- **Unattended copies.** A copy in a script that loses its connection exits
  non-zero (ssh exits 255, rsync and scp report the broken connection); rerun
  the same rsync to continue.

## Ownership and permissions

Everything you copy into a sandbox belongs to the guest user, the same user
your shells run as (on the community templates, `user`). Copying as another
user or as root is not possible: there is no run-as. rsync `-a` keeps
permissions and modification times, but cannot set another owner or group
(that needs root on the receiving side), so files arrive owned by the guest
user. To place files outside the guest user's directories, copy them into
the home directory and move them with `sudo` in the sandbox, if the sandbox
has guest sudo ([root in the guest](../sandboxes.md#root-in-the-guest)).

## Troubleshooting

To see what failed, run the same copy with ssh's own output: rsync and scp
print the error lines of both ssh and wssp. To test the connection alone, run
`ssh web.wssp true`.

Lines marked "…" continue with the server's error code, for example
``…: `sandbox.state_conflict`: the server answered HTTP 409``.

| You see                                                                                                                                                      | Meaning and fix                                                                                                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Command not found`, then `rsync: connection unexpectedly closed (0 bytes received so far)` and `rsync error: error in rsync protocol data stream (code 12)` | The sandbox has no `rsync`. Use a template that includes it (the community templates do), or install it in the sandbox (`sudo apt-get install -y rsync` with guest sudo).                                |
| `wssp: this sandbox has no sftp-server; add the openssh-sftp-server package to its template (scp -O and rsync work without it)`                              | The sandbox has no `sftp-server`, which scp's default mode and sftp need. Add `openssh-sftp-server` to the template, or use `scp -O` or rsync.                                                           |
| `[receiver] write failed on "…": No space left on device (28)` (rsync); scp and sftp report a failed write                                                   | The target file system is full: often `/tmp` (a memory file system), else the sandbox's disk. Copy into the home directory, or free space.                                                               |
| ``error: sandbox `web` is stopped; start it with `wssp sandbox start <id> --wait`…``                                                                         | The sandbox is stopped. Start it with the command shown (it names the sandbox's id), then copy again.                                                                                                    |
| ``error: the session ended (`sandbox_stopped`): the sandbox stopped``                                                                                        | The sandbox stopped during the copy. Start it and run the copy again; rsync continues where it stopped.                                                                                                  |
| ``error: the session ended (`revoked`): the login was revoked or expired, or access to the sandbox was withdrawn``                                           | Your login was revoked or expired during the copy. Log in again (`wssp login`, or `wssp login --server <url>` after `wssp logout`) and copy again.                                                       |
| ``error: not logged in; run `wssp login --server <url>` ``                                                                                                   | No login on this machine (or in the environment ssh runs in). Run `wssp login --server <url>`.                                                                                                           |
| `Host key verification failed.`                                                                                                                              | ssh runs `wssp` with another wssp user directory than the one `wssp ssh-config --install` used (a different `WSSP_USER_DIR` or XDG data directory). Run `wssp ssh-config --install` in that environment. |

Every wssp refusal and how a session ends are listed in the
[reference](../connect.md#exit-status).
