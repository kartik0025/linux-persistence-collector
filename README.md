# linux-persistence-collector

Malware that wants to survive a reboot on Linux has to leave something behind. A service file, a cron
entry, a line in a config the dynamic linker reads at startup. This script checks the usual places and
tells you if anything there looks wrong.

It has two modes.

**`--baseline`** records the current state of those locations to a JSON file. Run it on a machine you
trust, keep the file, and you have something to diff against later. The script does not do the diff for
you. That is the most obvious thing missing from it.

**`--scan`** applies six checks and prints what it found.

Python 3.7 or later. Nothing to install.

## Quick start

```bash
sudo python3 collector.py --baseline --output baseline.json
sudo python3 collector.py --scan
```

Root is recommended but not required. Without it the script still runs, skips the parts it cannot read,
and says so.

## Why the scope is so narrow

This began as a measurement instrument for a research project on how Linux persistence artifacts survive
an attacker's cleanup script. The study was pre-registered: its scoring rules were published before any
data was collected. The pre-registration and evidence are on Zenodo at
[doi:10.5281/zenodo.20364642](https://doi.org/10.5281/zenodo.20364642).

A research instrument has a different job from a security product. It has to check a fixed list of
locations the same way on every run, so that results stay comparable between runs. It does not have to
catch everything. This tool kept that shape. The narrowness is a design decision, not an unfinished
to-do list.

If you are here to learn what Linux persistence looks like, that is probably an advantage. Six checks you
can read in full and disagree with are more useful than a long list you have to take on trust.

## What it checks, and why each one matters

Each check is a judgement call, so the reasoning is written out. Read it and decide whether you agree
before you trust what the script tells you.

### 1. Timestamps that disagree

Every file has a modification time (`mtime`) and a change time (`ctime`). `mtime` is when the contents
last changed. `ctime` is when the file's metadata last changed, which includes permissions, ownership and
the content itself. Writing to a file updates both.

`ctime` is **not** the creation time, despite the name. That is a common misreading, and it has a real
source: on Windows `ctime` does mean creation time. Python's documentation spells out the split, calling
`st_ctime` "the time of most recent metadata change on Unix, the time of creation on Windows". Linux does
record a creation time, called `btime`, but it lives behind the `statx()` syscall and older tools do not
show it.

The check works because of one asymmetry: **you cannot set `ctime` directly.** `touch -t` and the
`utimes()` syscall change `atime` and `mtime`, and doing so sets `ctime` to the current time as a side
effect. So an attacker who backdates a file to make it look old leaves `mtime` in the past and `ctime` in
the present. Avoiding that means changing the system clock or editing the inode through the raw device,
which is a much higher bar.

The script flags anything where `ctime` is more than an hour later than `mtime`. Ordinary system activity
produces this sometimes, so treat it as a place to look rather than a verdict.

### 2. systemd links pointing at nothing

When a service is enabled, systemd creates a symbolic link in a `.wants/` directory pointing at the unit
file. Disabling the service removes the link. Deleting the unit file without disabling it first leaves
the link behind, pointing at a file that no longer exists.

That leftover link is worth noticing. It says a service used to be enabled here and something removed the
unit file without going through systemd. That is what a cleanup script does when it is in a hurry.

### 3. `/etc/ld.so.preload`

If this file exists, every dynamically linked program on the system loads the libraries listed in it
before anything else. That includes `ls`, `ps` and `sshd`.

It is a supported feature with legitimate uses, and it is also one of the oldest ways to hide a process
from the tools you would use to look for it. Most systems do not have this file at all. Its presence is
worth explaining.

### 4. Lingering users

Normally a user's systemd services stop when they log out. Enabling "linger" for a user keeps those
services running without them, across reboots.

It is a real feature for people who run long-lived background jobs. It is also a way to run something
persistently as an unprivileged user without touching any system-level config. The script lists every
user it is enabled for so you can check whether that is expected.

### 5. systemd timers

Timers are systemd's replacement for cron. They do the same job and get looked at far less often, partly
because most people still think to check `crontab` first.

**This check does less than it appears to.** It flags timer units whose filename contains the word
`research`, which was the marker the original experiment used when planting units. Nobody names real
malware that, so it will not find one. It stays as it is because the research this tool was built for
depends on that exact behaviour, and changing it would mean the published method no longer matches the
code.

The honest version is a list of the timers a clean installation is expected to have, flagging whatever
is not on it. That inverts the logic from "find what I planted" to "find what I did not expect", which
is what detection means. It is not implemented here.

### 6. Scripts in `/etc/update-motd.d/`

Files in this directory run as root every time someone logs in interactively over SSH, to build the
message-of-the-day banner. They are ordinary shell scripts, and adding one is a quiet way to get code
executed on a schedule you do not control but can predict.

The script flags anything beginning with `99-`, on the reasoning that a high number runs last and is
least likely to visibly break the banner, plus the same `research` marker as above. Both tests are weak.
Several distributions ship legitimate high-numbered scripts, and anyone who has read this file would
simply choose a different number.

## Where it looks

```
/etc/systemd/system/          /etc/cron.d/              /etc/ld.so.preload
/etc/passwd                   /var/tmp/                 /usr/lib/
/var/lib/systemd/linger/      /etc/profile.d/           /etc/update-motd.d/
```

For every file, directory and symlink under those paths, `--baseline` records the path, size, owner, group,
permissions, both timestamps and the type. Volatile data (`ps auxww` and `ss -tulpn`) is captured first,
because process and network state disappear the moment you stop looking and file metadata does not. That
ordering follows [RFC 3227](https://www.rfc-editor.org/rfc/rfc3227), the standard guidance on collecting
evidence most-volatile-first.

## Output

`--scan` prints a readable summary by default, or JSON with `--format json`.

```
$ sudo python3 collector.py --scan
[*] Reading file metadata...

2 alert(s)

[ORPHANED_SYMLINK] /etc/systemd/system/multi-user.target.wants/telemetry.service
    Points at /etc/systemd/system/telemetry.service, which does not exist.

[LD_PRELOAD] /etc/ld.so.preload
    Present. Read what it lists.
```

Progress messages go to standard error and findings go to standard output, so this gives you a file that
actually parses:

```bash
sudo python3 collector.py --scan --format json > findings.json
```

`--baseline` refuses to overwrite an existing file. Pass `--overwrite` when that is what you want.

## What it does not do

- **These are heuristics.** Every alert can have an innocent explanation. Package updates change
  timestamps. Administrators create timers. The script tells you where to look, not what happened.
- **Nine directories is not the whole picture.** Kernel modules, initramfs, shell startup files, PAM,
  systemd generators and container escapes are all real persistence locations and none of them are
  covered here.
- **It reads the live filesystem.** Anything with enough privilege to install a rootkit has enough
  privilege to lie to it. If you are investigating a real incident, image the disk.
- **Linux with systemd only.** No BSD, no macOS, no non-systemd init.
- **A baseline taken after a compromise makes the compromise look normal.** Capture it on a machine you
  have reason to trust.
- **Nothing reads the baseline back.** `--baseline` writes a file that no code in this repository
  consumes. Diffing two snapshots is the obvious missing feature and the one that would turn this from a
  recorder into a tool. There are no exit codes either, so it is not much use in a script yet.

## If you want something broader

Use [UAC](https://github.com/tclahr/uac). It collects artifacts comprehensively across most Unix-like
systems, handles order of volatility properly, and produces a full evidence archive for offline analysis.
It solves a different and larger problem than this does, and it solves it well.

The two are not alternatives. Collect with UAC when you need everything. Run this when you want a quick
answer to "has anything changed here, and does anything look odd".

## How this was built

The first version of this script was generated by an LLM from a description of what I wanted. It ran, it
produced plausible output, and I used it in a research project before I had properly read it.

When I did read it, it had fourteen defects. The headline timestamp check had never examined a single
file, because an `isdir()` guard skipped both files in the path list and nothing recursed. Three bare
`except:` clauses collapsed unrelated failures into one message and swallowed Ctrl-C along the way. A
`--baseline` flag accepted a filename and then wrote somewhere else entirely.

None of that stopped it working, which is the part worth thinking about. I wrote up everything I found,
and what I would tell anyone about to trust code they generated, here:
[The check that never checked a file](https://kartiksankhla.com/posts/the-check-that-never-checked-a-file/).

What is in this repository is the rewrite. The limitations listed above are the ones that survived it,
and they are listed because a limitation you only know in your head is one nobody else can act on.

## Licence

MIT. See [LICENSE](LICENSE).
