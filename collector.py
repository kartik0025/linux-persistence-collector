#!/usr/bin/env python3
"""
Triage tool for Linux persistence artifacts.

Looks in nine places where malware commonly hides to survive a reboot and
reports anything out of place. Standard library only, so it runs on a machine
where you are not allowed to install anything.

Every check is a heuristic. Findings are leads worth chasing, not proof. Two of
the checks only match artifacts planted by our own experiment, and say so where
they are defined.

    sudo ./collector.py --baseline --output clean.json
    sudo ./collector.py --scan
"""

import argparse
import datetime
import json
import os
import stat
import subprocess
import sys

PERSISTENCE_PATHS = [
    "/etc/systemd/system/",
    "/etc/cron.d/",
    "/etc/ld.so.preload",
    "/etc/passwd",
    "/var/tmp/",
    "/usr/lib/",
    "/var/lib/systemd/linger/",
    "/etc/profile.d/",
    "/etc/update-motd.d/",
]

LD_PRELOAD = "/etc/ld.so.preload"
LINGER_DIR = "/var/lib/systemd/linger/"
MOTD_DIR = "/etc/update-motd.d/"

VOLATILE_COMMANDS = [["ps", "auxww"], ["ss", "-tulpn"]]

TIMESTOMP_THRESHOLD_SECONDS = 3600
COMMAND_TIMEOUT_SECONDS = 30


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--baseline", action="store_true", help="capture a snapshot to --output")
    mode.add_argument("--scan", action="store_true", help="run the heuristic checks")
    parser.add_argument("--output", default="baseline.json", help="where --baseline writes")
    parser.add_argument("--overwrite", action="store_true", help="let --baseline replace an existing file")
    parser.add_argument("--format", choices=["human", "json"], default="human")
    args = parser.parse_args()

    if args.baseline:
        collect_baseline(args.output, args.overwrite)
    elif args.scan:
        report(run_scan(), args.format)
    else:
        parser.print_help()


def log(message):
    # Progress goes to stderr so that "--scan --format json > file" gives valid JSON.
    print(message, file=sys.stderr)


def file_type(mode):
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISBLK(mode):
        return "block device"
    if stat.S_ISCHR(mode):
        return "character device"
    return "unknown"


def list_paths():
    paths = []
    for base in PERSISTENCE_PATHS:
        # lexists, not exists. exists follows symlinks and would skip a dangling one.
        if not os.path.lexists(base):
            continue
        paths.append(base)
        if os.path.isdir(base):
            for directory, subdirs, files in os.walk(base):
                paths += [os.path.join(directory, name) for name in subdirs + files]
    return sorted(paths)


def describe(path):
    # lstat, not stat. stat follows symlinks and raises on a dangling one, which
    # is the artifact this tool most wants to see.
    try:
        info = os.lstat(path)
    except OSError as error:
        return {"path": path, "error": str(error)}

    return {
        "path": path,
        "type": file_type(info.st_mode),
        "size": info.st_size,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "permissions": stat.filemode(info.st_mode),
        "mtime": info.st_mtime,
        "ctime": info.st_ctime,
    }


def run_command(command):
    # A list, never a string with shell=True, so nothing in it reaches a shell.
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=COMMAND_TIMEOUT_SECONDS)
    except FileNotFoundError:
        return {"command": command, "error": "not installed on this system"}
    except subprocess.TimeoutExpired:
        return {"command": command, "error": f"timed out after {COMMAND_TIMEOUT_SECONDS}s"}

    return {"command": command, "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def collect_baseline(output_path, overwrite):
    if os.path.lexists(output_path) and not overwrite:
        log(f"[!] {output_path} already exists. Pass --overwrite to replace it.")
        return

    as_root = os.geteuid() == 0
    if not as_root:
        log("[!] Not running as root. Process owners and socket details will be missing.")

    # Volatile evidence first. It is the evidence that disappears on reboot.
    log("[*] Running volatile commands...")
    volatile = [run_command(command) for command in VOLATILE_COMMANDS]

    log("[*] Reading file metadata...")
    files = [describe(path) for path in list_paths()]

    snapshot = {
        "captured": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hostname": os.uname().nodename,
        "as_root": as_root,
        "volatile": volatile,
        "files": files,
    }

    with open(output_path, "w") as handle:
        json.dump(snapshot, handle, indent=2)
    log(f"[+] Wrote {output_path} ({len(files)} paths)")


def run_scan():
    log("[*] Reading file metadata...")
    records = [describe(path) for path in list_paths()]
    alerts = []

    # Timestomping. mtime is when the contents changed, ctime is when the inode
    # changed. There is no syscall to set ctime, so backdating mtime with touch
    # leaves ctime fresh and the two drift apart.
    for record in records:
        if "error" in record:
            continue
        drift = record["ctime"] - record["mtime"]
        if drift > TIMESTOMP_THRESHOLD_SECONDS:
            alerts.append({
                "type": "TIMESTOMP",
                "path": record["path"],
                "message": f"Metadata changed {round(drift / 3600, 1)} hours after the contents.",
            })

    # Orphaned symlinks. systemd enables a unit by symlinking it into a .wants
    # directory. Deleting the unit file afterwards leaves the link pointing at
    # nothing, and the link still names what was deleted.
    for record in records:
        if record.get("type") != "symlink":
            continue
        target = os.path.realpath(record["path"])
        if not os.path.exists(target):
            alerts.append({
                "type": "ORPHANED_SYMLINK",
                "path": record["path"],
                "message": f"Points at {target}, which does not exist.",
            })

    # Libraries listed here load into every dynamically linked program, so one
    # can replace library functions system wide. Most machines have no such file.
    if os.path.lexists(LD_PRELOAD):
        alerts.append({
            "type": "LD_PRELOAD",
            "path": LD_PRELOAD,
            "message": "Present. Read what it lists.",
        })

    # Linger keeps a user's systemd services running with no login session, so
    # they start at boot. It touches no system unit, so an audit of
    # /etc/systemd/system alone misses it.
    if os.path.isdir(LINGER_DIR):
        for user in sorted(os.listdir(LINGER_DIR)):
            alerts.append({
                "type": "USER_LINGER",
                "path": os.path.join(LINGER_DIR, user),
                "message": f"Linger enabled for {user}.",
            })

    # KNOWN LIMITATION, left in place deliberately.
    #
    # The next two checks match the word "research", which is the marker our own
    # experiment used when planting units. Nobody names real malware that, so
    # these will not find an attacker. They are kept because removing them would
    # change what the tool does, and the paper describes this behaviour.
    #
    # The real fix is a list of the timers and login scripts a clean system is
    # expected to have, flagging whatever is not on it. That inverts the logic
    # from "find what I planted" to "find what I did not expect", which is what
    # detection means. It is not implemented here.
    for record in records:
        name = os.path.basename(record["path"])
        if name.endswith(".timer") and "research" in name:
            alerts.append({
                "type": "EXPERIMENT_TIMER",
                "path": record["path"],
                "message": "Filename matches the experiment's marker.",
            })

    if os.path.isdir(MOTD_DIR):
        for name in sorted(os.listdir(MOTD_DIR)):
            if name.startswith("99-") or "research" in name:
                alerts.append({
                    "type": "MOTD_SCRIPT",
                    "path": os.path.join(MOTD_DIR, name),
                    "message": "Scripts here run as root at every SSH login.",
                })

    return alerts


def report(alerts, output_format):
    if output_format == "json":
        print(json.dumps({"alerts": alerts}, indent=2))
        return

    print(f"\n{len(alerts)} alert(s)")
    for alert in alerts:
        print(f"\n[{alert['type']}] {alert['path']}")
        print(f"    {alert['message']}")
    print("")


if __name__ == "__main__":
    main()
