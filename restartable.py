#!/usr/bin/env python3
#
# Copyright 2019 Ricardo Branco <rbranco@suse.de>
# MIT License
#
"""
list restartable programs or services using deleted libraries
"""

import os
import pwd
import re
import sys
from argparse import ArgumentParser

from procfs import ProcPid

VERSION = "0.5.1"

USAGE = """%s [OPTIONS]

List running processes using files deleted by recent upgrades

Options:
    -h, --help      Get help
    -V, --version   Show version and exit
    -P, --proc PROC_DIRECTORY
    -s, --short
         Create a short table not showing the deleted files. Given twice,
         show only processes which are associated with a system service.
         Given three times, list the associated system service names only.
    -v, --verbose   Show the complete command line
""" % os.path.basename(sys.argv[0])

# Ignore deleted files in these directories
IGNORE = (
    '/dev',
    '/run',
    '/ ',
)

# Regular expression to find systemd service unit in /proc/<pid>/cgroup
SYSTEMD_REGEX = r"\d+:name=systemd:/system\.slice/(?:.*/)?(.*)\.service$"

# Regular expression to match scripting languages
SCRIPT_REGEX = r"((perl|python|ruby)(\d?(\.\d)?)|(a|ba|c|da|fi|k|pdk|tc|z)?sh)$"

opts = None
services = set()


def guess_command(proc):
    """
    Guess the command being run
    /proc/comm & /proc/pid/stat truncate the command to 15 chars
    If running a script, get the name of the script instead of the interpreter
    Also, kernel usermode helpers use "none"
    """
    if opts.verbose:
        # cmdline is empty if zombie
        cmdline = " ".join(proc.cmdline)
        if not cmdline:
            return proc.stat.comm
    else:
        cmdline = proc.stat.comm
        if proc.cmdline[0] and (len(cmdline) == 15 or cmdline == "none"):
            cmdline = os.path.basename(proc.cmdline[0])
        if re.match(SCRIPT_REGEX, cmdline):
            # Skip options
            for arg in proc.cmdline[1:]:
                if not arg.startswith('-'):
                    cmdline = os.path.basename(arg)
                    break
    return cmdline


def print_info(proc, deleted):
    """
    Print information
    """
    try:
        service = re.findall(SYSTEMD_REGEX, proc.cgroup, re.MULTILINE)[0]
    except IndexError:
        if opts.short > 1:
            return
        service = "-"
    if opts.short > 2:
        services.add(service)
    else:
        uid = proc.status.Uid.real
        try:
            username = pwd.getpwuid(uid).pw_name
        except KeyError:
            username = uid
        cmdline = guess_command(proc)
        print("%s\t%s\t%s\t%-30s\t%40s\t%s" % (
            proc.pid, proc.stat.ppid, uid, username, service, cmdline))
    if not opts.short:
        for path in sorted(deleted):
            print("\t%s" % path)


def main():
    """
    Main function
    """
    argparser = ArgumentParser(usage=USAGE, add_help=False)
    argparser.add_argument('-h', '--help', action='store_true')
    argparser.add_argument('-P', '--proc', default='/proc')
    argparser.add_argument('-s', '--short', action='count', default=0)
    argparser.add_argument('-v', '--verbose', action='store_true')
    argparser.add_argument('-V', '--version', action='store_true')
    global opts
    opts = argparser.parse_args()
    if opts.help:
        print(USAGE)
        sys.exit(0)
    elif opts.version:
        print(VERSION)
        sys.exit(0)

    if os.geteuid() != 0:
        print("WARN: Run this program as root", file=sys.stderr)

    if opts.short < 3:
        print("%s\t%s\t%s\t%-30s\t%40s\t%s" % (
            "PID", "PPID", "UID", "User", "Service", "Command"))
    for pid in [_ for _ in os.listdir("/proc") if _.isdigit()]:
        try:
            with ProcPid(pid, proc=opts.proc) as proc:
                # Get deleted executable mappings
                deleted = {
                    _['pathname'][:-len(" (deleted)")]
                    for _ in proc.maps
                    if (_['pathname']
                        and 'x' in _['perms']
                        and _['pathname'].endswith(" (deleted)")
                        and not _['pathname'].startswith(IGNORE))
                }
                if deleted:
                    print_info(proc, deleted)
        except OSError:
            pass
    if opts.short > 2:
        print("\n".join(sorted(services)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
