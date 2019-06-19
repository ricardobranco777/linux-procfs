#!/usr/bin/env python3
#
# Copyright 2019 Ricardo Branco <rbranco@suse.de>
# MIT License
#
"""
list restartable programs or services using deleted libraries
"""

from __future__ import print_function

import os
import pwd
import re
import sys
from argparse import ArgumentParser
from collections import namedtuple

VERSION = "0.3"

USAGE = """%s [OPTIONS]

List running processes using files deleted by recent upgrades

Options:
    -h, --help      Get help
    -V, --version   Show version and exit
    -s, --short
         Create a short table not showing the deleted files. Given twice,
         show only processes which are associated with a system service.
         Given three times, list the associated system service names only.
""" % os.path.basename(sys.argv[0])

# Ignore deleted files in these directories
IGNORE = ('/dev',
          '/home',
          '/i915',
          '/memfd:',
          '/run',
          '/SYSV',
          '/tmp',
          '/var',
          '/[aio]')

# Regular expression to find systemd service unit in /proc/<pid>/cgroup
SYSTEMD_REGEX = r"\d+:name=systemd:/system\.slice/(?:.*/)?(.*)\.service$"


def get_stat_fields():
    """
    Return the names of stat fields supported by this kernel
    """
    # /proc/<pid>/stat fields as described by procfs(5)
    fields = ('pid comm state ppid pgrp session tty_nr tpgid flags '
              'minflt cminflt majflt cmajflt utime stime cutime cstime '
              'priority nice num_threads itrealvalue starttime vsize rss '
              'rsslim startcode endcode startstack kstkesp kstkeip signal '
              'blocked sigignore sigcatch wchan nswap cnswap exit_signal '
              'processor rt_priority policy delayacct_blkio_ticks guest_time '
              'cguest_time start_data end_data start_brk arg_start arg_end '
              'env_start env_end exit_code')
    with open("/proc/1/stat") as file:
        data = re.findall(r"\(.*\)|\S+", file.read().strip())
    return fields.split()[:len(data)]


# Create named tuple with stat fields as attributes
Stat = namedtuple('Stat', get_stat_fields())


# Create named tuple with /proc/<pid>/status fields as attributes
with open("/proc/1/status") as _file:
    Status = namedtuple(
        'Status',
        [_.split(':')[0] for _ in _file.read().splitlines()])


# Create named tuple for UID & GID
ID = namedtuple('ID', ('real', 'effective', 'saved_set', 'filesystem'))

args = None


def parse_proc_status(path):
    """
    Parse /proc/<PID>/status
    Returns Status named tuple
    """
    with open(path) as file:
        lines = file.read().splitlines()
    return Status(*[_.split(':')[1].strip() for _ in lines])


def parse_proc_stat(path):
    """
    Parse /proc/<PID>/stat
    Returns Stat named tuple
    """
    with open(path) as file:
        data = re.findall(r"\(.*\)|\S+", file.read().strip())
    return Stat(*data)


def parse_status_id(xid):
    """
    Parse the Uid/Gid field of /proc/<PID>/status
    Returns ID named tuple
    """
    return ID(*map(int, xid.split()))


def print_info(pid, deleted):
    """
    Print information
    """
    try:
        with open("cmdline") as file:
            cmdline = file.read().replace("\0", " ")
        with open("cgroup") as file:
            cgroup = file.read()
        status = parse_proc_status("status")
        stat = parse_proc_stat("stat")
    except OSError:
        return
    # cmdline is empty if zombie
    if not cmdline:
        cmdline = stat.comm
    uid = parse_status_id(status.Uid).real
    try:
        username = pwd.getpwuid(uid).pw_name
    except KeyError:
        username = uid
    try:
        service = re.findall(SYSTEMD_REGEX, cgroup, re.MULTILINE)[0]
    except IndexError:
        if args.short > 1:
            return
        service = "-"
    if args.short > 2:
        print(service)
    else:
        print("%s\t%s\t%s\t%s\t%40s\t%s" % (
            pid, stat.ppid, uid, username, service, cmdline))
    if not args.short:
        for path in sorted(deleted):
            print("\t%s" % path)


def main():
    """
    Main function
    """
    argparser = ArgumentParser(usage=USAGE, add_help=False)
    argparser.add_argument('-h', '--help', action='store_true')
    argparser.add_argument('-s', '--short', action='count', default=0)
    argparser.add_argument('-V', '--version', action='store_true')
    global args
    args = argparser.parse_args()
    if args.help:
        print(USAGE)
        sys.exit(0)
    elif args.version:
        print(VERSION)
        sys.exit(0)

    if os.geteuid() != 0:
        print("WARN: Run this program as root", file=sys.stderr)

    if args.short < 3:
        print("%s\t%s\t%s\t%s\t%40s\t%s" % (
            "PID", "PPID", "UID", "User", "Service", "Command"))
    for pid in [_ for _ in os.listdir("/proc") if _.isdigit()]:
        try:
            os.chdir("/proc/%s" % pid)
            map_files = ["map_files/" + f for f in os.listdir("map_files/")]
        except OSError:
            continue
        deleted = set()
        for path in ["exe"] + map_files:
            try:
                link = os.readlink(path)
            except OSError:
                pass
            if not link or link == "/ (deleted)":
                continue
            if link.endswith(' (deleted)') and not link.startswith(IGNORE):
                deleted.add(link[:-len(' (deleted)')])
        if deleted:
            print_info(pid, deleted)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
