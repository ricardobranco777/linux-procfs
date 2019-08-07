#
# Copyright 2019 Ricardo Branco <rbranco@suse.de>
# MIT License
#
"""
Module with classes to parse /proc entries
"""

import gzip
import os
import re
import stat
from itertools import zip_longest

from restartable.attrdict import AttrDict


class Proc(AttrDict):
    """
    Class to parse /proc entries
    """
    def __init__(self, proc="/proc"):
        self.proc = proc
        super().__init__()

    def pids(self):
        """
        Returns a list of all the processes in the system
        """
        return filter(str.isdigit, os.listdir(self.proc))

    def tasks(self):
        """
        Returns a list of all the tasks (threads) in the system
        """
        #  We could use a list comprehension but a PID could disappear
        for pid in self.pids():
            try:
                yield from os.listdir(os.path.join(self.proc, pid, "task"))
            except FileNotFoundError:
                pass

    def _config(self):
        """
        Parses /proc/config.gz and returns an AttrDict
        If /proc/config.gz doesn't exist, try /boot or /lib/modules/
        """
        lines = None
        paths = [
            os.path.join(self.proc, "config.gz"),
            "boot/config-%s" % os.uname().release,
            "/lib/modules/%s/build/.config" % os.uname().release
        ]
        for path in paths:
            if os.path.exists(path):
                if path.endswith("gz"):
                    with gzip.open(path) as file:
                        lines = file.read().decode('utf-8').splitlines()
                else:
                    with open(path) as file:
                        lines = file.read().splitlines()
                break
        if lines is None:
            return None
        return AttrDict(
            line.split('=') for line in lines if line.startswith("CONFIG_"))

    def _cgroups(self):
        """
        Parses /proc/cgroup and returns a list of AttrDict's
        """
        with open(os.path.join(self.proc, "cgroups")) as file:
            data = file.read()
        keys, *values = data.splitlines()
        return [AttrDict(zip(keys[1:].split(), _.split())) for _ in values]

    def _cmdline(self):
        """
        Parses /proc/cmdline and returns a list
        """
        with open(os.path.join(self.proc, "cmdline")) as file:
            return file.read().strip()

    def _cpuinfo(self):
        """
        Parses /proc/cpuinfo and returns a list of AttrDict's
        """
        with open(os.path.join(self.proc, "cpuinfo")) as file:
            cpus = [_ for _ in file.read()[:-1].split('\n\n')]
        return [
            AttrDict([map(str.strip, line.split(':'))
                      for line in cpu.splitlines()])
            for cpu in cpus]

    def _meminfo(self):
        """
        Parses /proc/meminfo and returns an AttrDict
        """
        with open(os.path.join(self.proc, "meminfo")) as file:
            lines = file.read().splitlines()
        return AttrDict([map(str.strip, line.split(':')) for line in lines])

    def _mounts(self):
        """
        Parses /proc/mounts and returns a list of AttrDict's
        """
        # /proc/mounts is a symlink to /proc/self/mounts
        with ProcPid(proc=self.proc) as proc_self:
            return proc_self.mounts

    def _swaps(self):
        """
        Parses /proc/swaps and returns a list of AttrDict's
        """
        with open(os.path.join(self.proc, "swaps")) as file:
            data = file.read()
        keys, *values = data.splitlines()
        return [AttrDict(zip(keys.split(), _.split())) for _ in values]

    def _vmstat(self):
        """
        Parses /proc/vmstat and returns an AttrDict
        """
        with open(os.path.join(self.proc, "vmstat")) as file:
            data = file.read()
        return AttrDict(line.split() for line in data.splitlines())

    def __getitem__(self, path):
        """
        Creates dynamic attributes for elements in /proc/
        """
        try:
            return dict.__getitem__(self, path)
        except KeyError:
            pass
        if path in ("config", "cgroups", "cmdline", "cpuinfo",
                    "meminfo", "mounts", "swaps", "vmstat"):
            func = getattr(self, "_" + path)
            self.__setitem__(path, func())
        elif path == "self":
            return ProcPid(proc=self.proc)
        elif path.isdigit():
            return ProcPid(path, proc=self.proc)
        else:
            path = os.path.join(self.proc, path)
            if os.path.islink(path):
                self.__setitem__(path, path)
            elif os.path.isfile(path):
                with open(path) as file:
                    self.__setitem__(path, file.read())
            elif os.path.isdir(path):
                return os.listdir(path)
        return dict.__getitem__(self, path)


_limits_fields = {
    'Max cpu time': 'cpu',
    'Max file size': 'fsize',
    'Max data size': 'data',
    'Max stack size': 'stack',
    'Max core file size': 'core',
    'Max resident set': 'rss',
    'Max processes': 'nproc',
    'Max open files': 'nofile',
    'Max locked memory': 'memlock',
    'Max address space': 'as',
    'Max file locks': 'locks',
    'Max pending signals': 'sigpending',
    'Max msgqueue size': 'msgqueue',
    'Max nice priority': 'nice',
    'Max realtime priority': 'rtprio',
    'Max realtime timeout': 'rttime',
}

_maps_fields = ('address', 'perms', 'offset', 'dev', 'inode', 'pathname')

_mounts_fields = ('fs_spec', 'fs_file', 'fs_vfstype',
                  'fs_mntops', 'fs_freq', 'fs_passno')

_stat_fields = (
    'pid comm state ppid pgrp session tty_nr tpgid flags '
    'minflt cminflt majflt cmajflt utime stime cutime cstime '
    'priority nice num_threads itrealvalue starttime vsize rss rsslim '
    'startcode endcode startstack kstkesp kstkeip signal blocked '
    'sigignore sigcatch wchan nswap cnswap exit_signal processor '
    'rt_priority policy delayacct_blkio_ticks guest_time cguest_time '
    'start_data end_data start_brk arg_start arg_end env_start env_end '
    'exit_code').split()

_statm_fields = ('size', 'resident', 'shared', 'text', 'lib', 'data', 'dt')

_status_XID_fields = ('real', 'effective', 'saved_set', 'filesystem')


class ProcPid(AttrDict):
    """
    Class for managing /proc/<pid>/*
    """
    def __init__(self, pid=None, proc="/proc"):
        if pid is None:
            pid = os.getpid()
        if not isinstance(pid, (int, str)) and int(pid) <= 0:
            raise ValueError("Invalid pid %s" % pid)
        self.pid = str(pid)
        self.dir_fd = None
        try:
            self.dir_fd = os.open(os.path.join(proc, self.pid), os.O_RDONLY)
        except OSError as err:
            raise err
        super().__init__()

    def __enter__(self):
        return self

    def __del__(self):
        if self.dir_fd is not None:
            os.close(self.dir_fd)
        self.dir_fd = None

    def __exit__(self, exc_type, exc_value, traceback):
        if self.dir_fd is not None:
            os.close(self.dir_fd)
        self.dir_fd = None

    def __opener(self, path, flags):
        return os.open(path, flags, dir_fd=self.dir_fd)

    def _cmdline(self):
        """
        Parses /proc/<pid>/cmdline and returns a list
        """
        with open("cmdline", opener=self.__opener) as file:
            data = file.read()
        # Escape newlines
        data = data.replace("\n", "\\n")
        if data.endswith('\0'):
            return data[:-1].split('\0')
        return [data]

    def _comm(self):
        """
        Parses /proc/comm
        """
        with open("comm", opener=self.__opener) as file:
            data = file.read()
        # Strip trailing newline
        return data[:-1]

    def _environ(self):
        """
        Parses /proc/<pid>/environ and returns a dictionary
        """
        with open("environ", opener=self.__opener) as file:
            data = file.read()
        try:
            return {
                k: v for k, v in [
                    _.split('=', 1) for _ in data[:-1].split('\0')]}
        except ValueError:
            return data

    def _io(self):
        """
        Parses /proc/<pid>/io and returns an AttrDict
        """
        with open("io", opener=self.__opener) as file:
            lines = file.read().splitlines()
        return AttrDict([_.split(': ') for _ in lines])

    def _limits(self):
        """
        Parses /proc/<pid>/limits and returns an AttrDict
        """
        with open("limits", opener=self.__opener) as file:
            data = re.findall(
                r'^(.*?)\s{2,}(\S+)\s{2,}(\S+)', file.read(), re.M)[1:]
        return AttrDict(
            {_limits_fields[k]: AttrDict(zip(('soft', 'hard'), v))
             for (k, *v) in data})

    def _maps(self):
        """
        Parses /proc/<pid>/maps and returns a list of AttrDict's
        """
        with open("maps", opener=self.__opener) as file:
            lines = file.read().splitlines()
        maps = [
            AttrDict(zip_longest(_maps_fields, line.split(maxsplit=5)))
            for line in lines]
        # From the proc(5) manpage:
        #  pathname is shown unescaped except for newline characters,
        #  which are replaced with an octal escape sequence. As a result,
        #  it is not possible to determine whether the original pathname
        #  contained a newline character or the literal \012 character sequence
        # So let's readlink() the address in the map_files directory
        for map_ in maps:
            if map_.pathname and "\\012" in map_.pathname:
                map_.pathname = os.readlink(
                    "map_files/%s" % map_.address,
                    dir_fd=self.dir_fd
                ).replace("\n", "\\n")
        return maps

    def _mounts(self):
        """
        Parses /proc/<pid>/mounts and returns a list of AttrDict's
        """
        with open("mounts", opener=self.__opener) as file:
            lines = file.read().splitlines()
        return [
            AttrDict(zip(_mounts_fields, line.split()))
            for line in lines]

    def _stat(self):
        """
        Parses /proc/<pid>/stat and returns an AttrDict
        """
        with open("stat", opener=self.__opener) as file:
            data = re.findall(r"\(.*\)|\S+", file.read()[:-1], re.M | re.S)
        info = AttrDict(zip(_stat_fields, data))
        # Remove parentheses
        info.comm = info.comm[1:-1]
        # Escape newlines
        info.comm = info.comm.replace("\n", "\\n")
        return info

    def _statm(self):
        """
        Parses /proc/<pid>/statm and returns an AttrDict
        """
        with open("statm", opener=self.__opener) as file:
            data = map(int, file.read().split())
        return AttrDict(zip(_statm_fields, data))

    def _status(self):
        """
        Parses /proc/<pid>/status and returns an AttrDict
        """
        with open("status", opener=self.__opener) as file:
            lines = file.read().splitlines()
        status = AttrDict([_.split(':\t') for _ in lines])
        status['Uid'] = AttrDict(
            zip(_status_XID_fields, map(int, status.Uid.split())))
        status['Gid'] = AttrDict(
            zip(_status_XID_fields, map(int, status.Gid.split())))
        # status['Name'] = status['Name'].replace("\\n", "\n")
        return status

    def __getitem__(self, path):
        """
        Creates dynamic attributes for elements in /proc/<pid>
        """
        try:
            return dict.__getitem__(self, path)
        except KeyError:
            pass
        if path in ('cmdline', 'comm', 'environ', 'io', 'limits',
                    'maps', 'mounts', 'stat', 'statm', 'status'):
            func = getattr(self, "_" + path)
            self.__setitem__(path, func())
        else:
            mode = os.lstat(path, dir_fd=self.dir_fd).st_mode
            if stat.S_ISLNK(mode):
                self.__setitem__(path, path)
            elif stat.S_ISREG(mode):
                with open(path, opener=self.__opener) as file:
                    self.__setitem__(path, file.read())
            elif stat.S_ISDIR(mode):
                dir_fd = os.open(path, os.O_RDONLY, dir_fd=self.dir_fd)
                listing = os.listdir(dir_fd)
                os.close(dir_fd)
                return listing
        return dict.__getitem__(self, path)
