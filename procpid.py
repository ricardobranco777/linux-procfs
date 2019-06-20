"""
Module for managing /proc/<pid/*
"""

import os
import re
try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest

from attrdict import AttrDict

_maps_fields = ('address', 'perms', 'offset', 'dev', 'inode', 'pathname')

_stat_fields = (
    'pid comm state ppid pgrp session tty_nr tpgid flags '
    'minflt cminflt majflt cmajflt utime stime cutime cstime '
    'priority nice num_threads itrealvalue starttime vsize rss rsslim '
    'startcode endcode startstack kstkesp kstkeip signal blocked '
    'sigignore sigcatch wchan nswap cnswap exit_signal processor '
    'rt_priority policy delayacct_blkio_ticks guest_time cguest_time '
    'start_data end_data start_brk arg_start arg_end env_start env_end '
    'exit_code')

_statm_fields = ('size', 'resident', 'shared', 'text', 'lib', 'data', 'dt')

_status_XID_fields = ('real', 'effective', 'saved_set', 'filesystem')


class ProcPid(AttrDict):
    """
    Class for managing /proc/<pid>/*
    """
    def __init__(self, pid=None, proc="/proc"):
        if pid is None:
            pid = os.getpid()
        if not pid.isdigit():
            raise ValueError("Invalid pid %s" % pid)
        self['pid'] = pid
        self._proc = proc
        super(ProcPid, self).__init__()

    def _cmdline(self):
        """
        Returns the content of /proc/<pid>/cmdline as a list
        """
        with open(os.path.join(self._proc, self.pid, "cmdline")) as file:
            data = file.read()
        if data[-1] == '\0':
            return data[:-1].split('\0')
        return [data]

    def _environ(self):
        """
        Returns the content of /proc/<pid>/environ as a dictionary
        """
        with open(os.path.join(self._proc, self.pid, "environ")) as file:
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
        with open(os.path.join(self._proc, self.pid, "io")) as file:
            lines = file.read().splitlines()
        return AttrDict([_.split(': ') for _ in lines])

    def _maps(self):
        """
        Parses /proc/<pid>/maps and returns a list of AttrDict's
        """
        with open(os.path.join(self._proc, self.pid, "maps")) as file:
            lines = file.read().splitlines()
        return [
            AttrDict(zip_longest(_maps_fields, line.split()))
            for line in lines]

    def _stat(self):
        """
        Parses /proc/<pid>/stat and returns an AttrDict
        """
        with open(os.path.join(self._proc, self.pid, "stat")) as file:
            data = re.findall(r"\(.*\)|\S+", file.read()[:-1])
        return AttrDict(zip(_stat_fields.split(), data))

    def _statm(self):
        """
        Parses /proc/<pid>/statm and returns an AttrDict
        """
        with open(os.path.join(self._proc, self.pid, "statm")) as file:
            data = map(int, file.read().split())
        return AttrDict(zip(_statm_fields, data))

    def _status(self):
        """
        Parses /proc/<pid>/status and returns an AttrDict
        """
        with open(os.path.join(self._proc, self.pid, "status")) as file:
            lines = file.read().splitlines()
        status = AttrDict([_.split(':\t') for _ in lines])
        status['Uid'] = AttrDict(
            zip(_status_XID_fields, map(int, status.Uid.split())))
        status['Gid'] = AttrDict(
            zip(_status_XID_fields, map(int, status.Gid.split())))
        return status

    def __getitem__(self, item):
        """
        Creates dynamic attributes for elements in /proc/<pid>
        """
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            pass
        if item in ('cmdline', 'environ', 'io', 'maps',
                    'stat', 'statm', 'status'):
            func = getattr(self, "_" + item)
            self.__setitem__(item, func())
        else:
            path = os.path.join(self._proc, self.pid, item)
            if os.path.islink(path):
                self.__setitem__(item, path)
            elif os.path.isfile(path):
                with open(path) as file:
                    self.__setitem__(item, file.read())
            elif os.path.isdir(path):
                return [
                    os.path.join(self._proc, path, _)
                    for _ in os.listdir(path)]
        return dict.__getitem__(self, item)
