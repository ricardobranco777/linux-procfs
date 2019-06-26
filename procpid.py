#
# Copyright 2019 Ricardo Branco <rbranco@suse.de>
# MIT License
#
"""
Module for managing /proc/<pid/*
"""

import os
import re
import stat
from itertools import zip_longest

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
        Returns the content of /proc/<pid>/cmdline as a list
        """
        with open("cmdline", opener=self.__opener) as file:
            data = file.read()
        if data[-1] == '\0':
            return data[:-1].split('\0')
        return [data]

    def _environ(self):
        """
        Returns the content of /proc/<pid>/environ as a dictionary
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
        with open("environ", opener=self.__opener) as file:
            lines = file.read().splitlines()
        return AttrDict([_.split(': ') for _ in lines])

    def _maps(self):
        """
        Parses /proc/<pid>/maps and returns a list of AttrDict's
        """
        with open("maps", opener=self.__opener) as file:
            lines = file.read().splitlines()
        return [
            AttrDict(zip_longest(_maps_fields, line.split(maxsplit=5)))
            for line in lines]

    def _stat(self):
        """
        Parses /proc/<pid>/stat and returns an AttrDict
        """
        with open("stat", opener=self.__opener) as file:
            data = re.findall(r"\(.*\)|\S+", file.read()[:-1])
        return AttrDict(zip(_stat_fields.split(), data))

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
        return status

    def __getitem__(self, path):
        """
        Creates dynamic attributes for elements in /proc/<pid>
        """
        try:
            return dict.__getitem__(self, path)
        except KeyError:
            pass
        if path in ('cmdline', 'environ', 'io', 'maps',
                    'stat', 'statm', 'status'):
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
                return [
                    os.path.join(path, _)
                    for _ in list(os.fwalk(path, dir_fd=self.dir_fd))[0][2]]
        return dict.__getitem__(self, path)
