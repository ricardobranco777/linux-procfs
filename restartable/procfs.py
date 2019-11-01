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
from functools import partialmethod
from itertools import zip_longest

from restartable.utils import AttrDict, FSDict, Property, IPAddr, Time, Uid, Gid, Pathname, try_int


class _Mixin:
    """
    Mixin class to share methods between Proc() and ProcPid()
    """

    _dir_fd = None

    def __del__(self):
        if self._dir_fd is not None:
            os.close(self._dir_fd)
        self._dir_fd = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._dir_fd is not None:
            os.close(self._dir_fd)
        self._dir_fd = None

    def _get_dirfd(self, path, dir_fd=None):
        """
        Get directory file descriptor
        """
        self._dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY, dir_fd=dir_fd)


class ProcNet(FSDict):
    """
    Class to parse /proc/self/net
    """
    def __new__(cls, *args, **kwargs):  # pylint: disable=unused-argument
        for proto in ('arp', 'rarp'):
            setattr(cls, proto, Property(partialmethod(cls._xarp, "net/%s" % proto), name=proto))
        for proto in (
                'icmp', 'icmp6', 'raw', 'raw6', 'tcp', 'tcp6',
                'udp', 'udp6', 'udplite', 'udplite6'):
            setattr(cls, proto, Property(partialmethod(cls._proto, "net/%s" % proto), name=proto))
        return super().__new__(cls)

    def __init__(self, dir_fd, *args, **kwargs):
        self._dir_fd = dir_fd
        super().__init__(*args, **kwargs)

    def __repr__(self):
        return "%s()" % type(self).__name__

    def _xarp(self, path):
        """
        Parse /proc/net/{arp,rarp}
        """
        with open(path, opener=self._opener) as file:
            header, *lines = file.read().splitlines()
        keys = [_.strip().replace(' ', '_') for _ in header.split('  ') if _]
        entries = [AttrDict(zip(keys, _.split())) for _ in lines]
        for entry in entries:
            entry.update(IP_address=IPAddr(entry.IP_address))
        return entries

    def _proto(self, path):
        """
        Parse /proc/net/{icmp,icmp6,raw,raw6,tcp,tcp6,udp,udp6,udplite,udplite6}
        """
        fields = (
            'local_address', 'local_port', 'remote_address', 'remote_port',
            'st', 'tx_queue', 'rx_queue', 'tr', 'tm_when', 'retrnsmt', 'uid',
            'timeout', 'inode', 'ref', 'pointer', 'drops')
        with open(path, opener=self._opener) as file:
            _, *lines = file.read().splitlines()
        entries = [AttrDict(zip(fields, _.replace(':', ' ').split()[1:])) for _ in lines]
        for entry in entries:
            entry.update(
                local_address=IPAddr(entry.local_address),
                remote_address=IPAddr(entry.remote_address),
                local_port=int(entry.local_port, base=16),
                remote_port=int(entry.remote_port, base=16),
                uid=Uid(entry.uid))
        return entries

    def _parser1(self, path):
        """
        Parse /proc/net/{netstat,snmp}
        """
        with open(path, opener=self._opener) as file:
            lines = file.read().splitlines()
        headers, values = lines[::2], lines[1::2]
        return AttrDict({
            keys.split()[0][:-1]: AttrDict(zip(keys.split()[1:], map(int, vals.split()[1:])))
            for keys, vals in zip(headers, values)})

    @Property
    def dev(self):
        """
        Parse /proc/net/dev
        """
        with open("net/dev", opener=self._opener) as file:
            _, line2, *lines = file.read().splitlines()
        rx, tx = line2.split('|')[1:]
        keys = ['RX_%s' % _ for _ in rx.split()] + ['TX_%s' % _ for _ in tx.split()]
        return AttrDict({
            iface[:-1]: AttrDict(zip(keys, map(int, values)))
            for _ in lines
            for iface, *values in [_.split()]})

    @Property
    def dev_mcast(self):
        """
        Parse /proc/net/dev_mcast
        """
        fields = ('index', 'interface', 'dmi_u', 'dmi_g', 'dmi_address')
        with open("net/dev_mcast", opener=self._opener) as file:
            lines = file.read().splitlines()
        return [AttrDict(zip(fields, _.split())) for _ in lines]

    @Property
    def netstat(self):
        """
        Parse /proc/net/netstat
        """
        return self._parser1("net/netstat")

    @Property
    def snmp(self):
        """
        Parse /proc/net/snmp
        """
        return self._parser1("net/snmp")

    @Property
    def snmp6(self):
        """
        Parse /proc/net/snmp6
        """
        with open("net/snmp6", opener=self._opener) as file:
            lines = file.read().splitlines()
        return AttrDict({
            k: int(v) for _ in lines
            for k, v in [_.split()]})

    @Property
    def route(self):
        """
        Parse /proc/net/route
        """
        with open("net/route", opener=self._opener) as file:
            header, *lines = file.read().splitlines()
        entries = [AttrDict(zip(header.split(), _.split())) for _ in lines]
        for entry in entries:
            entry.update({k: IPAddr(entry[k]) for k in ('Destination', 'Gateway', 'Mask')})
        return entries

    @Property
    def unix(self):
        """
        Parse /proc/net/unix
        """
        with open("net/unix", opener=self._opener) as file:
            keys, *lines = file.read().splitlines()
        # Ignore "Num"
        entries = [AttrDict(zip_longest(keys.split()[1:], _.split(maxsplit=7)[1:])) for _ in lines]
        for entry in entries:
            entry.update(Path=Pathname(entry.Path))
        return entries

    def __missing__(self, path):
        """
        Create dynamic keys for elements in /proc/net
        """
        if path in (
                'arp', 'dev', 'dev_mcast', 'icmp', 'icmp6',
                'netstat', 'rarp', 'raw', 'raw6', 'route',
                'snmp', 'snmp6', 'tcp', 'tcp6',
                'udp', 'udp6', 'udplite', 'udplite6', 'unix'):
            return getattr(self, path)
        return super().__missing__(os.path.join("net", path))


class Proc(FSDict, _Mixin):
    """
    Class to parse /proc entries
    """
    def __init__(self, proc="/proc"):
        self._proc = proc
        self._get_dirfd(proc)
        super().__init__()

    def __repr__(self):
        return "%s(proc=%s)" % (type(self).__name__, self._proc)

    def pids(self):
        """
        Returns a list of all the processes in the system
        """
        return filter(str.isdigit, os.listdir(self._dir_fd))

    def tasks(self):
        """
        Returns a list of all the tasks (threads) in the system
        """
        #  We could use a list comprehension but a PID could disappear
        tasks = []
        for pid in self.pids():
            with ProcPid(pid, dir_fd=self._dir_fd) as proc:
                try:
                    tasks.extend(proc.task)
                except FileNotFoundError:
                    pass
        return tasks

    @Property
    def config(self):
        """
        Parses /proc/config.gz and returns an AttrDict
        If /proc/config.gz doesn't exist, try /boot or /lib/modules/
        """
        lines = None
        paths = [
            "config.gz",
            "/boot/config-%s" % os.uname().release,
            "/lib/modules/%s/build/.config" % os.uname().release
        ]
        for path in paths:
            try:
                os.stat(path, dir_fd=self._dir_fd)
            except FileNotFoundError:
                continue
            if path.endswith(".gz"):
                with open(path, "rb", opener=self._opener) as f:
                    with gzip.open(f) as file:
                        lines = file.read().decode('utf-8').splitlines()
            else:
                with open(path) as file:
                    lines = file.read().splitlines()
            break
        if lines is None:
            return None
        return AttrDict(_.split('=') for _ in lines if _.startswith("CONFIG_"))

    @Property
    def cgroups(self):
        """
        Parses /proc/cgroup and returns an AttrDict
        """
        with open("cgroups", opener=self._opener) as file:
            header, *lines = file.read().splitlines()
        keys = header.split()[1:]
        return AttrDict({
            k: AttrDict(zip(keys, map(int, values))) for _ in lines
            for k, *values in [_.split()]})

    @Property
    def cmdline(self):
        """
        Parses /proc/cmdline and returns a list
        """
        with open("cmdline", opener=self._opener) as file:
            return file.read().strip()

    @Property
    def cpuinfo(self):
        """
        Parses /proc/cpuinfo and returns a list of AttrDict's
        """
        with open("cpuinfo", opener=self._opener) as file:
            cpus = file.read()[:-1].split('\n\n')
        return [
            AttrDict([map(str.strip, _.split(':')) for _ in cpu.splitlines()])
            for cpu in cpus
        ]

    @Property
    def meminfo(self):
        """
        Parses /proc/meminfo and returns an AttrDict
        """
        with open("meminfo", opener=self._opener) as file:
            lines = file.read().replace('kB\n', '\n').splitlines()
        return AttrDict({k: int(v.strip()) for k, v in [_.split(':') for _ in lines]})

    @Property
    def mounts(self):
        """
        Parses /proc/mounts and returns a list of AttrDict's
        """
        # /proc/mounts is a symlink to /proc/self/mounts
        with ProcPid(dir_fd=self._dir_fd) as proc_self:
            return proc_self.mounts

    @Property
    def swaps(self):
        """
        Parses /proc/swaps and returns a list of AttrDict's
        """
        with open("swaps", opener=self._opener) as file:
            keys, *values = file.read().splitlines()
        entries = [AttrDict(zip(keys.split(), _.rsplit(maxsplit=5))) for _ in values]
        for entry in entries:
            entry.update(Filename=Pathname(entry.Filename))
        return entries

    @Property
    def vmstat(self):
        """
        Parses /proc/vmstat and returns an AttrDict
        """
        with open("vmstat", opener=self._opener) as file:
            lines = file.read().splitlines()
        return AttrDict({k: int(v) for k, v in [_.split() for _ in lines]})

    def _sysvipc(self, path):
        """
        Parses /proc/sysvipc/{msg,sem,shm} and returns a list of AttrDict's
        """
        with open(os.path.join("sysvipc", path), opener=self._opener) as file:
            keys, *values = file.read().splitlines()
        entries = [AttrDict(zip(keys.split(), _.split())) for _ in values]
        for entry in entries:
            entry.update({k: Time(entry[k]) for k in entry if k.endswith('time')})
            entry.update({k: Uid(entry[k]) for k in ('uid', 'cuid')})
            entry.update({k: Gid(entry[k]) for k in ('gid', 'cgid')})
        return entries

    def __missing__(self, path):
        """
        Creates dynamic keys for elements in /proc/
        """
        if path in ("config", "cgroups", "cmdline", "cpuinfo",
                    "meminfo", "mounts", "swaps", "vmstat"):
            return getattr(self, path)
        if path == "self":
            return ProcPid(dir_fd=self._dir_fd)
        if path == "net":
            return ProcNet(dir_fd=self._dir_fd)
        if path.isdigit():
            return ProcPid(path, dir_fd=self._dir_fd)
        if path == "sysvipc":
            return FSDict(path=path, dir_fd=self._dir_fd, handler=self._sysvipc)
        return super().__missing__(path)


class ProcPid(FSDict, _Mixin):
    """
    Class for managing /proc/<pid>/*
    """
    def __init__(self, pid=None, proc="/proc", dir_fd=None):
        if pid is None:
            pid = os.getpid()
        elif int(pid) <= 0:
            raise ValueError("Invalid pid %s" % pid)
        self.pid = str(pid)
        if dir_fd is None:
            self._get_dirfd(os.path.join(proc, self.pid))
            self._proc = proc
        else:
            self._get_dirfd(self.pid, dir_fd=dir_fd)
            self._proc = None
        setattr(self, "ctime", Time(os.stat(".", dir_fd=self._dir_fd).st_ctime))
        super().__init__()

    def __repr__(self):
        return "%s(pid=%s, proc=%s)" % (
            type(self).__name__, self.pid, self._proc)

    @Property
    def cmdline(self):
        """
        Parses /proc/<pid>/cmdline and returns a list
        """
        with open("cmdline", opener=self._opener) as file:
            data = file.read()
        # Escape newlines
        data = data.replace("\n", "\\n")
        if data.endswith('\0'):
            return data.rstrip('\0').split('\0')
        return [data]

    @Property
    def comm(self):  # pylint: disable=method-hidden # https://github.com/PyCQA/pylint/issues/414
        """
        Parses /proc/comm
        """
        with open("comm", opener=self._opener) as file:
            data = file.read()
        # Strip trailing newline
        return data[:-1]

    @Property
    def environ(self):
        """
        Parses /proc/<pid>/environ and returns an AttrDict
        """
        with open("environ", "rb", opener=self._opener) as file:
            data = file.read()
        try:
            return AttrDict([_.split('=', 1) for _ in data.decode('utf-8')[:-1].split('\0')])
        except (UnicodeDecodeError, ValueError):
            return data

    @Property
    def io(self):
        """
        Parses /proc/<pid>/io and returns an AttrDict
        """
        with open("io", opener=self._opener) as file:
            lines = file.read().splitlines()
        return AttrDict({k: int(v) for k, v in [_.split(': ') for _ in lines]})

    @Property
    def limits(self):
        """
        Parses /proc/<pid>/limits and returns an AttrDict
        """
        fields = {
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
        with open("limits", opener=self._opener) as file:
            data = re.findall(
                r'^(.*?)\s{2,}(\S+)\s{2,}(\S+)',
                file.read().replace('unlimited', '-1'),
                re.MULTILINE)[1:]
        return AttrDict({
            fields[k]: AttrDict(zip(('soft', 'hard'), map(int, v)))
            for (k, *v) in data})

    @Property
    def maps(self):
        """
        Parses /proc/<pid>/maps and returns a list of AttrDict's
        """
        fields = ('address', 'perms', 'offset', 'dev', 'inode', 'pathname')
        with open("maps", opener=self._opener) as file:
            lines = file.read().splitlines()
        entries = [
            AttrDict(zip_longest(fields, _.split(maxsplit=5))) for _ in lines]
        for entry in entries:
            # From the proc(5) manpage:
            #  pathname is shown unescaped except for newline characters,
            #  which are replaced with an octal escape sequence. As a result,
            #  it is not possible to determine whether the original pathname
            #  contained a newline character or the literal \012 character sequence
            # So let's readlink() the address in the map_files directory
            pathname = entry.pathname
            if pathname and '\\012' in pathname:
                pathname = os.readlink("map_files/%s" % entry.address, dir_fd=self._dir_fd)
            entry.update(pathname=Pathname(pathname))
        return entries

    @Property
    def mounts(self):
        """
        Parses /proc/<pid>/mounts and returns a list of AttrDict's
        """
        fields = (
            'fs_spec', 'fs_file', 'fs_vfstype',
            'fs_mntops', 'fs_freq', 'fs_passno'
        )
        with open("mounts", opener=self._opener) as file:
            lines = file.read().splitlines()
        entries = [
            AttrDict(zip(fields, re.findall(r'^(\S+) (.*?) (\S+) (\S+) (\d+) (\d+)$', _)[0]))
            for _ in lines]
        for entry in entries:
            entry.update(
                fs_file=Pathname(entry.fs_file),
                fs_mntops=AttrDict({
                    k: try_int(v[0]) if v else None
                    for k, *v in [_.split('=', 1) for _ in entry.fs_mntops.split(',')]}))
        return entries

    @Property
    def numa_maps(self):   # pylint: disable=star-needs-assignment-target  # Make Pylint happy on Python 3.4
        """
        Parses /proc/<pid>/numa_maps and returns an AttrDict
        """
        with open("numa_maps", opener=self._opener) as file:
            lines = file.read().splitlines()
        entry = AttrDict({
            address: AttrDict({
                k: try_int(v[0]) if v else None
                for k, *v in [_.split('=', 1) for _ in ['policy=%s' % policy] + values]})
            for line in lines
            for address, policy, *values in [line.split()]})
        for key in entry:
            if 'file' in entry[key]:
                entry[key].update(file=Pathname(entry[key].file))
        return entry

    @Property
    def smaps(self):
        """
        Parses /proc/<pid>/smaps and returns a list of AttrDict's
        """
        with open("smaps", opener=self._opener) as file:
            lines = file.read().replace('kB\n', '\n').splitlines()
        step = int(len(lines) / len(self.maps))
        maps = [
            {
                k: try_int(v.strip()) if k != "VmFlags" else v.strip().split()
                for k, v in [_.split(':') for _ in lines[i + 1: i + step]]
            }
            for i in range(0, len(lines), step)
        ]
        return [AttrDict(**a, **b) for a, b in zip(maps, self.maps)]

    @Property
    def stat(self):
        """
        Parses /proc/<pid>/stat and returns an AttrDict
        """
        fields = (
            'pid comm state ppid pgrp session tty_nr tpgid flags '
            'minflt cminflt majflt cmajflt utime stime cutime cstime '
            'priority nice num_threads itrealvalue starttime vsize rss rsslim '
            'startcode endcode startstack kstkesp kstkeip signal blocked '
            'sigignore sigcatch wchan nswap cnswap exit_signal processor '
            'rt_priority policy delayacct_blkio_ticks guest_time cguest_time '
            'start_data end_data start_brk arg_start arg_end env_start env_end '
            'exit_code'
        ).split()
        with open("stat", opener=self._opener) as file:
            data = re.findall(r"\(.*\)|\S+", file.read()[:-1], re.M | re.S)
        info = AttrDict(zip(fields, data))
        # Remove parentheses
        info.comm = info.comm[1:-1]
        # Escape newlines
        info.comm = info.comm.replace("\n", "\\n")
        return info

    @Property
    def statm(self):
        """
        Parses /proc/<pid>/statm and returns an AttrDict
        """
        fields = ('size', 'resident', 'shared', 'text', 'lib', 'data', 'dt')
        with open("statm", opener=self._opener) as file:
            data = map(int, file.read().split())
        return AttrDict(zip(fields, data))

    @Property
    def status(self):
        """
        Parses /proc/<pid>/status and returns an AttrDict
        """
        fields = ('real', 'effective', 'saved_set', 'filesystem')
        with open("status", opener=self._opener) as file:
            lines = file.read().splitlines()
        status = AttrDict({
            k: try_int(v)
            for k, v in [_.split(':\t', 1) for _ in lines]})
        status.update({
            'Uid': AttrDict(zip(fields, map(Uid, status.Uid.split()))),
            'Gid': AttrDict(zip(fields, map(Gid, status.Gid.split()))),
            'Groups': list(map(Gid, str(status.Groups).split()))})
        status.update({
            k: int(status[k].replace('kB', '').strip())
            for k in (
                'VmPeak', 'VmSize', 'VmLck', 'VmPin', 'VmHWM', 'VmRSS',
                'RssAnon', 'RssFile', 'RssShmem', 'VmData', 'VmStk',
                'VmExe', 'VmLib', 'VmPTE', 'VmSwap', 'HugetlbPages')})
        return status

    def __missing__(self, path):
        """
        Creates dynamic keys for elements in /proc/<pid>
        """
        if path in ('cmdline', 'comm', 'environ', 'io', 'limits', 'maps',
                    'numa_maps', 'mounts', 'smaps', 'stat', 'statm', 'status'):
            return getattr(self, path)
        if path in ('fd', 'map_files', 'task'):
            return self._lsdir(path)
        if path == "net":
            return ProcNet(dir_fd=self._dir_fd)
        return super().__missing__(path)
