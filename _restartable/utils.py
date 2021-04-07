#
# Copyright 2019,2020 Ricardo Branco <rbranco@suse.de>
# MIT License
#
"""
Module for AttrDict
"""
import json
import os
import stat
import threading
from collections import UserDict, UserString
from datetime import datetime
from ipaddress import ip_address, IPv4Address, IPv6Address
from socket import htonl
from weakref import WeakValueDictionary
from pwd import getpwuid
from grp import getgrgid
from sys import byteorder


def try_int(string):
    """
    Return an integer if possible, else string
    """
    # Ignore octal & hexadecimal
    if len(string) > 1 and string[0] == '0' and string.isdigit():
        return string
    try:
        return int(string)
    except ValueError:
        return string


def sorted_alnum(list_):
    """
    Returns a list sorted in-place alphanumerically.
    Useful for directories, like /proc, that contain pids and other files
    """
    # Sort alphabetically
    list_.sort()
    # Sort numerically
    list_.sort(key=lambda x: int(x) if x.isdigit() else float('inf'))
    return list_


class Property:
    """
    Simple cached-property class decorator
    """
    def __init__(self, fget=None):
        self.fget = fget
        self.name = fget.__name__
        self.lock = threading.RLock()

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        if self.name not in obj:
            with self.lock:
                if self.name not in obj:
                    obj[self.name] = self.fget(obj)
        return obj[self.name]

    def __set__(self, obj, value):
        raise AttributeError


class Singleton:    # pylint: disable=no-member
    """
    Singleton decorator to avoid having multiple objects handling the same args
    """
    def __new__(cls, klass):
        if issubclass(klass, int):
            dict_ = dict()
        else:
            # We must use WeakValueDictionary() to let the instances be garbage-collected
            dict_ = WeakValueDictionary()
        _dict = dict(cls.__dict__, **{'cls': klass, 'instances': dict_})
        singleton = type(klass.__name__, cls.__bases__, _dict)
        obj = super().__new__(singleton)
        obj.lock = threading.RLock()
        return obj

    def __instancecheck__(self, other):
        return isinstance(other, self.cls)

    def __call__(self, *args, **kwargs):
        key = (args, frozenset(kwargs.items()))
        if key not in self.instances:
            with self.lock:
                if key not in self.instances:
                    instance = self.cls.__call__(*args, **kwargs)
                    self.instances[key] = instance
        return self.instances[key]


@Singleton
class Uid(int):
    """
    Class to hold user ID's
    """
    def __init__(self, uid):
        super().__init__()
        self.uid = int(uid)
        self._name = ""

    @property
    def name(self):
        if not self._name:
            try:
                self._name = getpwuid(self.uid).pw_name
            except KeyError:
                self._name = str(self.uid)
        return self._name


@Singleton
class Gid(int):
    """
    Class to hold user ID's
    """
    def __init__(self, gid):
        super().__init__()
        self.gid = int(gid)
        self._name = ""

    @property
    def name(self):
        if not self._name:
            try:
                self._name = getgrgid(self.gid).gr_name
            except KeyError:
                self._name = str(self.gid)
        return self._name


class Time(str):
    """
    Class for time objects
    """
    def __new__(cls, arg):
        dtime = datetime.fromtimestamp(float(arg))
        obj = str.__new__(cls, dtime.ctime())
        obj.datetime = dtime
        return obj


@Singleton
class IPAddr(str):
    """
    Class for IPv4/6 address objects
    """
    def __new__(cls, arg, big_endian=True):
        try:
            address = ip_address(arg)
        except ValueError:
            if big_endian:
                if len(arg) == 8:
                    address = IPv4Address(htonl(int(arg, base=16)))
                elif byteorder == "big":
                    address = IPv6Address(int(arg, base=16))
                elif byteorder == "little":
                    address = IPv6Address(
                        htonl(int(arg[:8], base=16)) << 24
                        | htonl(int(arg[8:16], base=16)) << 16
                        | htonl(int(arg[16:24], base=16)) << 8
                        | htonl(int(arg[24:], base=16)))
            else:
                if len(arg) == 8:
                    address = IPv4Address(int(arg, base=16))
                else:
                    address = IPv6Address(int(arg, base=16))
        obj = str.__new__(cls, address.compressed)
        obj.ip_address = address
        return obj


class Pathname(UserString):
    """
    Class for pathnames
    """
    def __new__(cls, arg):
        if arg is None:
            return None
        return super().__new__(cls)

    def __init__(self, arg):
        super().__init__(arg)
        self.raw = self.data
        # TODO: There are lots of funky characters that can mess with the terminal  # pylint: disable=fixme
        self.data = self.data.replace("\r", "\\r").replace("\n", "\\n")


class AttrDict(UserDict):
    """
    Class for accessing dictionary keys with attributes
    """
    def __getattr__(self, attr):
        if attr.startswith('__') and attr.endswith('__'):
            raise AttributeError    # Make help() work
        try:
            return self.__getitem__(attr)
        except KeyError as e:
            raise AttributeError(e)

    def __delattr__(self, attr):
        self.__delitem__(attr)


class FSDict(AttrDict):
    """
    Class for capturing a directory structure into a dictionary
    """
    _dir_fd = None
    _path = None
    _handler = None

    def __init__(self, path="", dir_fd=None, handler=None):
        if dir_fd is not None:
            self._dir_fd = dir_fd
        self._path = path
        self._handler = handler
        super().__init__()

    def __repr__(self):
        return "%s(path=%s, dir_fd=%s, handler=%s)" % (
            type(self).__name__, self._path if self._path else '""', self._dir_fd, self._handler)

    def __getitem__(self, item):
        value = super().__getitem__(item)
        super().__setitem__(item, value)
        return value

    def _opener(self, path, flags):
        return os.open(path, flags, dir_fd=self._dir_fd)

    def _lsdir(self, path):
        """
        Returns os.listdir() on path
        """
        if not path:
            return sorted_alnum(os.listdir(self._dir_fd))
        dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY, dir_fd=self._dir_fd)
        try:
            listing = os.listdir(dir_fd)
        except OSError as err:
            raise err
        finally:
            os.close(dir_fd)
        return sorted_alnum(listing)

    def __missing__(self, path):
        """
        Get contents from file, symlink or directory
        """
        if self._handler:
            return self._handler(path)
        path = os.path.join(self._path, path)
        mode = os.lstat(path, dir_fd=self._dir_fd).st_mode
        if stat.S_ISLNK(mode):
            return os.readlink(path, dir_fd=self._dir_fd)
        if stat.S_ISREG(mode):
            with open(path, opener=self._opener) as file:
                return file.read()
        if stat.S_ISDIR(mode):
            return FSDict(path=path, dir_fd=self._dir_fd)
        return None


class CustomJSONEncoder(json.JSONEncoder):
    """
    JSON Encoder for the objects defined here
    Use like this: json.dumps(obj, cls=CustomJSONEncoder)
    """
    def default(self, obj):     # pylint: disable=method-hidden,arguments-differ
        if isinstance(obj, (IPAddr, Uid, Gid, Time, AttrDict, Pathname)):
            return obj.data
        return json.JSONEncoder.default(self, obj)
