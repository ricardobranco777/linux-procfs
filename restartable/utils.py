#
# Copyright 2019 Ricardo Branco <rbranco@suse.de>
# MIT License
#
"""
Module for AttrDict
"""
import json
import os
import stat
import struct
from collections import UserDict, UserString
from datetime import datetime
from ipaddress import ip_address
from socket import htonl
from weakref import WeakValueDictionary
from pwd import getpwuid
from grp import getgrgid


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
    Simple cached-property class decorator that works with partialmethod
    """
    def __init__(self, fget=None, name=None):
        self.fget = fget
        self.name = fget.__name__ if name is None else name

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        if self.name not in obj:
            if callable(self.fget):
                obj[self.name] = self.fget(obj)
            else:   # partialmethod
                obj[self.name] = self.fget.func(obj, *self.fget.args, **self.fget.keywords)
        return obj[self.name]

    def __set__(self, obj, value):
        raise AttributeError


class Singleton:    # pylint: disable=no-member
    """
    Singleton decorator to avoid having multiple objects handling the same args
    """
    def __new__(cls, klass):
        # We must use WeakValueDictionary() to let the instances be garbage-collected
        _dict = dict(cls.__dict__, **{'cls': klass, 'instances': WeakValueDictionary()})
        singleton = type(klass.__name__, cls.__bases__, _dict)
        return super().__new__(singleton)

    def __instancecheck__(self, other):
        return isinstance(other, self.cls)

    def __call__(self, *args, **kwargs):
        key = (args, frozenset(kwargs.items()))
        if key not in self.instances:
            instance = self.cls.__call__(*args, **kwargs)
            self.instances[key] = instance
        return self.instances[key]


@Singleton
class Uid(UserString):
    """
    Class to hold user ID's
    """
    _name = None
    @property
    def name(self):
        """
        Convert a User ID string to a user name
        """
        if self._name is None:
            self._name = getpwuid(int(self.data)).pw_name
        return self._name


@Singleton
class Gid(UserString):
    """
    Class to hold user ID's
    """
    _name = None
    @property
    def name(self):
        """
        Convert a Group ID string to a group name
        """
        if self._name is None:
            self._name = getgrgid(int(self.data)).gr_name
        return self._name


@Singleton
class Time(UserString):
    """
    Class for time objects
    """
    _datetime = None
    @property
    def datetime(self):
        """
        Convert a time string to a datetime object
        """
        if self._datetime is None:
            self._datetime = datetime.fromtimestamp(float(self.data))
        return self._datetime


@Singleton
class IPAddr(UserString):
    """
    Class for IP address objects
    """
    _ip_address = None
    @property
    def ip_address(self):
        """
        Convert a IPv4/6 string to a ip_address object
        """
        if self._ip_address is None:
            string = self.data
            try:
                self._ip_address = ip_address(string)
                return self._ip_address
            except ValueError:
                pass
            if len(string) == 8:
                address = htonl(int(string, base=16))
            else:
                address = struct.pack('@IIII', *struct.unpack('>IIII', bytes.fromhex(string)))
            self._ip_address = ip_address(address)
        return self._ip_address


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
        if isinstance(obj, IPAddr):
            return obj.ip_address.compressed
        if isinstance(obj, (Uid, Gid)):
            return int(obj.data)
        if isinstance(obj, Time):
            return obj.datetime.ctime()
        if isinstance(obj, AttrDict):
            return obj.data
        return json.JSONEncoder.default(self, obj)
