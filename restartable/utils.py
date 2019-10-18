#
# Copyright 2019 Ricardo Branco <rbranco@suse.de>
# MIT License
#
"""
Module for AttrDict
"""
import os
import stat
import sys
from collections import UserDict, UserString
from datetime import datetime
from ipaddress import ip_address
from socket import htonl


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


class Time(UserString, str):
    _datetime = None

    @property
    def datetime(self):
        if self._datetime is None:
            self._datetime = datetime.fromtimestamp(int(self.data))
        return self._datetime


class IPAddr(UserString, str):
    _ip_address = None
    port = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.data.count(':') == 1:
            self.data, self.port = self.data.split(':')
            self.port = int(self.port, base=16)

    @property
    def ip_address(self):
        if self._ip_address is None:
            string = self.data
            try:
                self._ip_address = ip_address(string)
                return self._ip_address
            except ValueError:
                pass
            if sys.byteorder == "big":
                self._ip_address = ip_address(int(string, base=16))
            # Little endian
            else:
                if len(string) <= 8:
                    self._ip_address = ip_address(htonl(int(string, base=16)))
                else:
                    address = htonl(int(string[:8], base=16)) << 96
                    address |= htonl(int(string[8:16], base=16)) << 64
                    address |= htonl(int(string[16:24], base=16)) << 32
                    address |= htonl(int(string[24:], base=16))
                    self._ip_address = ip_address(address)
        return self._ip_address


# As dict is not supposed to be subclassed directly, use UserDict instead
# We use dict as the last class so isinstance(foo, dict) works
class AttrDict(UserDict, dict):
    """
    Class for accessing dictionary keys with attributes
    """
    def __getattr__(self, attr):
        if attr.startswith('__') and attr.endswith('__'):
            raise AttributeError    # Make help() work
        return self.__getitem__(attr)

    def __delattr__(self, attr):
        self.__delitem__(attr)


class FSDict(AttrDict):
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
