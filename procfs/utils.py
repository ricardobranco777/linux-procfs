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
from collections import UserDict, UserString
from datetime import datetime
from ipaddress import ip_address, IPv4Address, IPv6Address
from socket import htonl
from pwd import getpwuid
from grp import getgrgid
from sys import byteorder
from typing import List, Optional, Union


def try_int(string: str) -> Union[int, str]:
    """
    Return an integer if possible, else string
    """
    # Ignore octal & hexadecimal
    if len(string) > 1 and string[0] == "0" and string.isdigit():
        return string
    try:
        return int(string)
    except ValueError:
        return string


def sorted_alnum(list_: list) -> List[str]:
    """
    Returns a list sorted in-place alphanumerically.
    Useful for directories, like /proc, that contain pids and other files
    """
    # Sort alphabetically
    list_.sort()
    # Sort numerically
    list_.sort(key=lambda x: int(x) if x.isdigit() else float("inf"))
    return list_


class Uid(int):
    """
    Class to hold user ID's
    """

    def __init__(self, uid: str):
        super().__init__()
        self.uid = int(uid)
        self._name = ""

    @property
    def name(self) -> str:
        if not self._name:
            try:
                self._name = getpwuid(self.uid).pw_name
            except KeyError:
                self._name = str(self.uid)
        return self._name


class Gid(int):
    """
    Class to hold user ID's
    """

    def __init__(self, gid: str):
        super().__init__()
        self.gid = int(gid)
        self._name = ""

    @property
    def name(self) -> str:
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

    def __new__(cls, arg: str):
        dtime = datetime.fromtimestamp(float(arg))
        obj = str.__new__(cls, dtime.ctime())
        setattr(obj, "datetime", dtime)
        return obj


class IPAddr(str):
    """
    Class for IPv4/6 address objects
    """

    def __new__(cls, arg: str, big_endian: bool = True):
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
                        | htonl(int(arg[24:], base=16))
                    )
            else:
                if len(arg) == 8:
                    address = IPv4Address(int(arg, base=16))
                else:
                    address = IPv6Address(int(arg, base=16))
        obj = str.__new__(cls, address.compressed)
        setattr(obj, "ip_address", address)
        return obj


class Pathname(UserString):
    """
    Class for pathnames
    """

    def __new__(cls, arg: str):
        if arg is None:
            return None
        return super().__new__(cls)

    def __init__(self, arg: str):
        super().__init__(arg)
        self.raw = self.data
        # TODO: There are lots of funky characters that can mess with the terminal  # pylint: disable=fixme
        self.data = self.data.replace("\r", "\\r").replace("\n", "\\n")


class AttrDict(UserDict):
    """
    Class for accessing dictionary keys with attributes
    """

    def __getattr__(self, attr):
        if attr.startswith("__") and attr.endswith("__"):
            raise AttributeError  # Make help() work
        try:
            return self.__getitem__(attr)
        except KeyError as e:
            raise AttributeError(e) from e

    def __delattr__(self, attr):
        self.__delitem__(attr)


class FSDict(AttrDict):
    """
    Class for capturing a directory structure into a dictionary
    """

    _dir_fd: Optional[int] = None
    _path: str = ""
    _handler = None

    def __init__(self, path: str = "", dir_fd: Optional[int] = None, handler=None):
        if dir_fd is not None:
            self._dir_fd = dir_fd
        self._path = path
        self._handler = handler
        super().__init__()

    def __repr__(self):
        path = self._path if self._path else '""'
        return f'{type(self).__name__}(path="{path}", dir_fd={self._dir_fd}, handler={self._handler})'

    def __getitem__(self, item):
        value = super().__getitem__(item)
        super().__setitem__(item, value)
        return value

    def _opener(self, path: str, flags: int) -> int:
        return os.open(path, flags, dir_fd=self._dir_fd)

    def _lsdir(self, path: str) -> List[str]:
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

    def __missing__(self, path: str):
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
            with open(path, opener=self._opener, encoding="utf-8") as file:
                return file.read()
        if stat.S_ISDIR(mode):
            return FSDict(path=path, dir_fd=self._dir_fd)
        return None


class CustomJSONEncoder(json.JSONEncoder):
    """
    JSON Encoder for the objects defined here
    Use like this: json.dumps(obj, cls=CustomJSONEncoder)
    """

    def default(self, o):
        if isinstance(o, (IPAddr, Uid, Gid, Time, AttrDict, Pathname)):
            return o.data
        return json.JSONEncoder.default(self, o)
