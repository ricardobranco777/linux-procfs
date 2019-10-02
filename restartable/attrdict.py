#
# Copyright 2019 Ricardo Branco <rbranco@suse.de>
# MIT License
#
"""
Module for AttrDict
"""
from collections import UserDict


# As dict is not supposed to be subclassed directly, use UserDict instead
# We use dict as the last class so isinstance(foo, dict) works
class AttrDict(UserDict, dict):  # pylint: disable=too-many-ancestors
    """
    Class for accessing dictionary keys with attributes
    """
    def __getattr__(self, attr):
        if attr.startswith('__') and attr.endswith('__'):
            raise AttributeError    # Make help() work
        return self.__getitem__(attr)

    def __delattr__(self, attr):
        self.__delitem__(attr)
