#
# Copyright 2019 Ricardo Branco <rbranco@suse.de>
# MIT License
#
"""
Module for AttrDict
"""


class AttrDict(dict):
    """
    Class for accessing dictionaries as attributes
    """
    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)
        super().__init__()

    def __getattr__(self, attr):
        return self.__getitem__(attr)

    def __setattr__(self, attr, value):
        self.__setitem__(attr, value)

    def __delattr__(self, attr):
        self.__delitem__(attr)

    def get(self, key):
        return self.__getitem__(key)

    def update(self, *args, **kwargs):
        for key, val in dict(*args, **kwargs).items():
            self[key] = val
