import unittest
from unittest.mock import patch, mock_open
import json
import stat
import sys
from collections import namedtuple

from procfs.utils import sorted_alnum, try_int, CustomJSONEncoder, FSDict
from procfs.utils import AttrDict, IPAddr, Time, Uid, Gid, Pathname


# pylint: disable=line-too-long


class Test_utils(unittest.TestCase):
    def test_sorted_alnum(self):
        _list = ["abc", "2", "1", "10"]
        _sorted = ["1", "2", "10", "abc"]
        self.assertEqual(sorted_alnum(_list), _sorted)
        self.assertEqual(sorted_alnum(_sorted), _sorted)

    def test_try_int(self):
        self.assertEqual(try_int("0"), 0)
        self.assertEqual(try_int("00"), "00")
        self.assertEqual(try_int("2"), 2)
        self.assertEqual(try_int("c"), "c")

    def test_AttrDict(self):
        d = AttrDict({"a": 1})
        self.assertIsInstance(d, AttrDict)
        self.assertIs(d.a, d["a"])
        del d.a
        self.assertEqual(d, {})
        d["b"] = 2
        self.assertIs(d.b, d["b"])
        del d["b"]
        self.assertEqual(d, {})
        self.assertIsNone(d.get("a", None))
        self.assertEqual(d.get("a", 777), 777)
        _d = {"a": 888}
        d.update(_d)
        self.assertEqual(d, _d)

    def test_IPAddr(self):
        if sys.byteorder == "big":
            ipv4 = "7F000001"
            ipv6 = "00000000000000000000000000000001"
        else:
            ipv4 = "0100007F"
            ipv6 = "00000000000000000000000001000000"
        ipv4 = IPAddr(ipv4)
        ipv6 = IPAddr(ipv6)
        self.assertIsInstance(ipv4, IPAddr)
        self.assertEqual(ipv4, "127.0.0.1")
        self.assertEqual(ipv6, "::1")
        self.assertEqual(IPAddr("7F000001", big_endian=False), "127.0.0.1")
        self.assertEqual(
            IPAddr("00000000000000000000000000000001", big_endian=False), "::1"
        )

    def test_Time(self):
        t = Time("0")
        self.assertIsInstance(t, Time)
        self.assertEqual(t, "Thu Jan  1 00:00:00 1970")

    @patch("procfs.utils.getpwuid", return_value=namedtuple("_", "pw_name")("abc"))
    def test_Uid(self, *_):
        uid = Uid(777)
        self.assertIsInstance(uid, Uid)
        self.assertEqual(uid.name, "abc")

    @patch("procfs.utils.getpwuid", side_effect=KeyError)
    def test_Uid2(self, *_):
        uid = Uid(888)
        self.assertEqual(uid.name, "888")

    @patch("procfs.utils.getgrgid", return_value=namedtuple("_", "gr_name")("xyz"))
    def test_Gid(self, *_):
        gid = Gid(777)
        self.assertIsInstance(gid, Gid)
        self.assertEqual(gid.name, "xyz")

    @patch("procfs.utils.getpwuid", side_effect=KeyError)
    def test_Gid2(self, *_):
        gid = Gid(888)
        self.assertEqual(gid.name, "888")

    def test_Pathname(self):
        path = Pathname("file with \n char")
        self.assertIsInstance(path, Pathname)
        self.assertEqual(path, "file with \\n char")
        self.assertEqual(path.raw, "file with \n char")
        path = Pathname("no funky chars")
        self.assertEqual(path, "no funky chars")
        path = Pathname(None)
        self.assertIsNone(path)

    @patch("os.readlink", return_value="file")
    @patch("os.open", return_value=777)
    @patch("os.close")
    @patch("builtins.open", mock_open(read_data="data"))
    def test_FSDict(self, *_):
        def mock_lstat(path, *_, **__):
            if path == "dir":
                return namedtuple("_", "st_mode")(stat.S_IFDIR)
            if path == "symlink":
                return namedtuple("_", "st_mode")(stat.S_IFLNK)
            return namedtuple("_", "st_mode")(stat.S_IFREG)

        with patch("os.lstat", mock_lstat):
            fs = FSDict()
            self.assertIsInstance(fs, FSDict)
            self.assertEqual(fs.file, "data")
            self.assertEqual(fs.symlink, "file")
            self.assertIsInstance(fs.dir, FSDict)

    def test_CustomJSONEncoder(self):
        d = {
            "time": Time(0.0),
            "uid": Uid(0),
            "gid": Gid(0),
            "ip": IPAddr("0" * 8),
            "path": Pathname("/etc"),
        }
        s = '{"gid": 0, "ip": "0.0.0.0", "path": "/etc", "time": "Thu Jan  1 00:00:00 1970", "uid": 0}'
        self.assertEqual(
            s, json.dumps(AttrDict(d), cls=CustomJSONEncoder, sort_keys=True)
        )


if __name__ == "__main__":
    unittest.main()
