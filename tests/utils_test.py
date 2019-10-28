import unittest
import gc
import json
import stat
import sys
from collections import namedtuple
from functools import partialmethod
from mock import patch, mock_open

from restartable.utils import sorted_alnum, CustomJSONEncoder
from restartable.utils import AttrDict, Property, Singleton, IPAddr, Time, Uid, Gid, FSDict


class Test_utils(unittest.TestCase):
    def test_sorted_alnum(self):
        _list = ["abc", "2", "1", "10"]
        _sorted = ["1", "2", "10", "abc"]
        self.assertEqual(sorted_alnum(_list), _sorted)
        self.assertEqual(sorted_alnum(_sorted), _sorted)

    def test_AttrDict(self):
        d = AttrDict({'a': 1})
        self.assertIsInstance(d, AttrDict)
        self.assertEqual(d.a, d['a'])
        del d.a
        self.assertEqual(d, {})
        d['b'] = 2
        self.assertEqual(d.b, d['b'])
        del d['b']
        self.assertEqual(d, {})
        self.assertIsNone(d.get('a', None))
        self.assertEqual(d.get('a', 777), 777)
        _d = {'a': 888}
        d.update(_d)
        self.assertEqual(d, _d)

    def test_IPAddr(self):
        if sys.byteorder == "big":
            ipv4 = '7F000001'
            ipv6 = '00000000000000000000000000000001'
        else:
            ipv4 = '0100007F'
            ipv6 = '00000000000000000000000001000000'
        ipv4 = IPAddr(ipv4)
        ipv6 = IPAddr(ipv6)
        self.assertIsInstance(ipv4, IPAddr)
        self.assertEqual(ipv4.ip_address.compressed, '127.0.0.1')
        self.assertEqual(ipv6.ip_address.compressed, '::1')

    def test_Time(self):
        t = Time('0')
        self.assertIsInstance(t, Time)
        self.assertEqual(t.datetime.ctime(), 'Thu Jan  1 00:00:00 1970')

    @patch('restartable.utils.getpwuid', return_value=namedtuple('_', 'pw_name')('abc'))
    def test_Uid(self, *_):
        uid = Uid(777)
        self.assertIsInstance(uid, Uid)
        self.assertEqual(uid.name, 'abc')

    @patch('restartable.utils.getgrgid', return_value=namedtuple('_', 'gr_name')('xyz'))
    def test_Gid(self, *_):
        gid = Gid(888)
        self.assertIsInstance(gid, Gid)
        self.assertEqual(gid.name, 'xyz')

    @patch('os.readlink', return_value='file')
    @patch('os.open', return_value=777)
    @patch('os.close')
    @patch('builtins.open', mock_open(read_data="data"))
    def test_FSDict(self, *_):
        def mock_lstat(path, *_, **__):
            if path == "dir":
                return namedtuple('_', 'st_mode')(stat.S_IFDIR)
            if path == "symlink":
                return namedtuple('_', 'st_mode')(stat.S_IFLNK)
            return namedtuple('_', 'st_mode')(stat.S_IFREG)
        with patch('os.lstat', mock_lstat):
            fs = FSDict()
            self.assertIsInstance(fs, FSDict)
            self.assertEqual(fs.file, "data")
            self.assertEqual(fs.symlink, "file")
            self.assertIsInstance(fs.dir, FSDict)

    def test_Singleton(self):

        @Singleton
        class A:
            def __init__(self, *args, **kwargs):
                pass

        @Singleton
        class B:
            def __init__(self, *args, **kwargs):
                pass

        a = A(1)
        self.assertIsInstance(a, A)
        a_ = A(1)
        a2 = A(2)
        b = B(1)
        self.assertEqual(id(a), id(a_))
        self.assertNotEqual(id(a), id(a2))
        self.assertNotEqual(id(a), id(b))
        id_a = id(a)
        del a, a_
        gc.collect()
        a = A(1)
        self.assertNotEqual(id(a), id_a)

    def test_Property(self):

        class A(AttrDict):
            def __new__(cls):
                setattr(cls, 'a', Property(partialmethod(cls._a, 777), name='a'))
                return super().__new__(cls)

            def _a(self, value):
                self['a'] = value
                return self['a']

            @Property
            def b(self):
                return -self.a

        a = A()
        self.assertIsInstance(a, A)
        self.assertEqual(a.a, 777)
        self.assertEqual(a.b, a['b'])
        self.assertEqual(a.b, -777)

    def test_CustomJSONEncoder(self):
        d = AttrDict({'time': Time(0), 'uid': Uid(0), 'gid': Gid(0), 'ip': IPAddr('00000000')})
        s = '{"gid": 0, "ip": "0.0.0.0", "time": "Thu Jan  1 00:00:00 1970", "uid": 0}'
        self.assertEqual(s, json.dumps(d, cls=CustomJSONEncoder, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
