import os
import unittest
from collections import namedtuple
from resource import getrlimit, RLIMIT_STACK
from mock import patch, mock_open

from restartable.procfs import Proc, ProcNet, ProcPid
from restartable.utils import AttrDict, IPAddr, Uid, Gid, Time


# pylint: disable=no-member,unsubscriptable-object,unsupported-delete-operation


class Test_ProcNet(unittest.TestCase):
    def test_ProcNet(self):
        with Proc() as p, ProcPid() as p_:
            net = p.net
            net_ = p_.net
            self.assertIsInstance(net, ProcNet)
            self.assertIsInstance(net_, ProcNet)
            self.assertEqual(p.net.tcp[0], p_.net.tcp[0])

    def test_protos(self):
        with Proc() as p:
            net = p.net
            assert net.tcp
            self.assertEqual(net.tcp, net['tcp'])
            del net.tcp
            assert net['tcp']
            self.assertEqual(net.tcp, net['tcp'])
            self.assertIsInstance(net.tcp[0], AttrDict)
            self.assertEqual(net.tcp[0].local_address, net['tcp'][0]['local_address'])
            del net['tcp']
            self.assertEqual(net.data, {})
            self.assertIsInstance(net.tcp[0].local_address, IPAddr)
            self.assertIsInstance(net.tcp[0].local_port, int)
            self.assertIsInstance(net.tcp[0].uid, Uid)

    def test_arp(self):
        with Proc() as p:
            net = p.net
            assert net.arp
            self.assertEqual(net.arp, net['arp'])
            del net.arp
            assert net['arp']
            self.assertEqual(net.arp, net['arp'])
            self.assertIsInstance(net.arp[0], AttrDict)
            self.assertEqual(net.arp[0].IP_address, net['arp'][0]['IP_address'])
            del net['arp']
            self.assertEqual(net.data, {})
            self.assertIsInstance(net.arp[0].IP_address, IPAddr)

    def test_dev(self):
        with Proc() as p:
            net = p.net
            assert net.dev
            self.assertEqual(net.dev, net['dev'])
            del net.dev
            assert net['dev']
            self.assertIsInstance(net.dev, AttrDict)
            self.assertEqual(net.dev, net['dev'])
            self.assertEqual(net.dev.lo.RX_bytes, net['dev']['lo']['RX_bytes'])
            del net['dev']
            self.assertEqual(net.data, {})
            self.assertIsInstance(net.dev['lo'].RX_bytes, int)

    def test_netstat(self):
        with Proc() as p:
            net = p.net
            assert net.netstat
            self.assertEqual(net.netstat, net['netstat'])
            del net.netstat
            assert net['netstat']
            self.assertIsInstance(net.netstat, AttrDict)
            self.assertEqual(net.netstat, net['netstat'])
            self.assertEqual(
                net.netstat.TcpExt.SyncookiesSent,
                net['netstat']['TcpExt']['SyncookiesSent'])
            del net['netstat']
            self.assertEqual(net.data, {})
            self.assertIsInstance(net.netstat['TcpExt'].SyncookiesSent, int)

    def test_snmp(self):
        with Proc() as p:
            net = p.net
            assert net.snmp
            self.assertEqual(net.snmp, net['snmp'])
            del net.snmp
            assert net['snmp']
            self.assertIsInstance(net.snmp, AttrDict)
            self.assertEqual(net.snmp, net['snmp'])
            self.assertEqual(net.snmp.Ip.Forwarding, net['snmp']['Ip']['Forwarding'])
            del net['snmp']
            self.assertEqual(net.data, {})
            self.assertIsInstance(net.snmp['Ip'].Forwarding, int)

    def test_route(self):
        with Proc() as p:
            net = p.net
            assert net.route
            self.assertEqual(net.route, net['route'])
            del net.route
            assert net['route']
            self.assertIsInstance(net.route[0], AttrDict)
            self.assertEqual(net.route, net['route'])
            self.assertEqual(net.route[0].Iface, net['route'][0]['Iface'])
            del net['route']
            self.assertEqual(net.data, {})
            for key in ('Destination', 'Gateway', 'Mask'):
                self.assertIsInstance(net.route[0][key], IPAddr)

    def test_unix(self):
        with Proc() as p:
            net = p.net
            assert net.unix
            self.assertEqual(net.unix, net['unix'])
            del net.unix
            assert net['unix']
            self.assertEqual(net.unix, net['unix'])
            del net['unix']
            self.assertEqual(net.data, {})
            self.assertIsInstance(net.unix[0], AttrDict)


class Test_ProcPid(unittest.TestCase):
    def test_ProcPid(self):
        with ProcPid() as p, ProcPid(os.getpid()) as p_:
            self.assertIsInstance(p, ProcPid)
            self.assertEqual(p.pid, p_.pid)
            self.assertEqual(p.ctime, p_.ctime)

    @patch('os.stat', return_value=namedtuple('_', 'st_ctime')(float(0)))
    def test_ctime(self, *_):
        with ProcPid() as p:
            self.assertIsInstance(p.ctime, Time)
            self.assertEqual(p.ctime.datetime.ctime(), 'Thu Jan  1 00:00:00 1970')

    @patch('builtins.open', mock_open(read_data="a\nb\0c\0"))
    def test_cmdline(self, *_):
        with ProcPid() as p:
            self.assertIsInstance(p.cmdline, list)
            self.assertEqual(p.cmdline, ["a\\nb", "c"])
            self.assertEqual(p.cmdline, p['cmdline'])
            del p.cmdline
            self.assertEqual(p.cmdline, p['cmdline'])
            del p['cmdline']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data="ab\n"))
    def test_comm(self, *_):
        with ProcPid() as p:
            self.assertIsInstance(p.comm, str)
            self.assertEqual(p.comm, "ab")
            self.assertEqual(p.comm, p['comm'])
            del p.comm
            self.assertEqual(p.comm, p['comm'])
            del p['comm']
            self.assertEqual(p.data, {})

    def test_environ1(self, *_):
        with ProcPid() as p:
            self.assertIsInstance(p.environ, AttrDict)
            self.assertEqual(p.environ, os.environ)
            self.assertEqual(p.environ, p['environ'])
            del p.environ
            self.assertEqual(p.environ, p['environ'])
            del p['environ']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data=b'\xff\x00'))
    def test_environ2(self, *_):
        with ProcPid() as p:
            self.assertIsInstance(p.environ, bytes)
            self.assertEqual(p.environ, b'\xff\x00')

    @patch('builtins.open', mock_open(read_data="a: 1\nb: 2\n"))
    def test_io(self, *_):
        with ProcPid() as p:
            self.assertIsInstance(p.io, AttrDict)
            self.assertEqual(p.io, {'a': 1, 'b': 2})
            self.assertEqual(p.io, p['io'])
            del p.io
            self.assertEqual(p.io, p['io'])
            del p['io']
            self.assertEqual(p.data, {})

    def test_limits(self):
        with ProcPid() as p:
            self.assertIsInstance(p.limits, AttrDict)
            self.assertEqual(getrlimit(RLIMIT_STACK), (p.limits.stack.soft, p.limits.stack.hard))
            self.assertEqual(p.limits, p['limits'])
            del p.limits
            self.assertEqual(p.limits, p['limits'])
            del p['limits']
            self.assertEqual(p.data, {})

    def test_maps(self):
        with ProcPid() as p:
            self.assertIsInstance(p.maps[0], AttrDict)
            address = "-".join(map(lambda _: _.lstrip('0'), p.maps[0].address.split('-')))
            assert address in p.map_files
            self.assertEqual(p.maps, p['maps'])
            del p.maps
            self.assertEqual(p.maps, p['maps'])
            del p['maps']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data="tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"))
    def test_mounts(self, *_):
        with ProcPid() as p:
            self.assertIsInstance(p.mounts[0], AttrDict)
            self.assertEqual(p.mounts[0].fs_spec, "tmpfs")
            self.assertEqual(p.mounts[0].fs_file, "/dev/shm")
            self.assertEqual(p.mounts[0].fs_vfstype, "tmpfs")
            self.assertEqual(p.mounts[0].fs_mntops, "rw,nosuid,nodev")
            self.assertEqual(p.mounts[0].fs_freq, "0")
            self.assertEqual(p.mounts[0].fs_passno, "0")
            self.assertEqual(p.mounts, p['mounts'])
            del p.mounts
            self.assertEqual(p.mounts, p['mounts'])
            del p['mounts']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data="777 ( a \n b ) S" + " 1" * 49))
    def test_stat(self, *_):
        with ProcPid() as p:
            self.assertIsInstance(p.stat, AttrDict)
            self.assertEqual(p.stat.comm, " a \\n b ")
            self.assertEqual(p.stat, p['stat'])
            del p.stat
            self.assertEqual(p.stat, p['stat'])
            del p['stat']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data="0 1 2 3 4 5 6"))
    def test_statm(self, *_):
        with ProcPid() as p:
            self.assertIsInstance(p.statm, AttrDict)
            for value, key in enumerate('size resident shared text lib data dt'.split()):
                self.assertEqual(p.statm[key], value)
            self.assertEqual(p.statm, p['statm'])
            del p.statm
            self.assertEqual(p.statm, p['statm'])
            del p['statm']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data="Uid:\t0 1 2 3\nGid:\t4 5 6 7\nGroups:\t0 1\n"))
    def test_status(self, *_):
        with ProcPid() as p:
            self.assertIsInstance(p.status, AttrDict)
            self.assertIsInstance(p.status.Uid.real, Uid)
            self.assertIsInstance(p.status.Gid.real, Gid)
            self.assertIsInstance(p.status.Groups[0], Gid)
            for value, key in enumerate('real effective saved_set filesystem'.split()):
                self.assertEqual(p.status.Uid[key], str(value))
                self.assertEqual(p.status.Gid[key], str(value + 4))
            for i, group in enumerate(p.status.Groups):
                self.assertEqual(group, str(i))
            self.assertEqual(p.status, p['status'])
            del p.status
            self.assertEqual(p.status, p['status'])
            del p['status']
            self.assertEqual(p.data, {})

    def test_fd(self):
        with ProcPid() as p:
            self.assertIsInstance(p.task, list)
            self.assertEqual(p.fd, p['fd'])
            self.assertEqual(p['fd/0'], os.ttyname(0))

    def test_task(self):
        with ProcPid() as p:
            self.assertIsInstance(p.task, list)
            self.assertEqual(p.task, p['task'])
            assert p.pid in p.task
