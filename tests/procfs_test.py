import os
import unittest
from unittest.mock import patch, mock_open, PropertyMock
from collections import namedtuple

from restartable.procfs import Proc, ProcNet, ProcPid
from restartable.utils import AttrDict, FSDict, IPAddr, Uid, Gid, Time


# pylint: disable=no-member,unsubscriptable-object,unsupported-delete-operation,no-self-use,line-too-long


# NOTE: Addresses and ports in hexadecimal are stored in host-byte order, so they are all set to zeroes here
class Test_ProcNet(unittest.TestCase):
    n = 0

    def setUp(self):
        self.n = len(os.listdir("/proc/self/fd"))

    def tearDown(self):
        self.assertEqual(self.n, len(os.listdir("/proc/self/fd")))

    def test_ProcNet(self):
        with Proc() as p, ProcPid() as p_:
            net = p.net
            net_ = p_.net
            self.assertIsInstance(net, ProcNet)
            self.assertIsInstance(net_, ProcNet)
            self.assertEqual(p.net.tcp[0], p_.net.tcp[0])

    @patch('builtins.open', mock_open(read_data="""  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 00000000:0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 37742 1 0000000000000000 100 0 0 10 0\n"""))
    def test_protos(self):
        with Proc() as p:
            net = p.net
            self.assertIs(net.tcp, net['tcp'])
            del net.tcp
            self.assertIs(net.tcp, net['tcp'])
            self.assertIsInstance(net.tcp[0], AttrDict)
            self.assertIs(net.tcp[0].local_address, net['tcp'][0]['local_address'])
            del net['tcp']
            self.assertEqual(net.data, {})
            self.assertIsInstance(net.tcp[0].local_address, IPAddr)
            self.assertIsInstance(net.tcp[0].local_port, int)
            self.assertIsInstance(net.tcp[0].uid, Uid)
            self.assertEqual(net.tcp[0].local_address, "0.0.0.0")
            self.assertEqual(net.tcp[0].local_port, 0)
            self.assertEqual(net.tcp[0].uid, 0)

    @patch('builtins.open', mock_open(read_data="""IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1      0x1         0x2         52:54:00:46:2f:8d     *        enp61s0u1u2\n"""))
    def test_arp(self):
        with Proc() as p:
            net = p.net
            self.assertIs(net.arp, net['arp'])
            del net.arp
            self.assertIs(net.arp, net['arp'])
            self.assertIsInstance(net.arp[0], AttrDict)
            self.assertIs(net.arp[0].IP_address, net['arp'][0]['IP_address'])
            del net['arp']
            self.assertEqual(net.data, {})
            self.assertIsInstance(net.arp[0].IP_address, IPAddr)
            self.assertEqual(net.arp[0].IP_address, "10.0.0.1")
            self.assertEqual(net.arp[0].IP_address, "10.0.0.1")
            self.assertEqual(net.arp[0].HW_address, "52:54:00:46:2f:8d")

    @patch('builtins.open', mock_open(read_data="""Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 10393238   32573    0    0    0     0          0         0 10393238   32573    0    0    0     0       0          0\n"""))
    def test_dev(self):
        with Proc() as p:
            net = p.net
            self.assertIs(net.dev, net['dev'])
            del net.dev
            self.assertIsInstance(net.dev, AttrDict)
            self.assertIs(net.dev, net['dev'])
            self.assertIs(net.dev.lo.RX_bytes, net['dev']['lo']['RX_bytes'])
            del net['dev']
            self.assertEqual(net.data, {})
            self.assertEqual(net.dev['lo'].RX_bytes, 10393238)

    @patch('builtins.open', mock_open(read_data="6    eth0  1     0     01005e00006a\n"))
    def test_dev_mcast(self):
        with Proc() as p:
            net = p.net
            self.assertIs(net.dev_mcast, net['dev_mcast'])
            del net.dev_mcast
            self.assertIsInstance(net.dev_mcast, list)
            self.assertIs(net.dev_mcast, net['dev_mcast'])
            del net['dev_mcast']
            self.assertEqual(net.data, {})
            self.assertIs(net.dev_mcast[0].interface, net['dev_mcast'][0]['interface'])
            self.assertEqual(net.dev_mcast[0]['interface'], "eth0")

    @patch('builtins.open', mock_open(read_data="TcpExt: SyncookiesSent SyncookiesRecv\nTcpExt: 1 2\nIpExt: InNoRoutes InTruncatedPkts\nIpExt: 3 4\n"))
    def test_netstat(self):
        with Proc() as p:
            net = p.net
            self.assertIs(net.netstat, net['netstat'])
            del net.netstat
            self.assertIsInstance(net.netstat, AttrDict)
            self.assertIs(net.netstat, net['netstat'])
            self.assertIs(net.netstat.TcpExt.SyncookiesSent, net['netstat']['TcpExt']['SyncookiesSent'])
            del net['netstat']
            self.assertEqual(net.data, {})
            self.assertEqual(net.netstat['TcpExt'].SyncookiesSent, 1)
            self.assertEqual(net.netstat['IpExt'].InTruncatedPkts, 4)

    @patch('builtins.open', mock_open(read_data="Ip: Forwarding DefaultTTL\nIp: 1 64\nIcmp: InMsgs InErrors\nIcmp: 4 0\n"))
    def test_snmp(self):
        with Proc() as p:
            net = p.net
            self.assertIs(net.snmp, net['snmp'])
            del net.snmp
            self.assertIsInstance(net.snmp, AttrDict)
            self.assertIs(net.snmp, net['snmp'])
            self.assertIs(net.snmp.Ip.Forwarding, net['snmp']['Ip']['Forwarding'])
            del net['snmp']
            self.assertEqual(net.data, {})
            self.assertEqual(net.snmp['Ip'].Forwarding, 1)
            self.assertEqual(net.snmp['Icmp'].InErrors, 0)

    @patch('builtins.open', mock_open(read_data="Ip6InReceives                   	579556\nIp6InHdrErrors                  	0\n"))
    def test_snmp6(self):
        with Proc() as p:
            net = p.net
            self.assertIs(net.snmp6, net['snmp6'])
            del net.snmp6
            self.assertIsInstance(net.snmp6, AttrDict)
            self.assertIs(net.snmp6, net['snmp6'])
            self.assertIs(net.snmp6.Ip6InReceives, net['snmp6']['Ip6InReceives'])
            del net['snmp6']
            self.assertEqual(net.data, {})
            self.assertEqual(net.snmp6.Ip6InHdrErrors, 0)

    @patch('builtins.open', mock_open(read_data="""Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
enp61s0u1u2	00000000	00000000	0003	0	0	100	00000000	0	0	0"""))
    def test_route(self):
        with Proc() as p:
            net = p.net
            self.assertIs(net.route, net['route'])
            del net.route
            self.assertIsInstance(net.route[0], AttrDict)
            self.assertIs(net.route, net['route'])
            self.assertIs(net.route[0].Iface, net['route'][0]['Iface'])
            del net['route']
            self.assertEqual(net.data, {})
            for key in ('Destination', 'Gateway', 'Mask'):
                self.assertIsInstance(net.route[0][key], IPAddr)
                self.assertEqual(net.route[0][key], "0.0.0.0")

    @patch('builtins.open', mock_open(read_data="""Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 39837 @/tmp/.ICE-unix/2642"""))
    def test_unix(self):
        with Proc() as p:
            net = p.net
            self.assertIs(net.unix, net['unix'])
            del net.unix
            self.assertIs(net.unix, net['unix'])
            del net['unix']
            self.assertEqual(net.data, {})
            self.assertIsInstance(net.unix[0], AttrDict)
            self.assertEqual(net.unix[0].Path, net.unix[0]['Path'])
            self.assertEqual(net.unix[0].Path, "@/tmp/.ICE-unix/2642")

    def test_xxx(self):
        with Proc() as p:
            with self.assertRaises(FileNotFoundError):
                _ = p.net.xxx


class Test_ProcPid(unittest.TestCase):
    n = 0

    def setUp(self):
        self.n = len(os.listdir("/proc/self/fd"))

    def tearDown(self):
        self.assertEqual(self.n, len(os.listdir("/proc/self/fd")))

    def test_ProcPid(self):
        with ProcPid() as p, ProcPid(os.getpid()) as p_:
            self.assertIsInstance(p, ProcPid)
            self.assertEqual(p.pid, p_.pid)
            self.assertEqual(p.ctime, p_.ctime)

    @patch('os.stat', return_value=namedtuple('_', 'st_ctime')(float(0)))
    def test_ctime(self, *_):
        with ProcPid() as p:
            self.assertIsInstance(p.ctime, Time)
            self.assertEqual(p.ctime, 'Thu Jan  1 00:00:00 1970')

    @patch('builtins.open', mock_open(read_data="a\nb\0c\0"))
    def test_cmdline(self):
        with ProcPid() as p:
            self.assertIsInstance(p.cmdline, list)
            self.assertEqual(p.cmdline, ["a\\nb", "c"])
            self.assertIs(p.cmdline, p['cmdline'])
            del p.cmdline
            self.assertIs(p.cmdline, p['cmdline'])
            del p['cmdline']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data="ab\n"))
    def test_comm(self):
        with ProcPid() as p:
            self.assertIsInstance(p.comm, str)
            self.assertEqual(p.comm, "ab")
            self.assertIs(p.comm, p['comm'])
            del p.comm
            self.assertIs(p.comm, p['comm'])
            del p['comm']
            self.assertEqual(p.data, {})

    def test_environ1(self):
        with ProcPid() as p:
            self.assertIsInstance(p.environ, AttrDict)
            self.assertEqual(p.environ, os.environ)
            self.assertIs(p.environ, p['environ'])
            del p.environ
            self.assertIs(p.environ, p['environ'])
            self.assertIs(p.environ.PATH, p['environ']['PATH'])
            del p['environ']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data=b'\xff\x00'))
    def test_environ2(self):
        with ProcPid() as p:
            self.assertIsInstance(p.environ, bytes)
            self.assertEqual(p.environ, b'\xff\x00')

    @patch('builtins.open', mock_open(read_data="a: 1\nb: 2\n"))
    def test_io(self):
        with ProcPid() as p:
            self.assertIsInstance(p.io, AttrDict)
            self.assertEqual(p.io, {'a': 1, 'b': 2})
            self.assertIs(p.io, p['io'])
            del p.io
            self.assertIs(p.io, p['io'])
            del p['io']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data="Limit                     Soft Limit           Hard Limit           Units    \nMax stack size            8388608              unlimited            bytes   \n"))
    def test_limits(self):
        with ProcPid() as p:
            self.assertIsInstance(p.limits, AttrDict)
            self.assertEqual(p.limits.stack.soft, 8388608)
            self.assertEqual(p['limits']['stack']['hard'], -1)
            self.assertIs(p.limits, p['limits'])
            del p.limits
            self.assertIs(p.limits, p['limits'])
            del p['limits']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data="560646741000-560646745000 r--p 00000000 fe:01 7078353                    /usr/bin/cat\n"))
    def test_maps(self):
        with ProcPid() as p:
            self.assertIsInstance(p.maps[0], AttrDict)
            self.assertIs(p.maps, p['maps'])
            self.assertIs(p.maps[0].address, p['maps'][0]['address'])
            self.assertEqual(p.maps[0]['pathname'], "/usr/bin/cat")
            del p.maps
            self.assertIs(p.maps, p['maps'])
            del p['maps']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data="560646741000-560646745000 r--p 00000000 fe:01 7078353                    /usr/bin/cat\nSize:                 16 kB\nKernelPageSize:        4 kB\n"))
    def test_smaps(self):
        with patch('restartable.procfs.ProcPid.maps', new_callable=PropertyMock) as mock_maps:
            mock_maps.return_value = [AttrDict({'address': '560646741000-560646745000', 'perms': 'r--p', 'offset': '00000000', 'dev': 'fe:01', 'inode': '7078353', 'pathname': '/usr/bin/cat'})]
            with ProcPid() as p:
                self.assertIsInstance(p.smaps[0], AttrDict)
                self.assertIs(p.smaps, p['smaps'])
                self.assertIs(p.smaps[0].address, p['smaps'][0]['address'])
                self.assertEqual(p.smaps[0]['pathname'], "/usr/bin/cat")
                self.assertIs(p.smaps[0].Size, p['smaps'][0]['Size'])
                self.assertEqual(p.smaps[0]['KernelPageSize'], 4)
                del p.smaps
                self.assertIs(p.smaps, p['smaps'])
                del p['smaps']
                self.assertEqual(p.data, {})

    def test_map_files(self):
        with ProcPid() as p:
            address = "-".join(map(lambda _: _.lstrip('0'), p.maps[0].address.split('-')))
            self.assertIn(address, p.map_files)

    @patch('builtins.open', mock_open(read_data="tmpfs /dev/shm tmpfs rw,nosuid,nodev,foo=1,bar=baz 0 0\n"))
    def test_mounts(self):
        with ProcPid() as p:
            self.assertIsInstance(p.mounts[0], AttrDict)
            self.assertEqual(p.mounts[0].spec, "tmpfs")
            self.assertEqual(p.mounts[0].file, "/dev/shm")
            self.assertEqual(p.mounts[0].vfstype, "tmpfs")
            self.assertEqual(p.mounts[0].mntops, p.mounts[0]['mntops'])
            self.assertEqual(p.mounts[0].mntops['foo'], 1)
            self.assertEqual(p.mounts[0].mntops.bar, "baz")
            self.assertEqual(p.mounts[0].freq, "0")
            self.assertEqual(p.mounts[0].passno, "0")
            self.assertIs(p.mounts, p['mounts'])
            del p.mounts
            self.assertIs(p.mounts, p['mounts'])
            del p['mounts']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data="24 100 0:6 / /dev rw,nosuid shared:21 - devtmpfs devtmpfs rw,size=16352080k,nr_inodes=4088020,mode=755\n"))
    def test_mountinfo(self):
        with ProcPid() as p:
            self.assertIsInstance(p.mountinfo[0], AttrDict)
            self.assertEqual(p.mountinfo[0].major, "0")
            self.assertIs(p.mountinfo[0].super_options.size, p.mountinfo[0]['super_options']['size'])
            self.assertEqual(p.mountinfo[0].super_options.nr_inodes, 4088020)
            del p.mountinfo
            self.assertIs(p.mountinfo, p['mountinfo'])
            del p['mountinfo']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data="7f7f335d7000 default file=/lib/x86_64-linux-gnu/ld-2.27.so anon=1 dirty=1 N0=1 kernelpagesize_kB=4\n7ffc19d01000 default\n"))
    def test_numa_maps(self):
        with ProcPid() as p:
            self.assertIsInstance(p.numa_maps, AttrDict)
            self.assertIs(p.numa_maps, p['numa_maps'])
            del p.numa_maps
            self.assertIs(p.numa_maps, p['numa_maps'])
            del p['numa_maps']
            self.assertEqual(p.numa_maps['7f7f335d7000'].file, "/lib/x86_64-linux-gnu/ld-2.27.so")
            self.assertEqual(p.numa_maps['7ffc19d01000'].policy, "default")

    @patch('builtins.open', mock_open(read_data="777 ( a \n b ) S" + " 1" * 49))
    def test_stat(self):
        with ProcPid() as p:
            self.assertIsInstance(p.stat, AttrDict)
            self.assertEqual(p.stat.comm, " a \\n b ")
            self.assertIs(p.stat, p['stat'])
            del p.stat
            self.assertIs(p.stat, p['stat'])
            del p['stat']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data="0 1 2 3 4 5 6"))
    def test_statm(self):
        with ProcPid() as p:
            self.assertIsInstance(p.statm, AttrDict)
            for value, key in enumerate('size resident shared text lib data dt'.split()):
                self.assertEqual(p.statm[key], value)
            self.assertIs(p.statm, p['statm'])
            del p.statm
            self.assertIs(p.statm, p['statm'])
            del p['statm']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data=("Name:\tfoobar\nUid:\t0 1 2 3\nGid:\t4 5 6 7\nGroups:\t0\n" + "".join(["%s:\t  %s kB\n" % (s, i) for (i, s) in enumerate(('VmPeak', 'VmSize', 'VmLck', 'VmPin', 'VmHWM', 'VmRSS', 'RssAnon', 'RssFile', 'RssShmem', 'VmData', 'VmStk', 'VmExe', 'VmLib', 'VmPTE', 'VmSwap', 'HugetlbPages'))]))))
    def test_status(self):
        with ProcPid() as p:
            self.assertIsInstance(p.status, AttrDict)
            self.assertIsInstance(p.status.Uid.real, Uid)
            self.assertIsInstance(p.status.Gid.real, Gid)
            self.assertIsInstance(p.status.Groups[0], Gid)
            for value, key in enumerate('real effective saved_set filesystem'.split()):
                self.assertEqual(p.status.Uid[key], value)
                self.assertEqual(p.status.Gid[key], value + 4)
            self.assertEqual(p.status.Groups[0].name, "root")
            self.assertIs(p.status, p['status'])
            del p.status
            self.assertIs(p.status, p['status'])
            del p['status']
            self.assertEqual(p.data, {})

    @patch('os.readlink', return_value='file')
    def test_fd(self, *_):
        with ProcPid() as p:
            self.assertIsInstance(p.task, list)
            self.assertIs(p.fd, p['fd'])
            self.assertEqual(p['fd/0'], "file")

    def test_task(self):
        with ProcPid() as p:
            self.assertIsInstance(p.task, list)
            self.assertIs(p.task, p['task'])
            self.assertIn(p.pid, p.task)

    def test_personality(self):
        with ProcPid() as p:
            self.assertIs(p.personality, p['personality'])
            del p.personality
            self.assertIs(p.personality, p['personality'])
            del p['personality']
            self.assertEqual(p.data, {})
            self.assertIsInstance(int(p.personality, base=16), int)

    def test_xxx(self):
        with ProcPid() as p:
            with self.assertRaises(FileNotFoundError):
                _ = p.xxx
        with self.assertRaises(FileNotFoundError):
            p = ProcPid(proc="/xxx")
        with self.assertRaises(ValueError):
            p = ProcPid("/xxx")


class Test_Proc(unittest.TestCase):
    n = 0

    def setUp(self):
        self.n = len(os.listdir("/proc/self/fd"))

    def tearDown(self):
        self.assertEqual(self.n, len(os.listdir("/proc/self/fd")))

    def test_Proc(self):
        with Proc() as p, ProcPid() as p_:
            self.assertIsInstance(p, Proc)
            self.assertEqual(p.self.pid, p_.pid)

    def test_pids(self):
        with Proc() as p:
            self.assertIn(str(os.getpid()), p.pids())

    def test_tasks(self):
        with Proc() as p:
            self.assertIn(str(os.getpid()), p.tasks())

    @patch('builtins.open', mock_open(read_data="\n#\n# Compiler: gcc (SUSE Linux) 9.2.1 20190903 [gcc-9-branch revision 275330]\n#\nCONFIG_CC_IS_GCC=y\n"))
    def test_config(self):
        def mock_stat(path, *_, **__):
            if path == "config.gz":
                raise FileNotFoundError
        with Proc() as p, patch('os.stat', mock_stat):
            self.assertIsInstance(p.config, AttrDict)
            self.assertIs(p.config, p['config'])
            del p.config
            self.assertIs(p.config, p['config'])
            del p['config']
            self.assertEqual(p.data, {})
            self.assertIs(p.config.CONFIG_CC_IS_GCC, p['config']['CONFIG_CC_IS_GCC'])
            self.assertEqual(p.config.CONFIG_CC_IS_GCC, 'y')

    @patch('builtins.open', mock_open(read_data="#subsys_name\thierarchy\tnum_cgroups\tenabled\ncpuset\t8\t4\t1\n"))
    def test_cgroups(self):
        with Proc() as p:
            self.assertIsInstance(p.cgroups, AttrDict)
            self.assertIs(p.cgroups, p['cgroups'])
            del p.cgroups
            self.assertIs(p.cgroups, p['cgroups'])
            del p['cgroups']
            self.assertEqual(p.data, {})
            self.assertIs(p.cgroups.cpuset.hierarchy, p['cgroups']['cpuset']['hierarchy'])
            self.assertEqual(p.cgroups.cpuset['hierarchy'], 8)
            self.assertEqual(p.cgroups.cpuset.enabled, 1)

    @patch('builtins.open', mock_open(read_data="processor\t: 0\nvendor_id\t: GenuineXYZ\n\nprocessor\t: 1\nvendor_id\t: GenuineXYZ\n\n"))
    def test_cpuinfo(self):
        with Proc() as p:
            self.assertIsInstance(p.cpuinfo, list)
            self.assertIs(p.cpuinfo, p['cpuinfo'])
            del p.cpuinfo
            self.assertIs(p.cpuinfo, p['cpuinfo'])
            del p['cpuinfo']
            self.assertEqual(p.data, {})
            self.assertIs(p.cpuinfo[0].vendor_id, p.cpuinfo[0]['vendor_id'])
            self.assertEqual(p.cpuinfo[1].vendor_id, "GenuineXYZ")

    @patch('builtins.open', mock_open(read_data="MemTotal:       32727212 kB\nMemFree:        24443188 kB\n"))
    def test_meminfo(self):
        with Proc() as p:
            self.assertIsInstance(p.meminfo, AttrDict)
            self.assertIs(p.meminfo, p['meminfo'])
            del p.meminfo
            self.assertIs(p.meminfo, p['meminfo'])
            del p['meminfo']
            self.assertEqual(p.data, {})
            self.assertIs(p.meminfo.MemTotal, p['meminfo']['MemTotal'])
            self.assertEqual(p.meminfo['MemFree'], 24443188)

    def test_mounts(self):
        with Proc() as p, ProcPid() as p_:
            self.assertEqual(p.mounts, p_.mounts)
            self.assertIs(p.mounts, p['mounts'])
            del p.mounts
            self.assertIs(p.mounts, p['mounts'])
            del p['mounts']
            self.assertEqual(p.data, {})

    @patch('builtins.open', mock_open(read_data="Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n/dev/dm-1\t\t\t\tpartition\t\t32792572\t0\t-2\n"))
    def test_swaps(self):
        with Proc() as p:
            self.assertIsInstance(p.swaps, list)
            self.assertIsInstance(p.swaps[0], AttrDict)
            self.assertIs(p.swaps, p['swaps'])
            del p.swaps
            self.assertIs(p.swaps, p['swaps'])
            del p['swaps']
            self.assertEqual(p.data, {})
            self.assertIs(p.swaps[0].Filename, p['swaps'][0]['Filename'])
            self.assertEqual(p.swaps[0]['Filename'], "/dev/dm-1")

    @patch('builtins.open', mock_open(read_data="nr_free_pages 6097475\nnr_zone_inactive_anon 53530\n"))
    def test_vmstat(self):
        with Proc() as p:
            self.assertIsInstance(p.vmstat, AttrDict)
            self.assertIs(p.vmstat, p['vmstat'])
            del p.vmstat
            self.assertIs(p.vmstat, p['vmstat'])
            del p['vmstat']
            self.assertEqual(p.data, {})
            self.assertIs(p.vmstat.nr_free_pages, p['vmstat']['nr_free_pages'])
            self.assertEqual(p.vmstat['nr_zone_inactive_anon'], 53530)

    @patch('builtins.open', mock_open(read_data="""       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n         0          6  1600                524288  2669  7487      2  1000   100  1000   100 1572344073 1572344073 1572342595                 12288                     0\n"""))
    def test_sysvipc(self):
        with Proc() as p:
            self.assertIsInstance(p.sysvipc, FSDict)
            self.assertIs(p.sysvipc, p['sysvipc'])
            self.assertIs(p.sysvipc.shm, p['sysvipc']['shm'])
            del p.sysvipc
            self.assertIs(p.sysvipc, p['sysvipc'])
            self.assertIs(p.sysvipc.shm, p['sysvipc']['shm'])
            del p['sysvipc']
            self.assertEqual(p.data, {})
            for key in ('uid', 'cuid'):
                self.assertIsInstance(p.sysvipc.shm[0][key], Uid)
            self.assertEqual(p.sysvipc.shm[0].uid, 1000)
            for key in ('gid', 'cgid'):
                self.assertIsInstance(p.sysvipc.shm[0][key], Gid)
            self.assertEqual(p.sysvipc.shm[0].gid, 100)
            for key in [_ for _ in p.sysvipc.shm[0].keys() if _.endswith("time")]:
                self.assertIsInstance(p.sysvipc.shm[0][key], Time)
            self.assertEqual(p.sysvipc.shm[0].ctime, "Tue Oct 29 09:49:55 2019")

    @patch('builtins.open', mock_open(read_data="Linux version 5.3.7-1-default (geeko@buildhost) (gcc version 9.2.1 20190903 [gcc-9-branch revision 275330] (SUSE Linux)) #1 SMP Mon Oct 21 06:03:17 UTC 2019 (3eea5a9)"))
    def test_version(self):
        with Proc() as p:
            self.assertIs(p.version, p['version'])
            del p.version
            self.assertIs(p.version, p['version'])
            del p['version']
            self.assertEqual(p.data, {})
            self.assertIn("Linux", p.version)

    def test_xxx(self):
        with Proc() as p:
            with self.assertRaises(FileNotFoundError):
                _ = p.xxx
        with self.assertRaises(FileNotFoundError):
            p = ProcPid(proc="/xxx")
