import unittest

from restartable.procfs import Proc, ProcNet, ProcPid
from restartable.utils import AttrDict, IPAddr, Uid


class Test_ProcNet(unittest.TestCase):
    def test_ProcNet(self):
        with Proc() as p, ProcPid() as p_:
            net = p.net
            net_ = p_.net
            self.assertIsInstance(net, ProcNet)
            self.assertIsInstance(net_, ProcNet)
            self.assertEqual(p.net.tcp[0], p_.net.tcp[0])

    def test_ProcNet_protos(self):
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

    def test_ProcNet_arp(self):
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

    def test_ProcNet_dev(self):
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

    def test_ProcNet_netstat(self):
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

    def test_ProcNet_snmp(self):
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

    def test_ProcNet_route(self):
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

    def test_ProcNet_unix(self):
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
