"""
DHCP client
"""

from pox.proto.dhcp_client import DHCPClientBase
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr, netmask_to_cidr
from pox.core import core



class DHCPClient (DHCPClientBase):
  add_default_route = True

  def __init__ (self, netdev):
    self.netdev = netdev
    name = netdev.name
    if netdev.is_l2:
      eth = netdev.eth_addr
    else:
      eth = EthAddr("ff:ff:ff:ff:ff:ff")
    super(DHCPClient,self).__init__(port_eth=eth, total_timeout=100,
                                    auto_accept=True, name=name)
    self.log = core.getLogger("dhcpc").getChild(name)
    netdev.stack.add_sniffer(lambda p: self._sniff(p))
    self._really_finished = False

  def _check_done (self):
    if self._really_finished: return True
    if not self.bound: return False

    self._really_finished = True
    self.log.info("Accepted offer %s", self.bound)
    self.netdev.ip_addr = self.bound.address
    size = 32
    gw = None
    if self.bound.subnet_mask:
      size = netmask_to_cidr(self.bound.subnet_mask)
    if self.bound.routers:
      gw = self.bound.routers[0]
      r = self.netdev.stack.add_route(prefix=gw, dev=self.netdev)
      self.log.info("Adding route %s", repr(r))
      if self.add_default_route:
        r = self.netdev.stack.add_route(prefix="0.0.0.0/0", gw=gw,
                                        dev=self.netdev)
        self.log.info("Adding default route %s", repr(r))
    subnet = None
    if size != 32:
      subnet = self.bound.address.get_network(size)
    elif gw:
      subnet = gw.get_network(size)
    if subnet:
      prefix = "%s/%s" % subnet
      r = self.netdev.stack.add_route(prefix, gw=gw, dev=self.netdev)
      self.log.info("Adding route %s", repr(r))

    return True

  def _sniff (self, packet):
    if self._check_done(): return True # Remove sniffer
    if packet.rx_dev is not self.netdev: return
    if packet.ipv4 is None: return
    dhcp = packet.ipv4.find('dhcp')
    if dhcp is None: return
    self._rx(packet.ipv4)
    if self._check_done(): return True # Remove sniffer

  def _send_data (self, raw):
    if self.netdev.is_l2:
      self.netdev.send_raw_l2(raw)
      return
    p = pkt.ethernet(raw=raw)
    p = p.find("ipv4")
    if not p:
      self.log("Failed to send data")
      return
    po = self.netdev.stack.new_packet()
    po.ipv4 = p
    self.netdev.send(po, None)
