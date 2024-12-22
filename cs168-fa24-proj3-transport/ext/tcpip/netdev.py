# Copyright 2018 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Network devices (interfaces)

This contains:
* NetDev: a superclass for all interfaces/NICs
* Several NetDev subclasses for connecting the stack to the real
  world via tun or tap interfaces or via pcap
"""

import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, EthAddr

from pox.lib.interfaceio import TapInterface
from pox.lib.interfaceio import PCapInterface

from pox.lib.revent import Event, EventMixin

from pox.core import core

import random

log = core.getLogger()



class CapturedPacketBase (Event):
  """
  Event which is fired when sniffing packets on a netdev

  There are two variants of this -- one for TX and one for RX

  Event handlers for this should not raise exceptions.
  """
  is_tx = None
  def __init__ (self, dev, parsed, raw, is_ip):
    self.dev = dev
    self.is_ip = is_ip
    self._raw = raw
    self._parsed = parsed

  @property
  def raw (self):
    if self._raw is None:
      self._raw = self._parsed.pack()
    return self._raw

  @property
  def parsed (self):
    if self._parsed is None:
      if self.is_ip:
        self._parsed = pkt.ipv4(raw=self._raw)
      else:
        self._parsed = pkt.ethernet(raw=self._raw)
    return self._parsed

  @property
  def is_rx (self):
    return not self.is_tx


class CapturedPacketRX (CapturedPacketBase):
  is_tx = False

class CapturedPacketTX (CapturedPacketBase):
  is_tx = True



class NetDev (EventMixin):
  name = None
  ip_addr = None
  stack = None

  is_l2 = False

  enable_arp = False
  enable_ip_forward_from = True
  enable_ip_forward_to = True
  enable_ip_masquerade = False

  enable_tx = True
  enable_rx = True

  _eventMixin_events = (CapturedPacketTX,CapturedPacketRX)

  @property
  def log (self):
    # This is currently inefficient, but it's not used much?
    return log if not self.stack else self.stack.log.getChild(self.name)

  @property
  def enable (self):
    return self.enable_tx and self.enable_rx
  @enable.setter
  def enable (self, v):
    self.enable_tx = v
    self.enable_rx = v

  def has_ip_addr (self, addr):
    return self.ip_addr == addr

  def send (self, packet, gw):
    """
    Send IP(?) packet
    """
    raise NotImplementedError()



class L2NetDev (object):
  is_l2 = True

  def send_raw_l2 (self, raw_eth):
    raise NotImplementedError()

  @property
  def eth_addr (self):
    raise NotImplementedError()

  @property
  def mtu (self):
    raise NotImplementedError()



class NormalL2Dev (L2NetDev):
  def send (self, packet, gw):
    if not self.stack: return
    assert packet.ipv4 is not None

    e = pkt.ethernet()
    e.src = self.eth_addr
    e.type = e.IP_TYPE
    e.payload = packet.ipv4
    e.payload.parsed = True

    packet.set_payload()

    next_hop = gw if gw else packet.ipv4.dstip

    self.stack.arp_table.send(e, router_ip=next_hop, src_ip=self.ip_addr,
                              send_function=self.send_raw_l2)

  def send_raw_l2 (self, raw_eth):
    if self.stack is None:
      log.debug("Sending ARPed packets after netdev removed")
      return
    self.raiseEvent(CapturedPacketTX, self, None, raw_eth, False)
    self.iface.send(raw_eth)

  @property
  def eth_addr (self):
    return self.iface.eth_addr

  @property
  def mtu (self):
    return self.iface.mtu

  def _handle_RXData (self, e):
    if self.stack:
      p = self.stack.new_packet()
      p.rx_dev = self
      ethp = pkt.ethernet(raw=e.data)
      p.eth = ethp
      p.ipv4 = p.eth.find("ipv4")
      self.raiseEvent(CapturedPacketRX, self, ethp, e.data, False)
      self.stack.rx(p)



class FlexibleEthAddr (object):
  _eth_addr = False
  def _init_eth (self, eth_addr=None):
    if eth_addr is None:
      eth_addr = self._eth_addr
    if eth_addr is any:
      eth_addr = ["02"] + ["%02x" % (x,) for x in random.randint(0, 255)]
      eth_addr = EthAddr(":".join(eth_addr))
    if eth_addr not in (True,False):
      self._eth_addr = EthAddr(eth_addr)
    else:
      self._eth_addr = eth_addr

  @property
  def eth_addr (self):
    if self._eth_addr is False:
      return self.iface.eth_addr
    if self._eth_addr is True:
      addr = "02:" + str(self.iface.eth_addr).split(":",1)[1]
      addr = EthAddr(addr)
      self._eth_addr = addr
    return self._eth_addr



class TunTapDev (NetDev):
  def _init (self, dev_name, tun=False, ip_addr=None):
    if ip_addr: self.ip_addr = IPAddr(ip_addr)

    self.enable_arp = False if tun else True
    raw = False #if tun else True

    self.iface = TapInterface(dev_name, tun, raw = raw,
                              protocol = pkt.ethernet.IP_TYPE)
    self.iface.addListeners(self)

    self.name = self.iface.name



class TapDev (FlexibleEthAddr, NormalL2Dev, TunTapDev):
  def __init__ (self, *args, **kw):
    self._init_eth(kw.pop("eth_addr", None))

    kw['tun'] = False
    super(TapDev,self)._init(*args, **kw)

    if self._eth_addr is not False:
      self.iface.promiscuous = True



class TunDev (TunTapDev):
  def __init__ (self, *args, **kw):
    kw['tun'] = True
    super(TunDev,self)._init(*args, **kw)

  def send (self, packet, gw):
    assert packet.ipv4
    self.raiseEvent(CapturedPacketTX, self, packet.ipv4, None, True)
    self.iface.send(packet.ipv4.pack())

  def _handle_RXData (self, e):
    if self.stack:
      if e.interface.last_protocol != pkt.ethernet.IP_TYPE: return
      p = self.stack.new_packet()
      p.rx_dev = self
      p.ipv4 = pkt.ipv4(raw=e.data)
      self.raiseEvent(CapturedPacketRX, self, p.ipv4, e.data, True)
      self.stack.rx(p)



class PCapDev (FlexibleEthAddr, NormalL2Dev, NetDev):
  def __init__ (self, dev_name, ip_addr=None, eth_addr=None):
    """
    Initialize the interface

    If eth_addr is specified, it may be False to use the interface's actual
    address, True to just change the leading byte to 02, any to make
    a random one, or it can be an actual EthAddr to use.
    """
    self._init_eth(eth_addr)

    if ip_addr: self.ip_addr = IPAddr(ip_addr)

    self.enable_arp = True

    self.iface = PCapInterface(dev_name)
    self.iface.addListeners(self)

    self.name = self.iface.name

    if self._eth_addr is not False:
      self.iface.promiscuous = True
