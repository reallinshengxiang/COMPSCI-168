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
An IP stack

This takes care of a bunch of the lower parts of a TCP/IP stack.
Specifically, some stuff that's in here:
* The Routing class, which is a single routing table that can do LPM
* The Route class which is one route in a table
* Defragmenter: a helper class to defragment fragments (duh)
* The IPStack class.  You attach NetDevs to it.  Packets go in,
  ARPs get handled, IP packets get forwarded or sent up to the
  next layer (UDP/TCP/sockets).
* Launchers for IPStack as a component/from the commandline
"""
#TODO: RFC 1191 (PMTU discovery)
#TODO: Add more ICMP?
#TODO: Add routes/netdev for local IPs?
#      Currently, there's just a special case where it checks for
#      if the stack has an interface with the right IP.  It might
#      be nicer if that was done via a special Route entry.
#TODO: multicast support


import time
import fnmatch

from pox.lib.addresses import IPAddr, IP_ANY

import pox.lib.packet as pkt

from pox.proto.arp_table import ARPTable

from . netdev import *
from . time_manager import RealTimeManager

from pox.core import core
log = core.getLogger()



class MasqEntry (object):
  expire_time = 60*5
  expire_time_close = 60

  @staticmethod
  def make_tuple (p):
    return (p.rx_dev,p.ipv4.srcip,p.tcp.srcport,p.ipv4.dstip,p.tcp.dstport)

  def __init__ (self, stack, p, out_dev, out_port):
    self.near_ip = p.ipv4.srcip
    self.near_port = p.tcp.srcport
    self.out_dev = out_dev
    self.out_port = out_port
    self.in_dev = p.rx_dev
    self.out_tuple = self.make_tuple(p)
    t = (out_dev,p.ipv4.dstip,p.tcp.dstport,out_dev.ip_addr,out_port)
    self.in_tuple = t
    self.stack = stack
    self.update(p)

  def update (self, p):
    self.ts = self.stack.now
    if p is not None and (p.tcp.FIN or p.tcp.RST):
      self.expire_time = min(self.expire_time,self.expire_time_close)



class MasqTable (object):
  """
  IP Masquerading (NAT) helper
  """
  # Open question: Should there be one MasqTable per masquerading netdev,
  # or one shared among all?  Currently going with shared.

  expire_every = 100 # Every X new entries, try to expire some

  def __init__ (self, stack):
    self._in_table = {}
    self._out_table = {}
    self._next_out_port = 61001 #FIXME: Use socket manager for this
    self._next_out_port += random.randint(0,1000) #... and remove this!
    self._expire_counter = 0
    self.stack = stack

    # Should we have our own defragmenter(s)?
    self.in_defragger = stack.defragger
    self.out_defragger = stack.defragger

  def _maybe_do_expirations (self):
    if self.expire_every is None: return
    self._expire_counter += 1
    if self._expire_counter > self.expire_every:
      self._expire_counter = 0
      self._do_expirations()

  def _get_next_out_port (self):
    #FIXME: Use socket manager for this
    r = self._next_out_port
    self._next_out_port += 1
    if self._next_out_port >= 0xffFe:
      self._next_out_port = 61001
    return r

  def get_entry_out (self, p, out_dev):
    """
    Get the entry for an outgoing packet; creates if missing
    """
    if p.ipv4 is None or p.tcp is None: return None
    t = MasqEntry.make_tuple(p)
    me = self._out_table.get(t)
    if me is None:
      self._maybe_do_expirations()
      me = MasqEntry(self.stack, p, out_dev, self._get_next_out_port())
      self._out_table[t] = me
      self._in_table[me.in_tuple] = me
    me.update(p)
    return me

  def rewrite_out (self, p, out_dev):
    if not out_dev.ip_addr: return False
    p = self.out_defragger.rx_fragment(p)
    if not p: return False
    me = self.get_entry_out(p, out_dev)
    if me is None: return False
    p.ipv4.srcip = me.out_dev.ip_addr
    p.tcp.srcport = me.out_port
    return True

  def get_entry_in (self, p):
    if p.ipv4 is None or p.tcp is None: return None
    t = MasqEntry.make_tuple(p) # make_in_tuple()?
    me = self._in_table.get(t)
    if me is not None:
      me.update(p)
    return me

  def rewrite_in (self, p):
    p = self.in_defragger.rx_fragment(p)
    if not p: return False
    me = self.get_entry_in(p)
    if me:
      # It's masqueraded
      p.ipv4.dstip = me.near_ip
      p.tcp.dstport = me.near_port
      return True
    return False

  def _do_expirations (self):
    dead = []
    ts = self.stack.now
    for t,me in self._out_table.items():
      if ts - me.ts > me.expire_time:
        dead.append((t,me))
    if dead:
      self.stack.log.debug("Expiring %s masquerading entries", len(dead))
    for t,me in dead:
      del self._in_table[me.in_tuple]
      del self._out_table[t]



class Route (object):
  route_id = 0
  exportable = True
  def __init__ (self, prefix, size, metric, gw = None, dev_name = None):
    if prefix.get_network(size)[0] != prefix:
      raise RuntimeError("Route has the wrong size")
    self.prefix = prefix
    self.size = size
    self.metric = metric
    if self.size == 32:
      # Host routes always set the host as the GW too
      # (Should they?  I don't remember why this is, and to work around
      # some problems it causes requires .real_gw.)
      assert not gw
      gw = self.prefix
    self.gw = gw
    self.dev_name = dev_name
    if gw or dev_name:
      pass
    else:
      raise RuntimeError("Route must have gateway or device")
    Route.route_id += 1

  @property
  def real_gw (self):
    if self.size == 32:
      if self.gw == self.prefix:
        return None
    return self.gw

  @classmethod
  def new_default_route (cls, **kw):
    return cls(prefix=IPAddr("0.0.0.0"), size=0, **kw)

  def __str__ (self):
    p = "%s/%s" % (self.prefix, self.size)
    return "%-20s %-17s %6s %-20s" % (p, self.real_gw,
                                      self.metric, self.dev_name)
  def __repr__ (self):
    s = str(self)
    while "  " in s:
      s = s.replace("  ", " ")
    return "<" + s + ">"



class Routing (object):
  def __init__ (self):
    self.tables = [{} for _ in range(33)]
    # tables[x] -> prefixes of length x
    # Individual tables are prefix->[Route] with the routes sorted by metric
    # Since table 0 is a prefix size of 0, it will always match -- there
    # should only be zero or one keys in table 0.  If there is one, it
    # stores the default routes.

  def lookup (self, addr):
    """
    Returns matching Routes
    """
    for l in range(32,-1,-1):
      table = self.tables[l]
      if not table: continue
      e = table.get(addr.get_network(l)[0])
      if e: return e
    return []

  def lookup_best (self, addr):
    """
    Returns best route or None
    """
    r = self.lookup(addr)
    if not r: return None
    return r[0]

  def __contains__ (self, route):
    return bool(self.tables[route.size].get(route.prefix))

  def add (self, route):
    if not route in self:
      self.tables[route.size][route.prefix] = [route]
    else:
      self.tables[route.size][route.prefix].append(route)
      self.tables[route.size][route.prefix].sort(key = lambda r: r.metric)

  def get_all_routes (self):
    r = []
    for t in self.tables:
      for e in t.values():
        if e:
          r.append(e[0])
    return r

  def __str__ (self):
    o = []
    for r in self.get_all_routes():
      o.append(str(r))
    return "\n".join(o)



class Packet (object):
  ts_function = staticmethod(lambda: core.IPStack.now)

  def __init__ (self, ts=None):
    self.clear_data_pointers()
    self.rx_dev = None
    self.create_ts = ts if ts is not None else self.ts_function()
    self.tx_ts = None
    self.retx_ts = None
    self.timeout_count = 0 # Number of send timeouts
    #TODO: Remove some/all of the timestamps?

  def clone (self):
    p = type(self)(ts=False)
    for k,v in vars(self).items():
      setattr(p, k, v)
    return p

  def clear_data_pointers (self):
    self.eth = None
    self.ipv4 = None
    self.tcp = None
    self.udp = None
    self.icmp = None
    return self

  def __len__ (self):
    """
    Gets length of IP packet (not including Ethernet)
    """
    #NOTE: This is not a great implementation (at all)... we really need
    #      to do some work on the packet library to make this easy/clean.
    #      (It's basically options the dumb-attribute iplen and stuff
    #      which make it hard.)
    self.set_payload()
    return len(self.ipv4.pack())

  def set_payload (self):
    if self.eth is not None and self.eth.next is None:
      self.eth.payload = self.ipv4
    if self.ipv4 is not None and self.ipv4.next is None:
      self.ipv4.payload = self.tcp or self.udp or self.icmp

  def break_payload (self):
    if self.ipv4 is None and self.eth:
      self.ipv4 = self.eth.find("ipv4")

    #FIXME: Do this better by just inspecting .payload
    self.tcp = self.ipv4.find("tcp")
    self.udp = self.ipv4.find("udp")
    self.icmp = self.ipv4.find("icmp")

  def pack (self, force_eth=False, force_ip=False):
    self.set_payload()
    if force_ip: return self.ipv4.pack()
    if self.eth: return self.eth.pack()
    if force_eth:
      e = pkt.ethernet()
      e.payload = self.ipv4
      return e.pack()
    return self.ipv4.pack()

  @property
  def app (self):
    """
    Transport data (application layer) as bytes or None
    """
    r = None
    if self.tcp:
      r = self.tcp.payload
    elif self.udp:
      r = self.udp.payload
    else:
      return None
    if not isinstance(r, bytes):
      r = r.pack()
    return r

  @app.setter
  def app (self, data):
    if not isinstance(data, bytes): data = data.pack()
    if self.tcp: self.tcp.payload = data
    elif self.udp: self.udp.payload = data
    else:
      raise RuntimeError("Can't assign app layer payload to non-tcp/udp")




class Fragment (object):
  def __init__ (self, ts, defragmenter=None):
    self.frags = {} # off -> Packet
    self.assembled = None
    self.failed = False
    self.ts = ts
    self.defragmenter = defragmenter

  def add (self, p):
    self.frags[p.ipv4.frag] = p
    self._try_assemble()

  @property
  def log (self):
    if self.defragmenter:
      return self.defragmenter.stack.log
    return log

  def _try_assemble (self):
    if self.assembled: return
    if self.failed: return
    try:
      data = b''
      first = self.frags[0].ipv4
      length = 0
      # The packet library doesn't store raw data, unfortunately (a long-lived
      # deficiency), so this is sort of hacky, but should work in general.
      if isinstance(first.payload, (pkt.tcp, pkt.udp, pkt.icmp)):
        data = first.payload.pack()
      elif isinstance(first.payload, bytes):
        data = first.payload
      else:
        self.log.warn("Can't reassemble fragments")
        self.failed = True
        return
      cur = first
      while True:
        if cur.iplen <= 8:
          self.failed = True
          return
        length += cur.iplen - (cur.hl * 4)
        nxt = self.frags[length // 8]
        data += nxt.ipv4.payload
        if len(data) > 0xffff:
          self.failed = True
          return
        if nxt.ipv4.flags & nxt.ipv4.MF_FLAG: continue
        break

      copy = pkt.ipv4(raw=first.pack())
      copy.payload = data
      copy = pkt.ipv4(raw=copy.pack())
      p = self.frags[0].clone().clear_data_pointers()
      p.ipv4 = copy
      p.break_payload()
      self.assembled = p
      self.log.debug("Assembled %s fragments", len(self.frags))
    except KeyError as e:
      #self.log.debug("Missing fragment at offset %s", e)
      pass
    except Exception:
      self.log.exception("Exception while defragmenting")
      pass



class Defragmenter (object):
  MAX_AGE = 5
  MAX_FRAGS = 500

  def __init__ (self, stack):
    self.stack = stack
    self.frags = {} # ID -> Fragment

  def rx_fragment (self, p):
    if (p.ipv4.flags & p.ipv4.MF_FLAG) or p.ipv4.frag:
      pass
    else:
      return p

    fid = self.get_id(p)
    if fid not in self.frags:
      if len(self.frags) >= self.MAX_FRAGS:
        self.do_expirations()
        if len(self.frags) >= self.MAX_FRAGS:
          self.stack.log.debug("Too many fragments")
          return None
      self.frags[fid] = Fragment(ts=self.stack.now, defragmenter=self)
    self.frags[fid].add(p)
    r = self.frags[fid].assembled
    if r is not None: del self.frags[fid]
    return r

  @staticmethod
  def get_id (p):
    return (p.ipv4.srcip,p.ipv4.dstip,p.ipv4.protocol,p.ipv4.id)

  def do_expirations (self):
    #TODO: We should send an ICMP time exceeded...
    now = self.stack.now
    def expired (f):
      return now - f.ts > self.MAX_AGE
    bad = [k for k,v in self.frags if expired(v)]
    for k in bad:
      del self.frags[k]
    self.stack.log.debug("Removed %s expired fragments", len(bad))



class IPStack (object):
  SNIFF_EAT = 1     # Bit flag; if sniffer returns it, packet isn't passed on
  SNIFF_REMOVE = 2  # Bit flag; if sniffer returns it, sniffer is removed

  enable_ip_forward = True
  name = None

  def __repr__ (self):
    if self.name:
      return "<%s %s>" % (type(self).__name__, self.name)
    return super(IPStack,self).__repr__()

  def __init__ (self, routing=None, time=None):
    if routing is None: routing = Routing()

    self.log = log

    if time is None:
      self.time = RealTimeManager(timeshift=False)
    else:
      self.time = time

    self.netdevs = {} # name -> NetDev -- do not add manually

    self.routing = routing

    self.arp_table = ARPTable()

    self.defragger = Defragmenter(self)

    self.masq = MasqTable(self)
    def do_masq_expire (skip=False):
      core.call_delayed(60, do_masq_expire)
      if not skip: self.masq._do_expirations()
    do_masq_expire(skip=True)

    self._sniffers = {}
    self._next_sniffer = 1

  def get_netdev (self, name):
    """
    Gets a netdev by name

    The name can actually be a glob pattern.
    If the pattern would match more than one, raises an exception.
    Returns None if none found.
    """
    # Possibly more efficient to use fnmatch.filter(self.netdevs.keys())...
    r = None
    for k,v in self.netdevs.items():
      if fnmatch.fnmatchcase(k, name):
        if r is not None: raise RuntimeError("More than one match")
        r = v
    return r

  def get_netdevs (self, name):
    """
    Gets all netdevs matching a glob pattern
    """
    # Possibly more efficient to use fnmatch.filter(self.netdevs.keys())...
    r = []
    for k,v in self.netdevs.items():
      if fnmatch.fnmatchcase(k, name):
        r.append(v)
    return r

  @property
  def now (self):
    return self.time.now

  def has_ip (self, ip):
    ip = IPAddr(ip)
    for d in self.netdevs.values():
      if d.has_ip(ip): return True
    return False

  def add_netdev (self, netdev):
    if netdev.stack: raise RuntimeError("NetDev already has IP stack")
    self.netdevs[netdev.name] = netdev
    netdev.stack = self

  def lookup_dst (self, addr):
    """
    Returns dev,gateway

    If there's no gateway, returns None
    """
    r = self.routing.lookup_best(addr)
    if not r: return None,None
    gw = r.gw
    if not r.dev_name:
      # Need to find the device based on GW
      if not r.gw:
        self.log.error("Can't use route with no device or gateway")
        return None,None
      r = self.routing.lookup_best(r.gw)
      if not r:
        self.log.error("No route to gateway")
        return None,None
      if not r.dev_name:
        self.log.error("Route doesn't lead to a device")
        return None,None

    return self.netdevs.get(r.dev_name),gw

  def _rx_arp_reply (self, packet, arpp):
    if arpp.opcode != arpp.REPLY: return False
    self.arp_table.rx_arp_reply(arpp)

  def _rx_arp_request (self, packet, arpp):
    netdev = packet.rx_dev
    if not netdev.enable_arp: return False
    if not netdev.is_l2: return False

    if arpp.opcode != arpp.REQUEST: return False
    if arpp.hwtype != arpp.HW_TYPE_ETHERNET: return False
    if arpp.prototype != arpp.PROTO_TYPE_IP: return False
    if arpp.hwlen != 6: return False
    if arpp.protolen != 4: return False
    if not netdev.has_ip_addr(arpp.protodst): return False

    self.arp_table.rx_arp(arpp)

    #TODO: proxy ARP / respond for other interfaces?
    if netdev.ip_addr != arpp.protodst: return False

    # With any luck, other addresses will have been filtered out earlier,
    # but let's double-check.
    if packet.eth.dst.is_broadcast or (netdev.eth_addr == packet.eth.dst):
      pass # Cool
    else:
      return False

    r = pkt.arp()
    r.opcode = r.REPLY
    r.hwdst = arpp.hwsrc
    r.protodst = arpp.protosrc
    r.hwsrc = netdev.eth_addr
    r.protosrc = netdev.ip_addr
    e = pkt.ethernet(type=pkt.ethernet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
    e.payload = r
    netdev.send_raw_l2(e.pack())

  def add_sniffer (self, sniffer):
    """
    Add packet sniff function

    The sniffer is called with the packet as an argument.  It can return bits
    to control what happens afterwards.  If SNIFF_REMOVE is set, the sniffer
    will be removed.  If SNIFF_EAT is set, the packet will not be passed
    to further sniffers or the rest of the networking stack.  Returning
    True is a shortcut for both REMOVE and EAT.  Any other return value
    does neither.

    The return value of this function is a "sniffer handle" which can be
    used to remove the sniffer.

    Note that this is a low-level sniffing mechanism.  A higher-level
    interface involves setting an event handler on a netdev; see
    add_packet_capture() for a nice interface to that.

    This interface may be removed eventually in favor of the high-level one.
    """
    ns = self._next_sniffer
    self._next_sniffer += 1
    self._sniffers[ns] = sniffer
    return ns

  def remove_sniffer (self, sniffer):
    """
    Remove a packet sniffer

    Ideally, the argument is a sniffer handle returned by add_sniffer(), but
    passing in the sniff function works as well (but is slower).
    """
    if isinstance(sniffer, int):
      del self._sniffers[sniffer]
    else:
      for k,s in self._sniffers.items():
        if s is sniffer:
          del self._sniffers[k]
          break

  def add_packet_capture (self, devs, handler, rx=True, tx=False,
                          ip_only=False, eth_only=False):
    """
    Sets up packet capture on one or more devices

    This is a high-level packet capturing API.  See add_sniffer() for a low-
    level API.

    handler is an event handler for CapturedPacketRX or CapturedPacketTX events.
    Set rx or tx or capture only transmitted or received packets.  Received-
    only is the default.
    You can limit to capturing only IP or Ethernet packets.  By default, you
    get both.

    You can pass the return value to remove_packet_capture() to turn off
    capture.

    This method is just a convenience wrapper around the usual revent event-
    listening stuff on each individual NetDev.
    """
    assert rx or tx, "Must capture on either RX, TX or both"
    cap_ip = True
    cap_eth = True
    if ip_only: cap_eth = False
    if eth_only: cap_ip = False
    assert cap_ip or cap_eth, "Must capture either L2, L3, or both"

    if isinstance(devs, str): devs = self.get_netdevs(devs)

    result = []

    for dev in devs:
      if dev.is_l2 and not cap_eth: continue
      if not dev.is_l2 and not cap_ip: continue
      if rx:
        l = dev.addListener(CapturedPacketRX, handler)
        result.append((dev,l))
      if tx:
        l = dev.addListener(CapturedPacketTX, handler)
        result.append((dev,l))

    return result

  def remove_packet_capture (self, caplist):
    """
    Remove packet captures

    The parameter is the return value from add_packet_capture()
    """
    for dev,x in caplist:
      dev.removeListener(x)

  def rx (self, p):
    if p.rx_dev is not None and p.rx_dev.enable_rx is False: return

    dead_snoop = None
    sniff_eat = False
    for k,v in self._sniffers.items():
      r = v(p)
      if r and self.SNIFF_REMOVE:
        if dead_snoop is None: dead_snoop = []
        dead_snoop.append(k)
      if r and self.SNIFF_EAT:
        sniff_eat = True
        break
    if dead_snoop:
      self.log.debug("%s self-removing packet sniffer(s) removed", len(dead_snoop))
      for snoop in dead_snoop:
        del self._sniffers[snoop]
    if sniff_eat: return

    if p.eth:
      if not p.ipv4:
        arpp = p.eth.find("arp")
        if arpp:
          if arpp.opcode == arpp.REQUEST:
            self._rx_arp_request(p, arpp)
          elif arpp.opcode == arpp.REPLY:
            self._rx_arp_reply(p, arpp)
        return

    if p.ipv4:
      if p.ipv4.srcip.is_broadcast or p.ipv4.srcip.is_multicast:
        # Suspicious!
        self.log.warn("Dropping IPv4 packet with src=%s", p.ipv4.srcip)
        return

      try_local_deliver = True

      if p.rx_dev.enable_ip_masquerade:
        if p.rx_dev.has_ip_addr(p.ipv4.dstip):
          p.break_payload() #FIXME: We really should do this elsewhere...
          if self.masq.rewrite_in(p):
            try_local_deliver = False # Forward instead

      if try_local_deliver:
        # Local delivery
        # Try the RX dev first!
        if p.rx_dev.has_ip_addr(p.ipv4.dstip):
          self._local_rx(p.rx_dev, p)
          return
        else:
          # Try all the other devices.  Should we only do this if some
          # flag is set?
          for dev in self.netdevs.values():
            if dev.has_ip_addr(p.ipv4.dstip):
              # Local delivery
              #FIXME: Use a local route?
              self._local_rx(dev, p)
              return

      # Maybe forward it?
      if self.enable_ip_forward:
        if not p.rx_dev.enable_ip_forward_from: return #TODO: ICMP?
        ##r = self.routing.lookup_best(p.ipv4.dst)
        ##if not r: return #TODO: ICMP?

        out_dev,gw = self.lookup_dst(p.ipv4.dstip)

        p.ipv4.ttl -= 1
        if p.ipv4.ttl <= 0:
          self.log.warn("IP packet TTL expired")
          if p.ipv4.dstip.is_broadcast or p.ipv4.dstip.is_multicast:
            # No ICMP for these
            return
          tep = pkt.time_exceed()
          tep.payload = p.ipv4
          icmpp = pkt.icmp(type = pkt.TYPE_TIME_EXCEED, code = 0)
          icmpp.payload = tep
          ipp = pkt.ipv4(srcip = p.ipv4.dstip, dstip = p.ipv4.srcip)
          ipp.protocol = ipp.ICMP_PROTOCOL
          ipp.payload = icmpp
          #r = self.routing.lookup_best(ipp.dstip)
          #p.rx_dev.send(ipp, gw)
          rp = self.new_packet()
          rp.ipv4 = ipp
          rp.icmp = icmpp
          self.send(rp)
          return

        if out_dev is None: return #TODO: ICMP?

        if not out_dev.enable_ip_forward_to: return #TODO: ICMP?

        if out_dev.enable_ip_masquerade:
          if self.masq.rewrite_out(p, out_dev) is False:
            return False

        self.send_to_dev(p, out_dev, gw)

  def send (self, p, set_src=True):
    out_dev,gw = self.lookup_dst(p.ipv4.dstip)
    if not out_dev: return False
    self.send_to_dev(out_dev=out_dev, p=p, set_src=set_src, gw=gw)

  def send_to_dev (self, p, out_dev, gw=None, set_src=True):
    if out_dev.enable_tx is False: return

    if len(p) > out_dev.mtu:
      if p.ipv4 is None:
        self.log.warn("Dropping non-IP packet too big for MTU")
        return
      if p.ipv4.flags and p.ipv4.DF_FLAG:
        self.log.warn("Dropping IP packet too big for MTU with DF set")
        if p.ipv4.protocol == p.ipv4.ICMP_PROTOCOL:
          if p.ipv4.find("icmp").type == pkt.TYPE_DEST_UNREACH: return
        payload = p.ipv4.pack()
        payload = payload[:p.ipv4.hl * 4 + 8]
        unreachp = pkt.unreach()
        unreachp.next_mtu = out_dev.mtu
        unreachp.payload = payload
        icmpp = pkt.icmp()
        icmpp.type = pkt.TYPE_DEST_UNREACH
        icmpp.code = pkt.CODE_UNREACH_FRAG
        icmpp.payload = unreachp
        ipp = pkt.ipv4()
        if not out_dev.ip_addr:
          self.log.error("Can't send ICMP message from nowhere; faking it")
          ipp.srcip = p.ipv4.dstip
        else:
          ipp.srcip = out_dev.ip_addr
        ipp.dstip = p.ipv4.srcip
        ipp.payload = icmpp
        ipp.protocol = ipp.ICMP_PROTOCOL
        pp = self.new_packet()
        pp.ipv4 = ipp
        self.send(pp)
        return
      # We should fragment
      #FIXME: We currently copy all options to subsequent fragments.  We
      #       should actually only copy them if the high bit in the
      #       option type field is set.
      payload = p.ipv4.payload.pack()
      ipraw = p.ipv4.pack()
      payload_size = (out_dev.mtu - p.ipv4.hl * 4) & ~7
      if payload_size == 0:
        self.log.error("Fragment payload size would be zero")
        return
      frags = 0
      offset = 0
      while payload:
        part = payload[:payload_size]
        payload = payload[payload_size:]
        pp = self.new_packet()
        pp.ipv4 = pkt.ipv4(raw=ipraw)
        pp.ipv4.frag = offset // 8
        if payload:
          pp.ipv4.flags |= pp.ipv4.MF_FLAG
        pp.ipv4.payload = part
        self.send(pp, set_src)
        frags += 1
        offset += len(part)
      self.log.debug("Split packet into %s fragments", frags)
      return

    if set_src and p.ipv4 is not None and p.ipv4.srcip == IP_ANY:
      if not out_dev.ip_addr:
        self.log.warn("Can't set outgoing IP address for %s", out_dev)
        return
      p.ipv4.srcip = out_dev.ip_addr

    out_dev.send(p, gw)
    return True

  def _local_rx (self, dev, p):
    if p.ipv4.checksum() != p.ipv4.csum:
      self.log.warn("Packet checksum failed")
      return
    p = self.defragger.rx_fragment(p)
    if not p: return

    udpp = p.ipv4.find("udp")
    if udpp:
      p.udp = udpp
      self._local_rx_udp(dev, p)
      return
    tcpp = p.ipv4.find("tcp")
    if tcpp:
      p.tcp = tcpp
      self._local_rx_tcp(dev, p)
      return
    icmpp = p.ipv4.find("icmp")
    if icmpp:
      p.icmp = icmpp
      self._local_rx_icmp(dev, p)

  socket_manager = None #XXX

  def _local_rx_icmp (self, dev, p):
    if p.icmp.type == pkt.TYPE_ECHO_REQUEST:
      # Make the ping reply
      icmpp = pkt.icmp()
      icmpp.type = pkt.TYPE_ECHO_REPLY
      icmpp.payload = p.icmp.payload

      # Make the IP packet around it
      ipp = pkt.ipv4(srcip = p.ipv4.dstip, dstip = p.ipv4.srcip)
      ipp.protocol = ipp.ICMP_PROTOCOL
      ipp.payload = icmpp

      rp = self.new_packet()
      rp.ipv4 = ipp
      rp.icmp = icmpp

      self.send(rp)
    elif (p.icmp.type == pkt.TYPE_ECHO_REPLY
          and isinstance(p.icmp.payload, pkt.echo)):
      # As hack, we encode the timestamp in the payload.
      # When we have real support for ICMP (like ICMP sockets), we can
      # get rid of this.
      delay = "?"
      try:
        payload = p.icmp.payload.payload
      except Exception:
        payload = str(p.icmp.payload)
      if payload.startswith("PXIP"):
        # Might have the encoded ts
        import struct
        try:
          delay = struct.unpack("d", payload[4:4+8])[0]
          delay = self.now - delay
          delay = int(delay * 1000) # ms
        except Exception:
          raise
          pass
      self.log.info("Pong %s->%s seq:%s bytes:%s ttl:%s time:%sms",
                    p.ipv4.srcip, p.ipv4.dstip, p.icmp.payload.seq,
                    len(p.icmp.payload.payload), p.ipv4.ttl, delay)
    else:
      self.log.warn("Got unhandled ICMP: %s", p.icmp.dump())

  def _local_rx_udp (self, dev, p):
    pass

  def _local_rx_tcp (self, dev, p):
    """
    Receive a TCP packet

    dev is the interface with the corresponding IP address, which may
    not be the interface the packet actually arrived on
    """
    if self.socket_manager: self.socket_manager.rx(dev, p)

  def new_packet (self, *args, **kw):
    return Packet(ts = self.now)

  def add_route (self, prefix, gw=None, dev=None, metric=1):
    """
    Just a quick helper to add routes
    """
    assert gw or dev
    prefix = str(prefix)
    if "/" not in prefix:
      size = 32
    else:
      prefix,size = prefix.split("/")
      size = int(size)
    metric = int(metric)
    if gw: gw = IPAddr(gw)
    prefix = IPAddr(prefix)

    if isinstance(dev, NetDev):
      dev = dev.name

    r = Route(prefix, size, metric, gw, dev)

    self.routing.add(r)

    return r



# The following stuff is all for if you want to run the IPStack as a component

def _register_stack ():
  if not hasattr(core, "IPStack"):
    core.registerNew(IPStack)

def tap (ip, dev='', __INSTANCE__=None):
  _register_stack()
  d = TapDev(dev, tun=False, ip_addr=ip)
  core.IPStack.add_netdev(d)

def tun (ip, dev='', __INSTANCE__=None):
  _register_stack()
  d = TunDev(dev, tun=True, ip_addr=ip)
  core.IPStack.add_netdev(d)

def pcap (ip, dev, __INSTANCE__=None):
  _register_stack()
  d = PCapDev(dev, ip_addr=ip)
  core.IPStack.add_netdev(d)

def add_route (prefix, gw=None, dev=None, metric=1, __INSTANCE__=None):
  _register_stack()
  core.IPStack.add_route(prefix, gw, dev, metric)
