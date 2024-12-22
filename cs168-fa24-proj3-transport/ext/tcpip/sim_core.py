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
The simulator core
"""

from pox.core import core

import time
import datetime
from . time_manager import RealTimeManager, VirtualTimeManager
from . tcp_socket_manager import TCPSocketManager

from . units import *

from . queues import SimpleQueue, Queue
from . wires import SimpleWire, Wire
from . netdev import NetDev, CapturedPacketTX, CapturedPacketRX
from . sim_nodes import Node
from . ip_stack import Route

import pox.lib.packet as pkt

log = core.getLogger()



class SimNetDev (NetDev):
  """
  NetDev for use with simulator

  As far as IPStack is concerned, this is an L3 NetDev.
  As far as the simulator is concerned, it's a Wire.
  """
  # Does this belong in sim_core?

  #enable_ip_forward_from = True
  #enable_ip_forward_to = True

  mtu = 1500

  node = None # The Node we're installed on
  #dst = None # Remote Node we're connected to
  dst_dev = None # NetDev on dst that we're connected to
  name = None

  #TODO: Remove this capture proc stuff and replace with new
  #      CapturedPacket events?  The main difference at the
  #      moment is that the capture_procs can kill packets.
  tx_capture_proc = None # f(dev,is_rx,raw,parsed)
  rx_capture_proc = None # f(dev,is_rx,raw,parsed)

  @property
  def topo (self):
    return self.node.topo

  def __repr__ (self):
    return "<%s %s-%s>" % (type(self).__name__, self.node, self.dst_dev.node)

  def send (self, packet, gw):
    """
    TX packet to another SimNetDev
    """
    if packet.ipv4 is None: return
    packet.set_payload()
    raw = packet.ipv4.pack()
    if len(raw) > self.mtu:
      self.node.log.warn("TX drop for oversize packet")
      return
    ip = pkt.ipv4(raw = raw) # Copy it

    queue = self.topo.get_queue(self,self.dst_dev)
    if queue is None:
      self.node.log.error("No queue for %s<->%s", self, self.dst_dev)
      return
    if self.tx_capture_proc: self.tx_capture_proc(self,False,raw,ip)
    self.raiseEvent(CapturedPacketTX, self, ip, raw, True)
    queue.enqueue(ip)

  def rx (self, packet, src):
    """
    RX packet from another SimNetDev
    """
    if self.stack:
      p = self.stack.new_packet()
      p.rx_dev = self
      p.ipv4 = packet
      p.break_payload()
      if self.rx_capture_proc: self.rx_capture_proc(self,True,None,packet)
      self.raiseEvent(CapturedPacketRX, self, packet, None, True)
      self.node._do_simnetdev_rx(p)

  @classmethod
  def new_pair (cls, n1, n2):
    """
    Make a new pair of connected devs
    """
    i1 = cls(n1)
    i2 = cls(n2)
    #i1.dst = n2
    #i2.dst = n1
    i1.dst_dev = i2
    i2.dst_dev = i1
    i1.name = "<%s %s<->%s>" % (cls.__name__, n1, n2)
    i2.name = "<%s %s<->%s>" % (cls.__name__, n2, n1)

    n1.stack.add_netdev(i1)
    n2.stack.add_netdev(i2)

    return i1,i2

  def __init__ (self, node, **kw):
    """
    Usually you don't call this directly; use new_pair() instead.
    """
    self.node = node
    super(SimNetDev,self).__init__(**kw)



def make_factory (topo, cls, *args, **kw):
  """
  Simple factory-generator for queues and wires

  Queues and Wires both share the same pattern for initialization.
  This is a simple factory-generator to initialize them.
  """
  def factory (src, dst):
    o = cls(*args, **kw)
    o.src = src
    o.dst = dst
    o.topo = topo
    return o
  return factory



class TopologyBase (object):
  timestamp = None # For filenames
  started = False

  def __init__ (self):
    self.nodes = set()
    self.queues = {} # (src_node,dst_node) -> Queue
    self.wires = {} # (src_node,dst_node) -> Wire

    self.default_queue_factory = make_factory(self, SimpleQueue)
    self.default_wire_factory = make_factory(self, SimpleWire)

  def make_factory (self, *args, **kw):
    return make_factory(self, *args, **kw)

  def get_node (self, name):
    for n in self.nodes:
      if n.name == name: return n
    return n

  def _do_routing (self, force=False):
    # Hilariously bad shortest path routing

    if not (self.started or force): return # Don't bother yet

    def share_routes (srcdev, dstdev, wire):
      changed = False
      drt = dstdev.stack.routing
      routes = srcdev.stack.routing.get_all_routes()

      # Add in a route for the srcdev itself if it has an IP...
      if srcdev.ip_addr is not None:
        routes.append(Route(srcdev.ip_addr, 32, 0, None))

      for r in routes:
        if not r.exportable: continue

        # This next line is ugly...
        r2 = drt.tables[r.size].get(r.prefix)
        metric = r.metric + wire.max_latency
        if metric == r.metric: metric += Epsilon
        if not r2 or (r2 and r2[0].metric > metric):
          if r.size == 32 and r.prefix == dstdev.ip_addr: continue
          nr = Route(r.prefix, r.size, metric, dev_name=dstdev.name)
          drt.add(nr)
          changed = True
      return changed

    rounds = 0
    while True:
      rounds += 1
      changed = False
      for (a,b),wire in self.wires.items():
        c1 = share_routes(a, b, wire)
        c2 = share_routes(b, a, wire)
        if c1 or c2: changed = True
      if not changed: break
    log.debug("Routing completed in %s rounds", rounds)

  def _reset (self, n):
    """
    Reset a node between simulations
    """
    pass

  def start (self, duration = None):
    self.started = True
    self._do_routing(True)

    if duration is not None:
      self.set_timer_at(duration, self.halt)

    for n in self.nodes:
      self._reset(n)

    ts = datetime.datetime.now().isoformat()
    ts = ts.replace("T", "_").rsplit(".",1)[0]
    self.timestamp = ts

  def halt (self):
    raise NotImplementedError()

  def add_node (self, n, s=None):
    """
    Add host node n

    If s is specified, wire n to s using default wire/queue
    """
    self.nodes.add(n)
    n.topo = self

    #FIXME: This next bit of initializing stack stuff really doesn't belong
    #       here.  It should be in Node or something.  But the sequence of
    #       initializations and the constructor parameters all need to be
    #       redone.
    n.stack.time = self.time
    tcp = TCPSocketManager(n.stack)

    d1 = d2 = None
    if s is not None:
      d1,d2 = self.add_link(n, s)
    return n,d1,d2

  def add_link (self, n1, n2):
    """
    Adds netdevs, queues, and links

    Returns netdevs
    """
    d1,d2 = SimNetDev.new_pair(n1, n2)
    self.set_queue(d1, d2)
    self.set_wire(d1, d2)
    return d1,d2

  def get_devs (self, n1, n2):
    """
    For a pair of nodes, return connecting netdevs
    """
    for d1 in n1.stack.netdevs.values():
      if isinstance(d1, SimNetDev):
        if d1.dst_dev and d1.dst_dev.node is n2:
          return d1,d1.dst_dev
    return None,None

  def set_queue (self, n1, n2, factory1 = None, factory2 = None):
    """
    Adds a queue between two nodes

    If you do not specify a factory, a default wire is created.
    If you use True as a factory, it means use the default.
    If you specify False as a factory, it means *don't create that wire*.
    If you specify just one of either factory1 or factory2, then that
    factory is used *for both directions*.

    The naming is unfortunate, but factory1 and factory2 can also be not
    factories, but actual queues.
    """
    if isinstance(n1, str): src,dst = self.get_node(src),self.get_node(dst)
    if isinstance(n1, Node): n1,n2 = self.get_devs(n1,n2)
    assert n1 is not None and n2 is not None

    if factory1 is None and factory2 is None:
      factory1 = self.default_queue_factory
      factory2 = self.default_queue_factory
    elif factory1 is None and factory2:
      factory1 = factory2
    elif factory2 is None and factory1:
      factory2 = factory1

    if factory1 is True: factory1 = self.default_queue_factory
    if factory2 is True: factory2 = self.default_queue_factory

    if factory1 is not False:
      if not isinstance(factory1, Queue): factory1 = factory1(n1,n2)
      self.queues.pop((n1,n2), None) # Is this necessary?
      self.queues[n1,n2] = factory1
    if factory2 is not False:
      if not isinstance(factory2, Queue): factory2 = factory2(n2,n1)
      self.queues.pop((n2,n1), None) # Is this necessary?
      self.queues[n2,n1] = factory2

    return (factory1,factory2)

  def set_wire (self, n1, n2, factory1 = None, factory2 = None):
    """
    Adds a wire between two nodes

    If you do not specify a factory, a default wire is created.
    If you use True as a factory, it means use the default.
    If you specify False as a factory, it means *don't create that wire*.
    If you specify just one of either factory1 or factory2, then that
    factory is used *for both directions*.

    The naming is unfortunate, but factory1 and factory2 can also be not
    factories, but actual wires.
    """
    if isinstance(n1, str): src,dst = self.get_node(src),self.get_node(dst)
    if isinstance(n1, Node): n1,n2 = self.get_devs(n1,n2)
    assert n1 is not None and n2 is not None

    if factory1 is None and factory2 is None:
      factory1 = self.default_wire_factory
      factory2 = self.default_wire_factory
    elif factory1 is None and factory2:
      factory1 = factory2
    elif factory2 is None and factory1:
      factory2 = factory1

    if factory1 is True: factory1 = self.default_wire_factory
    if factory2 is True: factory2 = self.default_wire_factory

    if factory1 is not False:
      if not isinstance(factory1, Wire): factory1 = factory1(n1,n2)
      self.wires.pop((n1,n2), None) # Is this necessary?
      self.wires[n1,n2] = factory1
    if factory2 is not False:
      if not isinstance(factory2, Wire): factory2 = factory2(n2,n1)
      self.wires.pop((n2,n1), None) # Is this necessary?
      self.wires[n2,n1] = factory2

    self._do_routing()

    return (factory1,factory2)

  def _make_default_queue (self, src, dst):
    """
    Can be overridden to change default queue generation
    """
    return self.default_queue_factory(src, dst)

  def _make_default_wire (self, src, dst):
    """
    Can be overridden to change default wire generation
    """
    return self.default_wire_factory(src, dst)

  def get_queue (self, src, dst):
    if isinstance(src, str): src,dst = self.get_node(src),self.get_node(dst)
    if isinstance(src, Node): src,dst = self.get_devs(src,dst)
    if (src,dst) not in self.queues:
      log.warn("Using default queue for %s<->%s (you should probably specify "
               "this yourself!)", src, dst)
      self.queues[src,dst] = self._make_default_queue(src, dst)

    return self.queues[src,dst]

  def get_wire (self, src, dst):
    if isinstance(src, str): src,dst = self.get_node(src),self.get_node(dst)
    if isinstance(src, Node): src,dst = self.get_devs(src,dst)
    return self.wires[src,dst]

  def set_timer_in (self, t, f, *args, **kw):
    raise NotImplementedError()
  def set_timer_at (self, t, f, *args, **kw):
    raise NotImplementedError()
  @property
  def now (self):
    raise NotImplementedError()
  def resleep (self, t):
    raise NotImplementedError()



class Topology (TopologyBase):
  def set_timer_in (_self, *_args, **_kw):
    return _self.time.set_timer_in(*_args,**_kw)

  def set_timer_at (_self, *_args, **_kw):
    return _self.time.set_timer_at(*_args,**_kw)

  def resleep (self, t):
    return self.time.resleep(t)

  def halt (self):
    if self.is_virtual_time:
      return self.time.halt()
    else:
      core.quit()

  @property
  def is_virtual_time (self):
    return isinstance(self.time, VirtualTimeManager)

  def __init__ (self, virtual_time, *args, **kw):
    if virtual_time:
      self.time = VirtualTimeManager()
    else:
      self.time = RealTimeManager(timeshift=True)
    super(Topology,self).__init__(*args, **kw)

  def start (self, *args, **kw):
    #FIXME: Can we always use the same order or do we need the special cases?
    def start ():
      log.info("Starting simulation")
      self.time.start()
    #if not self.is_virtual_time: self.time.start()
    r = super(Topology,self).start(*args, **kw)
    #if self.is_virtual_time: self.time.start()
    core.call_delayed(0.5,start)
    return r

  @property
  def now (self):
    return self.time.now



class RealtimeTopology (Topology):
  def __init__ (self, *args, **kw):
    super(RealtimeTopology,self).__init__(False, *args, **kw)



class VirtualtimeTopology (Topology):
  def __init__ (self, *args, **kw):
    super(VirtualtimeTopology,self).__init__(True, *args, **kw)
