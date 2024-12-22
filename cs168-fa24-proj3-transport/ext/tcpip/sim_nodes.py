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
Nodes used by the simulator (or at least their base types)
"""

from pox.core import core
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
from . ip_stack import IPStack
import struct
from . recoco_sockets import RecocoSocketManager, DataLogger, FastSender, BasicStateTransServer
from . small_services import *
from weakref import WeakSet
from . import tcp_sockets
import socket


log = core.getLogger()



class Node (object):
  topo = None
  stack = None
  trace = False

  def __init__ (self, name):
    self.name = name
    self.stack = IPStack(time=False)
    # We set time to False to force it to be nothing for the moment (and keep
    # IPStack from creating a default TimeManager).  When the node is added
    # to the Topology, Topology sets the stack's .time.
    self.stack.name = name
    self.stack.log = core.getLogger(name).getChild("stack")

    # Function that should make a new usocket given a Node
    self.new_usocket = (lambda node:
                        tcp_sockets.Socket(node.stack.socket_manager))

    # This may get filled in later
    self.recoco_socket_manager = None

    self.apps = WeakSet() # Just to keep track of them

  def resocket (self, domain=socket.AF_INET, type=socket.SOCK_STREAM):
    """
    Returns a new RecocoSocket for this Node
    """
    # We currently only support INET STREAM sockets (TCP)
    assert domain == socket.AF_INET
    assert type == socket.SOCK_STREAM

    if self.recoco_socket_manager is None:
      f = lambda rsm: self.new_usocket(self)
      self.recoco_socket_manager = RecocoSocketManager(self.stack,
                                                       usocket_factory=f)
    return self.recoco_socket_manager.socket()

  @property
  def netdev (self):
    """
    Returns a netdev (one with an IP if possible)
    """
    r = None
    for d in self.stack.netdevs.values():
      if d.ip_addr: return d
      r = d
    return r

  @property
  def log (self):
    return self.stack.log

  def __repr__ (self):
    return "<%s %s>" % (type(self).__name__, self.name)

  @property
  def trace_all (self):
    return Node.trace
  @trace_all.setter
  def trace_all (self, v):
    Node.trace = v

  def _write (self, packet):
    if packet.ipv4:
      if self.trace or self.trace_all:
        # Currently IP only!
        self.log.debug(packet.ipv4.dump())

  def _do_simnetdev_rx (self, p):
    self._write(p)
    self.stack.rx(p)

  def _new_resocket_app (self, app, ip=None, port=None, listen=False, delay=0,
                         **kw):
    if listen is False:
      assert ip is not None
      assert port is not None
      ip = IPAddr(ip)
      # Convert port to int?
    else:
      assert port is not None
      port = int(port)
    o = app(socket=self.resocket(), ip=ip, port=port, listen=listen,
            connect_delay=delay, **kw)
    self.apps.add(o)
    return o

  def new_data_logger (self, ip=None, port=None, listen=False, delay=0):
    return self._new_resocket_app(DataLogger, ip=ip, port=port, listen=listen,
                                  delay=delay)

  def new_echo (self, ip=None, port=None, listen=False, delay=0):
    return self._new_resocket_app(Echo, ip=ip, port=port, listen=listen,
                                  delay=delay)

  def new_fast_sender (self, data, delay=0, ip=None, port=None, listen=False):
    return self._new_resocket_app(FastSender, bytes=data, ip=ip, port=port,
                                  listen=listen, delay=delay)

  def new_basic_state_trans (self, ip=None, port=None, listen=False, delay=0):
    return self._new_resocket_app(BasicStateTransServer, ip=ip, port=port,
                                  listen=listen, delay=delay)
  def nc (self, ip=None, port=None, listen=False, no_console=False, **kw):
    return self._new_resocket_app(NetCat, ip=ip, port=port, listen=listen,
                                  no_console=no_console, **kw)
  netcat = nc # Alias

  def start_small_services (self):
    """
    Start the small services
    """
    for s in [Echo, Discard, Daytime, CharGen, TimeServer, QuoteOfTheDay]:
      self._new_resocket_app(s, listen=True, port=s.default_listen_port)

  def ping (self, ip, count=1, interval=1, ttl=63, size=56, df=False):
    #TODO: Move some or all of this to IPStack?  It's so useful...
    ip = IPAddr(ip)

    s = "abcdefghijklmnopqrstuvwxyz"
    s += s.upper()
    s += "0123456789"

    def make_payload (px_timestamp=True):
      p = ""
      for i in xrange(size):
        p += s[i % len(s)]

      if px_timestamp and size > (4+8):
        p = "PXIP" + struct.pack("d", self.stack.now) + p[:-12]
      return p

    # Look it up...

    def send_ping (c,seq,eid=None):
      icmpp = pkt.icmp(type = pkt.TYPE_ECHO_REQUEST, code = 0)
      echop = pkt.echo()
      icmpp.payload = echop
      echop.payload = make_payload()
      echop.seq = seq
      if eid is not None: echop.id = eid
      ipp = pkt.ipv4(dstip = ip)
      ipp.protocol = ipp.ICMP_PROTOCOL
      if df: ipp.flags = ipp.flags | ipp.DF_FLAG
      ipp.payload = icmpp
      #r = self.routing.lookup_best(ipp.dstip)
      #p.rx_dev.send(ipp, gw)
      rp = self.stack.new_packet()
      rp.ipv4 = ipp
      rp.icmp = icmpp
      self.stack.send(rp)
      self.log.debug("Ping %s->%s seq:%s bytes:%s ttl:%s",
                     rp.ipv4.srcip, rp.ipv4.dstip, echop.seq,
                     len(echop.payload), rp.ipv4.ttl)

      if c <= 1: return
      self.topo.set_timer_in(interval, send_ping, c-1, seq+1, echop.id)

    send_ping(count, 0)



import sys
import pox.lib.revent as revent
from . import recoco_sockets
from pox.lib.recoco import task_function

class NetCat (recoco_sockets.SimpleReSocketApp):
  """
  NetCat for the POX console

  This is *not* a particularly clean solution, but it lets you communicate
  either via a .send() method or via the console.  It uses the console by
  default, but pass in no_console=True to the constructor to do without it.

  Pass in raw_mode=True to output directly to stdout instead of outputting
  complete lines via a logger.

  Pass in data=bytes to send some data and then quickly disconnect.
  """

  end_sequence = "+++"
  netcat_done = False
  raw_mode = False

  def __init__ (self, *args, **kw):
    self.no_console = kw.pop("no_console", False)
    self.raw_mode = kw.pop("raw_mode", self.raw_mode)
    self.send_data = kw.pop("data", None)
    super(NetCat,self).__init__(*args, **kw)

  @property
  def log (self):
    if self._log:
      return self._log
    elif self.sock and self.sock.usock and self.sock.usock.is_peered:
      n = "%s:%s<->%s:%s" % (self.sock.name[0], self.sock.name[1], self.sock.peer[0], self.sock.peer[1])
      self._log = core.getLogger("netcat").getChild(n)
      return self._log
    return super(NetCat,self).log

  @task_function
  def _on_connected (self):
    if self.send_data is not None:
      self.log.info("NetCat connected.  Sending %s bytes of data."
                    % len(self.send_data))
      yield self.sock.send(self.send_data)
      self.sock.stack.time.set_timer_in(0.1, self.close)
    elif self.no_console:
      self.log.info("NetCat connected.  Use _.send('data') to send.")
    else:
      core.Interactive.add_listener(self._handle_SourceEntered)
      self.log.info("NetCat connected.  Enter '%s' on an empty line to exit.",
                    self.end_sequence)
    if self.raw_mode:
      while True:
        d = yield self.sock.recv(1, at_least=True)
        if not d: break
        sys.stdout.write(d)
    else:
      data = b''
      while True:
        d = yield self.sock.recv(1, at_least=True)
        if not d:
          # Log any final data
          if data:
            self.log.info("NetCat: " + data)
          break
        data += d
        while '\n' in data:
          first,data = data.split("\n",1)
          if not first: continue # Don't print blank lines
          self.log.info("NetCat: " + first)

    self.log.info("Connection closed")
    self.netcat_done = True

  def close (self):
    self.netcat_done = True
    try:
      self.sock.usock.close()
    except Exception:
      pass

  def send (self, data):
    data += "\n"
    sent = self.sock.usock.send(data)
    if sent != len(data):
      self.log.error("%s of %s bytes sent", sent, len(data))

  def _handle_SourceEntered (self, event):
    if self.netcat_done:
      return revent.EventRemove
    src = event.source.encode("utf8")
    event.source = None
    if src == self.end_sequence:
      self.close()
      self.netcat_done = True
      return revent.EventHaltAndRemove
    try:
      self.send(src)
    except Exception:
      self.log.error("Error sending data")
      self.close()
      self.netcat_done = True
      return revent.EventHaltAndRemove
    return revent.EventHalt
