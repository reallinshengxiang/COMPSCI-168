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
Socket manager

The socket layer requires some bookkeeping, like finding unused ports, etc.
SocketManager takes care of this, interfacing with an actual transport
implementation.
"""

#TODO: Currently this is TCP-only.  We either need to extend it to handle UDP
#      too, or we need a UDP SocketManager equivalent.

from pox.core import core
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr, IP_ANY
import random
from . import tcp_sockets

log = core.getLogger()



class TCPSocketManager (object):
  EPHEMERAL_RANGE = (49152, 61000)
  TIMER_GRANULARITY = 0.1001 # sec

  deterministic = False

  stack = None

  def __init__ (self, stack=None):
    self.random = random.Random()
    self.unpeered = {} # (local_ip,local_port)->Socket
    self.peered = {} # (l_ip,l_port),(r_ip,r_port)->Socket
    if stack:
      self.install(stack)

  def install (self, stack):
    if self.deterministic:
      self.random.seed(str(stack))
    self.stack = stack
    assert not stack.socket_manager
    stack.socket_manager = self

    # Jitter the timer startup
    time_start = self.random.random() * self.TIMER_GRANULARITY * 0.5
    self.stack.time.set_timer_in(time_start, self._do_timers)

  def _do_timers (self):
    for s in list(self.peered.values()):
      s._do_timers()
    for s in list(self.unpeered.values()):
      s._do_timers()
    self.stack.time.set_timer_in(self.TIMER_GRANULARITY, self._do_timers)

  def get_unused_port (self, ip):
    """
    Finds an unused local port number for the given local IP
    """
    # Congratulations, you've found awful code.  As a reward, you can fix it.
    assert isinstance(ip, IPAddr)
    names = set(n for n,_ in self.peered.keys())
    names.update(self.unpeered.keys())
    if ip == IP_ANY: names = set([(IP_ANY,p) for _,p in names])
    for _ in range(10000):
      p = self.random.randint(*self.EPHEMERAL_RANGE)
      if (ip, p) not in names:
        return p
    return None

##  def _find_socket (self, name=(None,None), peer=(None,None), state=None):
##    s = self.sockets.get((name,peer))
##    if s and (state is None or s.state is state): return s
##    s = self.sockets.get(name)
##    if s and (state is None or s.state is state): return s
##    n = (IP_ANY,name[1])
##    s = self.sockets.get(n)
##    if s and (state is None or s.state is state): return s
##
##  def _has_socket (self, socket):
##    return self._has_or_remove_socket(socket, False)

  def _remove_socket (self, socket):
    if self._has_or_remove_socket(socket, True):
      log.debug("Removed socket %s", socket)
      return True
    return False

  def _has_or_remove_socket (self, socket, remove):
    name,peer = socket.name,socket.peer
    s = self.peered.get((name,peer))
    if s is socket:
      if remove: self.peered.pop((name,peer),None)
      return True
    s = self.unpeered.get(name)
    if s is socket:
      if remove: self.unpeered.pop(name,None)
      return True
    n = (IP_ANY,name[1])
    s = self.unpeered.get(n)
    if s is socket:
      if remove: self.unpeered.pop(n,None)
      return True
    return False

  def register_socket (self, socket):
    """
    Called when we need to be aware of socket

    This may represent a change in socket state from unpeered to peered.
    (The reverse should never happen!)
    """
    assert socket.is_bound

    if socket.is_peered:
      s = self.peered.get((socket.name,socket.peer))
      if s is socket:
        # Already registered!
        return
      elif s is not None:
        raise PSError("Address in use")

      # Remove self from unpeered
      n = socket.name
      s = self.unpeered.get(n)
      n2 = (IP_ANY,socket.name[1])
      s2 = self.unpeered.get(n2)
      if s is socket: del self.unpeered[n]
      if s2 is socket: del self.unpeered[n2]

      # Register it
      self.peered[(socket.name,socket.peer)] = socket

    else: # unpeered
      n = socket.name
      s = self.unpeered.get(n)
      n2 = (IP_ANY,socket.name[1])
      s2 = self.unpeered.get(n2)
      is_any = n == n2

      if not is_any:
        assert s2 is not s
        if s is socket:
          # Already registered
          return
        elif s is not None or s2 is not None:
          raise PSError("Address in use")

        self.unpeered[socket.name] = socket
      else: # Bind to any
        if s is socket:
          # Already registered
          return

        # Not optimal, but straightforward
        for n2,s2 in self.unpeered.items():
          if n2[1] == n[1]:
            raise PSError("Address in use")

        self.unpeered[socket.name] = socket

  def unregister_socket (self, socket):
    """
    Called when we no longer need to be aware of socket
    """
    self._remove_socket(socket)

  def tx (self, p):
    if self.stack: self.stack.send(p)

  def rx (self, dev, p):
    l = p.ipv4.dstip,p.tcp.dstport
    r = p.ipv4.srcip,p.tcp.srcport
    s = self.peered.get((l,r))
    if s: return s.rx(p)
    s = self.unpeered.get(l)
    if s and s.state is tcp_sockets.LISTEN: return s.rx(p)
    s = self.unpeered.get((IP_ANY,l[1]))
    if s and s.state is tcp_sockets.LISTEN: return s.rx(p)

    # Nobody home.  Send a RST
    log.debug("No connection for %s:%s<->%s:%s", l[0],l[1],r[0],r[1])

    rp = self.stack.new_packet()
    rp.ipv4 = pkt.ipv4(srcip = l[0], dstip = r[0])
    rp.ipv4.protocol = pkt.ipv4.TCP_PROTOCOL
    rp.tcp = pkt.tcp(srcport = l[1], dstport = r[1])

    rp.ipv4.payload = rp.tcp

    if p.tcp.ACK: rp.tcp.seq = p.tcp.ack
    rp.tcp.ack = (p.tcp.seq + tcp_sockets.tcplen(p.tcp)) & 0xffFFffFF
    rp.tcp.ACK = True
    rp.tcp.RST = True
    self.tx(rp)



def launch ():
  core.registerNew(TCPSocketManager)
  def _handle_GoingUpEvent (e):
    core.TCPSocketManager.install(core.IPStack)

  core.add_listener(_handle_GoingUpEvent)



def test (ip="172.16.0.2", port=20202):
  def up (e):
    log.debug("Starting socket test")
    s = Socket(core.TCPSocketManager)
    s.connect(IPAddr(ip), int(port))
    #s.state = SYN_RECEIVED
  core.addListenerByName("UpEvent", up)
