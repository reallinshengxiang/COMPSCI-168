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
SOCKS Proxy Server using ReSockets.

This implements the far side of a SOCKS proxy server using ReSockets.
The purpose of this is that you can run a normal application (say, a web
browser), and have it connect to a proxy server where the near side uses
OS sockets, but the far side uses ReSockets, thus letting you run
normal apps through a Python TCP stack.  If the Python TCP stack is then
bridged to the real world via a tun, tap, or pcap NetDev, then you can
use a normal application to access the normal Internet via Python
TCP socket implementations.
"""

from pox.lib.recoco import Task, task_function
from tcpip.recoco_sockets import ReSocketError
from pox.core import core
import socket
import struct
from socks_proxy import SOCKSFar, SOCKSServer
from pox.lib.addresses import IPAddr


class RecocoSOCKSFar (SOCKSFar):
  """
  This is the side of a SOCKS connection facing away from the requester
  """
  @task_function
  def connect (self, version, ip, port, domain):
    self.socket = self.server.node.resocket(socket.AF_INET, socket.SOCK_STREAM)

    try:
      yield self.socket.connect(IPAddr(ip), port)
    except ReSocketError as e:
      yield False

    self.start()
    yield True

  @task_function
  def send (self, data):
    # Far send
    if self._done: yield None
    try:
      yield (yield self.socket.send(data, timeout=self.TIMEOUT))
    except Exception:
      self.log.exception("While sending to far side")
      yield None

  def run (self):
    sock = self.socket

    self.log.debug("Far side starting to proxy")

    while core.running and not self._done:
      data = yield sock.recv(1, at_least=True, timeout=self.TIMEOUT)
      if not data: break
      self.log.debug("Far side read %s bytes", len(data))
      while data:
        r = yield self.near_side.send(data)
        if r is None:
          self._done = True
          break
        data = data[r:]

    self.near_side.shutdown(socket.SHUT_RDWR)
    self._close_exit()

  def shutdown (self, flags):
    try:
      self.socket.usock.shutdown(flags)
    except Exception:
      pass

  def _close_exit (self):
    self.log.debug("Far side done")
    if self._done: return
    try:
      self._done = True
      s = self.socket.usock
      s.shutdown(socket.SHUT_RDWR)
      s.close()
    except Exception:
      pass



class RecocoSOCKSServer (SOCKSServer):
  TIMEOUT = 5

  def __init__ (self, node, local_ip="0.0.0.0", port=1080):
    super(RecocoSOCKSServer,self).__init__(local_ip=local_ip, port=port)
    self.node = node

  def new_far_side (self, near_side):
    return RecocoSOCKSFar(self, near_side)



def launch (node):
  def _handle_UpEvent (e):
    n = core.sim_topo.get_node(node)
    t = RecocoSOCKSServer(n)
    t.start()
  core.add_listener(_handle_UpEvent)
