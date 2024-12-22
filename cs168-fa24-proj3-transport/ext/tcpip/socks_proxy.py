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
A SOCKS proxy server

This currently implements the SOCKS 4 and SOCKS4a proxy server protocols.
At present, only CONNECT is supported; not BIND.

A given SOCKS proxy session consists of instances of two classes: a "near"
class and a "far" class.  The near side is the one that faces the program
that is making the SOCKS request.  The default implementations run each
side as a Recoco Task.
"""

from pox.lib.recoco import Task, task_function
from pox.lib.recoco import Select, Recv, Send, CallBlocking
from pox.core import core
import socket
import struct


log = core.getLogger()

SOCKS_VERSION4 = 4
SOCKS_REPLY_VERSION4 = 0

SOCKS_CONNECT = 1
SOCKS_BIND = 2

SOCKS_FAILED = 91
SOCKS_GRANTED = 90



class SOCKSNear (Task):
  """
  This is the requester-facing side of a SOCKS connection
  """
  TIMEOUT = 5

  def __init__ (self, server, socket):
    super(SOCKSNear,self).__init__()
    self.server = server
    self.socket = socket
    self._done = False
    a,b = socket.getsockname()
    c,d = socket.getpeername()
    self.log = log.getChild("%s:%s %s:%s" % (a, b, c, d))
    self.start()

  def run (self):
    s = self.socket

    self.log.debug("New connection")

    header = yield Recv(s, 8, timeout=self.TIMEOUT)
    if not header or len(header) != 8:
      self.log.warn("Did not receive SOCKS header")
      self._close_exit()
      return

    version,command,port,ip = struct.unpack("!BBH4s", header)
    ip = socket.inet_ntoa(ip)

    if version != SOCKS_VERSION4:
      # May not even be SOCKS!
      self.log.warn("Bad SOCKS version")
      self._close_exit()
      return

    r = b''
    while True:
      tmp = yield Recv(s, 1, timeout=self.TIMEOUT)
      if not tmp:
        self.log.warn("Connection died before giving username")
        self._close_exit()
        return
      if not tmp:
        break
      if tmp == '\0': break
      r += tmp
    user = r or "(None provided)"
    self.log.debug("SOCKS user: %s", user)

    domain = b''
    if ip.startswith("0.0.0.") and ip != "0.0.0.0":
      # This is a SOCKS4a connection.
      r = b''
      while True:
        tmp = yield Recv(s, 1, timeout=self.TIMEOUT)
        if not tmp:
          r = None
          break
        if tmp == '\0': break
        r += tmp
      domain = r
      if not domain:
        self.log.warn("Bad domain name")
        self._close_exit() # Bad!
        return
    if not domain: domain = None
    else: ip = None

    if command == SOCKS_CONNECT:
      self.log.debug("SOCKS connect to %s", ip or domain)
      self.far_side = self.server.new_far_side(self)

      if domain:
        if not self.far_side.supports_dns_lookup:
          ip = yield self._dns_lookup(domain)
          if ip is None:
            self.log.warn("Bad domain name: %s", domain)
            self._send_response(SOCKS_FAILED)
            self._close_exit()
            return
          self.log.debug("Resolved %s to %s", domain, ip)

      if not (yield self.far_side.connect(version, ip, port, domain)):
        self.log.warn("Far side connect failed")
        self._close_exit()
        return
      self._send_response(SOCKS_GRANTED)
    #elif command == SOCKS_BIND:
    #  Not implemented
    else:
      self._send_response(SOCKS_FAILED)
      self._close_exit()
      return

    self.log.debug("Near side starting to proxy")

    ss = [s]

    while core.running and not self._done:
      rr,ww,xx = yield Select(ss, [], ss, self.TIMEOUT)
      if rr:
        data = yield Recv(s, 1024*64)
        if not data: break
        self.log.debug("Near side read %s bytes", len(data))
        while data:
          r = yield self.far_side.send(data)
          if r is None:
            self._done = True
            break
          data = data[r:]

    self.far_side.shutdown(socket.SHUT_RDWR)
    self._close_exit()

  @task_function
  def send (self, data):
    if self._done: yield None
    try:
      yield (yield Send(self.socket, data, timeout=self.TIMEOUT))
    except Exception:
      self.log.exception("While sending to near side")
      yield None

  @task_function
  def _dns_lookup (self, name):
    rv,ei = yield CallBlocking(socket.gethostbyname, (name,))
    yield rv

  def shutdown (self, flags):
    try:
      self.socket.shutdown(flags)
    except Exception:
      pass

  def _close_exit (self):
    self.log.debug("Near side done")
    if self._done: return
    try:
      self._done = True
      s = self.socket
      s.shutdown(socket.SHUT_RDWR)
      s.close()
    except Exception:
      pass

  def _send_response (self, code):
    data = struct.pack("BBHI", SOCKS_REPLY_VERSION4, code, 0, 0)
    self.socket.send(data)



class SOCKSFar (Task):
  """
  This is the side of a SOCKS connection facing away from the requester
  """
  TIMEOUT = 5
  supports_dns_lookup = False # Near side must do lookups

  def __init__ (self, server, near):
    super(SOCKSFar,self).__init__()
    self.server = server
    self.near_side = near

  @property
  def _done (self):
    return self.near_side._done

  @_done.setter
  def _done (self, value):
    self.near_side._done = value

  @property
  def log (self):
    return self.near_side.log

  @task_function
  def connect (self, version, ip, port, domain):
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket.setblocking(0)

    try:
      self.socket.connect((ip or domain, port))
    except socket.error as e:
      if e.errno != 115: raise # 115 is op in progress

    rr,ww,xx = yield Select([], [self.socket], [self.socket], self.TIMEOUT)
    if not ww:
      # Didn't connect!
      self.log.warn("CONNECT failed")
      self.near_side._send_response(SOCKS_FAILED)
      yield False

    self.start()
    yield True

  @task_function
  def send (self, data):
    # Far send
    if self._done: yield None
    try:
      yield (yield Send(self.socket, data, timeout=self.TIMEOUT))
    except Exception:
      self.log.exception("While sending to far side")
      yield None

  def run (self):
    sock = self.socket
    ss = [sock]

    self.log.debug("Far side starting to proxy")

    while core.running and not self._done:
      rr,ww,xx = yield Select(ss, [], ss, self.TIMEOUT)
      if rr:
        data = yield Recv(sock, 1024*64)
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
      self.socket.shutdown(flags)
    except Exception:
      pass

  def _close_exit (self):
    self.log.debug("Far side done")
    if self._done: return
    try:
      self._done = True
      s = self.socket
      s.shutdown(socket.SHUT_RDWR)
      s.close()
    except Exception:
      pass



class SOCKSServer (Task):
  TIMEOUT = 5

  def __init__ (self, local_ip="0.0.0.0", port=1080):
    super(SOCKSServer,self).__init__()
    self.log = log
    self.listen_port = port
    self.listen_addr = local_ip

  def new_near_side (self, socket):
    return SOCKSNear(self, socket)

  def new_far_side (self, near_side):
    return SOCKSFar(self, near_side)

  def run (self):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setblocking(0)
    s.bind((self.listen_addr, self.listen_port))
    s.listen(10)
    log.info("SOCKS server running at %s:%s", *s.getsockname())

    ss = [s]

    while core.running:
      rr,ww,xx = yield Select(ss, [], ss, self.TIMEOUT)
      if rr:
        cs,addr = s.accept()
        cs.setblocking(0)
        session = self.new_near_side(cs)
      if xx:
        log.warn("Listen socket error")
        break



def launch (port=1080, ip="0.0.0.0"):
  core.registerNew(SOCKSServer, local_ip=ip, port=int(port))
  def _handle_UpEvent (e):
    core.SOCKSServer.start()
  core.add_listener(_handle_UpEvent)
