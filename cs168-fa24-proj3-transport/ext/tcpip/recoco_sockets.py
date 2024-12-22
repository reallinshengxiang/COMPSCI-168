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
Recoco-friendly Socket wrapper

This provides a socket-like API atop the usockets which is useful for
Recoco Tasks.

To demonstrate, there are a couple simple demonstration applications.
"""

from pox.lib.recoco import task_function, Task
from . time_manager import Blocker, CountDown
from pox.core import core
from pox.lib.addresses import IPAddr
from . import tcp_sockets
from . import units
import socket



@task_function
def reselect (rlist, wlist, xlist, timeout=None):
  """
  select() for resockets

  I'm not sure if all the conditions are right here.
  A notable one is that a listen socket is readble if it has something
  in the accept queue.
  And a socket is readable when it's closed.
  There are currently no exceptional conditions, so x is useless.
  """
  rr = []
  ww = []
  xx = []
  rset = set(rlist)
  wset = set(wlist)
  xset = set(xlist)
  allset = rset.union(wset).union(xset)
  if not allset: yield ([],[],[])
  anysock = rlist[0] if rlist else wlist[0] if wlist else xlist[0]
  for s in allset:
    if s.stack is not anysock.stack:
      # We can probably ease this requirement.
      raise RuntimeError("All sockets must be from same stack")
  cd = anysock._get_countdown_timer(timeout)
  block = Blocker(anysock.stack, timeout)
  while not cd.is_expired:
    # Not very efficient (especially all the adding/removing)
    for s in allset: s.usock.poll(block)
    yield b.acquire()
    for s in allset:
      # We could check for just the ones where unpoll returns True...
      s.usock.unpoll(block)
      if s in rset:
        us = s.usock
        if us.state == tcp_sockets.LISTEN:
          if us.accept_queue: rr.append(s)
        elif us.state in (tcp_sockets.CLOSE_WAIT,tcp_sockets.ESTABLISHED):
          if us.bytes_readable: rr.append(s)
        else:
          # Just add it?  Idea is that recv will retur immediately?
          rr.append(s)
      if s in wset:
        us = s.usock
        if us.bytes_writable: rr.append(s)

      if rr or ww or xx: break
    yield (rr,ww,xx)

select = reselect # Alias



class RecocoSocketManager (object):
  def __init__ (self, stack, usocket_factory = None):
    self.stack = stack
    self.usocket_factory = usocket_factory # f(RecocoSocketManager)->usocket

  def socket (self):
    usock = None
    if self.usocket_factory:
      usock = self.usocket_factory(self)
    return RecocoSocket(self.stack, usock=usock)



class ReSocketError (RuntimeError):
  @property
  def errno (self):
    return str(self)



class RecocoSocket (object):
  #TODO: Actually do errno correctly

  connect_timeout = None # None or seconds; for connect and accept
  timeout = None

  def __init__ (self, stack, connect_timeout=connect_timeout, usock=None):
    self.stack = stack
    self.manager = stack.socket_manager
    self.usock = tcp_sockets.Socket(self.manager) if usock is None else usock
    self.connect_timeout = connect_timeout

  @property
  def log (self):
    return self.usock.log

  @property
  def peer (self):
    return self.usock.peer

  @property
  def name (self):
    return self.usock.name

  @property
  def _block (self):
    """
    Blocks on an underlying socket

    yield block()
    """
    def f (timeout=None):
      b = Blocker(stack=self.stack, timeout=timeout)
      self.usock.poll(b)
      return b.acquire()
    return f

  def _new (self, usock=None):
    return type(self)(self.stack, usock=usock,
                      connect_timeout=self.connect_timeout)

  def _get_countdown_timer (self, t):
    return CountDown(self.stack.time, t)

  @task_function
  def connect (self, ip, port, timeout=None):
    if timeout is None: timeout = self.connect_timeout
    self.usock.connect(ip, port)
    cd = self._get_countdown_timer(timeout)
    while not cd.is_expired:
      if self.usock.is_connected:
        yield True
      if self.usock.state is tcp_sockets.ERROR:
        self.errno = "socket error"
        break
      yield self._block(cd)
    else:
      self.errno = "timeout"
    raise ReSocketError(self.errno)

  @task_function
  def listen (self, backlog=5):
    yield self.usock.listen(backlog)

  @task_function
  def bind (self, ip, port):
    yield self.usock.bind(ip, port)

  @task_function
  def accept (self, timeout=None):
    if timeout is None: timeout = self.connect_timeout
    cd = self._get_countdown_timer(timeout)
    while not cd.is_expired:
      try:
         s = self.usock.accept()
         yield self._new(usock=s)
      except tcp_sockets.PSError:
        pass
      yield self._block(cd)
    self.errno = "timeout"
    raise ReSocketError(self.errno)

  @task_function
  def close (self):
    self.usock.close()

  @task_function
  def shutdown (self, flags):
    self.usock.shutdown(flags)

  @task_function
  def recv (self, length=None, flags=0, at_least=False, timeout=None):
    """
    receive data

    One twist on the traditional sockets interface is that if at_least
    is True, we might return *more* than length data, but we'll block
    until we get *at least* length.  If length is None, we'll return
    as soon as there's any date.

    If at_least is False and length is None, we'll do nonblocking read.
    This may change in the future.
    """
    if length is None:
      assert timeout is None
      r = self.usock.recv(length, flags)
      yield r
    else:
      if timeout is None: timeout = self.timeout
      if timeout:
        cd = self._get_countdown_timer(timeout)
      else:
        cd = None

      b = b''
      remain = length
      while True:
        r = self.usock.recv(None if at_least else remain, flags)
        if r is None: break
        b += r
        remain = remain - len(r)
        if at_least is False: assert remain >= 0
        if remain <= 0: break
        yield self._block(cd)
        if cd and cd.is_expired: break
      yield b

  @task_function
  def send (self, data, flags=0, timeout=None):
    """
    Sends data, returning the amount it actually sent
    """
    # Return value probably isn't right for closed sockets, etc.
    if flags & socket.MSG_DONTWAIT:
      # Just call usocket send...
      assert timeout is None
      yield self.usock.send(data, flags=flags & ~socket.MSG_DONTWAIT)

    if timeout is None: timeout = self.timeout
    if timeout:
      cd = self._get_countdown_timer(timeout)
    else:
      cd = None

    total_size = len(data)
    try:
      while data:
        r = self.usock.send(data, flags=flags)
        data = data[r:]
        if not data: break
        yield self._block(cd)
        if cd and cd.is_expired: break
    except tcp_sockets.PSError:
      pass
    yield total_size - len(data)



class SimpleReSocketApp (Task):
  """
  A small framework for writing Recoco socket "apps"

  The framework takes care of making them either clients or servers.
  You just implement _on_connected(), which is called when the
  connection is ready.  It needs to be written as a Recoco cooperative
  task: put on the @task_function decorator, and use Recoco syscalls
  via yield in it.
  """

  connect_delay = 0 # Wait before calling connect()
  _log = None

  def __init__ (self, socket, ip=IPAddr("0.0.0.0"), port=0, listen=False,
                parent=None, connect_delay=None, child_kwargs={}):
    super(SimpleReSocketApp,self).__init__()
    self.sock = socket
    self.ip = ip
    self.port = port
    self.listen = listen
    self.parent = parent
    self.child_kwargs = child_kwargs
    if connect_delay is not None: self.connect_delay = connect_delay
    self.children = set()
    if listen is False and parent is None:
      if ip == "0.0.0.0": raise RuntimeError("Must set IP address")
    self.start()

  @property
  def log (self):
    if self._log is None:
      self._log = self.sock.log
    return self._log

  def stop_listening (self):
    self.listen = False

  @task_function
  def _on_connected (self):
    """
    Called when connection is ready

    You should override this.
    """
    self.log.error("Unimplemented connection handler for %s",
                   type(self).__name__)

  def run (self):
    if self.parent:
      pass # We should be good to go!
    elif self.listen:
      if self.ip is not None:
        yield self.sock.bind(self.ip, self.port)
      else:
        yield self.sock.bind(IPAddr("0.0.0.0"), self.port)
      yield self.sock.listen()
      self.log.debug("Listening for connections on %s:%s", *self.sock.name)
      while core.running and self.listen:
        try:
          s = yield self.sock.accept(timeout=5)
          child = type(self)(s, parent=self, **self.child_kwargs)
          self.log.info("Got connection from %s:%s", *child.sock.peer)
          self.children.add(child)
        except ReSocketError as e:
          if e.errno == "timeout": continue
          self.log.error("Listening socket got error: %s", e)
          return
      self.log.debug("Done listening")
      return
    else:
      if self.connect_delay:
        yield self.sock.usock.stack.time.resleep(self.connect_delay)
      try:
        yield self.sock.connect(ip=self.ip, port=self.port)
        self.log.debug("%s connected to %s:%s", type(self).__name__,
                       self.ip, self.port)
      except ReSocketError as e:
        self.log.error("Connection to %s:%s failed: %s", self.ip, self.port, e)
        return

    try:
      yield self._on_connected()
    except Exception:
      if self.parent: self.parent.children.discard(self)
      raise
    finally:
      try:
        yield self.sock.shutdown(tcp_sockets.SHUT_RDWR)
      except tcp_sockets.PSError:
        pass
      try:
        yield self.sock.close()
      except tcp_sockets.PSError:
        pass



class DataLogger (SimpleReSocketApp):
  @task_function
  def _on_connected (self):
    data = b''
    lines = 0
    while True:
      d = yield self.sock.recv(1, at_least=True)
      if not d:
        # Log any final data
        if data:
          lines += 1
          self.log.info("RX: " + data)
        break
      data += d
      while '\n' in data:
        first,data = data.split("\n",1)
        if not first: continue # Don't print blank lines
        lines += 1
        self.log.info("RX: " + first)
    self.log.info("DataLogger logged %s lines", lines)



class FastSender (SimpleReSocketApp):
  """
  This little application just sends some amount of data as fast as it can

  It also discards all received data, so if it's sent to an echo or something,
  the other side should always have a max-sized rwnd.
  """
  _buf = None

  def __init__ (self, bytes, socket, ip=IPAddr("0.0.0.0"), port=0, listen=False,
                parent=None, connect_delay=None):
    super(FastSender,self).__init__(socket=socket,ip=ip,port=port,
                                    listen=listen,parent=parent,
                                    connect_delay=connect_delay)
    self.bytes = bytes
    if self._buf is None:
      self._buf = "*" * (1024 * 64)
      # Without window scaling, always big enough
      type(self)._buf = self._buf

  @task_function
  def _on_connected (self):
    yield self.sock.shutdown(tcp_sockets.SHUT_RD)

    remaining = self.bytes
    start = self.sock.usock.stack.now
    try:
      while remaining:
        b = self._buf
        if len(b) >= remaining:
          b = b[:remaining]
          #FIXME: We should send immediately/psh/etc. here
        d = yield self.sock.send(b)
        if not d: yield self.sock.close()
        remaining -= d
    except tcp_sockets.PSError:
      self.log.exception("Exception while sending bytes")

    finish = self.sock.usock.stack.now

    sent = self.bytes - remaining
    dur = finish - start

    t = units.seconds_to_str(dur)
    rate = units.bps_to_str( (sent * 8.0), dur )

    self.log.info("Sent %s of %s bytes in %s (%s)",
                  self.bytes-remaining, self.bytes, t, rate)

class BasicStateTransServer (SimpleReSocketApp):
  """
  This application only checks 3 way hand shake, and then closes the conn
  """

  @task_function
  def _on_connected (self):
    self.log.info("will shutdown socket now")
    yield self.sock.close()
    self.log.info("socket shutdown")
