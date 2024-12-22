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
Small services

Long ago, lots of hosts ran a few basic services defined in some RFCs
from 1983.  These are rarely enabled today (and when they are, they
usually turn out to be some sort of security problem).  But they can
be a bit useful and hearken back to a friendlier era of the Internet.

They were all defined for UDP and TCP.  We currently only support
the TCP versions.
"""

from pox.lib.recoco import Lock, task_function, CallBlocking
from pox.core import core
from . import tcp_sockets
from . import units
from . recoco_sockets import SimpleReSocketApp

import datetime
import subprocess
import time
import threading


log = core.getLogger()



class Echo (SimpleReSocketApp):
  """
  TCP echo service

  Compliant with RFC 862
  """
  default_listen_port = 7

  @task_function
  def _on_connected (self):
    count = 0
    while True:
      d = yield self.sock.recv(1, at_least=True)
      if not d: break
      count += len(d)
      yield self.sock.send(d)
    self.log.info("Echoed %s bytes", count)



class Discard (SimpleReSocketApp):
  """
  TCP discard service

  Compliant with RFC 863

  Reads and throws away data.  If shutdown is True, it immediately shuts
  the socket for reading so the advertised window will always be big.
  """
  shutdown = True
  default_listen_port = 9

  @task_function
  def _on_connected (self):
    start = self.sock.usock.stack.now

    if self.shutdown:
      yield self.sock.shutdown(tcp_sockets.SHUT_RD)

    count = 0
    while True:
      d = yield self.sock.recv(1, at_least=True)
      if not d: break
      count += len(d)

    finish = self.sock.usock.stack.now

    if count: self.log.info("Discarded %s bytes over %s", count,
                            units.seconds_to_str(finish-start))



class Daytime (SimpleReSocketApp):
  """
  TCP daytime service

  Compliant with RFC 867

  Gives the *real* date and time, no matter virtual time
  Does UTC if .utc=True, or local time otherwise
  """
  utc = True
  default_listen_port = 13

  @task_function
  def _on_connected (self):
    import datetime
    if self.utc:
      d = datetime.datetime.utcnow()
    else:
      d = datetime.datetime.utcnow()
    fmt = "{d:%A}, {d:%B} {d.day}, {d.year} {d:%X}"
    fmt += "-UTC\n" if self.utc else "\n"
    s = fmt.format(d=d)
    yield self.sock.send(s)
    yield self.sock.shutdown(tcp_sockets.SHUT_WR)



class TimeServer (SimpleReSocketApp):
  """
  TCP time service

  Compliant with RFC 868

  Sends the UTC time as an unsigned network-order 32 bit integer
  containing the seconds since the Unix epoch.

  You can query this with rdate -p <server> on an Ubuntu machine.
  """
  default_listen_port = 37

  @task_function
  def _on_connected (self):
    import datetime, struct
    d = datetime.datetime.utcnow()
    epoch = datetime.datetime(1900,1,1) # Why not the Unix epoch?!
    t = int((d - epoch).total_seconds()) & 0xffFFffFF
    yield self.sock.send(struct.pack("!I", t))
    yield self.sock.shutdown(tcp_sockets.SHUT_WR)



class CharGen (SimpleReSocketApp):
  """
  TCP chargen service

  Compliant with RFC 864
  """
  default_listen_port = 19

  @staticmethod
  def _generate_lines ():
    """
    Generate lines of text as per RFC 864
    """
    import string
    s = "".join(sorted(string.printable.strip())) + " "

    i = 0
    while True:
      x = s[i:i+72]
      if len(x) < 72: x+=s[0:72-len(x)]
      i += 1
      i %= len(s)
      yield x

  @task_function
  def _on_connected (self):
    yield self.sock.shutdown(tcp_sockets.SHUT_RD)

    sent = 0
    start = self.sock.usock.stack.now
    gen = self._generate_lines()
    outbuf = b''
    try:
      while True:
        while self.sock.usock.state == tcp_sockets.ESTABLISHED:
          w = self.sock.usock.bytes_writable
          while len(outbuf) < self.sock.usock.smss:
            outbuf += gen.next()
          d = yield self.sock.send(outbuf)
          sent += d
          if d != len(outbuf):
            self.log.warn("CharGen didn't send all data")
            outbuf = outbuf[d:]
          else:
            outbuf = b''
          if not w: break
        if self.sock.usock.state != tcp_sockets.ESTABLISHED: break
    except tcp_sockets.PSError:
      pass

    finish = self.sock.usock.stack.now
    dur = finish - start
    t = units.seconds_to_str(dur)
    rate = units.bps_to_str( (sent * 8.0), dur )
    self.log.info("Generated %s bytes in %s (%s)", sent, t, rate)



class QuoteOfTheDay (SimpleReSocketApp):
  """
  TCP quote of the day service

  Compliant with RFC 865
  """
  default_listen_port = 17
  quote = None
  day = None
  default_quote = ("Your quote of the day: Today is a good day to install\n"
                   "the 'fortune' command.")
  quote_command = "fortune"
  async_quote_fetch = True


  @staticmethod
  def fetch_quote ():
    """
    Fetch a quote using the "fortune" commandline utility
    """
    for _ in range(5): # Three tries maximum
      p = subprocess.Popen((QuoteOfTheDay.quote_command,),
                           stdout=subprocess.PIPE)
      timer = threading.Timer(5, p.terminate)
      timer.start()
      data,_ = p.communicate()

      try:
        timer.cancel()
      except Exception:
        pass

      data = data.strip() + "\n"
      if len(data) > 10 and len(data) < 512:
        return data
    return None

  @task_function
  def _on_connected (self):
    yield self.sock.shutdown(tcp_sockets.SHUT_RD)

    if self.day != datetime.date.today():
      # Update the quote
      self.log.debug("Getting quote for a new day")
      self.day = datetime.date.today()
      if self.async_quote_fetch:
        q,exc = yield CallBlocking(self.fetch_quote)
      else:
        q = self.fetch_quote()
      if not q: q = self.default_quote
      self.quote = q

    b = self.quote
    while b:
      sent = yield self.sock.send(b)
      if not sent: break
      b = b[sent:]

    self.log.info("Sent quote of the day")



__all__ = "Echo Discard Daytime CharGen TimeServer QuoteOfTheDay".split()
