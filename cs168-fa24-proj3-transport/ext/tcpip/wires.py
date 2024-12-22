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
Wires

Wires transmit data from the queue on the source side to the rx() method
on some destination.

They are primarily responsible for propagation delay (i.e., latency), and
have a .latency property to reflect this, though this *may* not always
reflect the exact delivery time -- since the Wire itself schedules the
delivery (that's its main responsibility!), it has some lattitude.

The wire is also were a rate is defined.  A Queue uses this to determine
the transmission delay.

Wires (like queues) are unidirectional.  To actually wire two things
together, you probably want a wire in both directions (and, in many
cases, the wire will be very similar!).

The src and dst are Nodes (just like with Queues).
"""
#TODO: Extend FlexibleWire to do some reordering


from tcpip.units import *



class Wire (object):
  """
  Wire connecting two nodes
  """
  rate = 1 * Mbps # bps
  latency = 10 * mSec # ms
  topo = None
  src = None # Node
  dst = None # Node

  @property
  def max_latency (self):
    return self.latency

  def transmit (self, packet):
    raise NotImplementedError()

  def __repr__ (self):
    return "[%s %s<->%s]" % (type(self).__name__, self.src, self.dst)



class SimpleWire (Wire):
  def __init__ (self, rate=None, latency=None):
    if rate is not None: self.rate = rate
    if latency is not None: self.latency = latency
    self.drop_conditions = []

  def _check_drop (self, packet):
    """
    Can be overridden to allow for dropping before transmitting

    return True to drop
    """
    for d in self.drop_conditions:
      if d(self, packet): return True
    return False

  def transmit (self, packet):
    if self._check_drop(packet): return
    if self.latency == 0:
      # Skip the timer
      self._on_transmit_finish(packet)
      return
    self.topo.set_timer_in(self.latency/Sec, self._on_transmit_finish, packet)

  def _on_transmit_finish (self, packet):
    self.dst.rx(packet, self.src)



class InfinityWire (SimpleWire):
  """
  Connects two nodes infinitely fast
  """
  rate = Infinity
  latency = 0

  def transmit (self, packet):
    if self._check_drop(packet): return
    self.dst.rx(packet, self.src)



class FlexibleWire (SimpleWire):
  """
  A slightly more flexible SimpleWire

  Instead of having transmit directly schedule a packet to be delivered,
  it has an internal queue of "packets on the wire", and just schedules
  for one of them to delivered.  In this case, it's the first one and
  the result is the same as SimpleWire.  But it'd be easy enough to
  pull a *random* packet out of the wire to get some reordering...
  """
  def __init__ (self, *args, **kw):
    super(FlexibleWire,self).__init__(*args, **kw)
    self._in_transit = []

  def transmit (self, packet):
    if self._check_drop(packet): return
    deliver_at = latency / Sec + self.topo.now
    self._in_transit.append((deliver_at,packet))
    if self.latency == 0:
      # Skip the timer
      self._on_transmit_finish()
      return
    self.topo.set_timer_at(deliver_at, self._on_transmit_finish)

  def _on_transmit_finish (self):
    _,packet = self._in_transit.pop(0)
    self.dst.rx(packet, self.src)
