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
Queues

Nodes are unidirectionally connected by a queue and a wire.  This file
has some Queues (and the base class).

Primarily queues are responsible for taking care of the queuing delay and
the transmission delay.  The wire then handles the propagation delay.

SimpleQueue (and descendents) can take a list of "dropper" functoids to
determine which packets to drop.  See the wire documentation for more
on those (they're very similar for both queues and wires).
"""


class Queue (object):
  topo = None
  src = None # Node
  dst = None # Node

  def enqueue (self, packet):
    raise NotImplementedError()

  def __len__ (self):
    raise NotImplementedError() # Should return queue occupancy

  def __repr__ (self):
    return "[%s %s<->%s]" % (type(self).__name__, self.src, self.dst)



class SimpleQueue (Queue):
  max_size = 20 # None = no limit
  queue = None
  _busy = False # Is a packet currently being transmitted?
  _idle_at = 0 # Last time the queue went idle (use idle_at property!)

  _max_queue = 0

  def __init__ (self, max_size=None):
    self.max_size = max_size if max_size is not None else self.max_size
    self.queue = [] #TODO: Use a deque instead
    self.drop_conditions = []

  @property
  def idle_at (self):
    if self._busy: return None # Not idle!
    return self._idle_at

  def __len__ (self):
    return len(self.queue)

  def _check_drop (self, packet):
    """
    Can be overridden to allow for dropping before enqueuing

    return True to drop
    """
    for d in self.drop_conditions:
      if d(self, packet): return True
    return False

  def enqueue (self, packet):
    if self._check_drop(packet): return

    if (self.max_size is not None) and (len(self.queue) >= self.max_size):
      self._drop_warning()
      return

    self.queue.append(packet)
    self._start_transmit()

  def _queue_pop (self):
    return self.queue.pop(0)

  def _on_queue_dry (self):
    """
    Called when queue has gone empty
    """
    pass

  def _start_transmit (self):
    if self._busy: return # Already transmitting
    if not self.queue:
      self._on_queue_dry()
      return
    packet = self._queue_pop()
    if packet is None:
      assert not self.queue
      self._on_queue_dry()
      return # Allow _queue_pop to run dry
    wire = self.topo.get_wire(self.src,self.dst)
    if wire is None:
      self.src.warn("No outgoing wire to %s", self.dst)
      return
    self._busy = True
    if len(self.queue) > self._max_queue:
      self._max_queue = len(self.queue)
      self.src.log.info("Max queue occupancy: %s", self._max_queue)
    trans_time = (len(packet.pack()) * 8.0) / wire.rate
    if trans_time <= 0:
      # Don't even bother with the timer (probably only when rate=infinity)
      self._on_transmit_finish(packet)
      return
    self.topo.set_timer_in(trans_time, self._on_transmit_finish, packet)

  def _on_transmit_finish (self, packet):
    self._busy = False
    self._idle_at = self.topo.now
    self._start_transmit()

    wire = self.topo.get_wire(self.src,self.dst)
    wire.transmit(packet)

  def _drop_warning (self):
    self.src.log.warn("Queue full -- dropping packet to %s", self.dst)



class InfinityQueue (SimpleQueue):
  max_size = None



class SimpleByteQueue (SimpleQueue):
  """
  Like the SimpleQueue, but based on bytes, not packets
  """
  _enqueued_bytes = 0
  max_size = 1460 * 30

  def enqueue (self, packet):
    if self._check_drop(packet): return

    size = len(packet)
    if self.max_size is not None:
      if size+self._enqueued_bytes >= self.max_size:
        self._drop_warning()
        return
    self._enqueued_bytes += size

    self.queue.append((size,packet))
    self._start_transmit()

  def _queue_pop (self):
    size,packet = self.queue.pop(0)
    self._enqueued_bytes -= size
    return packet



class CoDelQueue (SimpleByteQueue):
  """
  Implements the Controlled Delay AQM discipline

  This is very similar to SimpleByteQueue except for a few additions.

  See RFC 8289
  """
  # In the pseudocode from the RFC, it seems like dequeue() can get called
  # when the queue is empty, which doesn't happen for us.  I think I've
  # recreated the logic by implementing that code path in _on_queue_dry().

  max_size = 1460 * 60 # This seems to work better

  # See sections 4.2 and 4.3 of the RFC for setting these
  # (though these values should be good across a range of scenarios)
  # These are in seconds
  INTERVAL = 0.100
  TARGET =   0.005

  _first_above_time = 0
  _drop_next = 0 # Time to drop next packet
  _count = 0 # Packets dropped while _dropping=True
  _lastcount = 0 # count from previous iteration
  _dropping = False

  @property
  def _maxpacket (self):
    # This is the name used by CoDel
    return self.src.mtu

  def enqueue (self, packet):
    # Only real difference here is that we put a TS in the queue.
    if self._check_drop(packet): return

    size = len(packet)
    if self.max_size is not None:
      if size+self._enqueued_bytes >= self.max_size:
        self._drop_warning()
        return
    self._enqueued_bytes += size

    self.queue.append((size,self.src.stack.now,packet))
    self._start_transmit()

  def _on_queue_dry (self):
    super(CoDelQueue,self)._on_queue_dry()
    self._on_codel_queue_dry()

  def _on_codel_queue_dry (self):
    self._first_above_time = 0
    if self._dropping:
      self._dropping = False

  def _queue_pop (self):
    now = self.src.stack.now
    ok_to_drop,p = self._do_dequeue(now)

    if self._dropping:
      if not ok_to_drop:
        self._dropping = False
      while now > self._drop_next and self._dropping:
        # Drop p
        self._count += 1
        ok_to_drop,p = self._do_dequeue(now)
        if not ok_to_drop:
          self._dropping = False
        else:
          self._drop_next = self._control_law(self._drop_next, self._count)
    elif ok_to_drop:
      # Drop p
      ok_to_drop,p = self._do_dequeue(now)
      self._dropping = True

      delta = self._count - self._lastcount
      self._count = 1
      if (delta > 1) and ((now - self._drop_next) < (16*self.INTERVAL)):
        self._count = delta

      self._drop_next = self._control_law(now, self._count)
      self._lastcount = self._count

    return p

  def _do_dequeue (self, now):
    if not self.queue:
      self._first_above_time = 0
      return False,None
    ok_to_drop = False
    size,ts,packet = self.queue.pop(0)
    self._enqueued_bytes -= size
    sojourn_time = now - ts
    if sojourn_time < self.TARGET or self._enqueued_bytes <= self._maxpacket:
      self._first_above_time = 0
    else:
      if self._first_above_time == 0:
        self._first_above_time = now + self.INTERVAL
      elif now >= self._first_above_time:
        ok_to_drop = True
    return ok_to_drop,packet

  def _control_law (self, t, count):
    return t + self.INTERVAL / (count ** 0.5)
