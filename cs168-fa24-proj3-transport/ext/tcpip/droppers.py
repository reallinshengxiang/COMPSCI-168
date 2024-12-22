"""
A collection of droppers

SimpleWire and SimpleQueue can take a list of "droppers", which are
really just callables that are passed the wire/queue and a packet
and return True if they want the packet to be dropped.

If the drop condition isn't especially tied to the wire or queue,
then you could even use the same dropper as a queue or wire dropper
(a good example is a random dropper which doesn't need anything from
anyone, really).  Or, since both queues and wires have src and dst,
if that's all the dropper needs, it could be used for either.  On
the other hand, some droppers have a closer relationship with the
thing they're attached to.  For example, the REDDropper needs to
be attached to a queue, and needs to be able to get the current
queue occupancy.

Seed RandomDropper for an example of how to use the attached object
to seed a random number deterministically (assuming the attached
object has a deterministic string representation).
"""
#TODO: ProgrammableDropper (takes a list of things to drop)

import random



class RandomDropper (object):
  """
  A simple drop-deciding functoid

  Usable as both a wire-dropper and queue dropper
  """
  seed = 0
  def __init__ (self, drop_fraction, seed=seed):
    self._random = None
    self._drop_fraction = drop_fraction
    self.seed = seed

  def __call__ (self, obj, packet):
    if self._random is None:
      self._random = random.Random()
      self._random.seed(hash(str(obj)) ^ self.seed)
    if self._random.random() < self._drop_fraction():
      return True
    return False



class RegularDropper (object):
  """
  Simple dropper that accepts X and then drops Y packets
  """
  def __init__ (self, accept, deny=None, phase=0):
    self.accept = accept
    if deny is None: deny = accept
    self.deny = deny
    self.phase = phase % (accept+deny)

  def __call__ (self, obj, packet):
    p = self.phase
    self.phase = (self.phase + 1) % (self.accept+self.deny)
    return p >= self.accept



class REDDropper (object):
  """
  Random Early Detection functoid for queues

  It requires that the queue it's used with implement len() and
  idle_at.

  Based on:
    Random Early Detection Gateways for Congestion Avoidance
    (Floyd and Jacobson)
    http://www.icir.org/floyd/papers/early.twocolumn.pdf

    And specifically, this is based on Figure 2, which is the
    detailed idealized algorithm, as opposed to Figure 17 which
    is the efficient version.

  The queue size is currently measured in packets, but should
  probably be in bytes.

  Totally untested!
  """
  seed = 0

  average_packet_size = 420 / 2.0
  # Average packet size was from 2000, as per
  #  http://www.caida.org/research/traffic-analysis/AIX/plen_hist/
  # We cut it in half because RED wants a "small packet"

  wq = 0.002
  min_th = 5
  max_th =  15
  max_p = 0.02 # 2% maximum probability

  def __init__ (self, wq=wq, min_th=min_th, max_th=max_th, max_p=max_p,
                seed=seed):
    self.avg = 0
    self.count = -1
    self.wq = float(wq)
    self.min_th = float(min_th)
    self.max_th = float(max_th)
    self.max_p = float(max_p)

    self.seed = seed

    self._random = None

    # This is a hack
    if getattr(type(self), "WARNED", False) is False:
      log.warn("Using REDDropper which is totally untested")

  def __call__ (self, obj, packet):
    if self._random is None:
      self._random = random.Random()
      self._random.seed(hash(str(obj)) ^ self.seed)

    qlen = len(obj)
    idle_at = obj.idle_at
    if idle_at is None: # Not idle
      qlen += 1 # Include the one being transmitted
      self.avg = (1-self.wq) * self.avg + self.wq * qlen
    else:
      idle_time = obj.topo.now - idle_at
      trans_time = (self.average_packet_size * 8.0) / obj.rate
      m = idle_time / trans_time # num packets Might have been xmitted
      self.avg = ((1-self.wq) ** m) * avg
      # The above is what the paper says as best as I can figure; I don't
      # immediately have any sense of why it'd be right, and I haven't
      # worked through it.

    if self.min_th <= self.avg and self.avg < self.max_th:
      self.count += 1
      pb = self.maxp * (self.avg - self.min_th) / (self.max_th - self.min_th)
      pa = pb / (1.0 - self.count * pb)
      if self._random.random() < pa:
        self.count = 0
        return True # Drop!
    elif self.max_th <= self.avg:
      self.count = 0
      return True # Drop!
    else:
      self.count = -1
