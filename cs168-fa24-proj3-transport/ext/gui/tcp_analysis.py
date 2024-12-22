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
POX backend for TCP analysis GUI

The actual analysis part isn't strictly limited to the GUI and could easily
be repurposed, though it could certainly use improvement (in particular, if
a datastructure were added to allow for fast range queries, we could extend
it to find places where, for example, one packet acknowledges the middle of
another packet rather than just the end.

A caveat with the current implementation is that a newer packets are likely
to have more information available, e.g., about duplicates.  It'd be really
cool if we noticed when a new packet would change the data produced by some
older packet so that we could re-render it.  The particularly tricky aspect
of this is that old data is eventually lost, since the analysis engine only
keeps a certain amount of history.  So a new packet might cause new info to
be added, but the deletion of history may also cause some information to be
lost.  It's not clear how to balance these two things at the analyzer level
itself; it should probably be handled by higher-level class which keeps its
own history just for rendering a UI.
"""

from pox.core import core
from tcpip.modulo_math import *
from collections import deque, defaultdict
#from tcp_analysis import FlowManager


class FlowManager (object):
  max_packets = 1000

  def __init__ (self):
    self.flows = {} # key -> Flow

  def new_record (self, p):
    return Record(self, p)

  def get_flow (self, key):
    f1 = self.flows.get(key)
    if not f1:
      f1,f2 = Flow.new_pair(key, self.max_packets)
      self.flows[key] = f1
      self.flows[f2.key] = f2
    return f1


class Flow (object):
  @classmethod
  def new_pair (cls, key, max_packets):
    f1 = cls(key, max_packets=max_packets)
    assert f1
    f2 = cls(cls.reverse_key(key), buddy=f1, max_packets=max_packets)
    return f1,f2

  @staticmethod
  def reverse_key (key):
    return (key[1],key[0],key[3],key[2])

  def __init__ (self, key, buddy=None, max_packets=1000):
    self.max_packets = max_packets
    self.key = key
    if not buddy:
      self.pkts = deque() # [Record...]
      self._offset = 0
      self._primary = self
    else:
      self.pkts = buddy.pkts
      self._primary = buddy
      buddy.buddy = self
      self.buddy = buddy
    self.seqs = defaultdict(set) # seq -> set(Record)
    self.next_seqs = defaultdict(set) # seq+len -> set(Record)
    self.acks = defaultdict(set) # ack -> set(Record)
    self.dup_acks = {} # ack -> set(Record)

  def __getitem__ (self, num):
    """
    Get by ordering number
    """
    return self.pkts[num - self._primary._offset]

  @property
  def is_empty (self):
    """
    Whether we have packets stored
    """
    return len(self.pkts) == 0

  def add_record (self, r):
    self._trim()
    self.pkts.append(r)
    self.seqs[r.tcp.seq].add(r)
    self.next_seqs[r.next_seq].add(r)
    if r.tcp.ACK:
      self.acks[r.tcp.ack].add(r)
      if len(self.acks[r.tcp.ack]) > 1:
        self.dup_acks[r.tcp.ack] = self.acks[r.tcp.ack]

    return len(self.pkts) - 1 + self._primary._offset

  def _trim (self):
    """
    Remove old packets
    """
    def remove (d, k, p):
      d[k].discard(p)
      if not d[k]:
        del d[k]
        return True
      return False

    while len(self.pkts) > self.max_packets:
      p = self.pkts.pop_left()
      remove(self.seqs, p.tcp.seq, p)
      if p.tcp.ACK:
        if remove(self.acks, p.tcp.ack, p):
          self.dup_acks.pop(p.tcp.ack, None)
      self._primary._offset += 1


class Record (object):
  #TODO: Efficient range queries will allow finding overlapping packets,
  #      not just exact duplicates or whatever.
  def __init__ (self, mgr, p):
    self.mgr = mgr
    self.p = p
    ip = p.find("ipv4")
    tcp = ip.find("tcp")
    self.ip = ip
    self.tcp = tcp
    self.key = (ip.srcip,ip.dstip,tcp.srcport,tcp.dstport)
    self.flow = mgr.get_flow(self.key)
    self.buddy_flow = self.flow.buddy
    order = self.flow.add_record(self)
    self.order = order

    self.in_order = None # Indeterminate
    if not self.tcp.SYN: # Doesn't make sense for SYN
      try:
        #TODO: It'd be nice to be able to get unidirectional ordering too
        o = self.order - 1
        while True:
          if self.flow[o].key == self.key:
            self.in_order = self.flow[o].next_seq == self.tcp.seq
            break
          o -= 1
      except Exception as e:
        print(e)
        pass

  def __len__ (self):
    """
    length in sequence space
    """
    l = len(self.tcp)
    if self.tcp.SYN: l += 1
    if self.tcp.FIN: l += 1
    return l

  @property
  def next_seq (self):
    """
    The sequence number of the next packet in this flow
    """
    return self.tcp.seq |PLUS| len(self)

  @property
  def acked_packets (self):
    """
    The packets this packet directly ACKs or None
    """
    if not self.tcp.ACK: return None
    return self.buddy_flow.next_seqs.get(self.tcp.ack)

  @property
  def acked_data_packets (self):
    if not self.tcp.ACK: return None
    return list(x for x in self.acked_packets if len(x))

  def get_dup_seqs (self):
    """
    The packets with the same seqnumber
    """
    if len(self) != 0:
      for p in self.flow.seqs[self.tcp.seq]:
        if p is not self:
          if len(p) != 0:
            yield p

  def get_dup_acks (self):
    """
    The packets with the same ack number
    """
    if self.tcp.ACK and len(self) == 0:
      for p in self.flow.acks[self.tcp.ack]:
        if p is not self:
          if len(p) == 0:
            yield p
