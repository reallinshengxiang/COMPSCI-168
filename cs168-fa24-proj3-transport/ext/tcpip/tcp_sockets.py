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
TCP sockets implementation

This includes the actual "underlying" TCP socket implementation.  Elsewhere,
these are sometimes referred to as usockets.  usockets have a "socket-like"
interface.  It's vaguely socket-like, but it's sort of like the kernel
interface, and nothing blocks.  So a usocket can be used directly, but it
may be wrapped by a higher level socket to provide a more convenient API.
An example is RecocoSocket, which provides a Recoco-task-friendly socket
(that is, you call the socket functions using yield, and they can block).

Some of the major references include:

* RFC 793 - Transmission Control Protocol
  There are a bunch of RFCs that update or modify this.  Additionally, the
  API it describes is not a perfect match to the sockets API, which we
  follow more closely.  The biggest difference here is to do with LISTEN.
  In the RFC, you open a connection object or whatever you want to call
  it for listening (passive open); an active connection then meets up
  with it and forms a connection and you use it the same as if it had
  been actively opened.  In the sockets API, you open a socket for
  listening and then it sort of spawns off new sockets via accept().  The
  listening socket never actually becomes a communication channel.

* RFC 1122 - Requirements for Internet Hosts -- Communication Layers
  Most notably, this contains some fixes/updates to RFC 793.  Also
  contains discussion of zero window probes.

* RFC 6429 - TCP Sender Clarifications for Persist Condition
  The "persist condition" is the condition where we need to do ZWP.

* RFC 6298 - Computing TCP's Retransmission Timer
  The most up-to-date and comprehensive RFC on the retransmission
  timer.  This includes all the Karn/Partridge stuff.

* RFC 5681 - TCP Congestion Control
  The most up-to-date and comprehensive RFC on congestion control.

* RFC 3465 - TCP Congeston Control with Appropriate Byte Counting
  We may not actually refer to this directly, but we do refer to RFC 5681,
  which incorporates at least part of this.

* RFC 3042 - Enhancing TCP's Loss Recovery Using Limited Transmit
  Sends new data in response to the first two duplicate ACKs, which
  means you're more likely to keep the ACK clock going even if, e.g.,
  the cwnd is small (thus improving the change to do fast retransmit).

* RFC 6582 - The NewReno Modification to TCP's Fast Recovery Algorithm
  We currently implement the fast hole-filling from S3, but not the
  extra FRR-entry heuristics mention in S4.

* RFC 7323 - TCP Extensions for High Performance
  The most recent version of the TCP timestamp option information is here,
  as well as the most recent window scaling option info.  We implement
  both of these (at least to a first approximation).

* How TCP Backlog Works in Linux (post by Andreas Veithen)
  http://veithen.github.io/2014/01/01/how-tcp-backlog-works-in-linux.html
  We may not follow it exactly, but this page has a nice discussion of
  socket listen/accept behavior in Linux which is at least the inspiration
  for how we do it (as well as a description of how BSD does it, slightly
  differently).  In short, we have one queue shared by all sockets for
  passive connections which are waiting for their SYN+ACK to get ACKed;
  after that happens, they get moved to a per-LISTEN-socket queue from
  which they can be accept()ed.
"""

#TODO: Do / make sure of the following:
# * handle annoying packet accept case in top of rx_other?
# * actually call _unblock() from relevant places (many now done?)
# * Nagle (RFC 896)
# * Silly window syndrome mitigation
# * Check on our shut_rd semantics (adv window stays max forever)
# * CLOSING timer to actually delete TCB?
# * PAWS and ignoring segments with no TS if one is expected (RFC 7323)
# * Early retransmit (RFC 5827)
# * Redo rx_queue so that it doesn't work by resubmitting packets
#   in order (see discussion in _maybe_update_rto()).  At the
#   minimum, we probably want to monitor the length of rx_queue!
# * The additional FRR-entry heuristics from RFC 6582 S4
# * SYN/FIN retransmits


from pox.core import core
log = core.getLogger()

from pox.lib.addresses import IPAddr

import pox.lib.packet as pkt

import hashlib
import random
import collections
import inspect
from socket import SHUT_RD, SHUT_WR, SHUT_RDWR

from math import ceil

from . modulo_math import *


PSError = RuntimeError

# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

# Strings are just objects, so we can make these "symbolic constants" as
# strings; if we use "is" to do comparisons, it's just an object identity
# check which is as cheap as anything, *and* we can just print them out
# and get their name instead of a number of something.  Seems dippy, but
# it's actually not.

CLOSED = "CLOSED"
LISTEN = "LISTEN"
SYN_RECEIVED = "SYN RECEIVED"
ESTABLISHED = "ESTABLISHED"
SYN_SENT = "SYN_SENT"
FIN_WAIT_1 = "FIN_WAIT_1"
FIN_WAIT_2 = "FIN_WAIT_2"
CLOSING = "CLOSING"
TIME_WAIT = "TIME_WAIT"
CLOSE_WAIT = "CLOSE_WAIT"
LAST_ACK = "LAST_ACK"

INITIAL = "INITIAL" # NOT A NORMAL TCP STATE
ERROR = "ERROR" # NOT A NORMAL TCP STATE

# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
#  Window stuff
# ---------------------------------------------------------------------------

class Window (object):
  una = 0 # TX
  nxt = 0 # TX RX
  wnd = 0 # TX RX
  up  = 0 # TX RX (urgent pointer)
  wl1 = 0 # TX (seg seqno used for last window update)
  wl2 = 0 # TX (seg ackno used for last window update)
  isn = 0 # TX RX (initial sequence number) (iss / irs)

  # From RFC 793:
  # Note that SND.WND is an offset from SND.UNA, that SND.WL1
  # records the sequence number of the last segment used to update
  # SND.WND, and that SND.WL2 records the acknowledgment number of
  # the last segment used to update SND.WND.

  def check_accept (self, seg):
    # RFC 793 S3.3
    if seg.len == 0 and self.wnd == 0:
      return seg.seq == self.nxt
    if seg.len == 0 and self.wnd |MGT| 0:
      if ((self.nxt |MLE| seg.seq) and (seg.seq |MLT| (self.nxt |PLUS| self.wnd))): return True
      return False
    if seg.len > 0 and self.wnd == 0:
      return False
    if seg.len > 0 and self.wnd > 0:
      if ((self.nxt |MLE| seg.seq) and (seg.seq |MLT| (self.nxt |PLUS| self.wnd))): return True
      rhs = seg.seq |PLUS| (seg.len-1)
      if ((self.nxt |MLE| rhs) and (rhs |MLT| (self.nxt |PLUS| self.wnd))): return True
      return False
    return False


class RXWindow (Window):
  pass


class TXWindow (Window):
  def __init__ (self):
    # RFC 793 p66
    self.isn = self.generate_isn()
    self.nxt = self.isn |PLUS| 1
    self.una = self.isn

  def generate_isn (self):
    return random.randint(1,0xFFffFFff)

  @property
  def window_size (self):
    """
    How many bytes can we send?
    """
    # Hmmm... what about just .wnd?
    re = (self.una |PLUS| self.wnd)
    if re |MLT| self.nxt: return 0
    return re |MINUS| self.nxt

  def una_advance (self, ackno):
    self.una = ackno

# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def tcplen (tp):
  """
  Returns sequence space size of TCP
  """
  # Should maybe go in Packet?
  l = len(tp.payload)
  if tp.SYN: l += 1
  if tp.FIN: l += 1
  return l & 0xFFffFFff

class PacketQueue (list):
  """
  A queue for packets

  Add packets with .push(), and they are added sorted by sequence number
  .pop() pops from the start by default (as opposed to list's behavior)
  """
  def push (self, p):
    """
    Add Packet p in correct place (entries are seq,packet)
    """
    # This could be a lot more efficient with a binary search or something,
    # but for now, let's just optimize a couple simple cases.
    if len(self) == 0:
      self.append(p)
      return

    if p.tcp.seq |MLT| self[0].tcp.seq:
      self.insert(0, p)
      return

    self.append(p)
    if p.tcp.seq |MLT| self[-2].tcp.seq:
      self.sort(key=self._get_seqno)

  def pop (self, index=None):
    if index is None: index = 0
    return super(PacketQueue,self).pop(index)

  def pop_head (self, count=1):
    r = self[:count]
    del self[:count]
    return r

  def pop_tail (self, count=1):
    r = self[-count:]
    del self[-count:]
    return r

  @staticmethod
  def _get_seqno (p):
    return p.tcp.seq



class AcceptQueue (object):
  """
  A queue for server sockets waiting for syn or accept

  It's just a FIFO queue from which you can discard quickly
  """
  def __init__ (self):
    self._d = collections.OrderedDict()

  def push (self, o):
    self._d[o] = o

  def pop (self):
    return self._d.popitem(last=False)[0]

  def discard (self, o):
    return self._d.pop(o, None) is o

  def __len__ (self):
    return len(self._d)

  def __contains__ (self, item):
    return item in self._d

# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
#  TCP
# ---------------------------------------------------------------------------

class Socket (object):
  _state = INITIAL

  syn = None # Packet,tcpp if this was created by a listen socket
  synack = None # Packet,tcpp if was active connection

  peer = None,None # ip,port
  name = None,None # local ip,port

  parent = None # Listening socket that spawned us

  use_delayed_acks = True

  # If True, advertise a 0 initial window during SYN states
  zero_initial_window = False

  # SYN queue for listening sockets
  # Shared among all Sockets because there's no point in doing otherwise.
  # Eventually items in here either die or move to a Listener's accept queue.
  syn_queue = AcceptQueue()
  syn_queue_max = 4096

  MIN_RTO = 1  # Seconds
  MAX_RTO = 60 # Seconds

  # Maximum buffer sizes for tx_data and rx_data
  RX_DATA_MAX = 1024 * 1024 * 10 # Large buffer
  TX_DATA_MAX = 1024 * 1024

  # How often to probe zero windows?
  ZWP_TIMEOUT = 30 # RFC 793 says 120 seconds!

  _mss = None


  @property
  def state (self):
    return self._state

  @state.setter
  def state (self, v):
    if v != self._state:
      # Print a detailed log message
      callers = []
      for i in range(1,5):
        fr = inspect.stack()[i]
        if fr[0].f_locals.get("self") is not self: break
        callers.append("%s:%s" % (fr[3],fr[2]))
      callers = " ".join(callers)
      if callers: callers = " by " + callers
      self.log.debug("State %s -> %s%s", self._state, v, callers)

      # Change the state
      self._state = v

      # Might make a difference to someone
      self._unblock()

  @property
  def is_bound (self):
    return self.name != (None,None)

  @property
  def is_peered (self):
    return self.peer != (None,None)

  @property
  def is_connected (self):
    # Are there other cases here?
    return self.state in (ESTABLISHED,FIN_WAIT_1,FIN_WAIT_2,CLOSING)

  def _delete_tcb (self):
    """
    Called when socket is being truly closed
    """
    if self.parent:
      self.parent.syn_queue.discard(self)
      self.parent.accept_queue.discard(self)
    self.state = CLOSED
    self.manager.unregister_socket(self)
    self.log.info("Deleting TCB")

  def _new_packet (self, ack=True, data=None, syn=False):
    """
    Creates a new Packet for this connection

    Sets the IP several of the TCP fields.

    if ack is set, we set the ACK flag.
    if data is set, it is TCP payload data
    """
    assert self.is_peered
    assert self.is_bound
    p = self.stack.new_packet()
    p.ipv4 = pkt.ipv4(srcip = self.name[0], dstip = self.peer[0])
    p.ipv4.protocol = pkt.ipv4.TCP_PROTOCOL
    p.tcp = pkt.tcp(srcport = self.name[1], dstport = self.peer[1])

    p.ipv4.payload = p.tcp #FIXME: do this as part of Packet?

    p.tcp.seq = self.snd.nxt
    p.tcp.ack = self.rcv.nxt # Gets set regardless of ack param; is that ok?
    p.tcp.ACK = ack
    p.tcp.SYN = syn

    if self.allow_ws_option and p.tcp.SYN:
      if not p.tcp.ACK: # SYN
        add_ws = True # Always for SYN
      elif p.tcp.ACK:   # SYN+ACK
        wsopt = self.syn.tcp.get_option(pkt.tcp_opt.WSOPT)
        add_ws = wsopt is not None
      if add_ws:
        wnd = self.rcv.wnd
        shift = 0
        while wnd > 0xffFF:
          wnd >>= 1
          shift += 1
        shift = min(14, shift)
        self._rcv_wnd_shift = shift
        ws = pkt.tcp_opt(type=pkt.tcp_opt.WSOPT, val=shift)
        p.tcp.options.append(ws)
      else:
        self._rcv_wnd_shift = 0

    if self.allow_ts_option:
      # It'd probably be nice to be able to set _ts_last_ack here, but there
      # are cases where we create a new packet and then change the ack.
      # This means we set it in _tx and *also* in retx.
      ##self._ts_last_ack = p.tcp.ack # Assumes we're going to send the packet!

      if p.tcp.SYN and not p.tcp.ACK: # SYN
        # Offer the timestamp option
        add_ts = True
      elif p.tcp.SYN and p.tcp.ACK:   # SYN+ACK
        tsopt = self.syn.tcp.get_option(pkt.tcp_opt.TSOPT)
        add_ts = tsopt is not None
        if add_ts:
          # It hasn't actually been processed yet, so do it manually
          self._ts_recent = tsopt.val[0]
      elif self.use_ts_option is None:
        synp = (self.syn or self.synack)
        if synp is None:
          self.log.error("No SYN? %s %s", p.tcp.SYN, p.tcp.ACK)
        else:
          add_ts = synp.tcp.get_option(pkt.tcp_opt.TSOPT) is not None
          self.use_ts_option = add_ts
      else:
        add_ts = self.use_ts_option

      val = self._gen_timestamp()
      ech = (self._ts_recent or 0) if p.tcp.ACK else 0

      ts = pkt.tcp_opt(type=pkt.tcp_opt.TSOPT, val=(val,ech))
      p.tcp.options.append(ts)

    if data:
      p.tcp.payload = data
      self.snd.nxt = self.snd.nxt |PLUS| len(data)

    if self.state is LISTEN:
      pass
    elif (self.state in (SYN_SENT, SYN_RECEIVED)
          and self.zero_initial_window):
      pass
    else:
      p.tcp.win = self._get_wnd_advertisement()
      self._last_wnd_advertisement = p.tcp.win

    if data is None: self.log.info("CRAFTED PACKET WITH ACK %s", self.rcv.nxt|MINUS|self.rcv.isn) #XXX
    return p


  @property
  def stack (self):
    return self.manager.stack

  @property
  def log (self):
    l = getattr(self, "_log", None)
    if l: return l

    def name (n):
      if n == (None,None): return "?"
      return "%s:%s" % n

    nn = name(self.name) + "<->" + name(self.peer)
    l = log.getChild(nn)
    if "?" not in nn: self._log = l
    return l

  @property
  def mss (self):
    #TODO: Support the MSS option (RFC 6691)
    #TODO: Separate sending and receiving MSS?
    #TODO: Rename this!  It's not really the MSS but the max payload (which
    #      RFC 5681 seems to call the MSS so maybe it's fine?)

    if self._mss is not None: return self._mss
    #TODO: Clean this up so it computes things more reasonably (e.g.,
    #      actually taking IP/TCP options into account).

    mtu = self.stack.lookup_dst(self.peer[0])[0].mtu
    mss = mtu
    #mss -= 20 # Minimum IP
    mss -= 60 # Maximum IP
    #mss -= 20 # Minimum TCP
    mss -= 60 # Maximum TCP

    if mss <= 0:
      raise PSError("MSS is too small")
    elif mss <= 400:
      self.log.warn("MSS is very small")

    self._mss = mss
    return mss

  @property
  def smss (self):
    return self.mss

  @property
  def rmss (self):
    return self.mss

  def _is_dup_ack (self, seg):
    """
    Checks whether seg contains a duplicate ACK

    RFC 5681 S2 p4
    """
    if not seg.ACK: return False
    if not (self.tx_data or self.retx_queue): return False # Either or only tx?
    if seg.payload: return False
    if seg.SYN or seg.FIN: return False
    if seg.ack |NE| self.snd.una: return False
    if self._read_win(seg) != self.snd.wnd: return False
    return True


  def __init__ (self, manager, parent=None):
    self.manager = manager
    self.parent = parent

    # If this is a LISTEN socket, we have a queue of ready-to-go server
    # sockets that can be accept()ed.  Before the get in this queue,
    # they're in the global .syn_queue (while we're waiting for their
    # SYN+ACK to get ACKed).
    self.accept_queue = AcceptQueue()
    self.accept_queue_max = 0 # Set by listen()

    self._state = INITIAL

    self.snd = TXWindow()

    self.rcv = RXWindow()
    self.rcv.wnd = self.RX_DATA_MAX

    # Packets which were received out of order and thus need to be
    # held for later processing.
    self.rx_queue = PacketQueue() #TODO: Integrate with RXWindow?

    # Retransmission queue
    self.retx_queue = PacketQueue()

    # Send and recieve buffers
    self.rx_data = b''
    self.tx_data = b''

    # Number of dup ACKs for fast retransmit/recovery stuff in RFC 5681 S3.2
    self._dup_ack_count = 0

    # Amount of data sent due to limited transmit
    self.limited_transmit_sent = 0

    # This many bytes still need to be sent with PSH on
    self.tx_push_bytes = 0

    # This number of bytes in rx_data have been sent PSH
    self.rx_push_bytes = 0

    # RFC 6298
    self.rto = 1
    self.srtt = None
    self.rttvar = None
    self.alpha =  1.0/8
    self.beta = 1.0/4
    self.K = 4
    self.G = manager.TIMER_GRANULARITY # Timer granularity
    self._rto_backoff_count = 0 # Times backed off before new update

    ### These are from when we used to do a single RTT sample at a time.
    ##self._rtt_sample_seq = None # seq of packet used for RTT estimate
    ##self._rtt_sample_sent = 0   # time that RTT sample was sent

    # Sanity check
    if manager.TIMER_GRANULARITY > 0.5 and self.use_delayed_acks:
      self.log.error("Timer granularity too coarse for delayed ACKs")
      self.use_delayed_acks = False
    else:
      self.log.debug("ACK delay is %0.3f seconds", manager.TIMER_GRANULARITY)

    # Call all _INIT_ functions
    self._call_all("INIT")


  def _call_all (self, kind):
    """
    Call all methods with a name like _KIND_whatever
    """
    kind = "_" + kind.upper() + "_"
    for n in dir(self):
      if n.startswith(kind):
        f = getattr(self, n)
        if callable(f): f()



  # -------------------------------------------------------------------------
  #  Socket-like interface
  # -------------------------------------------------------------------------

  # These are socket-like calls.  They're used to implement socket calls.
  # They're kind of like the proto_ops functions in the Linux kernel.
  # They never block -- that's left up to something higher-level which
  # calls these underneath.

  _shut_rd = False # Has socket been shutdown for reading?


  def _INIT_socketlike (self):
    self._wakers = [] # Wake functions for poll()


  def _unblock (self):
    """
    Unblock any waiting socket-like consumers

    This calls whatever wake functions have been passed into poll().

    Essentially, anywhere in this class where an event happens which may cause
    a blocking socket function to unblock, we should call this function.  It's
    best to not call it unnecessarily, but it shouldn't actually break anything
    (it's just inefficient since it'll wake up blockers that will then just go
    right back to sleep).
    """
    for w in self._wakers:
      w()
    del self._wakers[:]


  def poll (self, wake):
    """
    Allow a socket-like consumer to register for event notification

    A consumer of the socket-like API might want to block.  For example, it
    may want to read a certain number of bytes.  recv(), however, will only
    return at most as are currently buffered -- it won't block.  So for the
    consumer to implement blocking, it calls poll() and passes in some
    function (a "wake" function).
    When this socket does something which might unblock the consumer, it
    calls the function.  That function should then check to see if progress
    has been made (e.g., can it read more data?).  It may then want to
    poll() again (if it still needs more data).
    Note that it's complete possible that the wake function will be called
    because of some irrelevant reason and the consumer won't be able to
    make any forward progress.  In particular, this is because there's
    only a single "signal", essentially telling the consumer, "Hey, *maybe*
    something useful happened -- you should check!"  This differs from Linux
    where a consumer can specify particular events it's interested in
    (e.g. POLLIN, POLLHUP, etc.).
    """
    self._wakers.append(wake)


  def unpoll (self, wake):
    """
    Removes a wake function if it's set
    """
    try:
      self._wakes.remove(wake)
      return True
    except ValueError:
      return False


  def connect (self, ip, port):
    if self.state is not INITIAL:
      raise PSError("operation illegal in %s" % (self.state,))

    self.peer = IPAddr(ip),port

    if self.is_bound:
      # For now, just assume the binding is good?
      pass
    else:
      dev = self.stack.lookup_dst(ip)[0]
      if dev is None: raise PSError("No route to " + str(ip))
      if not dev.ip_addr: raise PSError("No IP")
      self.bind(dev.ip_addr, 0)

    self.state = SYN_SENT

    rp = self._new_packet(ack=False, syn=True)
    rp.tcp.seq = self.snd.isn
    rp.tcp.ack = self.rcv.nxt

    self._tx(rp)


  def accept (self):
    if self.state is not LISTEN:
      raise PSError("operation illegal in %s" % (self.state,))
    if not self.accept_queue:
      raise PSError("no connection to accept")

    s = self.accept_queue.pop()

    return s


  def bind (self, ip, port):
    if self.state is not INITIAL:
      raise PSError("operation illegal in %s" % (self.state,))
    if self.is_bound:
      raise PSError("already bound")

    ip = IPAddr(ip)
    if port == 0:
      port = self.manager.get_unused_port(ip)
      if port is None:
        raise PSError("No free port")
    self.name = ip,port

    self.manager.register_socket(self)


  def listen (self, backlog=5):
    if self.state is not INITIAL:
      raise PSError("operation illegal in %s" % (self.state,))
    if not self.is_bound:
      raise PSError("socket not bound")

    self.state = LISTEN

    self.accept_queue_max = backlog


  def close (self):
    # RFC 793 p60
    if self.state is CLOSED:
      raise PSError("socket is closed")
    elif self.state is LISTEN:
      self._delete_tcb()
    elif self.state is SYN_SENT:
      self.shutdown(SHUT_RDWR)
      self._delete_tcb()
    elif self.state is SYN_RECEIVED:
      # The RFC demands that we queue the close() for processing until
      # after entering ESTABLISHED if send()s have been issued or there
      # is pending data to send.  In our implementation, this should
      # never be true, because send() is only valid from ESTABLISHED.
      # Thus, we can always do the simple thing.
      self.shutdown(SHUT_RDWR)
      self.state = FIN_WAIT_1
      self._set_fin_pending()
    elif self.state is ESTABLISHED:
      self.shutdown(SHUT_RDWR)
      self.state = FIN_WAIT_1
      self._set_fin_pending()
    elif self.state in (FIN_WAIT_1,FIN_WAIT_2):
      raise PSError("close() is invalid in FIN_WAIT states")
    elif self.state is CLOSE_WAIT:
      self.shutdown(SHUT_RDWR)
      if self._fin_pending or self._fin_sent:
        # Hmm... what should happen here?
        self.log.warn("close() called while socket shutting down")
      else:
        self._set_fin_pending(next_state = LAST_ACK)
    elif self.state in (CLOSING,LAST_ACK,TIME_WAIT):
      raise PSError("connecting closing")
    else:
      raise PSError("operation illegal in %s" % (self.state,))


  def shutdown (self, how):
    if how & SHUT_WR:
      if not (self._fin_sent or self._fin_pending):
        self._set_fin_pending()
        self.tx_push_bytes = len(self.tx_data)
    if how & SHUT_RD:
      self._shut_rd = True
      self.rx_data = b'' # Make adv window go back up


  def recv (self, length=None, flags=0):
    """
    Returns up to length (nonblocking)

    Returns None if no more data can be forthcoming.
    """
    # RFC 793 p58
    if flags: raise NotImplementedError()

    # Here's some old code inspired by the RFC.  See below.

    ##if self.state is CLOSED:
    ##  raise PSError("socket is closed")
    ##elif self.state in (LISTEN, SYN_SENT, SYN_RECEIVED):
    ##  # There can't be any data yet
    ##  return b''
    ##elif self.state in (CLOSE_WAIT, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2):
    ##  if length is None: length = len(self.rx_data)
    ##  b = self.rx_data[:length]
    ##  self.rx_data = self.rx_data[length:]
    ##  self.rcv.wnd = self.RX_DATA_MAX - len(self.rx_data)
    ##  if (not b) and (self.state is CLOSE_WAIT):
    ##    return None
    ##  return b
    ###elif self.state in (CLOSING, LAST_ACK, TIME_WAIT):
    ###  # Maybe return None here?
    ###  return None
    ##else:
    ##  raise PSError("operation illegal in %s" % (self.state,))

    # The above is closer to the RFC, but let's try the following new
    # socket-friendly logic:
    # * If socket shut down for reading, complain
    # * If socket is LISTEN socket, complain
    # * Try to read any data available
    # * If there's data waiting, allow reading it.
    # * If no more data and in a state where we could never get more
    #   (e.g., CLOSED), return None

    if self._shut_rd: raise PSError("socket shut down for reading")

    if self.state is LISTEN:
      # Never anything to read on LISTEN sockets!
      raise PSError("operation illegal in %s" % (self.state,))

    if length is None: length = len(self.rx_data)
    b = self.rx_data[:length]
    self.rx_data = self.rx_data[length:]

    if self.rx_push_bytes:
      # The socket interface doesn't really do anything with PSH, but...
      # we track it anyway?
      self.rx_push_bytes -= len(b)
      if self.rx_push_bytes <= 0:
        self.rx_push_bytes = 0
        self.log.debug("All pushed RX data has been read")

    self.rcv.wnd = self.RX_DATA_MAX - len(self.rx_data)

    # Update the other side on our window if it has changed.
    # We only do this if the window had been pretty small (or closed)
    cur = self._get_wnd_advertisement()
    prv = self._last_wnd_advertisement
    self._last_wnd_advertisement = cur
    if prv == 0 and cur != 0:
      self.log.warn("Local window had closed")
      self._set_ack_pending()
      self._maybe_send_pending_ack()
    elif cur > prv:
      prv <<= self._snd_wnd_shift
      cur <<= self._snd_wnd_shift
      split = self.rmss * 10
      if prv < split and cur >= split:
        # It opened up from pretty small.
        if self._ack_pending == 0: self._ack_pending = 1 #FIXME: this is ugly!
        self._maybe_send_pending_ack()
        self.log.info("Local window had been small")

    if (not b) and (self.state in (CLOSE_WAIT,CLOSED)):
      return None
    return b


  def send (self, data, flags=0, push=False, wait=False):
    """
    Send some data

    Currently, no flags are supported.
    Also, we allow manually specifying the push flag, which socekts interfaces
    generally don't.
    wait is also not part of the sockets interface.  If True, we just queue up
    data to send, but don't actually try to send it yet.
    """
    # RFC 793 p56
    # We vary from the RFC in a few ways.  First, we just don't allow
    # sends from some states that is wants you to queue things up
    # from.  Also, we just don't allow send() from LISTEN.
    if flags: raise NotImplementedError()

    if self._fin_pending or self._fin_sent:
      pass # Go to failure case below
    elif self.state is CLOSED:
      raise PSError("socket is closed")
    elif self.state in (ESTABLISHED, CLOSE_WAIT):
      remaining = self.TX_DATA_MAX - len(self.tx_data)
      assert remaining >= 0
      if remaining < len(data):
        data = data[:remaining]
      self.tx_data += data.encode('ascii')
      if push: self.tx_push_bytes = len(self.tx_data)
      if wait is False: self._maybe_send()
      return len(data)

    raise PSError("operation illegal in %s" % (self.state,))


  @property
  def bytes_readable (self):
    if self.state is LISTEN: return 0
    if self._shut_rd: return 0
    return len(self.rx_data)


  @property
  def bytes_writable (self):
    if self._fin_pending or self._fin_sent: return 0
    if self.state in (ESTABLISHED, CLOSE_WAIT):
      return self.TX_DATA_MAX - len(self.tx_data)
    return 0


  def _spawn_server_socket (self, packet):
    """
    Initialize a server socket

    Sets up this socket, which was spawned by a listening socket.

    Among other things, this puts us in the syn queue and sends a SYN.
    """
    if len(self.syn_queue) >= self.syn_queue_max:
      self.log.warn("Listening socket dropping SYN because queue full")
      return False

    if packet.ipv4.srcip.is_multicast:
      log.warn("TCP to multicast address not supported")
      return False

    s = Socket(self.manager, parent=self)
    s.syn = packet

    self.syn_queue.push(s)

    tp = packet.tcp
    s.peer = packet.ipv4.srcip,tp.srcport
    s.name = packet.ipv4.dstip,tp.dstport

    s.state = SYN_RECEIVED

    self.manager.register_socket(s)

    # RFC 793 p66
    s.rcv.isn = tp.seq
    s.rcv.nxt = tp.seq |PLUS| 1

    rp = s._new_packet(syn=True)
    rp.tcp.seq = s.snd.isn
    rp.tcp.ack = s.rcv.nxt

    s._tx(rp)

    return True

  # -------------------------------------------------------------------------



  # -------------------------------------------------------------------------
  #  Sending
  # -------------------------------------------------------------------------

  _retx_start = None # Time at which retransmit timer started

  retx_on_rto_count = None # max packets to retx when RTO expires
                           # None for no maximum


  def _maybe_send (self):
    """
    If we have pending tx_data, try to send some

    When there is data in tx_data that we can send, segmentize it and
    call _send() on it (which transmits it puts it in the retx_queue).
    """
    self._maybe_handle_zero_window()

    if not self.tx_data: return
    if self._fin_sent:
      self.log.error("Have data to send, but FIN already sent!")
      return

    # RFC 5681 S4.1 p11
    if self.last_send_ts is not None:
      # If we haven't sent data for longer than RTO, we set cwnd to RW.
      # The RFC says we do this if we haven't *received* data for longer
      # than an RTO.  But this is about wanting to restart the ACK clock
      # when we're *sending*, so isn't this more direct?
      if self.stack.now - self.last_send_ts > self.rto:
        self.log.debug("Reset cwnd = RW")
        self.cwnd = self.RW
        self.last_send_ts = None

    def get_send_size (limited_tx=True):
      cwnd = self.cwnd
      if self._dup_ack_count in (1,2):
        # Limited transmit RFC 3042 S2 / RFC 5681 3.2 (1) p9
        # This allows extra segments-worth of data to be in flight.
        delta = (self._dup_ack_count * self.smss) - self.limited_transmit_sent
        assert delta >= 0, "Sent too much via limited transmit"
        cwnd += delta
      ##window_size = min(self.snd.window_size, cwnd)
      window_size = min(self.snd.wnd, cwnd)
      max_size = window_size - self.flight_size
      self.log.debug("WND rwnd:%s cwnd:%s/%s wnd:%s flt:%s max:%s dupack:%s", self.snd.wnd, self.cwnd,cwnd, window_size, self.flight_size, max_size if max_size > 0 else 0, self._dup_ack_count) #XXX
      if max_size <= 0: return 0 # Already too much in flight
      return min(len(self.tx_data), max_size)

    total_size = get_send_size(limited_tx=True)

    if not total_size: return

    lt_sent = (total_size - get_send_size(limited_tx=False))
    self.limited_transmit_sent += lt_sent
    if lt_sent:
      self.log.info("%s bytes sent due to limited transmit")

    # Now actually segmentize it...
    count = 0
    remaining = total_size
    while remaining > 0:
      size = int(min(remaining, self.smss))
      remaining -= size
      data = self.tx_data[:size]
      self.tx_data = self.tx_data[size:]

      p = self._new_packet(data=data)

      if self.tx_push_bytes:
        self.tx_push_bytes -= size
        if self.tx_push_bytes < 0: self.tx_push_bytes = 0
        # Set PSH flag in last PSH segment, per RFC 793 p46
        if self.tx_push_bytes == 0: p.tcp.PSH = True

      self._tx(p)
      count += 1

    if count:
      self.log.debug("Sent %s packet(s) (%s payload bytes, %s remain)", count, total_size, len(self.tx_data))
      self.log.info("SENT TOT:%s  NEW:%s  FLT:%s BUF:%s", p.tcp.seq|MINUS|self.snd.isn, total_size, self.flight_size, len(self.tx_data))
    return count


  def _reset_retx_timer (self):
    if not self.retx_queue:
      # RFC 6298 5.2
      self._retx_start = None
      self.log.info("ReTX timer stopped")
    else:
      self._retx_start = self.stack.now
      #self.log.info("ReTX timer started (RTO:%s)", self.rto)


  def _maybe_retx (self, seqno = None):
    """
    Possibly retransmit data

    If from_timer is True, we are maybe going to do a retx due to possible
    RTO expiration.  Otherwise, we are being told to do a retx (e.g., due to
    fast retransmit).
    """
    #TODO: Check if .SYN is set, and if so, count how many SYNs we've set and
    # compare to maximum self.syn_retries.  Also possibly adjust retry rate
    # for SYNs?

    from_timer = seqno is None

    if self.state is CLOSED: return
    if from_timer:
      if self._retx_start is None:
        assert not self.retx_queue # If there is, timer should be running!
        return # No timer running
      if self._retx_start + self.rto > self.stack.now: return # Not expired yet

    if from_timer:
      self._recover = self.snd.nxt |MINUS| 1
      if self._in_fast_recovery:
        self._exit_frr()

    if from_timer:
      maximum = self.retx_on_rto_count
      if maximum is None: maximum = 0xffFFffFF # Lots and lots
      # The idea behind sending more than one is that if we've actually hit the
      # RTO, then we may have had multiple losses; if we hadn't, we'd hopefully
      # have entered FR/R.
    else:
      maximum = 1

    start_packet = 0
    if seqno:
      for i,p in enumerate(self.retx_queue):
        if p.tcp.seq |MGE| seqno:
          if (p.tcp.seq |PLUS| tcplen(p.tcp)) |MGT| seqno:
            self.log.info("Fast ReTX packet #%s (%s, %s)", i, p.tcp.seq, seqno)
            start_packet = i
            break
      else:
        self.log.warn("No packet %i (%i) for fast retx", seqno, seqno|MINUS|self.snd.isn)
        for i,p in enumerate(self.retx_queue):
          self.log.warn("> %s %s", p.tcp.seq, p.tcp.seq|MINUS|self.snd.isn)

    sent = 0
    for which in range(maximum):
      if (which+start_packet) >= len(self.retx_queue): break
      #now = self.stack.now
      p = self.retx_queue[which+start_packet]
      #age = p.tx_ts - now
      #if age < self.rto: return

      # RFC 6298 5.4
      # So it seems like we can update the ack field and window here, for
      # example.  When I first wrote this, I thought it'd be easiest to
      # just create a new packet and copy relevant stuff from the old one
      # into it.  I now think maybe just updating the old one would be
      # easier...
      np = self._new_packet(ack = p.tcp.ACK, syn = p.tcp.SYN)
      if p.tcp.ACK: self._unset_ack_pending()
      np.tcp.FIN = p.tcp.FIN
      np.tcp.PSH = p.tcp.PSH
      np.tcp.seq = p.tcp.seq
      np.tcp.payload = p.tcp.payload
      np.tx_ts = p.tx_ts
      np.retx_ts = self.stack.now #TODO: Remove?
      np.timeout_count = p.timeout_count + 1
      self.retx_queue[which+start_packet] = np # Replace old one
      if np.tcp.ACK: self._ts_last_ack = np.tcp.ack # Kind of ugly to have here

      #NOTE: Old single-RTT-sample stuff
      ##if np.tcp.seq == self._rtt_sample_seq:
      ##  # We're retransmitting this, so it's no longer valid as an RTT
      ##  # measurement, as per RFC 6298 S3 / PK88.
      ##  self._rtt_sample_seq = None

      self.manager.tx(np)
      sent += 1

      if which == 0 and from_timer:
        # Do this a max of once per call
        # Inform CC of timeout
        self._on_rto_retx(p.timeout_count == 0)

        # Get out of FR/R
        # I think this is correct based on RFC 6582 S3.1 paragraph 2
        self._exit_frr()

        # Doesn't make sense to me to do this for FRR, only timer
        # RFC 6298 5.5
        self._back_off_rto()

      # RFC 6298 5.7
      if self.state is SYN_SENT and self.rto < 3:
        # Hmm... are there other cases we need to do this?
        self.rto = 3

      self.log.debug("ReTX seq:%s len:%s rto:%s delta_time:%s", p.tcp.seq|MINUS|self.snd.isn,
                     0 if not p.tcp.payload else len(p.tcp.payload),
                     self.rto,
                     np.retx_ts - np.tx_ts)
      self.log.error("cwnd:%s flt:%s", self.cwnd, self.flight_size) #XXX

    # RFC 6298 5.6
    self._reset_retx_timer()

    return sent

  def _tx (self, p):
    """
    Send this packet

    Send the packet.  If the packet is something retransmittable (that is, the
    packet takes up sequence number space), put it in the retx queue.

    This is only used for initial transmissions, not retransmissions.
    """
    p.tx_ts = self.stack.now
    self.manager.tx(p)
    self.last_send_ts = p.tx_ts # RFC 5681 S4.1 p11

    if p.tcp.ACK:
      self._unset_ack_pending()
      self._ts_last_ack = p.tcp.ack

    #168: Skip this part for early version
    if p.tcp.SYN or p.tcp.FIN or p.tcp.payload:
      # This is something retransmittable.  So put it in the retx queue.
      self.retx_queue.push(p)

      # And make sure retransmit timer is running (RFC 6298 5.1)
      self._reset_retx_timer()

      #NOTE: Old single-RTT-sample stuff
      ##if self._rtt_sample_seq is None:
      ##  # Start a new RTT measurement
      ##  self._rtt_sample_seq = p.tcp.seq
      ##  self._rtt_sample_sent = self.stack.now
      ##  self.log.debug("RTT sample rseq:%i seq:%i", p.tcp.seq|MINUS|self.snd.isn, p.tcp.seq) #XXX


  def _process_ack (self, ack):
    """
    Removes ACKed entries from the retx queue
    """
    #self.log.debug("ReTX queue size: %s", len(self.retx_queue))
    old = 0 # Number of completely ACKed entries

    for p in self.retx_queue:
      seq = p.tcp.seq
      length = 1 if (p.tcp.FIN or p.tcp.SYN) else 0
      if p.tcp.payload: length += len(p.tcp.payload)

      partial = False
      if seq |MLT| ack:
        # Start of packet is ACKed
        partial = True
        #NOTE: Used to do RTT measurement here

      #print "seq(%s) < ack(%s) ? %s" % (seq,ack,seq|MLT|ack)
      #print ( "(seq(%s)+length(%s) = %s) <= ack(%s) ? %s"
      #        % (seq,length,seq|PLUS|length,ack,(seq|PLUS|length)|MLE|ack) )

      if (seq |PLUS| length) |MLE| ack:
        # Entire packet is acknowledged
        old += 1
      elif partial:
        # We're going to chop off the ACKed part at the front of this packet
        # and keep the rest in the retx queue.
        # This is a bit tricky and it's quite possibly buggy.
        seg = p.tcp
        acked_bytes = ack |MINUS| seq
        if seg.SYN:
          # We must have ACKed the SYN (since partial).  It's conceptually
          # at the start of the packet, so we acked 1 fewer bytes
          acked_bytes = acked_bytes |MINUS| 1
          seg.SYN = False # Remove SYN
        # We don't mess with acked_bytes for the FIN because it conceptually
        # "comes after" the data. (RFC 793 p26 at the bottom)
        self.log.warn("Segment partially ACKed (%s bytes of %s)",
                      acked_bytes,len(seg.payload))
        p.app = p.app[acked_bytes:]
        seg.seq = ack
        # Why did I write this? assert len(p.tcp.payload) > acked_bytes
        break
      else:
        # Not even partially ACKed
        break

    if old: self.retx_queue.pop_head(old)
    if old or len(self.retx_queue):
      self.log.debug("Removed %s segment(s) from ReTX queue (%s remain)",
                     old, len(self.retx_queue))
      self.log.debug("ACK:%s", ack |MINUS| self.snd.isn)

  # -------------------------------------------------------------------------



  # -------------------------------------------------------------------------
  #  Receive
  # -------------------------------------------------------------------------

  def rx (self, packet):
    """
    Called when a new packet arrives

    Processing goes something like this:
    * Possibly update the RTO based on this packet
    * Process the TCP timestamp (e.g., possibly update RTO and we *should*
      reject it if it fails a timestamp / PAWS check (currently unimplemented)
    * Process the new packet
    * If we have packets in rx_queue which can now be processed (because the
      new packet filled in a gap in the sequence space), process those
    * Try to send data, since the new packet may have changed the windows
      such that we now can
    * Send pending ACKs or FINs
    * Reset the ZWP timer since we just got window info from the new packet
    """

    # We do these first because we always want to do them immediately when
    # we get a packet, not subject to the in-order replay out of rx_queue.
    # But only do them if the packet is somewhere near expected seqno.
    # This seems kind of ugly and maybe we can move these into the normal
    # rx path.
    if self.state not in (CLOSED, LISTEN, SYN_SENT):
      lo = self.rcv.nxt|MINUS|(self.rcv.wnd // 2)
      hi = self.rcv.nxt|PLUS|(self.rcv.wnd // 2)
      if (packet.tcp.seq|MGE|lo) and (packet.tcp.seq|MLE|hi):
        if self.use_ts_option:
          self._process_timestamp(packet.tcp)
        else:
          self._maybe_update_rto(packet.tcp)

    if self._rx_one(packet): return

    while self.rx_queue and self.rx_queue[0].tcp.seq |LE| self.rcv.nxt:
      p = self.rx_queue.pop()
      self.log.debug("RX queued packet (seq:%s nxt:%s)",p.tcp.seq|MINUS|self.rcv.isn,self.rcv.nxt|MINUS|self.rcv.isn)
      if self._rx_one(p): return

    self._maybe_send()

    if self.state is LISTEN: return # No ACKs or FINs!

    # RFC 1122 S4.2.2.20 p 93 says that in general you must aggregte ACKs,
    # and specifically says that when processing a series of queued segments,
    # you must process them all before ACKing them.  So we do ACK-sending
    # here -- after processing the queue.  And we do it after _maybe_send,
    # since if it sends, it will also have ACKed.
    self._maybe_send_pending_ack()

    self._maybe_send_pending_fin()

    self._maybe_handle_zero_window()

    #TODO: We should probably do more fine-grained things internally, but a
    #      rx can surely do stuff that will unblock someome (e.g., change the
    #      window size or flight size).  So this may well over-unblock, but
    #      that's okay for now.  (Perhaps ublocking should be done via having
    #      variables that might unblock be properties...)
    self._unblock()


  def _rx_one (self, packet):
    """
    Called to process a single packet

    This is called by rx() to actually process a packet (though this function
    mostly just further outsources it)

    Returns True if the connection just closed
    """
    seg = packet.tcp
    tp = packet.tcp
    if self.state is CLOSED:
      if not tp.RST:
        # Send a RST
        rp = self._new_packet(ack=False)
        rp.tcp.RST = True
        if not tp.ACK:
          rp.tcp.seq = 0
          rp.tcp.ack = tp.seq |PLUS| tcplen(tp)
          rp.tcp.ACK = True
        else:
          rp.tcp.seq = tp.ack
        self._tx(rp)
      return False
    elif self.state is LISTEN:
      if self._rx_listen(packet) is False:
        pass
        #self.log.warn("Bad RX on LISTEN socket")
    elif self.state is SYN_SENT:
      self._rx_syn_sent(packet)
    else:
      self._rx_other(packet)

    return self.state is CLOSED


  def _rx_listen (self, packet):
    # RFC 793 p64
    tp = packet.tcp
    if tp.RST: return False
    if tp.FIN: return False
    if tp.ACK: return False
    if not tp.SYN: return False
    # It's a SYN
    return self._spawn_server_socket(packet)


  def _rx_syn_sent (self, packet):
    # RFC 793 p66

    is_other = packet.tcp.URG or packet.tcp.payload

    ack_ok = False
    if packet.tcp.ACK: # first
      if packet.tcp.ack |MLE| self.snd.isn or packet.tcp.ack |MGT| self.snd.nxt:
        if packet.tcp.RST: return
        #TODO: Check that this works
        rp = self._new_packet()
        rp.tcp.RST = True
        rp.tcp.seq = packet.tcp.ack
        self._tx(rp)
        return
      if (self.snd.una |MLE| packet.tcp.ack) and (packet.tcp.ack |MLE| self.snd.nxt):
        ack_ok = True
      else:
        self.log.warn("ACK unacceptable?") #FIXME

    if packet.tcp.RST: # second
      if ack_ok:
        self.log.warn("error: connection reset")
        self._delete_tcb()
      return

    # third - check security (ignored)

    if packet.tcp.SYN: # fourth (p68)
      self.rcv.nxt = packet.tcp.seq |PLUS| 1
      self.rcv.isn = packet.tcp.seq
      if packet.tcp.ACK:
        self.snd_una_advance(packet.tcp.ack)
        #NOTE: The RFC (top of page 68) says that we should remove any ACKed
        #      segments from the retx queue here.  Since we haven't hit
        #      ESTABLISHED yet, there should never be any.

      if self.snd.una |MGT| self.snd.isn:
        if self._establish(packet) is False:
          # Ack; abort!
          return

        # Next three lines are from RFC 1122 p94 (c)
        self.snd.wnd = self._read_win(packet.tcp)
        self.snd.wl1 = packet.tcp.seq
        self.snd.wl2 = packet.tcp.ack

        self._set_ack_pending()
        #FIXME: Continue processing in sixth step of normal RX (see RFC)
        #       This should only apply is is_other is True, and we don't
        #       really support that at present.

        if ack_ok:
          #TODO: Refactor with ESTABLISHED?
          seg = packet.tcp
          #NOTE: Used to do timestamp processing here.
          self._process_ack(seg.ack)
          self.snd_una_advance(seg.ack)
          self._reset_retx_timer() # RFC 6298 5.3
      else:
        # double-active connect
        rp = self._new_packet(syn=True)
        rp.tcp.seq = self.snd.isn

        self._tx(rp)

        self.state = SYN_RECEIVED

        if is_other:
          #TODO: Handle this case; queue up the data
          self.log.error("Double-active connect SYN had control or data")
        return
    else:
      return

    if is_other:
      #TODO: Handle this!  Deliver the data.
      self.log.error("SYN_SENT got control or data it won't handle")


  def _rx_other (self, packet):
    # RFC 793 p69...
    seg = packet.tcp
    rcv = self.rcv
    snd = self.snd

    if len(seg.payload) > 1: self.log.warn("GOT SEQ %s", seg.seq|MINUS|self.rcv.isn)


    if not rcv.check_accept(seg):
      # RFC 793 on page 69 has a statement that confuses me a bit.  It says
      # that if rcv.wnd is zero, no segments will be acceptable, but special
      # allowance should be made for valid ACKs, URGs, and RSTs.  ACKs with
      # no payload should already work, because of the first clause in
      # check_accept.  Same goes for standalone RSTs.  URGs, maybe not, but
      # I don't know (or, at the moment, care).  Is this just saying that we
      # need to process the ACK itself even if we ignore the data?  Okay,
      # we should probably do that.  On the other hand, their acceptance-
      # checking algorithm (and possibly some of the below -- based directly
      # on the RFC) are weirdly unhelpful for that case.

      #TODO: We should still handle valid ACKs, URGs, and RSTs...

      if seg.RST: return

      if not packet.app:
        self.log.error("Possibly-acceptable packet being ignored")
        #FIXME: FIXME FIXME FIXME!

      self._set_ack_pending()
      return

    #TODO: Move this block of stuff into Window?
    if seg.seq |EQ| rcv.nxt:
      pass # Perfect
    elif seg.seq |MLT| rcv.nxt:
      # Old sequence number (at least the start)
      # May contain new in-window data?  May just be a dup?
      # Can we just process as normal?  Let's try...
      self._set_ack_pending() # Send ACK per RFC 5681 p8
      self.log.debug("Packet with old sequence number")
    else:
      # It's a packet from the future; queue for later.
      self.rx_queue.push(packet)
      self._set_ack_pending() # Send ACK per RFC 5681 p8
      self.log.debug("Future packet queued for later (seq:%s nxt:%s)",
                     seg.seq|MINUS|rcv.isn, rcv.nxt|MINUS|rcv.isn)
      return

    if seg.RST:
      if self.state is SYN_RECEIVED:
        if self.parent is not None:
          # Must be from listen/passive-open
          # This differs from the behavior described in the RFC because we do
          # Berkeley sockets style listen/accept sockets.
          self._delete_tcb()
          return
        # Must be from double active open
        self.log.error("connection refused")
        #TODO: signal real error somehow
        self._delete_tcb()
        return
      elif self.state in (ESTABLISHED,FIN_WAIT_1,FIN_WAIT_2,CLOSE_WAIT):
        #TODO: flush segment queues (do we need to?)
        self.log.error("connection reset")
        self._delete_tcb()
        return
      elif self.state in (CLOSING,LAST_ACK,TIME_WAIT):
        self._delete_tcb()
        return

    if seg.SYN: # "fourth" (p71)
      # The next bit is an addition from RFC 1122 p94 (part e)
      if self.state is SYN_RECEIVED and self.parent is not None:
        # This is a passive open socket; RFC 1122 p94 (part e)
        # Note that the RFC says to go back to LISTEN, but *this* socket
        # was never actually in LISTEN, and the listening socket has
        # never *left* LISTEN.  So we just close and clean up.
        # This is another outcome of the RFC listen behavior not matching
        # with socket listen behavior.
        self._delete_tcb()
        return

      if self.state in (SYN_RECEIVED,ESTABLISHED,FIN_WAIT_1,FIN_WAIT_2,
                        CLOSE_WAIT,CLOSING,LAST_ACK,TIME_WAIT):
        # RFC says if the SYN is in the window, it's an error... and if
        # we get here, I think the SYN is always in the window!
        self.log.error("connection reset (by SYN)")

        #TODO: Check if this RST works
        rp = self._new_packet()
        rp.tcp.RST = True
        rp.tcp.seq = seg.ack
        self._tx(rp)

        self._delete_tcb()
        return

    # "fifth" (p72)
    if not seg.ACK: return

    if self.state is SYN_RECEIVED:
      if (snd.una |MLE| seg.ack) and (seg.ack |MLE| snd.nxt):
        # Woo!
        if self._establish(packet) is False:
          # Ack!  Abort!
          return False

        # Next three lines are from RFC 1122 p94 (f/c)
        self.snd.wnd = self._read_win(packet.tcp) # Read advertised window
        self.snd.wl1 = packet.tcp.seq
        self.snd.wl2 = packet.tcp.ack
      else:
        rp = self._new_packet()
        rp.tcp.RST = True
        rp.tcp.seq = seg.ack
        self._tx(rp)
        return

    if self.state in (ESTABLISHED,FIN_WAIT_1,FIN_WAIT_2,CLOSE_WAIT,CLOSING):
      # This part of 793 seems like kind of a mess
      # It's also sort of the heart of normal RX operations.

      if seg.ack |MGT| snd.nxt:
        # Acking beyond what we've sent!  Send an ACK and ignore
        self._set_ack_pending()
        self.log.info("Bad ACK ignored")
        return
      elif seg.ack |MLT| snd.una:
        # It's a duplicate ACK
        self.log.info("Got duplicate ACK ack:%s (seq:%s) or ack:%s (seq:%s)",
                      seg.ack, seg.seq,
                      seg.ack|MINUS|self.snd.isn, seg.seq|MINUS|self.rcv.isn)
        pass

      if (snd.una |MLE| seg.ack) and (seg.ack |MLE| snd.nxt):
        # Above is updated by RFC 1122 (g)

        # Fast retransmit/recovery stuff from RFC 5681 S3.2
        was_in_frr = False # True if we were in FRR when packet arrived
        if self._is_dup_ack(seg):
          self._dup_ack_count += 1
          self.log.debug("Dup ACKs: %s", self._dup_ack_count)

          if not self._in_fast_recovery:
            if self._dup_ack_count == 1:
              # Limited transmit RFC 3042 / RFC 5681 3.2 (1) p9
              self.limited_transmit_sent = 0
            elif self._dup_ack_count == 3:
              if seg.ACK and (seg.ack|MINUS|1) |MGT| self._recover: # RFC 6582 3.2
                self._recover = self.snd.nxt |MINUS| 1
                self._in_fast_recovery = True
                # RFC 5681 3.2 (2) p9
                self.ssthresh = (self.flight_size-self.limited_transmit_sent)/2
                self.ssthresh = max(self.ssthresh, 2*self.smss)
                # RFC 5681 3.2 (3) p9
                # This step of the RFC doesn't actually have a condition
                # associated with it, but I think it just follows immediately
                # after the previous one.
                self.cwnd = self.ssthresh + 3 * self.smss
                self.log.info("FAST RETX %s %s", self.snd.una|MINUS|self.snd.isn, seg.ack|MINUS|self.snd.isn)
                if not self._maybe_retx(self.snd.una):
                  self.log.warn("No retransmission in fast retransmit")
          else:
            # RFC 5681 3.2 (4) p9
            # We're in fast recovery.  We inflate the window, which should
            # allow more segments to be sent.
            self.cwnd += self.smss
        else:
          self._dup_ack_count = 0

        self._process_ack(seg.ack)

        if (snd.una |MLT| seg.ack):

          # SS/CA signal for RFC 5681
          self._on_unacked_data_acked(seg)
          #TODO: Adjust above for SYN/FIN in computing size of ACKed data?

          self.snd_una_advance(seg.ack)
          self._reset_retx_timer() # RFC 6298 5.3

        # Update window
        if ( (snd.wl1 |MLT| seg.seq)
            or
           ( (snd.wl1 |EQ| seg.seq) and snd.wl2 |MLE| seg.ack) ):
          snd.wnd = self._read_win(seg)
          snd.wl1 = seg.seq
          snd.wl2 = seg.ack

      if self.state == FIN_WAIT_1:
        #XXX: Uncomment this log
        ##self.log.debug("FIN_WAIT_1 snd.nxt:%s seg.ack:%s fin_seq:%s",
        ##               self.snd.nxt, seg.ack, self._fin_seqno)
        if self._acks_our_fin(seg.ack):
          self.state = FIN_WAIT_2
          # Do we want to fall through to the next case too?
          # I don't think so...
      elif self.state == FIN_WAIT_2:
        pass
        # The RFC says that we can now acknowledge the users' call to close().
        # For sockets API, is there really much we can do to acknowledge it?
        # I think maybe we just let it go.
      elif self.state == CLOSING:
        if self._acks_our_fin(seg.ack):
          self.state = TIME_WAIT
    elif self.state == LAST_ACK:
      # Check if FIN ACKed (p73)
      if self._acks_our_fin(seg.ack):
        self._delete_tcb()
        return # Should we return anyway?
    elif self.state == TIME_WAIT:
      self._set_ack_pending()
      # Restart 2 MSL timeout
      self._start_time_wait()
      return

    # "sixth" p73
    if seg.URG:
      self.log.error("Urgent data not supported")
      #TODO: Implement this someday
      return

    old_rcv_nxt = rcv.nxt

    #NOTE: Used to do timestamp processing here.

    # "seventh" Process segment data! (p74)
    #FIXME: This should probably be done by the netdev?  I think the dominant
    #       case for the TCP/IP stack is that we don't want L7 parsed.
    payload = seg.payload
    if payload is None: payload = b''
    elif not isinstance(payload, bytes): payload = payload.pack()

    if payload:
      if self.state in (ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2):
        self._process_payload(packet, payload)
      else:
        self.log.warn("Got data while in state %s", self.state)

    # "eighth" check the FIN (p75)
    if seg.FIN:
      if self.state in (CLOSED,LISTEN,SYN_SENT):
        return

      self.log.debug("Got FIN%s", "" if not payload else
                     " on a packet with payload")

      # The RFC says to signal the user "connection closing" and have
      # pending recv() get the same message.  We actually let recv()
      # take care of itself (if there's data in rx_data, we actually
      # want pending recv()s to get it before we start signaling that
      # the connection is closed).

      # The FIN is conceptually "after" the payload
      got_fin_seq = seg.seq |PLUS| len(payload)

      if self.rcv.nxt |EQ| got_fin_seq:
        # Advance over the FIN
        self.rcv.nxt = self.rcv.nxt |PLUS| 1
      else:
        self.log.warn("FIN seq isn't rcv.nxt (%s != %s) with payload size %s",
                      seg.seq, self.rcv.nxt, len(payload))
      self._set_ack_pending()

      if self.state in (SYN_RECEIVED,ESTABLISHED):
        self.state = CLOSE_WAIT
      elif self.state is FIN_WAIT_1:
        if self._acks_our_fin(seg.seq):
          # Our FIN is ACKED
          self._start_time_wait()
          #TODO: The RFC says to turn off the timers besides the TIME-WAIT
          #      one.  Do we need to do that?  Can it be inferred from the
          #      current state?
        else:
          self.state = CLOSING
      elif self.state is FIN_WAIT_2:
        self._start_time_wait()
      elif self.state is TIME_WAIT:
        self._start_time_wait() # Well, restart it in this case.


  def _process_payload (self, packet, payload):
    # RFC 793 p74

    seg = packet.tcp
    rcv = self.rcv

    if seg.seq |MLT| rcv.nxt:
      # Overlaps with data we already have; cut off the beginning
      offset = rcv.nxt |MINUS| seg.seq
      data = payload[offset:]
    elif seg.seq |EQ| rcv.nxt:
      data = payload
    else:
      # segment in future
      # This shouldn't happen on any code path known at the time of writing
      # because we put such packets into rx_queue and replay them when
      # they're in order.
      raise RuntimeError("Can't process packet from the future")

    if len(data) > rcv.wnd: data = data[:rcv.wnd] # Partial rx!

    if not data: return

    rcv.nxt = rcv.nxt |PLUS| len(data)

    #TODO: Congestion control?
    rcv.wnd -= len(data)

    assert rcv.wnd >= 0 # Due to partial rx adjust above, should be true

    self._set_ack_pending(delayable=True)

    # If reading is shut, just throw away data
    if not self._shut_rd: self.rx_data += data

    if packet.tcp.PSH or packet.tcp.FIN: # FIN implies PSH
      self.rx_push_bytes = len(self.rx_data)

    self._unblock()


  def _establish (self, packet):
    """
    Enter established state
    """
    assert packet.tcp.SYN or self.syn is not None

    if self.parent:
      assert not self in self.parent.accept_queue # I don't think this should happen?
      if len(self.parent.accept_queue) >= self.parent.accept_queue_max:
        # Accept queue full -- "drop" packet
        return False
      self.parent.accept_queue.push(self)
      self.parent.log.debug("Accept queue (size %s) got %s",
                            len(self.parent.accept_queue), self)
      self.parent._unblock()

    if self.syn is None: self.synack = packet

    synp = (self.syn or self.synack)
    wsopt = synp.tcp.get_option(pkt.tcp_opt.WSOPT)
    if self.allow_ws_option and wsopt is not None:
      self._use_ws_option = True
      self._snd_wnd_shift = min(wsopt.val, 14)
      if wsopt.val > 14: # RFC 7323 explains that shift can be at most 14.
        self.log.warn("Got window scale option with shift of %s", wsopt.val)
      # Leave rcv wnd shift as its computed value
    else:
      self._use_ws_option = False
      self._snd_wnd_shift = 0
      self._rcv_wnd_shift = 0

    self.state = ESTABLISHED
    return True

  # -------------------------------------------------------------------------



  # -------------------------------------------------------------------------
  #  ACK management
  # -------------------------------------------------------------------------

  _ack_pending = 0

  def _unset_ack_pending (self):
    """
    Mark no ACK as pending

    If we had an ack pending, we don't anymore.
    """
    self._ack_pending = 0

  def _set_ack_pending (self, delayable=False):
    """
    Express that we want to send an ACK

    The immediate result of this function is incrementing _ack_pending.
    Every time we actually send an ACK, we reset _ack_pending to zero.

    There are times that we know we want to send an ACK, but we might not
    want to send it *right now* for a couple of reasons.  The first use
    of this is simply to avoid sending an ACK packet if we end up sending
    a packet containing an ACK anyway (e.g., a data segment).
    The second use is implementing delayed ACKs.

    _maybe_send_pending_ack is called from appropriate places and, if
    _ack_pending is >= 2, an ACK is sent.  Thus, we increment _ack_pending
    by 2 to create an un-delayable ACK (the default), or 1 if the ACK
    is delayable.  Thus, two calls to this function will definitely
    result in an ACK sooner rather than later.

    Note that the RFC allows you to delay up to two MSS or so
    of data.  Since this function is called per *packet* we want to ACK
    no matter their size, we may send more ACKs than necessary (which is
    allowed by the RFC).
    """
    if self.use_delayed_acks is False: delayable = False
    self._ack_pending += 1 if delayable else 2


  def _maybe_send_pending_ack (self, ignore_delay=False):
    """
    If there's an ACK pending, send it.

    If ignore_delay, send any pending delayed ACK.

    This function is called in at least two cases.  The first is right
    after processing an incoming segment, since we may want to ACK it.
    The second is in a timer.  This ensures that we don't wait too long
    before sending a delayed ACK.

    The RFC says the maximum delayed ACK is 500ms.  We don't keep track
    of an actual deadline; instead, then timer just calls this function
    every time it elapses with ignore_delay set.  Thus, the actual
    maximum ACK delay is entirely a function of the timer granularity.
    Also note this means the timer must fire at least every 500ms!
    """
    if self._ack_pending >= 2:
      pass
    elif self._ack_pending and ignore_delay:
      pass
    else:
      return # No ACK

    self._ack_pending = 0

    self._tx(self._new_packet())

  # -------------------------------------------------------------------------



  # -------------------------------------------------------------------------
  #  FIN management
  # -------------------------------------------------------------------------

  _fin_pending = False
  _fin_sent = False
  _fin_seqno = None # if _fin_sent, this is the FIN's seqno
  _fin_next_state = None


  def _acks_our_fin (self, ack):
    """
    Checks whether an ACK acknowledges our FIN

    ack is a sequence number the other side has ACKed.
    """
    #NOTE: It's possible that we actually want one function which checks if
    #      our FIN has been ACKed in general, and another which checks if a
    #      given seqno ACKs it.  Or that this function support both of those
    #      slightly different queries.
    if self._fin_seqno is None: return False # We haven't sent, so no!

    if ack |MGE| self._fin_seqno: return True

    return False

  def _set_fin_pending (self, next_state = None):
    """
    Set our intention to send a FIN

    Sometimes we know we want to send a FIN, but we can't actually do it
    yet.  This happens when there's still data waiting in the tx_buffer --
    the FIN needs to come *after* it's all been sent.  So when we want to
    send a FIN, we call this function.  Periodically,
    _maybe_send_pending_fin() will check to see if a FIN is pending and
    take action when appropriate.

    next_state, if specified, is a new state to transition into once the
    FIN has actually been set.
    """
    if self._fin_sent and (next_state is not None):
      self.log.error("Tried to set FIN pending with new state, but FIN has "
                     "already been sent")
      if self.state is ESTABLISHED:
        self.state = next_state
      return
    self._fin_pending = True
    self._fin_next_state = next_state
    self._maybe_send_pending_fin()


  def _maybe_send_pending_fin (self):
    """
    Possibly send a pending FIN and change state

    If we have a pending FIN and the tx_buffer has gone empty, we can
    finally send the FIN.  If a new post-FIN state has been specified,
    we transition to it.

    We could think about piggybacking this on a data segment, but we
    currently don't.
    """
    if not self._fin_pending: return
    if self._fin_sent: return
    if self.tx_data: return # Still data to be sent

    self._fin_pending = False
    self._fin_sent = True
    if self._fin_next_state is not None:
      self.state = self._fin_next_state

    rp = self._new_packet()
    rp.tcp.FIN = True
    self._tx(rp)

    self.snd.nxt = rp.tcp.seq |PLUS| 1 # FIN takes up seq space
    self._fin_seqno = self.snd.nxt

  # -------------------------------------------------------------------------



  # -------------------------------------------------------------------------
  #  TIME_WAIT management
  # -------------------------------------------------------------------------

  _time_wait_ends_at = None

  # How long do we stay in TIME_WAIT before going to CLOSED?
  TIME_WAIT_TIMEOUT = 30

  def _start_time_wait (self):
    """
    Enters TIME_WAIT

    This enters TIME_WAIT and sets the timer for when we switch to CLOSED.
    This can also be used to reset the TIME-WAIT timer.
    """
    self.state = TIME_WAIT
    self._time_wait_ends_at = self.stack.now + self.TIME_WAIT_TIMEOUT

  def _maybe_do_time_wait_timeout (self):
    """
    If the TIME_WAIT period is over, close this socket

    Called from timer
    """
    if self._time_wait_ends_at is None: return
    if self._time_wait_ends_at > self.stack.now: return
    self._time_wait_ends_at = None
    self._delete_tcb()

  # -------------------------------------------------------------------------



  # -------------------------------------------------------------------------
  #  Zero Window Probe
  # -------------------------------------------------------------------------

  _zwp_at = None # Time to send ZWP or None
  _zwps_sent = 0 # Is reset every time we have a nonzero window
  _zwp_max_interval = 30 # Longest interval between ZWPs


  def _reset_zwp_timer (self, reset_backoff = True):
    """
    Helper for _maybe_handle_zero_window
    """
    if reset_backoff: self._zwps_sent = 0
    backoff = self._zwps_sent + 1
    interval = min(backoff * self.rto, self._zwp_max_interval)
    self._zwp_at = self.stack.now + interval

    # Just for logging purposes...
    prev_interval = min((backoff-1) * self.rto, self._zwp_max_interval)
    if interval == self._zwp_max_interval and prev_interval != interval:
      self.log.debug("Zero window probe timeout at the maximum")


  def _maybe_handle_zero_window (self):
    """
    Make sure we're doing the right thing with respect to zero rwnds

    # If we have a zero rwnd, the timer should be on and we should maybe send
    # a zero window probe.  If we don't have a zero window, the timer should
    # be off.
    """
    if self.state in (LISTEN,CLOSED): return
    if self.rcv.wnd != 0:
      if self._zwp_at is not None:
        # Stop timer
        self.log.debug("Receive window no longer zero")
        self._zwp_at = None
      return
    elif self._zwp_at is None:
      if not self.tx_data: return # No need to probe
      # Timer should be running!
      self._zwps_sent = 0 # make sure is reset
      # ZWP timer not running, but should be!
      self._reset_zwp_timer()

    if self.stack.now < self._zwp_at: return # Not elapsed yet

    if self._zwps_sent == 0:
      self.log.debug("Sending zero window probes")

    self._zwps_sent += 1 # Back it off
    self._reset_zwp_timer(reset_backoff=False) # Keep it going

    p = self._new_packet()
    p.tcp.seq = p.tcp.seq |MINUS| 1 # Keepalive-like; one less than window
    self._tx(p)

  # -------------------------------------------------------------------------



  # -------------------------------------------------------------------------
  #  Timer
  # -------------------------------------------------------------------------

  def _do_timers (self):
    """
    Run the various timers

    This should be called periodically
    """
    self._maybe_retx()
    self._maybe_do_time_wait_timeout()
    self._maybe_handle_zero_window()
    self._maybe_send_pending_ack(ignore_delay=True)

  # -------------------------------------------------------------------------



  # -------------------------------------------------------------------------
  #  RTO stuff
  # -------------------------------------------------------------------------

  def _on_rto_retx (self, first_retx):
    """
    Called when a packet has timed out and is being resent

    first_retx is True if this is the first time this particular
    segment has timed out.

    This is basically called to update CC
    """
    if first_retx:
      # RFC 5681 p7 (4)
      self.ssthresh = max(self.flight_size/2, 2*self.smss)

    self.cwnd = self.LW # Back to slow start


  def _maybe_update_rto (self, seg):
    """
    Given an incoming packet, possibly updates the RTO

    This only uses classic once-per-window RTT measurement.  Timestamp-based
    RTT measurment is done by _process_timestamp().
    """
    if not seg.ACK: return # Couldn't be responding to a sample!

    # This is similar to the expensive timestamp RTT update heuristic.
    # We search through the retx queue and find the packet that is
    # being ACKed.  We kept a timestamp of when we sent it, so we can
    # compute its RTT, ignoring it if it has actually been
    # *re*-transmitted.  Once we have it, we can check the delta from
    # when we sent the packet until now and pass that to _update_rto().
    # We need to set the "expected_samples" the same way as for the
    # TS-based version because the values for _update_rto() were
    # based on the assumption that we're only doing one sample per RTT,
    # but we're actually doing it for almost every packet because we
    # are keeping track of the time we sent each packet (so it ends
    # up being similar to the timestamp version).

    # Here, we use the (expensive but better?) heuristic of making sure
    # the ACK corresponds to something in the retx queue.
    for p in self.retx_queue:
      if seg.ack |MGT| p.tcp.seq:
        if seg.ack |MLE| (p.tcp.seq |PLUS| tcplen(p.tcp)):
          # This ACK falls within this packet.  Suitable for estimation.
          #NOTE: ACK division (as in TCP Daytona) can actually cause us
          #      to overly-weight the divided packet's RTT.  We might
          #      want to only consider ACKs which end exactly on a
          #      particular packet.  This goes for timestamp-based RTT
          #      estimation as well.
          if p.retx_ts is not None:
            # It's been retransmitted, so we don't want to use it for RTT
            # estimation after all.
            break

          self.log.debug("Maybe using packet to update RTO (rack:%s ack:%s "
                         "una:%s nxt:%s)", seg.ack|MINUS|self.snd.isn, seg.ack,
                                           self.snd.una,self.snd.nxt)
          t = self.stack.now - p.tx_ts
          if t > 0: #TODO: More sanity checks?
            expected_samples = ceil(self.flight_size / (self.smss * 2))
            # Hmm... Why not partial expected_samples?
            if expected_samples > 0: # At least one expected sample!
              self._update_rto(t, expected_samples)

          return
      else:
        break

    self.log.debug("Not using packet to update RTO (rack:%s)", seg.ack|MINUS|self.snd.isn) #XXX
    #NOTE: We used to reset the rtt sample variable here.


  def _update_rto (self, R, expected_samples = 1):
    """
    Updates .rto given an RTT sample R

    The expected_samples parameter is used when computing based on TCP
    timestamps, as described in RFC 7323 Appendix G.
    """
    self._rto_backoff_count = 0

    if self.srtt is None:
      # First measurement
      self.srtt = R
      self.rttvar = R/2.0
    else:
      alpha = self.alpha / expected_samples
      beta = self.beta / expected_samples
      self.rttvar = (1-beta)*self.rttvar + beta*abs(self.srtt-R)
      self.srtt = (1-alpha)*self.srtt + alpha*R

    old_rto = self.rto

    self.rto = self.srtt + max(self.G, self.K*self.rttvar)
    self.rto = min(self.MAX_RTO, max(self.MIN_RTO, self.rto)) # Clamp RTO

    #self.rto = ceil(self.rto * 2) / 2.0 # Quantize to half-sec (nice for debug)

    msg = ( "RTO now %0.3f (was:%0.3f - R:%0.3f SRTT:%0.3f RTTVAR:%0.3f)"
            % (self.rto, old_rto, R, self.srtt, self.rttvar) )
    #if self.rto != old_rto:
    if abs(self.rto - old_rto) > 0.5: # Big change
      self.log.info(msg)
    else:
      self.log.debug(msg)


  def _back_off_rto (self):
    """
    Exponential backoff of RTO

    This comes from RFC 6298 5.5
    """
    fmt = lambda x: "---" if x is None else "%0.3f" % (x,)
    self.log.warn("RTO BACKOFF now %0.3f (was:%0.3f - R:--- SRTT:%s RTTVAR:%s)"
                  % (self.rto*2, self.rto, fmt(self.srtt), fmt(self.rttvar)))
    self.rto *= 2 # Back off timer
    self._rto_backoff_count += 1
    if self._rto_backoff_count > 2:
      # RFC 6298 S5 at the very end mentions maybe doing this, and it is
      # probably a very good idea.  This is the whole reason we keep track
      # of backoff counts, so that we can reset these if we back off
      # "multiple" times (could we infer it based on the SRTT vs. RTO?).
      # This will force the next estimate to completely reset RTO rather
      # than needing to smooth in the next estimate which could take
      # absolutely forever if we had packet loss which closed down cwnd
      # while we had a bunch of packets in flight so that we can't
      # make much forward progress on new data.
      self.srtt = None
      self.rttvar = None
    if self.rto > self.MAX_RTO: self.rto = self.MAX_RTO

  # -------------------------------------------------------------------------



  # -------------------------------------------------------------------------
  #  Congestion control stuff
  # -------------------------------------------------------------------------

  ssthresh = 0xffFFffFFff # A big number
  ca_acked_bytes = 0 # Num bytes ACKed in congestion avoidance

  # Timestamp we last sent data, for RFC 5681 p4.1 p11
  last_send_ts = None # None means ignore

  # We do cwnd as a property so that it calculates IW as late as possible
  # (e.g., possibly after the MSS option) without having to maybe check/set
  # it in multiple places.
  _cwnd = None
  @property
  def cwnd (self):
    if self._cwnd is None:
      self._cwnd = self.IW
    return self._cwnd
  @cwnd.setter
  def cwnd (self, value):
    if value != self.cwnd: self.log.debug("CWND CHANGE %s -> %s (flgt:%s)", self._cwnd, value, self.flight_size) #XXX
    if value < 0:
      self.log.warn("CWND being set to negative value")
      return
    self._cwnd = value

  @property
  def flight_size (self):
    return self.snd.nxt |MINUS| self.snd.una

  @property
  def in_slow_start (self):
    return self.cwnd < self.ssthresh

  @property
  def IW (self):
    """
    Initial window as per RFC 5681
    """
    #RFC 5681 S3.1 p5
    #NOTE: This may need updating for PMTUD (RFC 1191).  See RFC 5681 p5.
    smss = self.smss
    # The RFC also says these MOST NOT be more than 2, 3, and 4 segments.
    # What else do we need to do to ensure that?
    if smss > 2190: return 2 * smss
    elif smss > 1095: return 3 * smss
    return 4 * smss

  @property
  def LW (self):
    """
    Loss window as per RFC 5681
    """
    return self.smss

  @property
  def RW (self):
    """
    Restart Window per RFC 5681 S4.1 p11
    """
    return min(self.IW, self.cwnd)


  def _on_unacked_data_acked (self, seg):
    """
    Called when "new" data is ACKed

    Previously unacknowledged data has now been ACKed

    acked_bytes is the count of ACKed bytes
    was_in_frr is True if we had been in FRR
    """
    acked_bytes = seg.ack |MINUS| self.snd.una

    assert acked_bytes > 0

    if self._in_fast_recovery:
      # This is based on RFC 6582 3.2 (3) p5 (NewReno)
      if seg.ack |MGT| self._recover:
        # Full acknowledgement
        self.log.debug("FRR Full ACK")
        # Deflate the window
        self.cwnd = min(self.ssthresh, max(self.flight_size, self.smss) + self.smss)
        self._exit_frr()
      else:
        # Partial acknowledgement
        self.log.debug("FRR Partial ACK; retx rseq:%s seq:%s", self.snd.una|MINUS|self.snd.isn, self.snd.una) #XXX
        if not self._maybe_retx(self.snd.una):
          self.log.warn("No retransmission in NewReno fast retransmit")
        self.cwnd -= acked_bytes
        if acked_bytes >= self.smss:
          self.cwnd += self.smss
        self._partial_ack_count += 1
        if self._partial_ack_count == 1:
          self._reset_retx_timer()
      return

    # RFC 5681 S3.1 p6
    old_cwnd = self.cwnd
    if self.in_slow_start:
      self.cwnd += min(acked_bytes, self.smss)
      #XXX Uncomment this log!
      self.log.debug("SS CWND %s -> %s (acked_bytes:%s smss:%s)",
                     old_cwnd, self.cwnd, acked_bytes, self.smss)
      if not self.in_slow_start:
        self.log.error("Leaving slow start and entering congestion avoidance")
        self.ca_acked_bytes = 0
    else: # congestion avoidance
      # This is (hopefully) the recommended method from RFC 5681 p6
      # It uses a new state variable (ca_acked_bytes), but avoids
      # Daytona ACK division issues as in TCP ABC (RFC 3465).
      # Note that if there are "extra" acked bytes (beyond cwnd), we
      # just throw them away.  This is sort of inexact, but it's meant
      # to make sure that we never increment more than SMSS per RTT
      # which is what the RFC wants.

      self.ca_acked_bytes += acked_bytes
      if self.ca_acked_bytes >= self.cwnd:
        self.cwnd += self.smss
        self.ca_acked_bytes = 0


  def _exit_frr (self):
    """
    Called to exit FRR
    """
    self._dup_ack_count = 0
    self.limited_transmit_sent = 0
    self._in_fast_recovery = False
    self._partial_ack_count = 0


  def _INIT_newreno (self):
    # Keep a separate FRR flag as per RFC 6582 S6 p10
    # Initially set when dup_ack_count == 3
    self._in_fast_recovery = False

    # Point that signifies a complete recovery when in FRR
    self._recover = self.snd.isn

    # Number of partial ACKs in FRR
    self._partial_ack_count = 0


  def snd_una_advance (self, ackno):
    greater = self.snd.una |MGE| self._recover
    self.snd.una_advance(ackno)
    if not self._in_fast_recovery:
      if (self.snd.una |MGE| self._recover) != greater:
        # We've wrapped around so just set it to the start.
        # (This is an attempt to address the issue mentioned in paragraph 3 of
        # RFC 6582 S6.)
        self._recover = self.snd.una

  # -------------------------------------------------------------------------



  # -------------------------------------------------------------------------
  #  TCP Timestamp Option
  # -------------------------------------------------------------------------

  allow_ts_option = True # Set to False to disable timestamp option
  _ts_granularity = 1    # In ms (1=1ms, 1000=1s)

  use_ts_option = None   # Gets set to True or False; used internally
  _ts_recent = None      # A recent TS from the peer
  _ts_last_ack = None    # Last ACKno we sent
  _ts_hash = None        # Stored hash used to offset TS values

  expensive_ts_heuristic = False # Selects the heuristic for RTO update

  def _INIT_timestamp (self):
    # If we just create timestamps starting at zero, they'll look almost the
    # same on both sides of the connection.  So we want to have them be
    # different.  And we want them to be deterministic (probably).  So we
    # base them off of the stack name.  *But* we can't just do a simple hash
    # of the stack name, because with a plain hash function, the difference
    # between, e.g., hash("r1") and hash("r2") is not very large, which
    # again means that the tsval and tsecr look almost the same.  So we use
    # a cryptographic hash against the stack name to actually get some real
    # difference, but still have it be deterministic.
    self._ts_hash = hash(hashlib.md5(self.stack.name.encode('utf-8')).hexdigest())
    self._ts_hash &= 0xffFFffFF
    self._ts_hash &= 0xffFF # Chop high bits off (Easier to read)

  def _gen_timestamp (self):
    ts = int(self.stack.now * 1000 / self._ts_granularity) # 10ms granularity
    ts = ts |PLUS| self._ts_hash
    return ts

  def _process_timestamp (self, seg):
    if not self.use_ts_option: return
    if not seg.ACK: return
    #TODO: Do PAWS here?
    ts = seg.get_option(pkt.tcp_opt.TSOPT)
    if ts is None:
      if self.use_ts_option is True:
        if not seg.RST:
          #TODO: We *should* drop this packet!  See RFC 7323 p12/13, etc.
          self.log.error("Was expecting TCP timestamp, but didn't get one")
      return
    tsval,tsech = ts.val
    if (self._ts_recent is None) or (tsval |MGE| self._ts_recent):
      if (self._ts_last_ack is None) or (seg.seq |MLE| self._ts_last_ack):
        if tsval != 0:
          # We ignore TS values of 0 since middleboxes may be causing them.
          # Is this a good idea?
          self._ts_recent = tsval
    if (tsech != 0):
      # Again, ignore 0
      ts_update = False

      # We don't want to pay attention to just any old TS echo, because if we
      # haven't sent a packet in a while, the echo could be arbitrarily old!
      # This might happen if the connection goes quiet and then the other
      # side sends a ZWP or starts sending new data or a keepalive, etc.
      # Essentially, we only want to pay attention to it if we think this
      # packet is in reply to something we sent recently.  There are a few
      # ways we could decide this.  A simple heuristic would be if we had
      # any unacknowledged data (snd.nxt != snd.una).  We might then
      # limit that so that seg.ack needs to be somewhere in that window.
      # This is probably pretty good, though duplicates and such might
      # throw it off.  Perhaps a bit better is checking to see whether the
      # ACK corresponds to a packet in our retx queue.  If so, we obviously
      # sent it recently.  This will also (at least in some cases)
      # prevent us from factoring the same timestamp into our RTT calculation
      # multiple times even if the packet was duplicated (assuming that
      # the first one led to its removal from the retx queue before we
      # got the next one, which isn't necessarily a sure thing at present
      # since we always process packets in order, but it's at least
      # *some* protection against this).  This also means that we don't use
      # timestamps on duplicate ACKs even though we potentially could.
      # Note that this isn't necessary for non-TS RTT estimation because we
      # keep track of the specific seqno we are sampling, and we only choose a
      # sample if it's going to be ACKed (e.g., because it has data or a SYN).

      if seg.ACK:
        if self.expensive_ts_heuristic:
          # Here, we use the (expensive but better?) heuristic of making sure
          # the ACK corresponds to something in the retx queue.
          for p in self.retx_queue:
            if seg.ack |MGT| p.tcp.seq:
              if seg.ack |MLE| (p.tcp.seq |PLUS| tcplen(p.tcp)):
                # This ACK falls within this packet.  Suitable for estimation
                ts_update = True
                break
            else:
              break
        else:
          # Here's the simple heuristic.  It only is really meant to accomplish
          # two things: 1) Make sure it's not some completely rogue packet
          # (possibly spoofed), 2) Make sure it might be timely.  We do this
          # by making sure that we are expecting ACKs and that this ACK is not
          # beyond what we've sent.
          if self.snd.una |NE| self.snd.nxt:
            if seg.ack |MLE| self.snd.nxt:
              ts_update = True

      if ts_update:
        # Sloppy log message...
        self.log.debug("Maybe using TS to update RTO (rack:%s ack:%s una:%s"
                       " nxt:%s)", seg.ack|MINUS|self.snd.isn, seg.ack,
                                   self.snd.una,self.snd.nxt)
        tsdif = self._gen_timestamp() |MINUS| tsech
        t = float(tsdif) * self._ts_granularity / 1000
        if t > 0: #TODO: More sanity checks?
          expected_samples = ceil(self.flight_size / (self.smss * 2))
          # Hmm... Why not partial expected_samples?
          if expected_samples > 0: # At least one expected sample!
            self._update_rto(t, expected_samples)
      else:
        self.log.debug("Not using TS to update RTO")

  # -------------------------------------------------------------------------



  # -------------------------------------------------------------------------
  #  Window scaling option
  # -------------------------------------------------------------------------

  allow_ws_option = True  # Whether to allow window scaling
  _use_ws_option = None   # Whether WS is enabled
  _snd_wnd_shift = 0 # From received option
  _rcv_wnd_shift = 0 # Gets computed when sending a SYN/SYN+ACK

  _last_wnd_advertisement = 0

  def _read_win (self, seg):
    """
    Returns the real value of the advertised window in a segment

    The only trick here is that the value may be scaled, and this accounts
    for that possibility.
    """
    if seg.SYN: return seg.win
    return seg.win << self._snd_wnd_shift


  def _get_wnd_advertisement (self):
    """
    Get the current size of the window to advertise
    """
    shift = self._rcv_wnd_shift if self._use_ws_option else 0
    return min(0xffFF, self.rcv.wnd >> shift)

  # -------------------------------------------------------------------------
