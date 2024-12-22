from pox.core import core
log = core.getLogger()

from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt

# We don't support/implement SYN_RECEIVED, LISTEN states
from tcpip.tcp_sockets import CLOSED, LISTEN, SYN_RECEIVED, ESTABLISHED, \
                              SYN_SENT, FIN_WAIT_1, FIN_WAIT_2, CLOSING, \
                              TIME_WAIT, CLOSE_WAIT, LAST_ACK

from . modulo_math import *

from socket import SHUT_RD, SHUT_WR, SHUT_RDWR
import random
import inspect
import functools

"""
Partially implements following RFCs:

793: Transmission Control Protocol
6298: Computing TCP's Retransmission Timer
1122: Requirements for Internet Hosts -- Communication Layers
"""

class StudentUSocketBase(object):
  """
  Most of this class implements the interface to POX.
  """
  _state = CLOSED

  peer = (None, None) # peer's ip, port
  name = (None, None) # our ip, port

  # Maximum buffer sizes for tx_data and rx_data
  RX_DATA_MAX = 1024 * 1024 * 10 # Large buffer
  TX_DATA_MAX = 1024 * 1024

  _mss = None

  def __init__(self, manager):
    self.manager = manager

    # Send and receive buffers
    self.rx_data = b''
    self.tx_data = b''

    self._init_socketlike()

  @property
  def state(self):
    return self._state

  @state.setter
  def state(self, v):
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
  def is_bound(self):
    return self.name != (None,None)

  @property
  def is_peered(self):
    return self.peer != (None,None)

  @property
  def is_connected(self):
    return self.state in (ESTABLISHED,FIN_WAIT_1,FIN_WAIT_2,CLOSING)

  @property
  def stack(self):
    return self.manager.stack

  @property
  def log(self):
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
  def mss(self):
    if self._mss:
      return self._mss

    mtu = self.stack.lookup_dst(self.peer[0])[0].mtu
    mss = mtu
    mss -= 60 # Maximum IP
    mss -= 60 # Maximum TCP

    if mss <= 0:
      raise RuntimeError("MSS is too small")
    elif mss <= 400:
      self.log.warn("MSS is very small")

    self._mss = mss
    return mss

  def _delete_tcb(self):
    """
    Called when socket is being truly closed
    """
    self.state = CLOSED
    self.manager.unregister_socket(self)
    self.log.info("Deleting TCB")

  def _init_socketlike(self):
    self._wakers = [] # Wake functions for poll()

  def _unblock(self):
    for w in self._wakers:
      w()
    del self._wakers[:]

  def poll(self, wake):
    self._wakers.append(wake)

  def unpoll(self, wake):
    """
    Removes a wake function if it's set
    """
    try:
      self._wakes.remove(wake)
      return True
    except ValueError:
      return False

  def bind(self, ip, port):
    assert self.state is CLOSED
    assert not self.is_bound

    ip = IPAddr(ip)
    if port == 0:
      port = self.manager.get_unused_port(ip)
      if port is None:
        raise RuntimeError("No free port")
    self.name = ip,port

    self.manager.register_socket(self)


  def shutdown(self, how):
    pass

  def recv(self, length=None, flags=0):
    """
    Returns up to length (nonblocking)
    """
    assert not flags
    assert self.state not in (LISTEN, SYN_RECEIVED)

    if length is None:
      length = len(self.rx_data)

    b = self.rx_data[:length]
    self.rx_data = self.rx_data[length:]
    self.rcv.wnd = self.RX_DATA_MAX - len(self.rx_data)
    return b

  def send(self, data, flags=0, push=False, wait=False):
    """
    Send some data
    """
    # RFC 793 p56
    # We vary from the RFC in a few ways.  First, we just don't allow
    # sends from some states that is wants you to queue things up
    # from.  Also, we just don't allow send() from LISTEN.
    assert not flags

    if self.state is CLOSED:
      raise RuntimeError("socket is closed")
    elif self.state in (ESTABLISHED, CLOSE_WAIT):
      remaining = self.TX_DATA_MAX - len(self.tx_data)
      assert remaining >= 0
      if remaining < len(data):
        data = data[:remaining]

      self.tx_data += data.encode('ascii')
      if not wait:
        self.maybe_send()

      return len(data)

    raise RuntimeError("operation illegal in %s" % (self.state,))

  @property
  def bytes_readable(self):
    return len(self.rx_data)

  @property
  def bytes_writable(self):
    if self.state in (ESTABLISHED, CLOSE_WAIT):
      return self.TX_DATA_MAX - len(self.tx_data)

    return 0


class RXControlBlock:
  """
  Maintains the receive sequence space for a socket
  """
  nxt = 0  # next expected receive sequence number
  wnd = 0  # receive window

class TXControlBlock:
  """
  Maintains the send sequence space for a socket
  """
  una = 0  # oldest unacknowledged sequence number
  nxt = 0  # next send sequence number to use
  wnd = 0  # send window
  wl1 = 0  # seg sequence num used for last window update
  wl2 = 0  # seg ack num used for last window update)
  iss = 0  # initial send sequence number

  def __init__ (self):
    # RFC 793 p66
    self.iss = random.randint(1,0xFFffFFff)
    self.nxt = self.iss |PLUS| 1
    self.una = self.iss

class FinControl:
  socket = None
  sent = False
  sent_seqno = 0
  next_state = None
  pending = False

  def __init__(self, socket):
    self.socket = socket

  def acks_our_fin(self, ack):
    """
    Checks whether an ACK acknowledges our FIN

    ack is a sequence number the other side has ACKed.
    """
    if not self.sent_seqno:
      return False

    return ack |GE| self.sent_seqno

  def set_pending(self, next_state = None):
    """
    Set our intention to send a FIN

    Sometimes we know we want to send a FIN, but we can't actually do it
    yet.  This happens when there's still data waiting in the tx_buffer --
    the FIN needs to come *after* it's all been sent.  So when we want to
    send a FIN, we call this function.  Periodically,
    try_send() will check to see if a FIN is pending and
    take action when appropriate.

    next_state, if specified, is a new state to transition into once the
    FIN has actually been set.
    """
    assert not self.sent

    self.pending = True
    self.next_state = next_state
    self.try_send()

  def try_send (self):
    """
    Possibly send a pending FIN and change state

    If we have a pending FIN and socket.tx_data is empty, we can
    finally send the FIN. If a new post-FIN state has been specified,
    we transition to it.
    """
    if not self.pending or self.sent or self.socket.tx_data:
      return

    rp = self.socket.new_packet()
    rp.tcp.FIN = True
    self.socket.tx(rp)

    if self.next_state:
      self.socket.state = self.next_state

    self.socket.snd.nxt = rp.tcp.seq |PLUS| 1  # FIN takes up seq space
    self.sent_seqno = self.socket.snd.nxt
    self.pending = False
    self.sent = True

class RetxQueue(object):
  """
  A retransmission queue for packets. The queue assumes all packets
  are push()ed in ascending sequence order.
  """
  def __init__(self):
    self.q = []

  def push(self, p):
    """
    p is an IP packet

    Add p at end (must always be in order)
    """
    seq_no = p.tcp.seq
    # all seq no must be in order
    assert len(self.q) == 0 or seq_no |GT| self.q[-1][0]

    self.q.append((seq_no, p))

  def pop(self):
    """
    Removes and returns a tuple (seq_no, p) where p is an IP
    packet at the front of the queue, and seq_no is the TCP
    sequence number of p.
    """
    return self.q.pop(0)

  def pop_upto(self, seq_no):
    """
    seq_no is an int

    Returns a list of tuples as defined by pop().
    Pops packets as long as their sequence number are < seq_no, or
    the queue is empty.
    """
    packets = []
    while len(self.q) > 0:
      if self.q[0][0] |GE| seq_no:
        break

      packets.append(self.pop())

    log.debug("pop up to seq={0}, pkts={1}".format(seq_no, packets))
    return packets

  def get_earliest_pkt(self):
    """
    Returns (does not remove) the tuple (seq_no, p) where p is the packet
    with the minimum transmission timestamp (tx_ts), and seq_no is p's
    sequence number.
    """
    if not self.q:
      return None

    return min(self.q, key=lambda x: x[1].tx_ts)

  def empty(self):
    """
    Returns whether the queue is empty
    """
    return len(self.q) == 0

  def peek(self):
    """
    Returns the tuple (seq_no, packet) with the smallest seq_no in the queue,
    but does not remove it from the queue.
    """
    return self.q[0]

class RecvQueue(RetxQueue):
  """
  Implements a receive queue that behaves almost exactly like
  a RetxQueue, except packets push()ed can arrive out of order.
  """
  def __init__(self):
    super(RecvQueue, self).__init__()

  def push(self, p):
    """
    p is an IP packet

    Pushes a packet to the end of the queue, then checks if the new
    packet is out of order, if so, it sorts the queue on ascending
    sequence number order.
    """
    def compare(x, y):
      if x[0] == y[0]:
        return 0
      elif x[0] |LE| y[0]:
        return -1
      else:
        return 1

    self.q.append((p.tcp.seq, p))

    # if new packet is out of order
    if len(self.q) > 1 and self.q[-2][0] |GT| self.q[-1][0]:
      self.q.sort(key=functools.cmp_to_key(compare))



class StudentUSocket(StudentUSocketBase):
  MIN_RTO = 1  # Seconds
  MAX_RTO = 60 # Seconds

  ack_pending = False

  next_timewait = float('inf')
  TIMER_TIMEWAIT = 30 #  30 secs

  # RFC 6298
  rto = 1  # retransmission timeout
  srtt = 0  # smoothed round-trip time
  rttvar = 0  # round-trip time variation
  alpha =  1.0/8
  beta = 1.0/4
  K = 4
  G = 0  # clock granularity

  def __init__(self, manager):
    super(StudentUSocket, self).__init__(manager)

    self.G = manager.TIMER_GRANULARITY # Timer granularity

    self.fin_ctrl = FinControl(self)
    self.retx_queue = RetxQueue()
    self.rx_queue = RecvQueue()

  def _do_timers(self):
    """
    Called by POX every so often (100s of ms); you must not call this directly.
    """
    self.check_timer_retx()
    self.check_timer_timewait()

  def new_packet(self, ack=True, data=None, syn=False):
    """
    Creates and returns a new TCP segment encapsulated in an IP packet.

    If ack is set, it sets the ACK flag.
    If data is set, it is set as the TCP payload.
    If syn is set, it sets the SYN flag
    """
    assert self.is_peered
    assert self.is_bound
    p = self.stack.new_packet()
    p.ipv4 = pkt.ipv4(srcip = self.name[0], dstip = self.peer[0])
    p.ipv4.protocol = pkt.ipv4.TCP_PROTOCOL
    p.tcp = pkt.tcp(srcport = self.name[1], dstport = self.peer[1])
    p.ipv4.payload = p.tcp

    p.tcp.seq = self.snd.nxt
    p.tcp.ack = self.rcv.nxt
    p.tcp.ACK = ack
    p.tcp.SYN = syn

    if data:
      p.tcp.payload = data

    p.tcp.win = min(0xffFF, self.rcv.wnd)
    return p

  def close(self):
    assert self.state not in (SYN_RECEIVED, LISTEN)
    # RFC 793 p60
    if self.state is CLOSED:
      raise RuntimeError("socket is closed")
    elif self.state is SYN_SENT:
      self._delete_tcb()
    elif self.state is ESTABLISHED:
      ## Start of Stage 7.1 ##
      self.fin_ctrl.set_pending(next_state='FIN_WAIT_1')
      ## End of Stage 7.1 ##
      pass
    elif self.state in (FIN_WAIT_1,FIN_WAIT_2):
      raise RuntimeError("close() is invalid in FIN_WAIT states")
    elif self.state is CLOSE_WAIT:
      ## Start of Stage 6.2 ##
      self.fin_ctrl.set_pending(next_state = LAST_ACK)
      ## End of Stage 6.2 ##
      pass
    elif self.state in (CLOSING,LAST_ACK,TIME_WAIT):
      raise RuntimeError("connecting closing")
    else:
      raise RuntimeError("operation illegal in %s" % (self.state,))

  def acceptable_seg(self, seg, payload):
    """
    seg is a TCP segment
    payload is the TCP payload, its type is string

    Returns whether the seg is acceptable according to rfc 793 page 69
    """
    seg_len = len(payload)
    rcv = self.rcv
    rnxtpwnd = rcv.nxt |PLUS| rcv.wnd
    
    if seg_len == 0:
      if rcv.wnd == 0:
        return seg.seq |EQ| rcv.nxt  # ACKs can be accepted
      elif rcv.wnd |GT| 0:
        return rcv.nxt |GE| seg.seq and seg.seq |LT| rnxtpwnd
    elif seg_len > 0 and rcv.wnd |GT| 0:
      seqplenm1 = seg.seq |PLUS| seg_len
      seqplenm1 = seqplenm1 |MINUS| 1
      return (rcv.nxt |LE| seg.seq and seg.seq |LT| rnxtpwnd) or \
              ((rcv.nxt |LE| seqplenm1) and (seqplenm1 |LE| rnxtpwnd))

    return False

  def connect(self, ip, port):
    """
    ip is an integer
    port is integer

    Begins the TCP handshake by initializing the socket and sends a SYN to the peer.
    Called by POX.
    """
    assert self.state is CLOSED
    assert not self.is_bound

    self.snd = TXControlBlock()
    self.rcv = RXControlBlock()
    self.rcv.wnd = self.RX_DATA_MAX

    dev = self.stack.lookup_dst(ip)[0]
    if dev is None:
      raise RuntimeError("No route to " + str(ip))
    if not dev.ip_addr:
      raise RuntimeError("No IP")

    self.peer = IPAddr(ip), port
    self.bind(dev.ip_addr, 0)

    ## Start of Stage 1.1 ##
    self.snd.nxt = self.snd.iss
    p = self.new_packet(False,None,True)
    self.tx(p)
    self.state = SYN_SENT
    self.snd.nxt = self.snd.nxt |PLUS| 1
    ## End of Stage 1.1 ##

  def tx(self, p, retxed=False):
    """
    p is an IP packet (its TCP segment can be accessed with p.tcp)
    retxed is an optional argument, if True, then this will be a retransmission

    Transmits this packet through POX
    """
    p.retxed = retxed

    ## Start of Stage 8.1 ##
    # in Stage 8, you may need to modify what you implemented in Stage 4.
    if (p.tcp.SYN or p.tcp.FIN or p.tcp.payload) and not retxed:
        p.tx_ts = self.stack.now
        self.retx_queue.push(p)
      ## Start of Stage 4.4 ##
        if p.tcp.payload:
          self.snd.nxt = self.snd.nxt |PLUS| len(p.tcp.payload)
      ## End of Stage 4.4 ##

    ## End of Stage 8.1 ##
    
    self.log.debug("tx seqno={0}".format(p.tcp.seq))
    self.manager.tx(p)

  def rx(self, p):
    """
    p is an IP packet (its TCP segment can be accessed with p.tcp)
    Called by POX when a new packet arrives

    Processing goes something like this:
    * Process the new packet
    * Try to send data, since the new packet may have changed the windows
      such that we now can
    * Send pending ACKs and FINs
    """
    seg = p.tcp
    payload = p.app

    assert self.state not in (SYN_RECEIVED, LISTEN)

    if self.state is CLOSED:
      return
    ## Start of Stage 1.2 ##
    elif self.state is SYN_SENT:
      self.handle_synsent(seg)
    ## End of Stage 1.2 ##
    elif self.state in (ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2,
                        CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT):
      if self.acceptable_seg(seg, payload):
        ## Start of Stage 2.1 ##
        #if seg.seq == self.rcv.nxt:
          #self.handle_accepted_seg(seg, payload)
        #else:
          #self.set_pending_ack()
        ## End of Stage 2.1 ##
        #pass
        ## Start of Stage 3.1 ##
        # you may need to remove Stage 2's code.
         self.rx_queue.push(p)
        ## End of Stage 3.1 ##
      else:
        self.set_pending_ack()

     
    ## Start of Stage 3.2 ##
    # checking recv queue
    # Hint: data = packet.app[self.rcv.nxt |MINUS| packet.tcp.seq:]
    while not self.rx_queue.empty():
      s, packet = self.rx_queue.peek()
      if s != self.rcv.nxt:
        self.set_pending_ack()
        break
      s, packet = self.rx_queue.pop()
      payload = packet.app[self.rcv.nxt |MINUS| packet.tcp.seq:]
      self.handle_accepted_seg(packet.tcp, payload)
    ## End of Stage 3.2 ##

    self.maybe_send()

    # RFC 1122 S4.2.2.20 p 93 says that in general you must aggregte ACKs,
    # and specifically says that when processing a series of queued segments,
    # you must process them all before ACKing them.  So we do ACK-sending
    # here -- after processing the queue.  And we do it after maybe_send,
    # since if it sends, it will also have ACKed.
    self.maybe_send_pending_ack()
    self.fin_ctrl.try_send()
    self._unblock()

  def handle_synsent (self, seg):
    """
    seg is a TCP segment

    Performs various actions required when in the SYN_SENT state,
    still part of the 3 way handshake.
    """
    assert seg.SYN  # don't support SYN_RECEIVED

    acceptable_ack = False
    if seg.ACK:
      if seg.ack |LE| self.snd.iss or seg.ack |GT| self.snd.nxt:
        return

      if self.snd.una |LE| seg.ack and seg.ack |LE| self.snd.nxt:
        acceptable_ack = True
        acked_pkts = self.retx_queue.pop_upto(seg.ack)
        self.log.debug("acked SYN of pkt={0}".format(acked_pkts))

    if acceptable_ack:
      ## Start of Stage 1.3 ##
      self.rcv.nxt = seg.seq |PLUS| 1
      self.snd.una = seg.ack
      
      if self.snd.una |GT| self.snd.iss:
        self.snd.nxt = self.snd.una
        self.state = ESTABLISHED
        self.set_pending_ack()
        self.update_window(seg)
      ## End of Stage 1.3 ##

  def update_rto(self, acked_pkt):
    """
    acked_pkt is an IP packet

    Updates the rto based on rfc 6298.
    """

    ## Start of Stage 9.1 ##
    current_time = self.stack.now
    R = current_time - acked_pkt.tx_ts

    if self.srtt == 0:
        self.srtt = R
        self.rttvar = R / 2
    else:
        self.rttvar = (1 - self.beta) * self.rttvar + self.beta * abs(self.srtt - R)
        self.srtt = (1 - self.alpha) * self.srtt + self.alpha * R
    self.rto = self.srtt + max(self.G, self.K * self.rttvar)
    self.rto = max(self.MIN_RTO, min(self.rto, self.MAX_RTO))
    ## End of Stage 9.1 ##


  def handle_accepted_payload(self, payload):
    """
    payload is the TCP payload, its type is bytearray

    Handles a payload of a segment that has been cleared by
    acceptable_seg(), and not dropped by check_ack()
    """
    assert len(payload) > 0
    rcv = self.rcv

    if len(payload) > rcv.wnd:
      payload = payload[:rcv.wnd] # Chop to size!

    ## Start of Stage 2.3 ##
    rcv.nxt = rcv.nxt |PLUS| len(payload)
    rcv.wnd = rcv.wnd |MINUS| len(payload)
    self.rx_data += payload
    self.set_pending_ack()
    ## End of Stage 2.3 ##

  def update_window(self, seg):
    """
    seg is a TCP segment

    Updates various parameters of the send sequence space related
    to the advertised window
    """

    ## Start of Stage 5.1 ##
    self.snd.wnd = seg.win
    self.snd.wl1 = seg.seq
    self.snd.wl2 = seg.ack
    ## End of Stage 5.1 ##

  def handle_accepted_ack(self, seg):
    """
    seg is a TCP segment

    Handles an ack we haven't seen so far, cleared by
    acceptable_seg()
    """
    ## Start of Stage 4.2 ##
    if seg.ack |GT| self.snd.una:
      self.snd.una = seg.ack
      #self.snd.wnd = seg.win
    ## End of Stage 4.2 ##


    ## Start of Stage 8.2 ##
    acked_pkts = self.retx_queue.pop_upto(seg.ack)
    ## End of Stage 8.2 ##


    ## Start of Stage 9.2 ##

    #acked_pkts = [] # remove when implemented
    for (ackno, p) in acked_pkts:
      if not p.retxed:
        self.update_rto(p)
    
    ## End of Stage 9.2 ##

  def handle_accepted_fin(self, seg):
    """
    seg is a TCP segment

    Handles a FIN that has been cleared by
    acceptable_seg(), and not dropped by check_ack()
    """
    if self.state in (CLOSED, SYN_SENT):
      return

    self.log.info("Got FIN!")

    ## Start of Stage 6.1 ##
    if self.state == ESTABLISHED:
        self.rcv.nxt = seg.seq |PLUS| 1
        self.set_pending_ack()
        self.state = CLOSE_WAIT
    ## End of Stage 6.1 ##


    ## Start of Stage 7.2 ##
    elif self.state == FIN_WAIT_1:
        if seg.ack:
            self.start_timer_timewait()
        else:
            self.set_pending_ack()
            self.state = CLOSING

    elif self.state == FIN_WAIT_2:
        if seg.FIN:
            self.rcv.nxt = seg.seq |PLUS| 1
            self.set_pending_ack()
            self.start_timer_timewait()
    ## End of Stage 7.2 ##

  def check_ack(self, seg):
    """
    seg is a TCP segment

    Handles several checks that we need to do on this ack.
    A segment that arrives here has been cleared by acceptable_seg().
    Returns whether or not to continue processing this segment.
    """
    snd = self.snd
    continue_after_ack = True

    # fifth, check ACK field
    if self.state in (ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING):
      ## Start of Stage 4.1 ##
      if seg.ack |LT| snd.una:
            continue_after_ack = False
      elif seg.ack |GT| snd.nxt:
            continue_after_ack = True
      else:
            self.handle_accepted_ack(seg)
      ## End of Stage 4.1 ##

      if snd.una |LE| seg.ack and seg.ack |LE| snd.nxt:
        if snd.wl1 |LT| seg.seq or (snd.wl1 |EQ| seg.seq and snd.wl2 |LE| seg.ack):
          self.update_window(seg)

    ## Start of Stage 6.3 ##
    ## Start of Stage 7.3 ##
    # if self.state == FIN_WAIT_1:
    #   pass
    # elif self.state == FIN_WAIT_2:
    #   if self.retx_queue.empty():
    #     self.set_pending_ack()
    # elif self.state == CLOSING:
    #   pass
    # elif self.state == LAST_ACK:
    #   if self.fin_ctrl.acks_our_fin(seg.ack):
    #         self._delete_tcb() 
    # elif self.state == TIME_WAIT:
    #   # restart the 2 msl timeout
    #   self.set_pending_ack()
    #   self.start_timer_timewait()
    if self.state == FIN_WAIT_1:
        if self.fin_ctrl.acks_our_fin(seg.ack):
            self.state = 'FIN_WAIT_2'
    elif self.state == FIN_WAIT_2:
        if self.retx_queue.empty():
            self.set_pending_ack()
    elif self.state == CLOSING:
        if self.fin_ctrl.acks_our_fin(seg.ack):
            self.start_timer_timewait()
    elif self.state == LAST_ACK:
        if self.fin_ctrl.acks_our_fin(seg.ack):
            self._delete_tcb() 
    elif self.state == TIME_WAIT:
        self.set_pending_ack()
        self.start_timer_timewait()
    ## End of Stage 6.3 ##
    ## End of Stage 7.3 ##

    return continue_after_ack

  def handle_accepted_seg(self, seg, payload):
    """
    seg is a TCP segment
    payload is the TCP payload, its type is string

    A segment that arrives here has been cleared by acceptable_seg()
    This is the main function that processes in-order segments
    """
    snd = self.snd
    rcv = self.rcv

    assert not seg.SYN
    if not seg.ACK:
      return

    continue_after_ack = self.check_ack(seg)
    if not continue_after_ack:
      return

    ## Start of Stage 2.2 ##
    if self.state in [ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2] and len(payload) != 0:
      self.handle_accepted_payload(payload)
    ## End of Stage 2.2 ##

    # eight, check FIN bit
    if seg.FIN:
      self.handle_accepted_fin(seg)

  def maybe_send(self):
    """
    Segmentizes and calls tx() on data available in tx_data
    """
    if not self.tx_data:
      return

    # segmentize self.tx_data
    snd = self.snd
    num_pkts = 0
    bytes_sent = 0

    ## Start of Stage 4.3 ##
    remaining = min(len(self.tx_data), snd.una |PLUS| snd.wnd |MINUS| snd.nxt)
    while remaining > 0:
        payload_size = min(self.mss, remaining)
        payload = self.tx_data[:payload_size]
        packet = self.new_packet(True,payload,False)
        self.tx(packet)
        num_pkts += 1
        bytes_sent += payload_size
        self.tx_data = self.tx_data[payload_size:]
        remaining = min(len(self.tx_data), snd.una |PLUS| snd.wnd |MINUS| snd.nxt)
    #remaining = 0
    #while remaining > 0:

      #num_pkts += 1
      #bytes_sent += len(payload)

        self.log.debug("sent {0} packets with {1} bytes total".format(num_pkts, bytes_sent))
    ## End of Stage 4.3 ##

  def start_timer_timewait(self):
    """
    Moves state to TIME_WAIT and initiates the next_timewait timer
    """
    self.state = TIME_WAIT
    self.next_timewait = self.stack.now + self.TIMER_TIMEWAIT

  def check_timer_timewait(self):
    """
    Checks whether next_timewait has passed since it was set
    """
    if self.next_timewait <= self.stack.now:
      self.next_timewait = float('inf')
      self._delete_tcb()

  def check_timer_retx(self):
    """
    Check retx_queue in order (in seq num increasing order). Retransmit any packet
    that has been in the queue longer than self.rto
    """

    ## Start of Stage 8.3 ##
    time_in_queue = 0 
    if not self.retx_queue.empty():
        s, p = self.retx_queue.get_earliest_pkt()
        current_time = self.stack.now
        time_in_queue = current_time - p.tx_ts
    ## End of Stage 8.3 ##

    if time_in_queue > self.rto:
      self.log.debug("earliest packet seqno={0} rto={1} being rtxed".format(p.tcp.seq, self.rto))
      self.tx(p, retxed=True)

      ## Start of Stage 9.3 ##
      self.rto *= 2
      self.rto = min(self.rto, self.MAX_RTO)
      ## End of Stage 9.3 ##

  def set_pending_ack(self):
    """
    Express that we want to send an ACK
    """
    self.ack_pending = True

  def maybe_send_pending_ack(self):
    """
    If there's an ACK pending, transmit it.
    """
    if not self.ack_pending:
      return

    self.ack_pending = False
    self.tx(self.new_packet())

