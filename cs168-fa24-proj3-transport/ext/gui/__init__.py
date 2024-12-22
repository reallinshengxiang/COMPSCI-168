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
POX backend for CableBear

CableBear is a POXDesk GUI for TCP analysis.
"""

from pox.core import core
from tcpip.modulo_math import *
from web.websocket import WebsocketHandler
from collections import deque, defaultdict
from . tcp_analysis import FlowManager
from weakref import WeakSet
import json

log = core.getLogger()


class TCPAnalysisSession (WebsocketHandler):
  # send(msg)

  @property
  def gui (self):
    return self.args

  def _on_start (self):
    #key = self.path.rsplit("/", 1)[-1]

    if self.gui.register_session(self):
      if self.gui._go_up_deferral:
        self.gui._go_up_deferral()
        self.gui._go_up_deferral = None

  def _on_message (self, op, msg):
    pass

  def _on_stop (self):
    self.gui.unregister_session(self)

  def sendmsg (self, msg):
    self.send(json.dumps(msg))



class CableBear (object):
  def __init__ (self):
    self._go_up_deferral = None
    self._waiting = True
    self.sessions = WeakSet()
    core.listen_to_dependencies(self, components=["WebServer"])

  def _all_dependencies_met (self):
    core.WebServer.set_handler("/cable_bear/ws", TCPAnalysisSession, self)

  def _handle_POXDesk_NewSession (self, event):
    if self._waiting is False: return
    self._waiting = False
    event.session.sendmsg(dict(method="new_CableBear"))
    log.debug("New POXDesk session -- starting CableBear frontend")

  def _handle_POXDesk_EndSession (self, event):
    if event.session in self.sessions:
      self.sessions.discard(event.session)
    if not self.sessions:
      self._waiting = True

  def _handle_core_GoingUpEvent (self, e):
    if self._waiting:
      self._go_up_deferral = e.get_deferral()
      log.info("Waiting for CableBear frontend to connect")

  def register_session (self, session):
    if self.sessions: return False # One at a time
    self.sessions.add(session)
    return True

  def unregister_session (self, session):
    self.sessions.discard(session)

  def add_record (self, msg):
    bad = None
    for s in self.sessions:
      try:
        s.sendmsg(msg)
      except Exception:
        log.exception("While trying to send to CableBear frontend")
        if bad is None: bad = []
        bad.append(s)
    if bad:
      for b in bad:
        self.sessions.discard(b)



def launch ():

  def setup ():
    log = core.getLogger()
    topo = core.sim_topo

    c1 = core.sim_topo.get_node("c1")
    s1 = core.sim_topo.get_node("s1")
    r1 = core.sim_topo.get_node("r1")
    r2 = core.sim_topo.get_node("r2")
    tm = core.sim_topo.time
    #s1_ip = s1.netdev.ip_addr

    flows = FlowManager()

    def finish_cap (r):
      r.state = r.sock.state
      details = []
      details.append("Packet #%s @ %0.3f from %s:%s to %s:%s" % (r.order,
                     r.ts, r.ip.srcip, r.tcp.srcport, r.ip.dstip,
                     r.tcp.dstport))
      try:
        details.append("Client state: " + str(r.sock.state))
      except Exception:
        pass
      try:
        details.append("RX Queue size: " + str(len(r.sock.rx_queue.q)))
      except Exception:
        pass
      try:
        details.append("ReTX Queue size: " + str(len(r.sock.retx_queue.q)))
      except Exception:
        pass
      try:
        details.append("rto:%s srtt:%s rttvar:%s" % (r.sock.rto, r.sock.srtt,
                                                     r.sock.rttvar))
      except Exception:
        pass

      msg = dict(
        src_ip = str(r.ip.srcip),
        dst_ip = str(r.ip.dstip),
        src_port = r.tcp.srcport,
        dst_port = r.tcp.dstport,
        ts = r.ts,
        num = r.order,
        seq = r.tcp.seq,
        awin = r.tcp.win,
        in_order = r.in_order,
        len = len(r),
        is_tx = r.is_tx,
        rwnd = None,
      )
      try:
        msg['rwnd'] = r.sock.rcv.wnd
      except Exception:
        pass

      if len(r.tcp.payload) == 0:
        msg['data'] = None
      else:
        try:
          r.tcp.payload.encode('ascii') # Exception if not ASCII
          msg['data'] = 'ASCII: ' + r.tcp.payload
        except Exception:
          try:
            msg['data'] = 'Hex: \n'
            msg['data'] += hexdump(r.tcp.payload)
          except Exception:
            msg['data'] = None

      flags = ''
      if r.tcp.SYN: flags += "S"
      if r.tcp.FIN: flags += "F"
      if r.tcp.PSH: flags += "P"
      if r.tcp.URG: flags += "U"
      #if r.tcp.ACK: flags += "A"
      msg['flags'] = flags

      dups = sorted(r.get_dup_acks(), key=lambda p: p.order)
      if dups:
        s = " ".join(str(p.order) for p in dups)
        details.append("Duplicate ACKs: " + s)
        msg['dup_ack'] = True
      else:
        msg['dup_ack'] = False

      dups = sorted(r.get_dup_seqs(), key=lambda p: p.order)
      if dups:
        s = " ".join(str(p.order) for p in dups)
        details.append("ReTXes: " + s)
        #msg['retxes'] = dups
        msg['retx'] = True
      else:
        msg['retx'] = False

      if r.tcp.ACK:
        msg['ack'] = r.tcp.ack

        acks = r.acked_data_packets
        if acks:
          acks = sorted(acks, key=lambda p: p.order)
          #msg['acks'] = acks
          s = "Acknowledges: " + " ".join(str(p.order) for p in acks)
          details.append(s)
      else:
        msg['ack'] = "-"

      msg['details'] = details

      core.CableBear.add_record(msg)


    def on_cap (e):
      ipp = e.parsed
      if not ipp: return
      tcpp = ipp.find("tcp")
      if tcpp is None: return
      r = flows.new_record(ipp)
      r.ts = tm.now
      r.is_tx = e.is_tx
      r.is_rx = not r.is_tx

      loc = r.ip.dstip,r.tcp.dstport
      rem = r.ip.srcip,r.tcp.srcport
      if e.is_tx: loc,rem = rem,loc
      r.sock = e.dev.stack.socket_manager.peered.get((loc,rem))

      if e.is_tx:
        # Finish capture *after* the current task gives up control so
        # that whatever additional state we grab is "final" for this
        # packet (otherwise they might still change state after right
        # now, since a TX capture happens immediately on a call to TX;
        # there's no queuing or anything yet).
        tm.set_timer_in(0, finish_cap, r)
      else:
        finish_cap(r)

    c1.stack.add_packet_capture("*", on_cap, ip_only=True, rx=True, tx=True)

  core.call_when_ready(setup, ["sim_topo", "POXDesk"], "tcp_gui")
  core.registerNew(CableBear)
