# Author:
# James McCauley, 2018
# amaro, 2018

from tcpip.recoco_sockets import SimpleReSocketApp
from tcpip.tcp_sockets import CLOSED, LISTEN, SYN_RECEIVED, ESTABLISHED, \
                              SYN_SENT, FIN_WAIT_1, FIN_WAIT_2, CLOSING, \
                              TIME_WAIT, CLOSE_WAIT, LAST_ACK
from tcpip.time_manager import CountDown
from pox.lib.recoco import task_function, Sleep
from pox.core import core
from tcpip.modulo_math import *
from cs168p2.tests import Tester
from tcpip.tcp_sockets import TXWindow
import random
from ast import literal_eval

class ClosingRXApp(SimpleReSocketApp):
  all_rx = []
  @task_function
  def _on_connected (self):
    which = len(self.all_rx)
    entry = [self.sock.usock.peer,b'']
    self.all_rx.append(entry)
    while True:
      d = yield self.sock.recv(1, at_least=True)
      if not d:
        break

      entry[1] += d

def launch (log_name="", run_time=3, server_isn=None):
  def setup ():
    log = core.getLogger(log_name)
    tester = Tester(log)
    topo = core.sim_topo

    if server_isn is None:
      TXWindow.generate_isn = lambda _: random.randint(1000,100000)
    else:
      TXWindow.generate_isn = lambda _: literal_eval(server_isn)

    def get_client_socket ():
      try:
        return next(iter(c1.stack.socket_manager.peered.values()))
      except Exception:
        return None

    c1 = core.sim_topo.get_node("c1")
    s1 = core.sim_topo.get_node("s1")
    r1 = core.sim_topo.get_node("r1")
    r2 = core.sim_topo.get_node("r2")
    tm = core.sim_topo.time
    r1c1_dev = core.sim_topo.get_devs(r1,c1)[0]

    # sapp calls close() after receiving data
    # capp calls sends data and immediately calls close()
    sapp = s1._new_resocket_app(ClosingRXApp, port=1000, listen=True)
    capp = c1.new_fast_sender(data=1000, ip=s1.netdev.ip_addr, port=1000, delay=0.5)

    pkts = []
    def on_cap (e):
      parsed = e.parsed
      if not parsed: return
      parsed = parsed.find("tcp")
      if not parsed: return
      # Giant hack, but just tack this stuff on
      parsed._devname = e.dev.name
      parsed._client = e.dev is r1c1_dev
      parsed._server = not parsed._client
      csock = get_client_socket()
      parsed._client_state = csock.state if csock else None
      pkts.append(parsed)
      #print e.dev,parsed.dump()

    r1.stack.add_packet_capture("*", on_cap, ip_only=True)

    def do_score ():
      tester.expect_eq(("*" * 1000).encode('ascii'), sapp.all_rx[0][1], "payload correctly sent")

      payload_pkts = sum(1 for p in pkts if p.payload)
      tester.expect_eq(1, payload_pkts, "1 retransmission")

    class drop_payload(object):
      def __init__(self):
        self.dropped = False

      def __call__ (self, dev, packet):
        tcp = packet.find("tcp")
        if not tcp:
          return False

        if tcp.payload and not self.dropped:
          self.dropped = True
          log.info("dropped packet seq={0}, ack={1}".format(tcp.seq, tcp.ack))
          return True

        return False

    topo.get_wire(c1,r1).drop_conditions.append(drop_payload())

    def on_end ():
      try:
        do_score()
        tester.finish()
      except Exception:
        log.exception("Exception during scoring")
      core.quit()

    tm.set_timer_at(float(run_time), on_end)

  core.call_when_ready(setup, ["sim_topo"], "test")
