# Authors:
# James McCauley, 2018
# amaro, 2018

from tcpip.recoco_sockets import SimpleReSocketApp
from tcpip.tcp_sockets import CLOSED, LISTEN, SYN_RECEIVED, ESTABLISHED, \
                              SYN_SENT, FIN_WAIT_1, FIN_WAIT_2, CLOSING, \
                              TIME_WAIT, CLOSE_WAIT, LAST_ACK
from pox.lib.recoco import task_function, Sleep
from pox.core import core
from tcpip.modulo_math import *
from cs168p2.tests import Tester
from tcpip.tcp_sockets import TXWindow
import random
from ast import literal_eval


def launch (log_name="test", server_isn=None):
  run_time = 2

  def setup ():
    log = core.getLogger(log_name)
    tester = Tester(log)
    topo = core.sim_topo

    TXWindow.generate_isn = lambda _: literal_eval("0xFFffFFff")

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

    # Create two echo applications.  Nobody should be sending, so
    # they should just three-way handshake and then sit and stare
    # at each other until the simulation ends.
    sapp = s1.new_echo(port=1000, listen=True)
    capp = c1.new_echo(ip=s1.netdev.ip_addr, port=1000, delay=0.1)

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
      # SYN from client
      client_seq = pkts[0].seq
      tester.expect_true(pkts[0]._client and not pkts[0]._server, "first pkt comes from client")
      tester.expect_true(pkts[0].SYN and not pkts[0].ACK, "first pkt is SYN not ACK")

      # SYN+ACK from server
      server_seq = pkts[1].seq
      tester.expect_true(not pkts[1]._client and pkts[1]._server, "second pkt comes from server")
      tester.expect_true(pkts[1].SYN and pkts[1].ACK, "second pkt is SYN+ACK")
      tester.expect_eq(client_seq |PLUS| 1, pkts[1].ack, "second pkt ack seq num is correct")
      tester.expect_eq(SYN_SENT, pkts[1]._client_state, "state is SYN_SENT when r1 receives SYN+ACK")

      # ACK from client
      tester.expect_true(pkts[2]._client, "third pkt comes from client")
      tester.expect_true(not pkts[2].SYN and pkts[2].ACK, "third pkt is ACK")
      tester.expect_eq(server_seq |PLUS| 1, pkts[2].ack, "third pkt ack seq num is correct")
      tester.expect_eq(ESTABLISHED, pkts[2]._client_state, "state is ESTABLISHED when r1 receives ACK")

      tester.expect_eq(3, len(pkts), "3 packets total")

    def on_end ():
      try:
        do_score()
        tester.finish()
      except Exception:
        log.exception("Exception during scoring")
      core.quit()

    tm.set_timer_at(float(run_time), on_end)

  core.call_when_ready(setup, ["sim_topo"], "test")
