# Authors:
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

class DelayedCloseApp (SimpleReSocketApp):
  @task_function
  def _on_connected (self):
    self.log.info("DELAYED will shutdown socket at 1 sec")
    cd = CountDown(self.sock.stack.time, 1)
    while not cd.is_expired:
      yield self.sock._block(cd)

    self.log.info("DELAYED will shutdown socket now")
    yield self.sock.close()

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

    # sapp calls close() immediately after connect()
    # capp calls close() after 1 sec
    sapp = s1.new_basic_state_trans(port=1000, listen=True)
    capp = c1._new_resocket_app(DelayedCloseApp, ip=s1.netdev.ip_addr, port=1000, delay=0.1)

    pkts = []
    client_socket = None

    def on_cap (e):
      if not pkts:
        global client_socket
        client_socket = get_client_socket()

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

    def from_server(p):
      return p._server and not p._client

    def from_client(p):
      return not p._server and p._client

    def do_score ():
      # SYN from client
      tester.expect_true(from_client(pkts[0]), "1st SYN from client")

      # SYN+ACK from server
      tester.expect_true(from_server(pkts[1]), "2nd pkt comes from server")
      tester.expect_eq(pkts[1]._client_state, SYN_SENT, "state is SYN_SENT when r2 receives SYN+ACK")

      # ACK from client
      tester.expect_true(from_client(pkts[2]), "3rd pkt comes from client")
      tester.expect_eq(pkts[2]._client_state, ESTABLISHED, "state is ESTABLISHED when r2 receives ACK")

      # FIN+ACK from server
      tester.expect_true(from_server(pkts[3]), "4th pkt comes from server")
      tester.expect_eq(pkts[3]._client_state, ESTABLISHED, "state is ESTABLISHED when r2 receives FINACK")
      tester.expect_true(pkts[3].ACK and pkts[3].FIN, "4th pkt is FIN+ACK")

      # ACK from client
      tester.expect_true(from_client(pkts[4]), "5th pkt comes from client")
      tester.expect_true(pkts[4].ACK, "5th pkt is ACK")

      # FIN+ACK from client
      tester.expect_true(from_client(pkts[5]), "6th pkt comes from client")
      tester.expect_true(pkts[5].ACK and pkts[5].FIN, "6th pkt is FIN+ACK")

      # ACK from server
      tester.expect_true(from_server(pkts[6]), "7th pkt comes from server")
      tester.expect_eq(LAST_ACK, pkts[6]._client_state, "state is LAST_ACK when r2 receives ACK")
      tester.expect_true(pkts[6].ACK, "7th pkt is ACK")

      global client_socket
      tester.expect_eq(CLOSED, client_socket.state, "At end, client state is CLOSED")

    def on_end ():
      try:
        do_score()
        tester.finish()
      except Exception:
        log.exception("Exception during scoring")
      core.quit()

    tm.set_timer_at(float(run_time), on_end)

  core.call_when_ready(setup, ["sim_topo"], "test")
