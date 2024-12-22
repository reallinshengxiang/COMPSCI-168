from tcpip.recoco_sockets import SimpleReSocketApp
from pox.lib.recoco import task_function, Sleep
from pox.core import core
from tcpip.modulo_math import *
from cs168p2.tests import Tester
from tcpip.wires import InfinityWire
from tcpip.tcp_sockets import TXWindow
import random
from ast import literal_eval



class RXApp (SimpleReSocketApp):
  # Missing rx_buffer = b''
  @task_function
  def _on_connected (self):
    while True:
      d = yield self.sock.recv(1, at_least=True)
      if not d: break
      self.rx_buffer += d



def launch (log_name="", data="", drop_count=0,
            run_time=5, server_isn=None):

  perpkt = 1380
  pkts = 50
  data = "*!" * int((perpkt / 2) * pkts)

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

    # This gets connected between r1 and c1
    class MyWire (InfinityWire):
      def transmit (self, packet):
        #print get_client_socket().state
        self.dst.rx(packet, self.src) # Always this!
        #print get_client_socket().state

    c1 = core.sim_topo.get_node("c1")
    s1 = core.sim_topo.get_node("s1")
    r1 = core.sim_topo.get_node("r1")
    r2 = core.sim_topo.get_node("r2")
    r1c1_wire = topo.make_factory(MyWire)
    topo.set_wire(r1,c1, r1c1_wire, False)
    tm = core.sim_topo.time
    r1c1_dev = core.sim_topo.get_devs(r1,c1)[0]
    s1_ip = s1.netdev.ip_addr

    # Create a couple applications.
    child_kwargs = dict(data=data)
    sapp = s1.netcat(port=1000, listen=True, child_kwargs=child_kwargs)
    capp = c1._new_resocket_app(RXApp, ip=s1_ip, port=1000, delay=0.5)
    capp.rx_buffer = b''

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
      tester.expect_eq(data.encode('ascii'), capp.rx_buffer, "payload correctly received")
      num_pkts_payload = sum(1 for p in pkts if p.payload)
      tester.expect_true(50 <= num_pkts_payload <= 120, "50 <= num_pkts_payload <= 120")

    def on_end ():
      try:
        do_score()
        tester.finish()
      except Exception:
        log.exception("Exception during scoring")
      core.quit()
    tm.set_timer_at(float(run_time), on_end)
  core.call_when_ready(setup, ["sim_topo"], "test")
