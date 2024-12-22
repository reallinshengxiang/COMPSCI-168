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

  data = "**Hello, CS168!**" * 240

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
    r1c1_wire = topo.make_factory(InfinityWire)
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

      # # pkts = 3 for hs + 3 payload + 1-3 payload ack + maybe 4 for close + 1 threshold
      #tester.expect_true(12 <= len(pkts) <= 14, "4 <= num of packets <= 10")

    class drop_one_pass_one(object):

      def __init__ (self):
        self.dropnext = True
        self.sent_pkts = {}

      def __call__ (self, dev, packet):
        tcp = packet.find("tcp")
        # only packets with payload
        if not tcp or not tcp.payload:
          return False

        k = tcp.seq
        if k in self.sent_pkts or self.dropnext:
          self.dropnext = False
          log.info("dropped packet seq={0}, ack={1}".format(k, tcp.ack))
          return True
        else:
          self.dropnext = True
          self.sent_pkts[k] = True
          log.info("let packet through seq={0}, ack={1}".format(k, tcp.ack))
          return False

    topo.get_wire(r1,c1).drop_conditions.append(drop_one_pass_one())

    def on_end ():
      try:
        do_score()
        tester.finish()
      except Exception:
        log.exception("Exception during scoring")
      core.quit()
    tm.set_timer_at(float(run_time), on_end)
  core.call_when_ready(setup, ["sim_topo"], "test")
