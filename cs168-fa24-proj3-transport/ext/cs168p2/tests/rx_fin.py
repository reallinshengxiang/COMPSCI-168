# Authors:
# James McCauley, 2018

from tcpip.recoco_sockets import SimpleReSocketApp
from pox.lib.recoco import task_function, Sleep
from pox.core import core
from tcpip.modulo_math import *
from cs168p2.tests import Scorer
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



def launch (log_name="rx_basic_test", data="Hello, World!", drop_count = 0,
            run_time = 5, server_isn = None):

  def setup ():
    log = core.getLogger(log_name)
    score = Scorer(log)
    topo = core.sim_topo

    if server_isn is None:
      TXWindow.generate_isn = lambda _: random.randint(1000,100000)
    else:
      TXWindow.generate_isn = lambda _: literal_eval(server_isn)

    def get_client_socket ():
      try:
        return next(iter(c1.stack.socket_manager.peered.itervalues()))
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

    # Create applications.
    s1.start_small_services()
    capp = c1._new_resocket_app(RXApp, ip=s1_ip, port=13, delay=0.5)
    capp.rx_buffer = b''

    other_data = {}
    pkts = []
    def on_cap (e):
      if other_data.get('client_socket', None) is None:
        other_data['client_socket'] = get_client_socket()
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
      socket = other_data['client_socket']
      score.item("Reasonable packet count")
      score.success(len(pkts) > 3 and len(pkts) < 10)
      # Find server's fin
      score.item("Found FIN")
      fin = None
      last_client = None
      for p in pkts:
        if p._server:
          if p.FIN: fin = p
        else:
          if fin is not None: last_client = p
      score.success(fin is not None)
      score.item("State before FIN", 1)
      if fin: score.expect("ESTABLISHED", fin._client_state)
      score.item("FIN is ACKed correctly", 1)
      if last_client is not None:
        score.expect(fin.seq|PLUS|1, last_client.ack)
      score.item("State after last ACK", 1)
      if last_client is not None:
        score.expect("CLOSING", last_client._client_state)


    class drop_first_payloads (object):
      def __init__ (self, drop_count=1):
        self.drops_remaining = drop_count
      def __call__ (self, dev, packet):
        if self.drops_remaining <= 0: return
        tcp = packet.find("tcp")
        if tcp is None: return
        if not tcp.payload: return
        self.drops_remaining -= 1
        log.debug("Dropped a packet")
        return True
    if drop_count:
      r2r1_wire.drop_conditions.append(drop_first_payloads(int(drop_count)))


    def on_end ():
      try:
        do_score()
        score.finish()
      except Exception:
        log.exception("Exception during scoring")
      core.quit()
    tm.set_timer_at(float(run_time), on_end)
  core.call_when_ready(setup, ["sim_topo"], "test")
