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
Network stack and simulator
"""

from . sim_core import Topology,RealtimeTopology  
from pox.core import core
from pox.lib.addresses import IPAddr, EthAddr
from . import sim_nodes
from . droppers import RandomDropper, RegularDropper
from . wires import InfinityWire
from . queues import InfinityQueue


def init_standard_topo (topo, num_clients=1, num_servers=1):
  r"""
  Generates a basic testing topology, adding it to the given Topology.

  c1                   s1
    \                 /
     --- r1 --- r2 ---
    /                 \
  c2                   s2

  This generates a simple topology for testing.  Essentially, it's two
  wheel graphs with the hubs connected.  The hub of one is router r1, the
  hub of the other is r2.  All clients connect to r1; all servers connect
  to r2.

  The clients have IP addresses like 10.0.0.x, and the servers have IP
  addresses like 10.255.255.x.

  Returns the tuple ([clients...], [servers...])
  """
  assert num_clients < 256
  assert num_servers < 256

  r1 = sim_nodes.Node("r1")
  r2 = sim_nodes.Node("r2")

  topo.add_node(r1)
  topo.add_node(r2)
  topo.add_link(r1, r2)

  # Now switch to infinitely fast links/queues
  topo.default_queue_factory = topo.make_factory(InfinityQueue)
  topo.default_wire_factory = topo.make_factory(InfinityWire)

  for c in range(1, 1+num_clients):
    ip = IPAddr("10.0.0.%s" % (c,))
    n = sim_nodes.Node("c" + str(c)) #str(ip))
    _,dev,_ = topo.add_node(n, r1)
    dev.ip_addr = ip

  for c in range(1, 1+num_servers):
    ip = IPAddr("10.255.255.%s" % (c,))
    n = sim_nodes.Node("s" + str(c)) #str(ip))
    _,dev,_ = topo.add_node(n, r2)
    dev.ip_addr = ip



def simple_test (virtual_time=False, clients=1, servers=1):
  """
  A launcher for a basic test.
  """
  t = Topology(virtual_time=virtual_time)
  if _default_queue_type:
    t.default_queue_factory = t.make_factory(_default_queue_type)
  core.register("sim_topo", t)
  init_standard_topo(t, num_clients=int(clients), num_servers=int(servers))
  core.add_listener(handler=lambda _:t._do_routing, event_name="UpEvent")
  core.register("sim", t)
  core.Interactive.variables["topo"] = t
  for n in t.nodes:
    core.Interactive.variables[n.name] = n
  core.addListenerByName("UpEvent", lambda e: t.start())



def _new_app (node, f_name, port=0, ip=None, listen=False, **kw):
  def do_it (n):
    f = getattr(n, f_name)
    o = f(ip=ip, port=int(port), listen=listen, **kw)
  if core.starting_up:
    def _handle_UpEvent (e):
      n = core.sim_topo.get_node(node)
      do_it(n)
    core.add_listener(_handle_UpEvent)
  else:
    do_it(core.sim_topo.get_node(node))


def data_logger (node, port=0, ip=None, listen=False, delay=None,
                 __INSTANCE__=None):
  if delay is None: delay = 0 if listen else 1
  else: delay = float(delay)
  _new_app(node, "new_data_logger", port, ip, listen, delay=delay)


def basic_state_trans (node, port=0, ip=None, listen=True, delay=None,
                       __INSTANCE__=None):
  if delay is None: delay = 0 if listen else 1
  else: delay = float(delay)
  _new_app(node, "new_basic_state_trans", port, ip, listen, delay=delay)


def echo (node, port=0, ip=None, listen=False, __INSTANCE__=None):
  _new_app(node, "new_echo", port, ip, listen)


def small_services (node, __INSTANCE__=None):
  def _handle_UpEvent (e):
    n = core.sim_topo.get_node(node)
    n.start_small_services()
  if core.starting_up:
    core.add_listener(_handle_UpEvent)
  else:
    _handle_UpEvent()


def fast_sender (node, bytes, delay=0, port=0, ip=None, listen=False,
                 __INSTANCE__=None):
  bytes = int(bytes)
  delay = float(delay)
  _new_app(node, "new_fast_sender", port, ip, listen, data=bytes, delay=delay)



def realworld_test (tap=None, tun=None, pcap=None, ip_addr=None, dhcp=False,
                    masq=False, local_eth=None):
  t = RealtimeTopology()
  if _default_queue_type:
    t.default_queue_factory = t.make_factory(_default_queue_type)
  core.register("sim_topo", t)
  init_standard_topo(t)

  core.add_listener(handler=lambda _:t._do_routing, event_name="UpEvent")

  gw = sim_nodes.Node("gw") # A gateway
  _,dev,_ = t.add_node(gw)
  t.add_link(gw, t.get_node("r2"))

  from netdev import TapDev, TunDev, PCapDev

  assert sum(1 for x in (tap,tun,pcap) if x) <= 1
  if tap:
    d = TapDev(tap, tun=False, eth_addr=local_eth)#, ip_addr=ip)
  elif tun:
    d = TunDev(tun, tun=False)#, ip_addr=ip)
  elif pcap:
    d = PCapDev(pcap, eth_addr=local_eth)
  else:
    d = None

  if d:
    gw.stack.add_netdev(d)
    d.enable_ip_masquerade = masq

    assert not (ip_addr and dhcp)
    if ip_addr:
      d.ip_addr = IPAddr(ip_addr)
    elif dhcp:
      from dhcpc import DHCPClient
      c = DHCPClient(d)
      c.state = c.INIT
      def _handle_DHCPLeased (e):
        core.call_later(t._do_routing)
      c.add_listener(_handle_DHCPLeased)

  core.register("sim", t)
  core.Interactive.variables["topo"] = t
  for n in t.nodes:
    core.Interactive.variables[n.name] = n
  core.addListenerByName("UpEvent", lambda e: t.start())



def add_route (node, prefix, gw=None, dev=None, metric=1, __INSTANCE__=None):
  """
  Launcher to add a route statically
  """
  n = core.sim_topo.get_node(node)
  n.stack.add_route(prefix, gw, dev, metric)



def random_loss (loss, node1="r1", node2="r2", unidirectional=False,
                 __INSTANCE__=None):
  loss = float(loss)
  l = core.sim_topo.get_wire(node1, node2)
  l.sniffers.append(RandomDropper(loss, seed=node1+"."+node2))
  if not unidirectional:
    l = core.sim_topo.get_wire(node2, node1)
    l.sniffers.append(RandomDropper(loss, seed=node2+"."+node1))



def regular_loss (accept=None, drop=None, node1="r1", node2="r2",
                  unidirectional=False, phase=0, phase2=0,
                  __INSTANCE__=None):
  accept = int(accept)
  drop = int(drop)
  phase = accept if phase is True else int(phase)
  phase2 = accept if phase2 is True else int(phase2)
  l = core.sim_topo.get_wire(node1, node2)
  l.sniffers.append(RegularDropper(accept, drop, phase=phase))
  if not unidirectional:
    l = core.sim_topo.get_wire(node2, node1)
    l.sniffers.append(RegularDropper(accept, drop, phase=phase2))



def set_ip (node, ip, dev=None, devpat=None, first=False, __INSTANCE__=None):
  """
  Sets an IP address of a device on node

  Normally, you use either dev or devpat to specify the specific interface you
  want to give the IP to.  If you use dev, it should be the exact name of the
  interface.  devpath does glob-style matching, so that if the interface has
  an annoyingly long name you could do "*eth3*" or something like that.
  If you do not specify dev or devpat, it will just look for any interface
  without an IP address.

  Normally, it will complain if there is more than one possible interface that
  could be matched.  If you don't care about this and just want to set the IP
  of the first matching interface, set --first.
  """
  log = core.getLogger("set_ip")
  n = core.sim_topo.get_node(node)
  ip = IPAddr(ip)
  if devpat:
    assert not dev, "Only one of dev or devpat"
    dev = devpat
    import fnmatch
    matches = lambda a : fnmatch.fnmatch(a.name, devpat)
  elif dev is None:
    # No dev or devpat specified; just any dev with no IP
    matches = lambda a : a.ip_addr is None
  else:
    assert not devpat, "Only one of dev or devpat"
    matches = lambda a : a.name == dev
  matching = []
  for name,d in n.stack.netdevs.iteritems():
    if matches(d): matching.append(d)
  if not matching:
    raise RuntimeError("No matching device (%s)" % (dev,))
  matching.sort(key=lambda d:d.name)
  if len(matching) > 1 and not first:
    names = " ".join(d.name for d in matching)
    raise RuntimeError("More than one device matching '%s': %s"
                       % (dev, names))
  device = matching[0]
  log.info("Changing IP address of %s from %s to %s", device.name,
           device.ip_addr, ip)
  device.ip_addr = ip



def quit_at (time):
  """
  Shuts down POX at a specified simulation time
  """
  time = float(time)
  def quit ():
    core.getLogger().info("Quitting at requested time (%s)",
                          units.seconds_to_str(time))
    core.quit()
  def _handle_GoingUp (e):
    core.sim_topo.set_timer_at(time, quit)
  if core.hasComponent("sim_topo"):
    _handle_GoingUp(None)
  else:
    core.add_listener(_handle_GoingUp)



def log_at (time, message=None, repeating=False, __INSTANCE__=None):
  """
  Logs a message at a given sim time
  """
  time = float(time)
  def msg ():
    t = units.seconds_to_str(core.sim_topo.now, True)
    if message is None:
      m = "It is now %s" % (t,)
    else:
      m = t + ": " + message
    core.getLogger().info(m)
    if repeating:
      core.sim_topo.set_timer_in(time, msg)

  def _handle_GoingUp (e):
    core.sim_topo.set_timer_at(time, msg)
  if core.hasComponent("sim_topo"):
    _handle_GoingUp(None)
  else:
    core.add_listener(_handle_GoingUp)



_default_queue_type = None
def default_queue (type):
  import queues
  global _default_queue_type
  qtype = getattr(queues, type)
  if not issubclass(qtype, queues.Queue):
    raise RuntimeError("Not a valid queue type")
  _default_queue_type = qtype



import logging
class SimTimeFilter (logging.Filter):
  time_manager = None
  def filter (self, record):
    if not self.time_manager:
      if not core.hasComponent("sim_topo"): return True
      self.time_manager = core.sim_topo

    record.msg = "[" + units.seconds_to_str(self.time_manager.now) + "] " + record.msg
    return True



def log_simtime ():
  """
  Put the sim time in the log
  """
  import pox.core
  pox.core._default_log_handler.addFilter(SimTimeFilter())
  # Is there a better way to do this?  I can't remember!
