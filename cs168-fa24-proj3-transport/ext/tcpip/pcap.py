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
PCap capture of SimNetDev devices

Currently somewhat limited.  You can't capture things besides SimNetDevs
(though if they're real interfaces, you might be able to just use
Wireshark or whatever!).  You can't specify a specific interface to
record (only whole nodes).
"""

#TODO: Reset pcaps between simulation runs (will require event or something).
#      But maybe you're creating new wires anyway?

from pox.lib.pxpcap.writer import PCapRawWriter
from pox.core import core
from . sim_core import SimNetDev


log = core.getLogger()



class PCapper (object):
  _pcap = None
  def __init__ (self, name, log, basename, topo=None):
    self.name = name
    self.basename = basename
    self.topo = None
    self.log = log

  def _init_pcap (self):
    if self.topo is None:
      self.topo = core.sim_topo
    fn = self.basename
    if fn is None: fn = self.topo.timestamp
    fn = "%s_%s.pcap" % (fn, self.name)
    self.log.debug("Writing to %s", fn)
    self._pcap = PCapRawWriter(open(fn, "wb"), True, ip=True)

  def tx_capture_proc (self, *args):
    self.rx_capture_proc(*args)

  def rx_capture_proc (self, dev, is_rx, raw, parsed):
    if self._pcap is None: self._init_pcap()
    # Currently this is hardwired to only write IP (not Ethernet)
    raw = raw if raw else parsed.pack()
    self._pcap.write(raw, time=self.topo.now)



_basename = None
_nodes = {}
_all_nodes = [False,False]



def _add_pcap (node, rx, tx):
  pcap = PCapper(node.name, node.log, _basename)

  for dev in node.stack.netdevs.values():
    # Currently only SimNetDevs supported
    if not isinstance(dev, SimNetDev): continue
    if not isinstance(dev.dst_dev, SimNetDev): continue
    if tx:
      if dev.tx_capture_proc:
        log.warn("%s is already TX-capturing", dev)
        continue
      dev.tx_capture_proc = pcap.tx_capture_proc
    if rx:
      if dev.rx_capture_proc:
        log.warn("%s is already RX-capturing", dev)
        continue
      dev.rx_capture_proc = pcap.rx_capture_proc



def _handle_GoingUpEvent (e):
  if _all_nodes != [False,False]:
    rx,tx = _all_nodes
    for n in core.sim_topo.nodes:
      if n.name in _nodes: continue # It'll override
      _add_pcap(n, rx, tx)
  for name,(rx,tx) in _nodes.items():
    n = core.sim_topo.get_node(name)
    _add_pcap(n, rx, tx)



def launch (filename=None, nodes=None, node=None, no_tx=False, no_rx=False,
            __INSTANCE__=None):
  if node and nodes:
    nodes += "," + node
  elif node:
    nodes = node
  tx = not no_tx
  rx = not no_rx
  global _basename
  global _all_nodes
  _basename = filename
  if nodes is None:
    _all_nodes = [rx,tx]
  else:
    for n in nodes.split(","):
      _nodes[n] = [rx,tx]

  if __INSTANCE__ and __INSTANCE__[0] == 0:
    core.add_listener(_handle_GoingUpEvent)
