# Copyright 2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

# This file is based on the discovery component in NOX, though it has
# been substantially rewritten.

from pox.core import core
import pox.messenger as messenger

from pox.lib.util import dpidToStr
from pox.lib.recoco import Timer


log = core.getLogger()

class TinyTopo (messenger.ChannelBot):
  def __init__ (self):
    core.listen_to_dependencies(self, components=['MessengerNexus'])
    self.switches = set()
    self.links = set()

    self.pending = False

  def _all_dependencies_met (self):
    self._startup("poxdesk_topo")

    # Periodically just send a topo
    self.timer = Timer(10, self.send_table, recurring=True)
    log.debug("Ready to rip.")

  def send_table (self):
    if self.pending: return
    self.pending = True
    Timer(.2, self._do_send_table, recurring=False)

  def _do_send_table (self):
    assert self.pending
    self.pending = False
    switches = {}
    for s in self.switches:
      switches[s] = {'label':s}
    edges = []
    for e in self.links:
      if e[0] not in switches: continue
      if e[1] not in switches: continue
      edges.append(e)

    #print self.switches,switches
    #print self.links,edges

    self.send(topo={'links':edges,'switches':switches})

  def _handle_openflow_ConnectionUp (self, event):
    #print "CU"
    self.switches.add(dpidToStr(event.dpid))
    self.send_table()

  def _handle_openflow_ConnectionDown (self, event):
    #print "CD"
    self.switches.remove(dpidToStr(event.dpid))
    self.send_table()

  def _handle_openflow_discovery_LinkEvent (self, event):
    #print "LE"
    s1 = event.link.dpid1
    s2 = event.link.dpid2
    if s1 > s2: s1,s2 = s2,s1
    s1 = dpidToStr(s1)
    s2 = dpidToStr(s2)

    if event.added:
      self.links.add((s1,s2))
    elif event.removed and (s1,s2) in self.links:
      self.links.remove((s1,s2))

    self.send_table()

  def _exec_cmd_refresh (self, event):
    self.send_table()


def launch ():
  core.registerNew(TinyTopo)
