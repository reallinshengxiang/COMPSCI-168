# Copyright 2011,2012 James McCauley
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

"""
Provides a service to connect to a shell on the host.  Probably
POSIX only.

To use, invite a TerminalBot.
"""

import os
import time
import threading
import pty
import select
from pox.core import core
from pox.messenger import *

log = core.getLogger()


class TerminalMaster:
  """ Handles IO and stuff for Terminals """
  
  def __init__ (self):
    self.lock = threading.Lock()
    self.ioThread = threading.Thread(target = self._io_thread)
    self.terminals = set()
    self.ioThread.start()
    core.MessengerNexus.default_bot.add_bot(TerminalBot)
        
  def _io_thread (self):
    while core.running:
      with self.lock:
        fds = list(self.terminals)
      if len(fds) == 0:
        time.sleep(2)
        continue
      print "READ",fds
      (r,w,x) = select.select(list(fds), [], list(fds), 2)
      if len(r):
        for f in r:
          data = os.read(f.child_fd, 1024*2)
          f.send(rx=data)
      if len(x):
        for f in x:
          #TODO: check errno
          #log.error("Error on %s", f)
          try:
            f.close()
          except:
            pass
          f.send(rx="\n[Connection closed]")


class TerminalBot (ChannelBot):
  def __repr__ (self):
    return "<TerminalBot pid:%s>" % (self.child_pid)

  def _init (self, extra):
    (pid, fd) = pty.fork()
    #(pid,fd) = os.forkpty()
    if pid == 0:
      # Child
      os.environ["LINES"] = "25"
      os.environ["COLUMNS"] = "80"
      os.environ["TERM"] = "linux"#"vt102"  
      os.execlp("bash", "bash")
      print "Failed to start child"
      raise "Failed to start child"

    #print "child is...",pid
    self.child_pid = pid
    self.child_fd = fd
   
    with core.TerminalMaster.lock:
      core.TerminalMaster.terminals.add(self)
    log.info("Starting up terminal %s", self)

  def close (self):
    with core.TerminalMaster.lock:
      if self in core.TerminalMaster.terminals:
        core.TerminalMaster.terminals.remove(self)
    if self.child_pid is not None:
      os.waitpid(self.child_pid, 0)
      self.child_pid = None
    if self.child_fd is not None:
      try:
        os.close(self.child_fd)
      except:
        log.exception("Error quitting terminal")
      self.child_fd = None

  def _destroyed (self):
    log.info("Destroying terminal %s", self)
    self.close()

  def fileno (self):
    return self.child_fd
  
  def _exec_rx (self, event, value):
    #TODO: queue it and wait for select to return that this is writable
    if self.child_fd is not None:
      os.write(self.child_fd, value)


def launch ():
  core.registerNew(TerminalMaster)

