# Copyright 2012,2018 James McCauley
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
This allows you to easily run POXDesk.
"""

from pox.core import core
import os.path
from pox.web.webcore import InternalContentHandler
from pox.web.websocket import WebsocketHandler
from pox.lib.revent import Event, EventMixin
from weakref import WeakSet
from collections import OrderedDict
import json
import uuid


log = core.getLogger()



class Returner (object):
  #TODO: Merge with DispatchContext
  called = False
  def __init__ (self, f):
    self.f = f
  def __call__ (self, value):
    self.called = True
    self.f(value)



class DispatchContext (object):
  __slots__ = "ret err session".split()

  def __init__ (self, err, ret, handler):
    self.err = err
    self.ret = ret
    self.session = handler

  def send (self, data):
    self.handler.send(data)



class NewSession (Event):
  def __init__ (self, session):
    self.session = session

class EndSession (Event):
  def __init__ (self, session):
    self.session = session

class Query (Event):
  def __init__ (self, args, kw):
    self.args = args
    self.kw = kw



class DispatcherSession (WebsocketHandler):
  _count = 1

  @property
  def dispatcher (self):
    return self.args

  @property
  def locked (self):
    if self.dispatcher.secret is None: return False
    return self._locked

  def _pdmethod__unlock (self, ctxt, secret):
    if secret == self.dispatcher.secret:
      log.debug("Session %s unlocked", self._count)
      self._locked = False

  def _init (self):
    super(DispatcherSession,self)._init()
    self._locked = True
    self.dispatcher._register_session(self)
    self.exposed_objects = {}
    self.exposed_functions = {}
    self._count = self._count
    DispatcherSession._count += 1

  def _on_start (self):
    self.dispatcher.raiseEvent(NewSession, self)
    log.debug("Session %s started", self._count)

  def _on_stop (self):
    self.dispatcher.raiseEvent(EndSession, self)
    log.debug("Session %s stopped", self._count)

  def sendmsg (self, msg):
    if 'on_err' in msg:
      msg['on_err'] = self.dispatcher._create_waiting_error(msg['on_err'])
    if 'on_ret' in msg:
      msg['on_ret'] = self.dispatcher._create_waiting_return(msg['on_ret'])
    self.send(json.dumps(msg))

  def _on_message (self, op, msg):
    #TODO: The log messages here would be more helpful if they mentioned the
    #      actual method name or whatever that caused them!
    #TODO: Special error values for common errors (e.g., missing method/object)
    errf = Returner(lambda data: None)
    retf = errf
    try:
      msg = json.loads(msg)
      if 'on_err' in msg:
        errf = Returner(lambda data: self.sendmsg(dict(method="_error_dispatch",
                        args=dict(identifier=msg["on_err"], data=data))))
      if 'on_ret' in msg:
        retf = Returner(lambda data: self.sendmsg(dict(method="_return_dispatch",
                        args=dict(identifier=msg["on_ret"], data=data))))

      if self.locked and msg['method'] != '_unlock':
        raise RuntimeError("Session is locked")

      if "object" in msg and msg['object'] is not None:
        o = self.exposed_objects.get(msg['object'])
        if o is None:
          o = self.dispatcher.exposed_objects.get(msg['object'])
          if o is None:
            raise RuntimeError("No such object '%s'" % (msg['object'],))
        method = getattr(o, "_pdmethod_" + msg['method'])
      else:
        mname = msg['method']
        method = self.exposed_functions.get(mname)
        if method is None:
          method = self.dispatcher.exposed_functions.get(mname)
          if method is None:
            method = getattr(self, "_pdmethod_" + msg['method'])
            if method is None:
              method = getattr(self.dispatcher, "_pdmethod_" + msg['method'])

      args = msg['args'] if 'args' in msg else ()
      kw = msg['kw'] if 'kw' in msg else {}
      ctxt = DispatchContext(errf, retf, self)
      v = method(ctxt, *args, **kw)
      if (retf.called or errf.called) and (v is not None):
        log.error("Local method returned value, but also called return/error"
                  " function")
      else:
        retf(v)
    except Exception as e:
      if retf.called or errf.called:
        log.exception("Local method resulted in exception, but also called "
                      "return/error function")
      else:
        log.exception("Local method resulted in exception")
        #log.warn("Local method resulted in exception")
        errf(str(e))



#class POXDeskProxyMethod (object):
#  def __call__ (self, *args, **kw):
#    on_err = kw.pop("on_err", None)
#    on_ret = kw.pop("on_ret", None)
#class POXDeskProxyObject (object):
#  def __getattr__ (self, method_name):
#    return POXDeskProxyMethod(method_name)



class POXDeskConfigHandler (InternalContentHandler):
  args_content_lookup = False

  def GET_config_json (self, handler):
    return ("application/json", json.dumps(self.args.config))



class Dispatcher (EventMixin):
  #TODO: Factor out the dispatcher part
  _eventMixin_events = set([NewSession, EndSession, Query])

  secret = None

  max_waiting = 75

  _websocket_enabled = False

  def __init__ (self, websocket_path, websocket_session_type):
    self.exposed_objects = {}
    self.exposed_functions = {}
    self.websocket_path = websocket_path
    self.websocket_session_type = websocket_session_type
    self.sessions = WeakSet()
    if websocket_path:
      self.websocket_enabled = True

    #self.exposed_functions['_query'] = self._query
    #self.exposed_functions['_return_dispatch'] = self._return_dispatch
    #self.exposed_functions['_error_dispatch'] = self._error_dispatch

    self._waiting_returns = OrderedDict()
    self._waiting_errors = OrderedDict()
    self._waiting_id = 1

  def _pdmethod__new_uuid (self, ctxt):
    ctxt.ret(str(uuid.uuid1()))

  def _pdmethod__query (self, ctxt, *args, **kw):
    self.raiseEvent(Query, args, kw)

  def _pdmethod__return_dispatch (self, ctxt, identifier, data):
    f = self._waiting_returns.pop(identifier, None)
    if f is None:
      self.error("Didn't have waiting return event %s", identifier)
      return
    f(data)

  def _pdmethod__error_dispatch (self, ctxt, identifier, data):
    f = self._waiting_errors.pop(identifier, None)
    if f is None:
      self.error("Didn't have waiting error event %s", identifier)
      return
    f(data)

  def _create_waiting (self, d, f):
    while len(d) > self.max_waiting:
      d.popitem(last=False)
    identifier = self._waiting_id
    self._waiting_id += 1
    d[identifier] = f
    return identifier

  def _create_waiting_return (self, f):
    return self._create_waiting(self._waiting_returns, f)

  def _create_waiting_error (self, f):
    return self._create_waiting(self._waiting_errors, f)

  def _register_session (self, session):
    self.sessions.add(session)

  @property
  def websocket_enabled (self):
    return self._websocket_enabled

  @websocket_enabled.setter
  def websocket_enabled (self, value):
    if self._websocket_enabled is value: return
    if value is False: return # Currently don't support disabling it
    self._websocket_enabled = True
    core.WebServer.set_handler(self.websocket_path,
                               self.websocket_session_type,
                               args=self)



class POXDesk (Dispatcher):
  def __init__ (self, path, enable_websocket=False):
    self.config = {}
    self.path = path
    if enable_websocket:
      super(POXDesk,self).__init__(websocket_path = "/poxdesk/_/ws/main",
                                   websocket_session_type = DispatcherSession)
      if 'ws' not in self.config: self.config['ws'] = {}

    core.listen_to_dependencies(self, components=["WebServer"])

    # Used to also require ["MessengerNexus", "of_service"]

  def _all_dependencies_met (self):
    httpd = core.WebServer
    httpd.add_static_dir('poxdesk', self.path, relative=True)
    httpd.add_static_dir('qx', 'qx', relative=True)
    httpd.set_handler("/poxdesk/_/cfg", POXDeskConfigHandler, self)

    core.register("POXDesk", self)



def ask_name ():
  """
  A simple test of POXDesk
  """
  def log_it (msg):
    log.info("User's name is: %s", msg)

  def _handle_NewSession (e):
    e.session.sendmsg(dict(method="promptBox", args=("What is your name?",),
                           on_ret=log_it))

  def start ():
    core.POXDesk.add_listener(_handle_NewSession)
  core.call_when_ready(start, ["POXDesk"])



def launch (websocket=False, secret_file=None, force_source=False):
  base = os.path.dirname(__file__)

  have_qx = os.path.exists(os.path.join(base,"qx"))
  have_build = os.path.exists(os.path.join(base,"poxdesk","build"))
  if force_source and have_qx: have_build = False


  if not have_qx and not have_build:
    log.error("You need to have Qooxdoo in a directory named 'qx', or "
              + "you need a built version of POXDesk")
    return

  path = "poxdesk"
  if have_build:
    path = os.path.join(path, 'build')
    log.debug("Using built version of POXDesk")
  else:
    log.debug("Using source version of POXDesk")

  poxdesk = POXDesk(path, enable_websocket=websocket)
