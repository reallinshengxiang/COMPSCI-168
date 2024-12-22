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
Handles timing for IPStack
"""

import time
import pox.lib.recoco
from pox.lib.recoco import Lock
import heapq
from pox.core import core
import pox.lib.recoco as recoco
from . units import Infinity


log = core.getLogger()



class StopTimer (RuntimeError):
  """
  Raise or return this from inside a recurring timer to stop it
  """
  pass



class TimeManager (object):
  def set_timer_in (_self, _t, _f, *_args, **_kw):
    raise NotImplementedError()
  def set_timer_at (_self, _t, _f, *_args, **_kw):
    """
    Sets a timer

    When the timer expires (at time _t), _f is called with the given arguments
    and keyword arguments.

    The return value is a callable that will cancel the timer
    """
    #FIXME: Bad locality of cost here.
    # The return value as a callable is sort of expensive, especially if it's
    # not actually used, which a lot of the time, it won't be.  We might want
    # to change the API so that it returns an identifier, and then you need
    # to call cancel_timer(identifier).
    raise NotImplementedError()
  @property
  def now (self):
    raise NotImplementedError()
  def resleep (self, t):
    raise NotImplementedError()

  def set_timer_every (_self, _t, _f, skip_first_timer=True, *_args, **_kw):
    data = [_self.now, None, False]

    def timer_func (skip=False):
      if data[2]:
        data[1] = None
        return # Cancel
      data[0] += _t
      try:
        if not skip:
          if _f(*_args, **_kw) is StopTimer: raise StopTimer()
      except StopTimer:
        data[2] = True
        data[1] = None
        return
      t = self.set_timer_at(data[0], timer_func)
      data[1] = t
      return True

    def cancel ():
      data[2] = True
      if data[1]:
        try:
          data[1].cancel()
        except Exception:
          pass

    timer_func(skip=skip_first_timer)
    return cancel



class RealTimeManager (TimeManager):
  _event_number = 0

  def __init__ (self, timeshift=False, start=None):
    if start is None: start = False if timeshift else True

    self._real_start = None
    self._pre_events = [] # Relative events queued before start
    self._events = []

    if timeshift is False:
      if start is False:
        raise RuntimeError("Time and tide wait for no man.  "
                           "You can't avoid starting when not shifting time.")
      self._real_start = 0.0
    elif start:
      self.start()

  def start (self):
    self._real_start = time.time()
    for _t,_f,_args,_kw in self._pre_events:
      self.set_timer_in(_t,_f,*_args,**_kw)
    del self._pre_events[:]

  @property
  def now (self):
    if self._real_start is None: return 0.0
    return time.time() - self._real_start

  def set_timer_in (_self, _t, _f, *_args, **_kw):
    return _self.set_timer_at(_t+_self.now, _f, *_args, **_kw)

  def set_timer_at (_self, _t, _f, *_args, **_kw):
    if _self._real_start is None:
      # Before the simulation starts, time is relative to the start time,
      # so we can just treat this as a pre_event.
      _self._pre_events.append((_t,_f,_args,_kw))
      return
    _t = _t + _self._real_start
    t = recoco.Timer(_t, _self._run_timers, absoluteTime=True)
    en = _self._event_number
    heapq.heappush(_self._events, (_t, en, _f, _args, _kw, t))
    _self._event_number += 1
    return lambda: _self._cancel_timer(en)

  @staticmethod
  def _do_nothing (*args, **kw):
    pass

  def _cancel_timer (self, event_number):
    # This is... not great.
    for i,(ts,en,f,args,kw,timer) in enumerate(self._events):
      if en == event_number:
        self._events[i] = (ts,en,self._do_nothing,(),{},None)
        if timer: timer.cancel()
        break

  def _run_timers (self):
    if not self._events: return
    now = time.time()
    while self._events:
      ts,en,f,args,kw,timer = self._events[0]
      if now < ts: break # Too early for this
      heapq.heappop(self._events)
      f(*args,**kw)

    # now *should* be exactly ts, but it may be somewhat later (larger)
    d = now - ts
    if d > 0.01:
      if d > 0.5: f = log.error
      elif d > 0.1: f = log.warn
      elif d > 0.05: f = log.info
      else: f = log.debug
      f("Timers are %ss behind", d)

    return True

  @property
  def now (self):
    if self._real_start is None: return 0.0
    return time.time() - self._real_start

  def resleep (self, t):
    return recoco.Sleep(t)



class Blocker (Lock):
  def __init__ (self, stack=None, timeout=None):
    #TODO: More efficient timer (or recycle Blocker?)
    self.timed_out = False
    if isinstance(timeout, CountDown):
      self.kill_timer = timeout.create_timer(self._on_timeout)
    elif timeout:
      self.kill_timer = stack.set_timer_in(timeout, self._on_timeout)
    else:
      self.kill_timer = lambda: None

    super(Blocker,self).__init__(locked=True)

  def _on_timeout (self):
    self.timed_out = True
    self._blocker_release()

  def __call__ (self):
    self.unblock()

  def unblock (self):
    if self.kill_timer: self.kill_timer()
    self._blocker_release()

  def _blocker_release (self):
    if self._locked: self._do_release(None, core.scheduler)



class CountDown (object):
  def __init__ (self, time_manager, expire_time):
    if expire_time is None: expire_time = float("inf")
    self.time_manager = time_manager
    self.expire_time = expire_time
    self.start_time = self.time_manager.now

  def create_timer (self, f):
    if self.is_expired:
      f()
      return lambda: None
    if self.expire_time == float("inf"):
      # Fake timer!
      return lambda: None
    return self.time_manager.set_timer_in(self.remaining, f)

  @property
  def expire_at (self):
    return self.start_time + self.expire_time

  @property
  def remaining (self):
    t = self.expire_at - self.time_manager.now
    if t < 0: return 0
    return t

  @property
  def is_expired (self):
    return self.remaining == 0



class VirtualTimeManager (TimeManager):
  events_per_cycle = 1
  _halted = False
  _dry = False # True if we've run out of events
  auto_quit = False
  task = None

  def _dry_restart (self):
    """
    Kicks off the event loop again if we've run dry
    """
    if not self._dry: return
    self._dry = False
    core.scheduler.schedule(self.task)

  def set_timer_in (_self, _t, _f, *args, **kw):
    _self._dry_restart()
    return _self.set_timer_at(_t + _self._now, _f, *args, **kw)

  def set_timer_at (_self, _t, _f, *args, **kw):
    _self._dry_restart()
    if args or kw:
      f = lambda: _f(*args, **kw)
    else:
      f = _f
    en = _self._event_number
    heapq.heappush(_self._events, (_t, en, f))
    _self._event_number += 1
    # The point of the event number is so that if multiple events are
    # scheduled at the same time, they fire in the order they were
    # added.  This makes things deterministic and easier to understand.
    # Finally, we apparently now use it to kill off old timers.
    return lambda: _self._cancel_timer(en)

  @staticmethod
  def _do_nothing (*args, **kw):
    pass

  def _cancel_timer (self, event_number):
    # This is... not great.
    for i,(ts,en,f) in enumerate(self._events):
      if en == event_number:
        self._events[i] = (ts,en,self._do_nothing)
        break

  @property
  def _next_at (self):
    if not self._events: return None
    return self._events[0][0]

  def _do_one_event (self):
    if not self._events: return False
    t,en,f = heapq.heappop(self._events)
    assert t >= self._now
    self._now = t
    try:
      f()
    except Exception:
      log.exception("While processing event")
      core.quit()

    return True

  def halt (self):
    del self._events[:]
    self._halted = True

  def __init__ (self, start=False, auto_quit=auto_quit):
    self._events = []
    self._event_number = 0
    self._now = 0.0
    if start: self.start()

  def start (self, *args, **kw):
    assert not self.task
    self.task = VirtualTimeTask()
    self.task.time = self
    core.scheduler.schedule(self.task)

  @property
  def now (self):
    return self._now

  def resleep (self, t):
    return Blocker(self, timeout=t).acquire()



class VirtualTimeTask (recoco.Task):
  time = None # VirtualTimeManager instance
  priority = 0
  def run (self):
    time = self.time
    while not time._halted:
      for _ in range(time.events_per_cycle):
        if not time._do_one_event(): break

      if time._halted: return

      if time._next_at is not None:
        yield 0.0
      else:
        time._dry = True
        if time.auto_quit:
          log.info("Out of events -- quitting")
          core.quit()
        yield False # Unschedule
