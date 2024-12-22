# Authors:
# James McCauley, 2018
# amaro, 2018

class Scorer (object):
  def __init__ (self, log):
    self.log = log
    self.max_points = 0
    self.points = 0
    self._pending_name = None
    self._pending_points = None
    self._pending_default = None

  def _score (self, points = True, msg = None):
    if self._pending_name is None:
      raise RuntimeError("No pending item to score")
    name = self._pending_name
    self._pending_name = None
    qpts = self._pending_points
    self._pending_points = None
    self._pending_default = None
    if points is True: points = True if qpts is None else qpts
    elif points is False: points = 0
    if qpts is not None and points is not None and points > qpts:
      raise RuntimeError("Too many points?")
    if qpts and points:
      self.points += points

    m = name
    if points is None:
      m += ": Didn't Run - A previous test probably failed"
      if qpts: m += " (-- of %s)" % (qpts,)
    elif qpts is None:
      if points:
        m += ": Success"
      else:
        m += ": Failure"
      if msg: m += " - " + msg
    else:
      if points == qpts:
        m += ": Success"
      else:
        m += ": Failure"
      if msg: m += " - " + msg
      m += " (%s of %s)" % (points, qpts)

    if qpts is None:
      if points:
        lg = self.log.debug
      else:
        lg = self.log.warn
    else:
      if points == qpts:
        lg = self.log.info
      elif points == 0:
        lg = self.log.error
      else:
        lg = self.log.warn

    lg(m)

  def _finish_pending (self):
    if self._pending_name is None: return
    self._score(self._pending_default)

  def item (self, name, points=None, default=None):
    self._finish_pending()
    self._pending_name = name
    self._pending_points = points
    self._pending_default = None
    if points: self.max_points += points

  def success (self):
    self._score(True)

  def fail (self):
    self._score(0)

  def expect (self, expected, got):
    if expected == got:
      self._score(True)
    else:
      self._score(False, "Expected %s.  Got %s." % (repr(expected), repr(got)))

  def finish (self):
    self._finish_pending()
    def fn (n):
      n = "%0.2f" % (n,)
      if n.endswith(".00"): n = n[:-3]
      return n
    maxpt = self.max_points or self._max_points
    args = (fn(self.points), fn(maxpt),
            fn(self.points*100.0/maxpt))
    if self.points > maxpt:
      raise RuntimeError("Scoring problem")
    if self.points == maxpt:
      l = self.log.info
    elif self.points <= 0:
      l = self.log.error
    else:
      l = self.log.warn
    l("Total score: %s of %s (%s%%)", *args)

class Tester (object):
  def __init__ (self, log):
    self.log = log
    self.checks = []

  def expect_eq (self, expected, got, desc):
    msg = "check {0}: {1}".format(len(self.checks), desc)

    if expected == got:
      self.checks.append(True)
      self.log.info("{0}: OK".format(msg))
    else:
      self.checks.append(False)
      self.log.error("{0}: FAIL. Expected \"{1}\", got \"{2}\"".format(msg, expected, got))

  def expect_true (self, got, desc):
    self.expect_eq(True, got, desc)

  def finish (self):
    all_ok = all(self.checks)
    if all_ok:
      self.log.info("All checks passed, test PASSED")
    else:
      self.log.error("At least one check failed, test FAILED")
