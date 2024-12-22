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
Basic units used for TCP/IP stuff
"""

# We use bits per second as the base unit
bps  = 1
Kbps = 1000   # nonstandard     :(
kbps = Kbps   # noncapitalized  :(
Mbps = 1000000
Gbps = 1000000000

# We use milliseconds as the base unit
nSec = 0.000001 # nano
uSec = 0.001 # micro
mSec = 1
Sec = 1000.0


Infinity = float("inf")

import sys
import math

Epsilon = sys.float_info.epsilon



def seconds_to_str (s, fractional=None):
  """
  Converts seconds to hh:mm:ss[.frac]

  By default, fractional is automatic, but can be overridden with True/False.
  """
  s,ps = divmod(s, 1)
  m, s = divmod(s, 60)
  h, m = divmod(m, 60)
  r = "%02i:%02i:%02i" % (h, m, s)
  if ((fractional is True)
      or (fractional is None and ps != 0)):
    r += (".%0.3f" % (ps,))[2:]
  return r



def bps_to_str (bits, duration=None):
  """
  Format a nice bitrate

  Can be called in two ways:
  * With one parameter, bits is the bps
  * With two parameters, the first is the number of bits, and second is time

  The point of the second form is that it can avoid a division by zero if the
  duration is 0.  bps_to_str() handles it nicely for you rather than you
  needing to deal with it.
  """
  if duration is not None:
    if duration == 0:
      return "InfiniteGbps"
    else:
      bps = bits/float(duration)
  else:
    bps = bits
  for n in "Gbps Mbps kbps bps".split():
    f = globals()[n]
    if f > bps: continue
    r = "%0.3f" % (float(bps)/f,)
    # There is surely a better way, but I never remember it...
    while r.endswith("0"): r = r[:-1]
    if r.endswith("."): r = r[:-1]
    return r + n
