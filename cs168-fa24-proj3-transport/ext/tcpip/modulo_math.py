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
Modulo math stuff

TCP has all this unsigned modulo math which of course maps directly to C,
but that's not how numbers work in Python!  So we add these "operators"
that work how we want them to.  So, for example, to add numbers and get
the expected wraparound behavior, you'd do:
 0xffFFffFF |PLUS| 1 (equals 0)
"""

import operator

class DeferredOp (object):
  def __init__ (self, f):
    self.f = f

  def __or__ (self, other):
    return self.f(other)


class U32BinaryOperator (object):
  def __ror__ (self, other):
    return DeferredOp(lambda o: self.op(other, o))


U32_MASK = 0xFFffFFff

def u32_binary_op (f):
  return lambda a,b: f(a & U32_MASK, b & U32_MASK) & U32_MASK

def _make_u32_binary_op (name, op):
  c = type(name, (U32BinaryOperator,), dict(op=staticmethod(u32_binary_op(op))))
  globals()[name] = c()

def _MLT (s, t):
  return 0 < (t |MINUS| s) < 0x80000000

def _MGT (t, s):
  return 0 < (t |MINUS| s) < 0x80000000

def _MLE (s, t):
  return 0 <= (t |MINUS| s) < 0x80000000

def _MGE (t, s):
  return 0 <= (t |MINUS| s) < 0x80000000

_make_u32_binary_op("PLUS", operator.add)
_make_u32_binary_op("MINUS", operator.sub)
_make_u32_binary_op("TIMES", operator.mul)
_make_u32_binary_op("DIVIDED_BY", operator.truediv)
_make_u32_binary_op("GT", operator.gt)
_make_u32_binary_op("GE", operator.ge)
_make_u32_binary_op("LT", operator.lt)
_make_u32_binary_op("LE", operator.le)
_make_u32_binary_op("EQ", operator.eq)
_make_u32_binary_op("NE", operator.ne)
_make_u32_binary_op("MGT", _MGT)
_make_u32_binary_op("MGE", _MGE)
_make_u32_binary_op("MLT", _MLT)
_make_u32_binary_op("MLE", _MLE)
