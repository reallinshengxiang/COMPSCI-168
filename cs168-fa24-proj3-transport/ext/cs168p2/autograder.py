import unittest
import socket
import subprocess
import threading
import os
import shlex
import re
import sys
import datetime

class Application(object):
  def __init__(self, cmdline):
    self.cmdline = cmdline
    self.thread = None
    self.popen = None
    self.stdout = None
    self.stderr = None

  # execute in self.thread
  def __exec(self):
    print(self.cmdline)
    self.popen = subprocess.Popen(self.cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    self.stdout, self.stderr = self.popen.communicate()

  def start(self):
    self.thread = threading.Thread(target=self.__exec)
    self.thread.start()

    while not self.is_alive():
      pass

  def is_alive(self):
    return self.thread.is_alive() and self.popen

  def wait_finish(self):
    self.thread.join(5)
    if self.thread.is_alive():
      self.popen.terminate()
      return False

    return True

  def get_pid(self):
    return self.popen.pid

  def get_retcode(self):
    return self.popen.returncode

  def get_stdout(self):
    return self.stdout

  def get_stderr(self):
    return self.stderr

class Pox(Application):
  POX_PY = '../../pox.py'

  def __init__(self, test, tracefile):
    cmdline = "{0} config={1} tcpip.pcap --node=r1 --no-tx --filename={2}".format(self.POX_PY, test, tracefile)
    super(Pox, self).__init__(cmdline)

class IndTestCase(unittest.TestCase):
  pass_str = "All checks passed, test PASSED"

  # Runs pox with the config
  def run_pox(self, test, trace):

    pox = Pox(test, trace)
    pox.start()
    self.assertTrue(pox.wait_finish(),
        "Test didn't finish in less than 5 seconds. Run this test manually for more details (see spec 3.6.1 for instructions).")

    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    self.assertEqual(pox.get_retcode(), 0,
        "Something went wrong while executing test. Run this test manually for more details (see spec 3.6.1 for instructions).")
    output = str(pox.get_stderr())
    output = ansi_escape.sub('', output)
    self.assertTrue(self.pass_str in output, "Test failed, the console output was:\n{0}".format(output))

class AutoGrader():
  def __init__(self):
    self.test_dir = "./tests"
    self.configs = self.get_configs(self.test_dir)
    self.num_stages = 9
    self.test_cases = {}
    for i in range(1 + self.num_stages):
      self.create_test_for_stage(i)
    self.create_trace_dir()

  # Lists all .cfg test configs in the test directory
  def get_configs(self, test_path):
    cfg_file = lambda f: os.path.isfile(os.path.join(self.test_dir, f)) and f.endswith(".cfg")
    return [f for f in os.listdir(self.test_dir) if cfg_file(f)]

  # Lists all .cfg test configs in the test directory
  def get_configs_for_stage(self, stage):
    return [f for f in self.configs if f.startswith(stage)]

  # Creates methods for each config for a particular stage and also the method for the whole stage
  def create_test_for_stage(self, stage):
    stage_configs = self.get_configs_for_stage("s" + str(stage) + "_")
    for t in stage_configs:

      def unit_test(self):
        print("\n    Running test: " + self.cfg)
        print("    Tracefile: " + self.trace)
        self.run_pox(self.cfg, self.trace)

      name = "test_" + t.replace(".cfg", "")
      sub_class = type(name, (IndTestCase,), {name: unit_test})
      trace = datetime.datetime.now().isoformat()
      tracedir = t.replace(".cfg", "") + "/"
      setattr(sub_class, "cfg", os.path.join(self.test_dir, t))
      setattr(sub_class, "trace", "./trace/" + tracedir + trace)

      self.test_cases[name] = sub_class

  # Returns all tests for a given stage
  def get_tests_for_stage(self, stage):
    tests = [y for x, y in self.test_cases.items() if x.startswith("test_s{0}_".format(stage))]
    return sorted(tests, key=lambda x: x.cfg)

  # Sets up the trace folder with the correct sub directories
  def create_trace_dir(self):
    try:
      os.makedirs("./trace")
    except:
      pass
    for d in self.test_cases.keys():
      d = d.replace("test_", "")
      try:
        os.makedirs("./trace/" + d)
      except:
        pass

  # Creates a TestSuite and runs the TestCases
  def test(self, test_cases):
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for test_class in test_cases:
        t = loader.loadTestsFromTestCase(test_class)
        suite.addTests(t)
    unittest.TextTestRunner(verbosity=2).run(suite)

  # If input is sX, then run all tests for stage X
  # If input is sX_tY, then run the test sX_tY
  # If input is all, then run all tests
  # If input is all Z, then run all tests up to and including stage Z
  def run(self, input):
    tests = []
    if input[0] == "all":
      if len(input) == 1:
        upto = self.num_stages
      else:
        upto = int(input[1])
      for i in range(upto + 1):
        tests.extend(self.get_tests_for_stage(i))
    else:
      for inp in input:
        if "_" not in inp:
          tests.extend(self.get_tests_for_stage(inp[1:]))
        else:
          tests.append(self.test_cases["test_" + inp])

    self.test(tests)

if __name__ == '__main__':
  input = sys.argv[1:]
  ag = AutoGrader()
  ag.run(input)
