from pox.core import core
from . student_socket import StudentUSocket

log = core.getLogger()


def student_socket ():
  """
  Sets all client Nodes to use the student socket class
  """
  new_usock = lambda node: StudentUSocket(node.stack.socket_manager)
  nodes = []
  for n in core.sim_topo.nodes:
    # Look for nodes with names like c<int>
    if not n.name.startswith("c"): continue
    try:
      if str(int(n.name[1:])) != n.name[1:]: continue
    except Exception:
      continue
    n.new_usocket = new_usock
    nodes.append(n.name)

  if nodes:
    log.debug("Using student socket for: %s", ", ".join(nodes))
  else:
    log.warn("Found no nodes for the student socket")
