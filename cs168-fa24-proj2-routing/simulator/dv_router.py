"""
Your awesome Distance Vector router for CS 168

Based on skeleton code by:
  MurphyMc, zhangwen0411, lab352
"""

import sim.api as api
from cs168.dv import (
    RoutePacket,
    Table,
    TableEntry,
    DVRouterBase,
    Ports,
    FOREVER,
    INFINITY,
)


class DVRouter(DVRouterBase):

    # A route should time out after this interval
    ROUTE_TTL = 15

    # -----------------------------------------------
    # At most one of these should ever be on at once
    SPLIT_HORIZON = False
    POISON_REVERSE = False
    # -----------------------------------------------

    # Determines if you send poison for expired routes
    POISON_EXPIRED = False

    # Determines if you send updates when a link comes up
    SEND_ON_LINK_UP = False

    # Determines if you send poison when a link goes down
    POISON_ON_LINK_DOWN = False

    def __init__(self):
        """
        Called when the instance is initialized.
        DO NOT remove any existing code from this method.
        However, feel free to add to it for memory purposes in the final stage!
        """
        assert not (
            self.SPLIT_HORIZON and self.POISON_REVERSE
        ), "Split horizon and poison reverse can't both be on"

        self.start_timer()  # Starts signaling the timer at correct rate.

        # Contains all current ports and their latencies.
        # See the write-up for documentation.
        self.ports = Ports()

        # This is the table that contains all current routes
        self.table = Table()
        self.table.owner = self

        ##### Begin Stage 10A #####
        self.history = {}
        ##### End Stage 10A #####

    def add_static_route(self, host, port):
        """
        Adds a static route to this router's table.

        Called automatically by the framework whenever a host is connected
        to this router.

        :param host: the host.
        :param port: the port that the host is attached to.
        :returns: nothing.
        """
        # `port` should have been added to `peer_tables` by `handle_link_up`
        # when the link came up.
        assert port in self.ports.get_all_ports(), "Link should be up, but is not."

        ##### Begin Stage 1 #####
        latency = self.ports.get_latency(port)
        entry = TableEntry(dst=host, port=port, latency=latency, expire_time=FOREVER)
        self.table[host] = entry 
        ##### End Stage 1 #####

    def handle_data_packet(self, packet, in_port):
        """
        Called when a data packet arrives at this router.

        You may want to forward the packet, drop the packet, etc. here.

        :param packet: the packet that arrived.
        :param in_port: the port from which the packet arrived.
        :return: nothing.
        """
        
        ##### Begin Stage 2 #####
        
        dst = packet.dst
        if dst in self.table:
            entry = self.table[dst]
            if entry.latency < INFINITY:
                if in_port != entry.port:
                    self.send(packet, port=entry.port)
        ##### End Stage 2 #####
        
    def send_routes(self, force=False, single_port=None):
        """
        Send route advertisements for all routes in the table.

        :param force: if True, advertises ALL routes in the table;
                      otherwise, advertises only those routes that have
                      changed since the last advertisement.
               single_port: if not None, sends updates only to that port; to
                            be used in conjunction with handle_link_up.
        :return: nothing.
        """
        
        ##### Begin Stages 3, 6, 7, 8, 10 #####
        packet_list = []
        port_list = [] 
        map = {}
        for host, entry in self.table.items():
            packet_list.append(RoutePacket(host, entry.latency))
            map[host] = entry.port
        if (single_port == None):
            port_list = self.ports.get_all_ports()
        else:
            port_list.append(single_port)
        for port in port_list:
            for item in packet_list:
                update_flag = 0
                tmp = item
                new_flag = ((port, tmp.destination) in self.history and self.history[(port, tmp.destination)] == tmp.latency)            
                if (self.POISON_REVERSE and port == map[item.destination]):
                    tmp = RoutePacket(item.destination, INFINITY)
                    new_flag = ((port, tmp.destination) in self.history and self.history[(port, tmp.destination)] == tmp.latency)
                    if (force == True or (not new_flag)):
                        self.send_route(port, tmp.destination, INFINITY)
                        update_flag = 1
                elif(not(self.SPLIT_HORIZON and port == map[item.destination])):
                    if (force == True or (not new_flag)):
                        self.send_route(port, tmp.destination, tmp.latency)
                        update_flag = 1
                if (update_flag == 1):
                    if (not new_flag):
                        self.history[(port, tmp.destination)] = tmp.latency
        ##### End Stages 3, 6, 7, 8, 10 #####

    def expire_routes(self):
        """
        Clears out expired routes from table.
        accordingly.
        """
        
        ##### Begin Stages 5, 9 #####
        current_time = api.current_time()
        for dst, entry in list(self.table.items()):
            if entry.expire_time < current_time:
                if self.POISON_EXPIRED:
                    self.table[dst] = TableEntry(dst=self.table[dst].dst, port=self.table[dst].port, latency=INFINITY, expire_time=current_time + self.ROUTE_TTL)
                    self.log(f"Route to {dst} expired and was poisoned.")
                else:
                    self.table.pop(dst)
                    self.log(f"Route to {dst} expired and was removed from the routing table.")
        ##### End Stages 5, 9 #####

    def handle_route_advertisement(self, route_dst, route_latency, port):
        """
        Called when the router receives a route advertisement from a neighbor.

        :param route_dst: the destination of the advertised route.
        :param route_latency: latency from the neighbor to the destination.
        :param port: the port that the advertisement arrived on.
        :return: nothing.
        """
        
        ##### Begin Stages 4, 10 #####
        new_latency = route_latency + self.ports.get_latency(port)
        update_flag = 0
        expire_time = 0  
        if route_dst in self.table:
            entry = self.table[route_dst]
            if (new_latency < entry.latency):
                update_flag = 1
            elif (entry.port == port):
                update_flag = 1
                if (route_latency >= INFINITY):
                    update_flag = 2
                    expire_time = entry.expire_time
        else:
            update_flag = 1
        if (update_flag == 1):
            self.table[route_dst] = TableEntry(dst=route_dst, port=port, latency=new_latency, expire_time=api.current_time() + self.ROUTE_TTL)
        elif (update_flag == 2):
            self.table[route_dst] = TableEntry(dst=route_dst, port=port, latency=INFINITY, expire_time=expire_time)
        self.send_routes(False, None)
        ##### End Stages 4, 10 #####

    def handle_link_up(self, port, latency):
        """
        Called by the framework when a link attached to this router goes up.

        :param port: the port that the link is attached to.
        :param latency: the link latency.
        :returns: nothing.
        """
        self.ports.add_port(port, latency)

        ##### Begin Stage 10B #####
        if (self.SEND_ON_LINK_UP):
            self.send_routes(True, port)
        ##### End Stage 10B #####

    def handle_link_down(self, port):
        """
        Called by the framework when a link attached to this router goes down.

        :param port: the port number used by the link.
        :returns: nothing.
        """
        self.ports.remove_port(port)

        ##### Begin Stage 10B #####
        if (self.POISON_ON_LINK_DOWN):
            for host, entry in self.table.items():
                if (entry.port == port):
                    self.table[host] = TableEntry(dst=host, port=entry.port, latency=INFINITY, expire_time=api.current_time() + self.ROUTE_TTL)
            self.send_routes(False, None)
        ##### End Stage 10B #####

    # Feel free to add any helper methods!