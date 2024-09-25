import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
       # pass  # TODO
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.version = int(b[0:4], 2)
        self.header_len = int(b[4:8], 2) * 4  
        self.tos = int(b[8:16], 2)
        self.length = int(b[16:32], 2)
        self.id = int(b[32:48], 2)
        self.flags = int(b[48:51], 2)
        self.frag_offset = int(b[51:64], 2)
        self.ttl = int(b[64:72], 2)
        self.proto = int(b[72:80], 2)
        self.cksum = int(b[80:96], 2)
        self.src = '.'.join(str(int(b[i:i+8], 2)) for i in range(96, 128, 8))
        self.dst = '.'.join(str(int(b[i:i+8], 2)) for i in range(128, 160, 8))
    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
      #  pass  # TODO
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.type = int(b[0:8], 2)
        self.code = int(b[8:16], 2)
        self.cksum = int(b[16:32], 2)

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
      #  pass  # TODO
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.src_port = int(b[0:16], 2)
        self.dst_port = int(b[16:32], 2)
        self.len = int(b[32:48], 2)
        self.cksum = int(b[48:64], 2)
    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like
import time

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """  
    # TODO Add your implementation
   # for ttl in range(1, TRACEROUTE_MAX_TTL+1):
     #   util.print_result([], ttl)
    #return []

    routers = []
    other_routers = []
    for ttl in range(1, TRACEROUTE_MAX_TTL+1):
        sendsock.set_ttl(ttl)
        found_routers = []
        other_routers = []
        for attempt in range(3):
            sendsock.sendto(b'Garlic', (ip, TRACEROUTE_PORT_NUMBER + ttl - 1))      
        remaining_run_time = 3
        while(remaining_run_time > 0):
            remaining_run_time = remaining_run_time-1
            if recvsock.recv_select():
                buf, addr = recvsock.recvfrom()
                if len(buf) < 20:
                    continue
                ipv4_header = IPv4(buf[:20])
                if ipv4_header.proto != 1: 
                    continue
                if len(buf) < ipv4_header.header_len + 8:
                    continue
                icmp_header = ICMP(buf[ipv4_header.header_len:ipv4_header.header_len + 8])
                if icmp_header.type not in [3, 11]:
                    continue 
                if icmp_header.type == 11 and icmp_header.code != 0:
                    continue 
                icmp_payload_start = ipv4_header.header_len + 8
                if len(buf) < icmp_payload_start + 20 + 8:
                    continue 
                original_ipv4_header = IPv4(buf[icmp_payload_start:icmp_payload_start + 20])
                original_udp_header = UDP(buf[icmp_payload_start + original_ipv4_header.header_len:icmp_payload_start + original_ipv4_header.header_len + 8])
                if original_ipv4_header.dst != ip:
                    continue  
                if original_udp_header.dst_port != TRACEROUTE_PORT_NUMBER + ttl - 1:
                    remaining_run_time += 1
                    continue 
                if ipv4_header.src in found_routers:
                    continue
                router_ip = ipv4_header.src
                if icmp_header.type == 11:
                    if (router_ip not in found_routers) and (router_ip not in other_routers) and ((original_udp_header.dst_port==TRACEROUTE_PORT_NUMBER+ttl-1) or (len(found_routers)<1)):
                        found_routers.append(router_ip)
                    elif (router_ip not in found_routers) and (router_ip not in other_routers) and ((original_udp_header.dst_port!=TRACEROUTE_PORT_NUMBER+ttl-1 )):
                        other_routers.append(router_ip)
                elif icmp_header.type == 3 and icmp_header.code == 3:
                    if (router_ip not in found_routers) and (router_ip not in other_routers) and ((original_udp_header.dst_port==TRACEROUTE_PORT_NUMBER+ttl-1) or (len(found_routers)<1)):
                        found_routers.append(router_ip)
                    elif (router_ip not in found_routers) and (router_ip not in other_routers) and ((original_udp_header.dst_port!=TRACEROUTE_PORT_NUMBER+ttl-1)):
                        other_routers.append(router_ip)
        routers.append(found_routers)
        if len(other_routers)>0:
            routers.append(other_routers)
        util.print_result(found_routers, ttl)
        if ip in found_routers:
            break

    return routers

if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
