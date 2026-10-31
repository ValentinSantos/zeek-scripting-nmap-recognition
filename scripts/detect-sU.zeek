# Detects Nmap UDP scans (nmap -sU).
# For most ports -sU sends an empty UDP datagram. Closed ports answer
# with ICMP port unreachable, open or filtered ports usually stay silent.
# Either way the UDP connection carries no data from the scanner.

@load base/frameworks/notice

module UdpScan;

export {
    redef enum Notice::Type += { UDP_Scan };

    # Number of different ports before a notice is raised
    const threshold = 50 &redef;
}

# Ports probed per (scanner, target) since the last notice
global ports_seen: table[addr, addr] of set[port];

# Number of notices raised so far per (scanner, target)
global notices: table[addr, addr] of count &default=0;

event connection_state_remove(c: connection)
{
    # Only UDP connections
    if ( get_port_transport_proto(c$id$resp_p) != udp )
        return;

    # The scanner sent an empty datagram
    if ( c$orig$size > 0 )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( [src, dst] !in ports_seen )
        ports_seen[src, dst] = set();

    add ports_seen[src, dst][c$id$resp_p];

    if ( |ports_seen[src, dst]| >= threshold )
    {
        NOTICE([$note=UDP_Scan, $src=src, $dst=dst,
                $msg=fmt("Possible Nmap UDP scan (-sU) from %s to %s, %d ports. Previous notices: %d",
                         src, dst, threshold, notices[src, dst])]);

        notices[src, dst] += 1;
        delete ports_seen[src, dst];
    }
}
