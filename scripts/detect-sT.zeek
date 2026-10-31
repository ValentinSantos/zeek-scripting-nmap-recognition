# Detects Nmap connect scans (nmap -sT).
# -sT uses the normal connect() call, so on an open port the three-way
# handshake completes (history starts with ShA). Nmap then closes the
# connection right away with a RST, without sending any data.

@load base/frameworks/notice

module ConnectScan;

export {
    redef enum Notice::Type += { Connect_Scan };

    # Number of different ports before a notice is raised
    const threshold = 5 &redef;
}

# Ports probed per (scanner, target) since the last notice
global ports_seen: table[addr, addr] of set[port];

# Number of notices raised so far per (scanner, target)
global notices: table[addr, addr] of count &default=0;

event connection_state_remove(c: connection)
{
    # Only TCP connections
    if ( get_port_transport_proto(c$id$resp_p) != tcp )
        return;

    local h = c$history;

    # The handshake was completed at the start of the connection
    if ( find_str(h, "ShA") != 0 )
        return;

    # The scanner closed it with a reset
    if ( find_str(h, "R") == -1 )
        return;

    # No data was sent in either direction
    if ( find_str(h, "D") != -1 || find_str(h, "d") != -1 )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( [src, dst] !in ports_seen )
        ports_seen[src, dst] = set();

    add ports_seen[src, dst][c$id$resp_p];

    if ( |ports_seen[src, dst]| >= threshold )
    {
        NOTICE([$note=Connect_Scan, $src=src, $dst=dst,
                $msg=fmt("Possible Nmap connect scan (-sT) from %s to %s, %d ports. Previous notices: %d",
                         src, dst, threshold, notices[src, dst])]);

        notices[src, dst] += 1;
        delete ports_seen[src, dst];
    }
}
