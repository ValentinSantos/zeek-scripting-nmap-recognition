
@load base/frameworks/notice

module SYNScan;

export {
    redef enum Notice::Type += {
        SYN_Scan_Detected
    };

    const scan_threshold: count = 5 &redef;
}

# Store unique suspicious TCP ports per source/destination
global scanned_ports: table[addr, addr] of set[port]
    &create_expire=5min;

# Count previous Notices for each source/destination pair
global notice_count: table[addr, addr] of count
    &default=0;

event zeek_init()
{
    print "[INIT] SYN Scan detector loaded";
}

event connection_state_remove(c: connection)
{
    # 1. Process only TCP connections
    if (get_port_transport_proto(c$id$resp_p) != tcp)
        return;

    # 2. Extract connection information
    local src: addr = c$id$orig_h;
    local dst: addr = c$id$resp_h;
    local p: port = c$id$resp_p;
    local history: string = c$history;

    # 3. Require SYN from the originator
    if (find_str(history, "S") == -1)
        return;

    # 4. Ignore completed TCP handshakes
    if (find_str(history, "A") != -1)
        return;

    # 5. Ignore connections containing originator payload
    if (find_str(history, "D") != -1)
        return;

    print fmt("[SYN] %s -> %s:%s | History: %s",
              src, dst, p, history);

    # 6. Initialize port set if necessary
    if ([src, dst] !in scanned_ports)
    {
        scanned_ports[src, dst] = set();
    }

    # 7. Ignore ports already observed
    if (p in scanned_ports[src, dst])
        return;

    # 8. Store destination port
    add scanned_ports[src, dst][p];

    local total: count = |scanned_ports[src, dst]|;

    print fmt("[COUNT] %s -> %s | Ports: %d",
              src, dst, total);

    # 9. Check detection threshold
    if (total >= scan_threshold)
    {
        local previous: count = notice_count[src, dst];

        print fmt(
            "[ALERT] Possible SYN Scan: %s -> %s | Previous Notices: %d",
            src, dst, previous
        );

        NOTICE([
            $note=SYN_Scan_Detected,
            $src=src,
            $dst=dst,
            $n=total,
            $msg=fmt(
                "Possible SYN Scan from %s to %s. Ports: %d. Previous Notices: %d",
                src, dst, total, previous
            )
        ]);

        # 10. Update previous Notices counter
        notice_count[src, dst] += 1;

        # 11. Reset scanned ports for this pair
        delete scanned_ports[src, dst];
    }
}
