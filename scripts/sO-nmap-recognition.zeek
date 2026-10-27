
@load base/frameworks/notice
@load base/protocols/conn

module IPProtocolScan;

export {
    redef enum Notice::Type += {
        IP_Protocol_Scan_Detected
    };

    const scan_threshold: count = 10 &redef;
}

# Unique IP protocol numbers per source/destination
global scanned_protocols: table[addr, addr] of set[count]
    &create_expire=60secs;

# Previous alerts per source/destination
global notice_count: table[addr, addr] of count
    &default=0;

event zeek_init()
{
    print "[INIT] IP Protocol Scan detector loaded";
}

event Conn::log_conn(rec: Conn::Info)
{
    # 1. Ensure the IP protocol field exists
    if ( ! rec?$ip_proto )
        return;

    # 2. Extract relevant information
    local src: addr = rec$id$orig_h;
    local dst: addr = rec$id$resp_h;
    local proto: count = rec$ip_proto;

    # 3. Only analyze IPv4 traffic
    if ( ! is_v4_addr(src) || ! is_v4_addr(dst) )
        return;

    # 4. Initialize protocol set
    if ([src, dst] !in scanned_protocols)
    {
        scanned_protocols[src, dst] = set();
    }

    # 5. Ignore already observed protocols
    if (proto in scanned_protocols[src, dst])
        return;

    # 6. Store new protocol number
    add scanned_protocols[src, dst][proto];

    # 7. Count unique protocols
    local total: count = |scanned_protocols[src, dst]|;

    print fmt(
        "[PROTO] %s -> %s | Protocol: %d | Total: %d",
        src, dst, proto, total
    );

    # 8. Check the detection threshold
    if (total >= scan_threshold)
    {
        local previous: count = notice_count[src, dst];

        print fmt(
            "[ALERT] IP Protocol Scan: %s -> %s | Previous Notices: %d",
            src, dst, previous
        );

        NOTICE([
            $note=IP_Protocol_Scan_Detected,
            $src=src,
            $dst=dst,
            $n=total,
            $identifier=fmt("%s-%s-%d", src, dst, previous),
            $msg=fmt(
                "Possible Nmap -sO scan from %s to %s. Protocols: %d. Previous Notices: %d",
                src, dst, total, previous
            )
        ]);

        # 9. Increase previous Notice counter
        notice_count[src, dst] += 1;

        # 10. Reset the protocol set
        delete scanned_protocols[src, dst];
    }
}
