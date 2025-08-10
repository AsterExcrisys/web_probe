package com.asterexcrisys.webprobe.types;

import org.xbill.DNS.Type;

public enum DnsRecord {

    A(Type.A),
    AAAA(Type.AAAA),
    CNAME(Type.CNAME),
    DNAME(Type.DNAME),
    PTR(Type.PTR),
    MX(Type.MX),
    PX(Type.PX),
    NS(Type.NS),
    TXT(Type.TXT),
    SOA(Type.SOA),
    SRV(Type.SRV),
    CAA(Type.CAA);

    public final int type;

    DnsRecord(int type) {
        this.type = type;
    }

    public int type() {
        return type;
    }

    public static DnsRecord nameOf(String name) {
        for (DnsRecord record : DnsRecord.values()) {
            if (record.name().equalsIgnoreCase(name)) {
                return record;
            }
        }
        return null;
    }

}