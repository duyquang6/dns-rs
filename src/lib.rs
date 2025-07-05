struct DNSHeader {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

struct DNSQuestion {
    qname: String,
    qtype: u16,
}

struct DNSResourceRecord {
    name: String,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

struct DNSMessage {
    header: DNSHeader,
    questions: DNSQuestion,
    answers: DNSResourceRecord,
    authorities: DNSResourceRecord,
    additional: DNSResourceRecord,
}

impl DNSHeader {
    fn from_bytes(bytes: &[u8]) -> Self {
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
        let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
        let nscount = u16::from_be_bytes([bytes[8], bytes[9]]);
        let arcount = u16::from_be_bytes([bytes[10], bytes[11]]);

        Self {
            id,
            flags,
            qdcount,
            ancount,
            nscount,
            arcount,
        }
    }
}

impl DNSQuestion {
    fn from_bytes(bytes: &[u8]) -> Self {
        let qname = String::from_utf8_lossy(&bytes[12..]).to_string();
        let qtype = u16::from_be_bytes([bytes[12 + qname.len()], bytes[13 + qname.len()]]);

        Self { qname, qtype }
    }
}

impl DNSResourceRecord {
    fn from_bytes(bytes: &[u8]) -> Self {
        let name = String::from_utf8_lossy(&bytes[12..]).to_string();
        let rtype = u16::from_be_bytes([bytes[12 + name.len()], bytes[13 + name.len()]]);
        let rclass = u16::from_be_bytes([bytes[14 + name.len()], bytes[15 + name.len()]]);
        let ttl = u32::from_be_bytes([
            bytes[16 + name.len()],
            bytes[17 + name.len()],
            bytes[18 + name.len()],
            bytes[19 + name.len()],
        ]);
        let rdata = bytes[20 + name.len()..].to_vec();

        Self {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        }
    }
}

impl DNSMessage {
    fn from_bytes(bytes: &[u8]) -> Self {
        let header = DNSHeader::from_bytes(bytes);
        let questions = DNSQuestion::from_bytes(bytes);
        let answers = DNSResourceRecord::from_bytes(bytes);
        let authorities = DNSResourceRecord::from_bytes(bytes);
        let additional = DNSResourceRecord::from_bytes(bytes);
        Self {
            header,
            questions,
            answers,
            authorities,
            additional,
        }
    }
}
