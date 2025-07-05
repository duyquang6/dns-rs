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
    qclass: u16,
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
    answers: Option<DNSResourceRecord>,
    authorities: Option<DNSResourceRecord>,
    additional: Option<DNSResourceRecord>,
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
    fn from_bytes(bytes: &[u8]) -> (Self, usize) {
        let mut offset = 0;
        // parse qname
        let mut qname = String::new();
        while bytes[offset] != 0 {
            let length = bytes[offset];
            offset += 1;

            qname.push_str(&String::from_utf8_lossy(
                &bytes[offset..offset + length as usize],
            ));
            offset += length as usize;
            if bytes[offset] != 0 {
                qname.push('.');
            }
        }

        let qtype = u16::from_be_bytes([bytes[offset + 1], bytes[offset + 2]]);
        let qclass = u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]);

        offset += 5;

        (
            Self {
                qname,
                qtype,
                qclass,
            },
            offset,
        )
    }
}

impl DNSResourceRecord {
    fn from_bytes(bytes: &[u8]) -> (Self, usize) {
        let name = String::from_utf8_lossy(&bytes[0..]).to_string();
        let offset = name.len();
        let rtype = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let rclass = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
        let ttl = u32::from_be_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        let rdata = bytes[offset + 8..].to_vec();

        (
            Self {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            },
            offset + 10,
        )
    }
}

impl DNSMessage {
    fn from_bytes(bytes: &[u8]) -> Self {
        let header = DNSHeader::from_bytes(bytes);
        let (questions, next_offset) = DNSQuestion::from_bytes(&bytes[12..]);

        let mut offset = next_offset + 12;

        let mut answers = None;
        let mut authorities = None;
        let mut additional = None;

        if offset < bytes.len() {
            let (answer, next_offset) = DNSResourceRecord::from_bytes(&bytes[offset..]);
            answers = Some(answer);
            offset += next_offset;
        }

        if offset < bytes.len() {
            let (authority, next_offset) = DNSResourceRecord::from_bytes(&bytes[offset..]);
            authorities = Some(authority);
            offset += next_offset;
        }

        if offset < bytes.len() {
            let (additional_record, _) = DNSResourceRecord::from_bytes(&bytes[offset..]);
            additional = Some(additional_record);
        }

        Self {
            header,
            questions,
            answers,
            authorities,
            additional,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_header_from_bytes() {
        let bytes =
            hex::decode("b7170100000100000000000006676f6f676c6503636f6d0000010001").unwrap();
        let dns_header = DNSHeader::from_bytes(&bytes);
        assert_eq!(dns_header.id, 0xb717);
        assert_eq!(dns_header.flags, 0x0100);
        assert_eq!(dns_header.qdcount, 1);
        assert_eq!(dns_header.ancount, 0);
        assert_eq!(dns_header.nscount, 0);
        assert_eq!(dns_header.arcount, 0);
    }

    #[test]
    fn test_dns_question_from_bytes() {
        let bytes =
            hex::decode("b7170100000100000000000006676f6f676c6503636f6d0000010001").unwrap();
        let (dns_question, next_offset) = DNSQuestion::from_bytes(&bytes[12..]);
        assert_eq!(dns_question.qname, "google.com");
        assert_eq!(dns_question.qtype, 1);
        assert_eq!(next_offset + 12, bytes.len());
    }

    #[test]
    fn test_dns_message_from_bytes() {
        let bytes =
            hex::decode("b7170100000100000000000006676f6f676c6503636f6d0000010001").unwrap();
        let dns_message = DNSMessage::from_bytes(&bytes);
        assert_eq!(dns_message.header.id, 0xb717);
        assert_eq!(dns_message.header.flags, 0x0100);
        assert_eq!(dns_message.header.qdcount, 1);
        assert_eq!(dns_message.header.ancount, 0);
        assert_eq!(dns_message.header.nscount, 0);
        assert_eq!(dns_message.header.arcount, 0);
        assert_eq!(dns_message.questions.qname, "google.com");
        assert_eq!(dns_message.questions.qtype, 1);
        assert_eq!(dns_message.questions.qclass, 1);
        assert_eq!(dns_message.answers.is_none(), true);
        assert_eq!(dns_message.authorities.is_none(), true);
        assert_eq!(dns_message.additional.is_none(), true);
    }
}
