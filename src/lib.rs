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
    fn from_bytes(bytes: &[u8]) -> (Self, usize) {
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
        let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
        let nscount = u16::from_be_bytes([bytes[8], bytes[9]]);
        let arcount = u16::from_be_bytes([bytes[10], bytes[11]]);

        (
            Self {
                id,
                flags,
                qdcount,
                ancount,
                nscount,
                arcount,
            },
            12,
        )
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.qdcount.to_be_bytes());
        bytes.extend_from_slice(&self.ancount.to_be_bytes());
        bytes.extend_from_slice(&self.nscount.to_be_bytes());
        bytes.extend_from_slice(&self.arcount.to_be_bytes());
        bytes
    }
}

impl DNSQuestion {
    fn from_bytes(bytes: &[u8], start_offset: usize) -> (Self, usize) {
        let mut offset = start_offset;
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

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in self.qname.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&self.qtype.to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());
        bytes
    }
}

fn parse_label(bytes: &[u8], start_offset: usize) -> (String, usize) {
    let mut label = String::new();
    let mut offset = start_offset;
    while bytes[offset] != 0 {
        // pointer to another label
        if bytes[offset] == 0xc0 {
            let pointer = bytes[offset + 1] as usize;
            let (label, _) = parse_label(bytes, pointer);
            return (label, offset + 2);
        }
        let length = bytes[offset];
        offset += 1;
        label.push_str(&String::from_utf8_lossy(
            &bytes[offset..offset + length as usize],
        ));
        offset += length as usize;
        if bytes[offset] != 0 {
            label.push('.');
        }
    }
    // skip zero byte
    offset += 1;
    (label, offset)
}

impl DNSResourceRecord {
    fn from_bytes(bytes: &[u8], start_offset: usize) -> (Self, usize) {
        let mut offset = start_offset;
        let (name, next_offset) = parse_label(bytes, offset);
        offset = next_offset;

        let rtype = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let rclass = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
        let ttl = u32::from_be_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);

        let rdata_length = u16::from_be_bytes([bytes[offset + 8], bytes[offset + 9]]);
        let rdata = bytes[offset + 10..offset + 10 + rdata_length as usize].to_vec();

        (
            Self {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            },
            offset + 10 + rdata_length as usize,
        )
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.name.as_bytes());
        bytes.extend_from_slice(&self.rtype.to_be_bytes());
        bytes.extend_from_slice(&self.rclass.to_be_bytes());
        bytes.extend_from_slice(&self.ttl.to_be_bytes());
        bytes.extend_from_slice(&self.rdata);
        bytes
    }
}

impl DNSMessage {
    fn from_bytes(bytes: &[u8]) -> Self {
        let (header, offset) = DNSHeader::from_bytes(bytes);
        let (questions, offset) = DNSQuestion::from_bytes(&bytes, offset);

        let mut answers = None;
        let mut authorities = None;
        let mut additional = None;

        let mut offset = offset;
        if offset < bytes.len() {
            let (answer, next_offset) = DNSResourceRecord::from_bytes(&bytes, offset);
            answers = Some(answer);
            offset = next_offset;
        }

        if offset < bytes.len() {
            let (authority, next_offset) = DNSResourceRecord::from_bytes(&bytes, offset);
            authorities = Some(authority);
            offset = next_offset;
        }

        if offset < bytes.len() {
            let (additional_record, next_offset) = DNSResourceRecord::from_bytes(&bytes, offset);
            additional = Some(additional_record);
            offset = next_offset;
        }

        Self {
            header,
            questions,
            answers,
            authorities,
            additional,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.questions.to_bytes());
        if let Some(answer) = &self.answers {
            bytes.extend_from_slice(&answer.to_bytes());
        }
        if let Some(authority) = &self.authorities {
            bytes.extend_from_slice(&authority.to_bytes());
        }
        if let Some(additional) = &self.additional {
            bytes.extend_from_slice(&additional.to_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::UdpSocket;

    use super::*;

    #[tokio::test]
    async fn test_query_root_server() {
        let mut dns_message = DNSMessage {
            header: DNSHeader {
                id: 0,
                flags: 0,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: DNSQuestion {
                qname: "google.com".to_string(),
                qtype: 1,
                qclass: 1,
            },
            answers: None,
            authorities: None,
            additional: None,
        };

        let root_server = "198.41.0.4:53";
        let mut socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        socket
            .send_to(dns_message.to_bytes().as_slice(), root_server)
            .await
            .unwrap();

        let mut buf = [0; 1024];
        let (amt, src) = socket.recv_from(&mut buf).await.unwrap();

        println!(
            "Received response from {}, length: {}, hex_message: {}",
            src,
            amt,
            hex::encode(&buf[..amt])
        );

        let dns_message = DNSMessage::from_bytes(&buf[..amt]);
    }

    #[test]
    fn test_parse_dns_answer() {
        let bytes =
            hex::decode("00008080000100010000000006676f6f676c6503636f6d0000010001c00c000100010000002d00048efa47ee").unwrap();
        let (dns_rr, next_offset) = DNSResourceRecord::from_bytes(&bytes, 28);
        assert_eq!(dns_rr.name, "google.com");
        assert_eq!(dns_rr.rtype, 1);
        assert_eq!(dns_rr.rclass, 1);
        assert_eq!(dns_rr.ttl, 45);
        assert_eq!(dns_rr.rdata, vec![0x8e, 0xfa, 0x47, 0xee]);
        assert_eq!(next_offset, 44);
    }

    #[test]
    fn test_parse_dns_message_with_pointer() {
        let bytes =
            hex::decode("00008080000100010000000006676f6f676c6503636f6d0000010001c00c000100010000002d00048efa47ee").unwrap();

        let dns_message = DNSMessage::from_bytes(&bytes);
        assert_eq!(dns_message.header.id, 0x0000);
        assert_eq!(dns_message.header.flags, 0x8080);
        assert_eq!(dns_message.header.qdcount, 1);
        assert_eq!(dns_message.header.ancount, 1);
        assert_eq!(dns_message.header.nscount, 0);
        assert_eq!(dns_message.header.arcount, 0);

        assert_eq!(dns_message.questions.qname, "google.com");
        assert_eq!(dns_message.questions.qtype, 1);
        assert_eq!(dns_message.questions.qclass, 1);
        assert_eq!(dns_message.answers.is_some(), true);

        let answer = dns_message.answers.unwrap();
        assert_eq!(answer.name, "google.com");
        assert_eq!(answer.rtype, 1);
        assert_eq!(answer.rclass, 1);
        assert_eq!(answer.ttl, 45);
        assert_eq!(answer.rdata, vec![0x8e, 0xfa, 0x47, 0xee]);
    }
    #[test]
    fn test_dns_header_from_bytes() {
        let bytes =
            hex::decode("b7170100000100000000000006676f6f676c6503636f6d0000010001").unwrap();
        let (dns_header, _) = DNSHeader::from_bytes(&bytes);
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
        let (dns_question, next_offset) = DNSQuestion::from_bytes(&bytes, 12);
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
