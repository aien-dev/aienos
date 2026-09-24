//! Pure, bounded network protocol primitives. All packet offsets are checked.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Invalid,
    Unsupported,
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacAddress(pub [u8; 6]);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Address(pub [u8; 4]);

fn be16(b: &[u8], n: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes([
        *b.get(n).ok_or(Error::Truncated)?,
        *b.get(n + 1).ok_or(Error::Truncated)?,
    ]))
}
fn put16(b: &mut [u8], n: usize, v: u16) -> Result<(), Error> {
    let x = b.get_mut(n..n + 2).ok_or(Error::Truncated)?;
    x.copy_from_slice(&v.to_be_bytes());
    Ok(())
}

/// RFC 1071 one's-complement checksum. The final odd byte occupies the high octet.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in data.chunks(2) {
        sum += if c.len() == 2 {
            u16::from_be_bytes([c[0], c[1]]) as u32
        } else {
            (c[0] as u32) << 8
        };
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthernetFrame<'a> {
    pub destination: MacAddress,
    pub source: MacAddress,
    pub ethertype: u16,
    pub payload: &'a [u8],
}
impl<'a> EthernetFrame<'a> {
    pub fn parse(b: &'a [u8]) -> Result<Self, Error> {
        if b.len() < 14 {
            return Err(Error::Truncated);
        };
        let mut d = [0; 6];
        d.copy_from_slice(&b[..6]);
        let mut s = [0; 6];
        s.copy_from_slice(&b[6..12]);
        Ok(Self {
            destination: MacAddress(d),
            source: MacAddress(s),
            ethertype: be16(b, 12)?,
            payload: &b[14..],
        })
    }
    pub fn build(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = 14usize
            .checked_add(self.payload.len())
            .ok_or(Error::Capacity)?;
        if out.len() < n {
            return Err(Error::Truncated);
        };
        out[..6].copy_from_slice(&self.destination.0);
        out[6..12].copy_from_slice(&self.source.0);
        put16(out, 12, self.ethertype)?;
        out[14..n].copy_from_slice(self.payload);
        Ok(n)
    }
}

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpPacket {
    pub operation: u16,
    pub sender_mac: MacAddress,
    pub sender_ip: Ipv4Address,
    pub target_mac: MacAddress,
    pub target_ip: Ipv4Address,
}
impl ArpPacket {
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 28 {
            return Err(Error::Truncated);
        };
        if be16(b, 0)? != 1 || be16(b, 2)? != ETHERTYPE_IPV4 || b[4] != 6 || b[5] != 4 {
            return Err(Error::Invalid);
        };
        let op = be16(b, 6)?;
        if op != ARP_REQUEST && op != ARP_REPLY {
            return Err(Error::Unsupported);
        };
        let mut sm = [0; 6];
        sm.copy_from_slice(&b[8..14]);
        let mut si = [0; 4];
        si.copy_from_slice(&b[14..18]);
        let mut tm = [0; 6];
        tm.copy_from_slice(&b[18..24]);
        let mut ti = [0; 4];
        ti.copy_from_slice(&b[24..28]);
        Ok(Self {
            operation: op,
            sender_mac: MacAddress(sm),
            sender_ip: Ipv4Address(si),
            target_mac: MacAddress(tm),
            target_ip: Ipv4Address(ti),
        })
    }
    pub fn build(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < 28 {
            return Err(Error::Truncated);
        };
        out[..8].copy_from_slice(&[
            0,
            1,
            8,
            0,
            6,
            4,
            (self.operation >> 8) as u8,
            self.operation as u8,
        ]);
        out[8..14].copy_from_slice(&self.sender_mac.0);
        out[14..18].copy_from_slice(&self.sender_ip.0);
        out[18..24].copy_from_slice(&self.target_mac.0);
        out[24..28].copy_from_slice(&self.target_ip.0);
        Ok(28)
    }
}

#[derive(Clone, Copy)]
struct ArpEntry {
    ip: Ipv4Address,
    mac: MacAddress,
    expires: u64,
}
/// Fixed capacity ARP cache. Caller owns the clock and expiry policy.
pub struct ArpCache<const N: usize> {
    entries: [Option<ArpEntry>; N],
}
impl<const N: usize> ArpCache<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }
    pub fn lookup(&mut self, ip: Ipv4Address, now: u64) -> Option<MacAddress> {
        for e in &mut self.entries {
            if e.map(|x| x.expires <= now).unwrap_or(false) {
                *e = None
            }
            if let Some(x) = e {
                if x.ip == ip {
                    return Some(x.mac);
                }
            }
        }
        None
    }
    /// Learn only solicited senders unless `allow_unsolicited` is explicitly true.
    pub fn learn(
        &mut self,
        p: ArpPacket,
        solicited: bool,
        allow_unsolicited: bool,
        now: u64,
        ttl: u64,
    ) -> Result<(), Error> {
        if !solicited && !allow_unsolicited {
            return Err(Error::Invalid);
        };
        let expires = now.saturating_add(ttl);
        let mut slot = None;
        for (i, e) in self.entries.iter().enumerate() {
            if e.map(|x| x.ip == p.sender_ip).unwrap_or(false) {
                slot = Some(i);
                break;
            }
            if e.is_none() && slot.is_none() {
                slot = Some(i)
            }
        }
        let i = slot.ok_or(Error::Capacity)?;
        self.entries[i] = Some(ArpEntry {
            ip: p.sender_ip,
            mac: p.sender_mac,
            expires,
        });
        Ok(())
    }
}
impl<const N: usize> Default for ArpCache<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Header {
    pub dscp_ecn: u8,
    pub identification: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
}
impl Ipv4Header {
    pub fn parse(b: &[u8]) -> Result<(Self, &[u8]), Error> {
        if b.len() < 20 {
            return Err(Error::Truncated);
        };
        if b[0] >> 4 != 4 {
            return Err(Error::Invalid);
        };
        let h = ((b[0] & 15) as usize) * 4;
        if h < 20 || b.len() < h {
            return Err(Error::Invalid);
        };
        let total = be16(b, 2)? as usize;
        if total < h || total > b.len() {
            return Err(Error::Truncated);
        };
        let flags_fragment = be16(b, 6)?;
        // RFC 791: the reserved flag bit (0x8000) must be zero.
        if flags_fragment & 0x8000 != 0 {
            return Err(Error::Invalid);
        };
        // More-fragments or a non-zero offset: reassembly is not supported.
        if flags_fragment & 0x3fff != 0 {
            return Err(Error::Unsupported);
        };
        if b[8] == 0 {
            return Err(Error::Invalid);
        };
        if checksum(&b[..h]) != 0 {
            return Err(Error::Invalid);
        };
        let mut s = [0; 4];
        s.copy_from_slice(&b[12..16]);
        let mut d = [0; 4];
        d.copy_from_slice(&b[16..20]);
        Ok((
            Self {
                dscp_ecn: b[1],
                identification: be16(b, 4)?,
                ttl: b[8],
                protocol: b[9],
                source: Ipv4Address(s),
                destination: Ipv4Address(d),
            },
            &b[h..total],
        ))
    }
    pub fn build(&self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let total = 20usize.checked_add(payload.len()).ok_or(Error::Capacity)?;
        if total > u16::MAX as usize || out.len() < total {
            return Err(Error::Truncated);
        };
        out[..20].fill(0);
        out[0] = 0x45;
        out[1] = self.dscp_ecn;
        put16(out, 2, total as u16)?;
        put16(out, 4, self.identification)?;
        out[8] = self.ttl;
        out[9] = self.protocol;
        out[12..16].copy_from_slice(&self.source.0);
        out[16..20].copy_from_slice(&self.destination.0);
        put16(out, 10, checksum(&out[..20]))?;
        out[20..total].copy_from_slice(payload);
        Ok(total)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IcmpEcho {
    pub reply: bool,
    pub identifier: u16,
    pub sequence: u16,
    pub data_len: usize,
}
impl IcmpEcho {
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 8 {
            return Err(Error::Truncated);
        };
        if b[0] != 0 && b[0] != 8 || b[1] != 0 {
            return Err(Error::Unsupported);
        };
        if checksum(b) != 0 {
            return Err(Error::Invalid);
        };
        Ok(Self {
            reply: b[0] == 0,
            identifier: be16(b, 4)?,
            sequence: be16(b, 6)?,
            data_len: b.len() - 8,
        })
    }
    pub fn build(&self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let n = 8 + data.len();
        if out.len() < n {
            return Err(Error::Truncated);
        };
        out[..n].fill(0);
        out[0] = if self.reply { 0 } else { 8 };
        put16(out, 4, self.identifier)?;
        put16(out, 6, self.sequence)?;
        out[8..n].copy_from_slice(data);
        put16(out, 2, checksum(&out[..n]))?;
        Ok(n)
    }
}

fn pseudo(src: Ipv4Address, dst: Ipv4Address, len: u16) -> u32 {
    let mut b = [0u8; 12];
    b[..4].copy_from_slice(&src.0);
    b[4..8].copy_from_slice(&dst.0);
    b[9] = 17;
    b[10..].copy_from_slice(&len.to_be_bytes());
    let mut s = 0u32;
    for c in b.chunks(2) {
        s += u16::from_be_bytes([c[0], c[1]]) as u32
    }
    s
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpDatagram {
    pub source_port: u16,
    pub destination_port: u16,
}
impl UdpDatagram {
    pub fn parse(b: &[u8], src: Ipv4Address, dst: Ipv4Address) -> Result<(Self, &[u8]), Error> {
        if b.len() < 8 {
            return Err(Error::Truncated);
        };
        let n = be16(b, 4)? as usize;
        if n < 8 || n > b.len() {
            return Err(Error::Invalid);
        };
        let c = be16(b, 6)?;
        if c != 0 {
            let mut sum = pseudo(src, dst, n as u16);
            for x in b[..n].chunks(2) {
                sum += if x.len() == 2 {
                    u16::from_be_bytes([x[0], x[1]]) as u32
                } else {
                    (x[0] as u32) << 8
                };
                while sum >> 16 != 0 {
                    sum = (sum & 0xffff) + (sum >> 16)
                }
            }
            if sum as u16 != 0xffff {
                return Err(Error::Invalid);
            }
        }
        Ok((
            Self {
                source_port: be16(b, 0)?,
                destination_port: be16(b, 2)?,
            },
            &b[8..n],
        ))
    }
    pub fn build(
        &self,
        data: &[u8],
        src: Ipv4Address,
        dst: Ipv4Address,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let n = 8 + data.len();
        if n > u16::MAX as usize || out.len() < n {
            return Err(Error::Truncated);
        };
        out[..n].fill(0);
        put16(out, 0, self.source_port)?;
        put16(out, 2, self.destination_port)?;
        put16(out, 4, n as u16)?;
        out[8..n].copy_from_slice(data);
        let mut sum = pseudo(src, dst, n as u16);
        for x in out[..n].chunks(2) {
            sum += if x.len() == 2 {
                u16::from_be_bytes([x[0], x[1]]) as u32
            } else {
                (x[0] as u32) << 8
            };
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16)
            }
        }
        let c = !(sum as u16);
        put16(out, 6, if c == 0 { 0xffff } else { c })?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksum_vectors() {
        assert_eq!(checksum(&[0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
        assert_eq!(checksum(&[1]), 0xfeff)
    }
    #[test]
    fn ethernet_and_arp_vector() {
        let req = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x52, 0x54, 0, 0x12, 0x34, 0x56, 0x08, 0x06, 0, 1,
            8, 0, 6, 4, 0, 1, 0x52, 0x54, 0, 0x12, 0x34, 0x56, 192, 168, 1, 10, 0, 0, 0, 0, 0, 0,
            192, 168, 1, 1,
        ];
        let f = EthernetFrame::parse(&req).unwrap();
        assert_eq!(f.ethertype, ETHERTYPE_ARP);
        let a = ArpPacket::parse(f.payload).unwrap();
        assert_eq!(a.operation, ARP_REQUEST);
        let mut out = [0; 28];
        a.build(&mut out).unwrap();
        assert_eq!(out, &req[14..]);
    }
    #[test]
    fn ipv4_icmp_ping_vector() {
        let p = [
            0x45, 0, 0, 0x1c, 0, 1, 0, 0, 64, 1, 0x8e, 0xa9, 192, 0, 2, 1, 198, 51, 100, 2, 8, 0,
            0xe5, 0xca, 0x12, 0x34, 0, 1,
        ];
        let (h, body) = Ipv4Header::parse(&p).unwrap();
        assert_eq!(h.protocol, 1);
        let e = IcmpEcho::parse(body).unwrap();
        assert_eq!(e.identifier, 0x1234);
        let mut out = [0; 28];
        assert_eq!(h.build(body, &mut out).unwrap(), 28);
        assert_eq!(out, p);
    }
    #[test]
    fn udp_known_checksum() {
        let src = Ipv4Address([192, 0, 2, 1]);
        let dst = Ipv4Address([198, 51, 100, 2]);
        let d = UdpDatagram {
            source_port: 1234,
            destination_port: 53,
        };
        let mut b = [0; 11];
        d.build(b"abc", src, dst, &mut b).unwrap();
        assert_eq!(&b[6..8], &[0x4a, 0x37]);
        assert_eq!(UdpDatagram::parse(&b, src, dst).unwrap().1, b"abc");
    }
    #[test]
    fn rejects_short_bad_and_fragments() {
        assert_eq!(EthernetFrame::parse(&[]), Err(Error::Truncated));
        assert_eq!(ArpPacket::parse(&[0; 27]), Err(Error::Truncated));
        assert_eq!(Ipv4Header::parse(&[0; 20]), Err(Error::Invalid));
        let mut b = [
            0x45, 0, 0, 20, 0, 0, 0x20, 0, 64, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let c = checksum(&b[..20]);
        b[10..12].copy_from_slice(&c.to_be_bytes());
        assert_eq!(Ipv4Header::parse(&b), Err(Error::Unsupported));
    }
    #[test]
    fn cache_requires_solicited_and_expires() {
        let mut c = ArpCache::<1>::new();
        let p = ArpPacket {
            operation: 2,
            sender_mac: MacAddress([1; 6]),
            sender_ip: Ipv4Address([1; 4]),
            target_mac: MacAddress([0; 6]),
            target_ip: Ipv4Address([2; 4]),
        };
        assert_eq!(c.learn(p, false, false, 0, 5), Err(Error::Invalid));
        c.learn(p, true, false, 0, 5).unwrap();
        assert_eq!(c.lookup(p.sender_ip, 4), Some(p.sender_mac));
        assert_eq!(c.lookup(p.sender_ip, 5), None);
    }
    #[test]
    fn ipv4_reserved_flag_is_rejected() {
        let mut h = [
            0x45u8, 0, 0, 20, 0x12, 0x34, 0x80, 0x00, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let c = checksum(&h);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        assert_eq!(Ipv4Header::parse(&h).map(|_| ()), Err(Error::Invalid));
        // Don't-fragment (0x4000) alone stays valid.
        h[6] = 0x40;
        h[10..12].copy_from_slice(&[0, 0]);
        let c = checksum(&h);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        assert!(Ipv4Header::parse(&h).is_ok());
    }
}
