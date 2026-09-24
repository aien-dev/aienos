//! AIENOS ABI v1: the frozen wire contract for handles, rights, capabilities,
//! memory regions and messages (ADR 0013).
//!
//! Every type here has an explicit little-endian byte encoding that does not
//! depend on Rust's in-memory layout, the host architecture, or pointer width.
//! Decoding fails closed: short or long input, reserved bits or fields that
//! are not zero, unknown discriminants, unknown versions and generation-zero
//! handles are all rejected with a distinct [`AbiError`].
//!
//! The in-memory structs are also `repr(C)` with explicit reserved fields so
//! their layout matches the wire layout on little-endian targets; `const`
//! assertions below pin sizes, alignments and field offsets. The byte
//! encoding, not the struct layout, is the contract.
//!
//! No allocation, no `usize` or pointer fields, no implicit enum layout.

use crate::caps;
use core::mem::{align_of, offset_of, size_of};

/// ABI version carried in every envelope. Decoders reject every other value.
pub const ABI_VERSION: u16 = 1;

/// Size in bytes of the envelope header that precedes a persisted or
/// transported payload: tag u16, version u16, payload length u32.
pub const ENVELOPE_HEADER_SIZE: usize = 8;

/// Why an ABI value failed to encode or decode. Each failure has its own
/// variant so callers and tests can tell them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiError {
    /// Input is shorter than the encoding requires.
    Truncated,
    /// Input is longer than the encoding, or an envelope length field does
    /// not match the payload size for its tag.
    WrongLength,
    /// Envelope version is not [`ABI_VERSION`].
    UnknownVersion,
    /// Envelope tag is not a known [`EnvelopeTag`].
    UnknownTag,
    /// Envelope tag is known but names a different type than requested.
    TagMismatch,
    /// A reserved field is not zero.
    ReservedNonZero,
    /// A reserved rights bit (6 through 31) is set.
    ReservedBits,
    /// An enum discriminant (for example a resource kind) is not defined.
    UnknownDiscriminant,
    /// A handle has generation 0, which is never issued.
    InvalidHandle,
    /// The output buffer is too small for the encoding.
    BufferTooSmall,
}

/// A type with a fixed-size v1 wire encoding.
pub trait Wire: Sized {
    /// Envelope tag identifying this type when it is persisted or transported.
    const TAG: EnvelopeTag;
    /// Exact encoded size in bytes.
    const SIZE: usize;

    /// Write exactly [`Self::SIZE`] bytes to the front of `out`.
    fn encode_into(&self, out: &mut [u8]) -> Result<usize, AbiError>;

    /// Decode from a buffer of exactly [`Self::SIZE`] bytes.
    fn decode(bytes: &[u8]) -> Result<Self, AbiError>;
}

// Little-endian field helpers. Callers pass fixed arrays whose size is checked
// by the type, so the offsets are always in range.

const fn get_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

const fn get_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

const fn get_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        b[at],
        b[at + 1],
        b[at + 2],
        b[at + 3],
        b[at + 4],
        b[at + 5],
        b[at + 6],
        b[at + 7],
    ])
}

fn put(out: &mut [u8], at: usize, bytes: &[u8]) {
    out[at..at + bytes.len()].copy_from_slice(bytes);
}

/// Check that `bytes` is exactly `size` long.
const fn exact(bytes: &[u8], size: usize) -> Result<(), AbiError> {
    if bytes.len() < size {
        Err(AbiError::Truncated)
    } else if bytes.len() > size {
        Err(AbiError::WrongLength)
    } else {
        Ok(())
    }
}

macro_rules! wire_impl {
    ($ty:ty, $tag:expr, $size:expr) => {
        impl Wire for $ty {
            const TAG: EnvelopeTag = $tag;
            const SIZE: usize = $size;

            fn encode_into(&self, out: &mut [u8]) -> Result<usize, AbiError> {
                let dst = out.get_mut(..$size).ok_or(AbiError::BufferTooSmall)?;
                dst.copy_from_slice(&self.to_bytes());
                Ok($size)
            }

            fn decode(bytes: &[u8]) -> Result<Self, AbiError> {
                exact(bytes, $size)?;
                let mut array = [0u8; $size];
                array.copy_from_slice(bytes);
                Self::from_bytes(&array)
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Handle

/// A 64-bit generational capability handle: slot index plus the slot's
/// generation at issue time. Generation 0 is never issued, so it is invalid.
///
/// Wire: index u32 LE, then generation u32 LE (8 bytes). Register form:
/// `(generation << 32) | index`, the packing the syscall path already uses.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle {
    pub index: u32,
    pub generation: u32,
}

impl Handle {
    pub const SIZE: usize = 8;

    /// Build a handle. Fails with [`AbiError::InvalidHandle`] on generation 0.
    pub const fn new(index: u32, generation: u32) -> Result<Self, AbiError> {
        if generation == 0 {
            Err(AbiError::InvalidHandle)
        } else {
            Ok(Self { index, generation })
        }
    }

    pub const fn index(self) -> u32 {
        self.index
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }

    /// Register form: `(generation << 32) | index`.
    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 32) | self.index as u64
    }

    /// Parse the register form. Fails closed on generation 0.
    pub const fn from_raw(raw: u64) -> Result<Self, AbiError> {
        Self::new(raw as u32, (raw >> 32) as u32)
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        put(&mut out, 0, &self.index.to_le_bytes());
        put(&mut out, 4, &self.generation.to_le_bytes());
        out
    }

    pub const fn from_bytes(bytes: &[u8; 8]) -> Result<Self, AbiError> {
        Self::new(get_u32(bytes, 0), get_u32(bytes, 4))
    }
}

wire_impl!(Handle, EnvelopeTag::Handle, 8);

// caps::Handle is a direct re-export of crate::abi::Handle

// ---------------------------------------------------------------------------
// Plain identifiers

macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident, $int:ty, $size:expr, $tag:expr, $get:ident) => {
        $(#[$doc])*
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(pub $int);

        impl $name {
            pub const SIZE: usize = $size;

            pub const fn to_bytes(&self) -> [u8; $size] {
                self.0.to_le_bytes()
            }

            pub const fn from_bytes(bytes: &[u8; $size]) -> Result<Self, AbiError> {
                Ok(Self($get(bytes, 0)))
            }
        }

        wire_impl!($name, $tag, $size);
    };
}

id_type!(
    /// Identity of a task. Wire: u32 LE. Every value is well formed.
    TaskId, u32, 4, EnvelopeTag::TaskId, get_u32
);
id_type!(
    /// Identity of a kernel object. Wire: u64 LE. Every value is well formed.
    ObjectId, u64, 8, EnvelopeTag::ObjectId, get_u64
);
id_type!(
    /// Identity of a kernel message channel. Wire: u32 LE.
    ChannelId, u32, 4, EnvelopeTag::ChannelId, get_u32
);
id_type!(
    /// Identity of a device. Wire: u32 LE.
    DeviceId, u32, 4, EnvelopeTag::DeviceId, get_u32
);

// ---------------------------------------------------------------------------
// ResourceId

/// What kind of resource a capability names. Discriminants are frozen and
/// never reused; 0 is invalid.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    Console = 1,
    Channel = 2,
    Object = 3,
    Device = 4,
    MemoryRegion = 5,
}

impl ResourceKind {
    pub const fn from_u16(value: u16) -> Result<Self, AbiError> {
        match value {
            1 => Ok(Self::Console),
            2 => Ok(Self::Channel),
            3 => Ok(Self::Object),
            4 => Ok(Self::Device),
            5 => Ok(Self::MemoryRegion),
            _ => Err(AbiError::UnknownDiscriminant),
        }
    }

    pub const fn to_u16(self) -> u16 {
        self as u16
    }
}

/// A typed resource reference. Wire: kind u16 LE, reserved u16 (zero),
/// id u32 LE (8 bytes). `id` is the kernel's resource number for that kind.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceId {
    kind: ResourceKind,
    reserved: u16,
    id: u32,
}

impl ResourceId {
    pub const SIZE: usize = 8;

    pub const fn new(kind: ResourceKind, id: u32) -> Self {
        Self {
            kind,
            reserved: 0,
            id,
        }
    }

    pub const fn kind(self) -> ResourceKind {
        self.kind
    }

    pub const fn id(self) -> u32 {
        self.id
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        put(&mut out, 0, &self.kind.to_u16().to_le_bytes());
        // Bytes 2..4 reserved, written as zero.
        put(&mut out, 4, &self.id.to_le_bytes());
        out
    }

    pub const fn from_bytes(bytes: &[u8; 8]) -> Result<Self, AbiError> {
        let kind = match ResourceKind::from_u16(get_u16(bytes, 0)) {
            Ok(kind) => kind,
            Err(e) => return Err(e),
        };
        if get_u16(bytes, 2) != 0 {
            return Err(AbiError::ReservedNonZero);
        }
        Ok(Self::new(kind, get_u32(bytes, 4)))
    }
}

wire_impl!(ResourceId, EnvelopeTag::ResourceId, 8);

// ---------------------------------------------------------------------------
// Rights

/// Capability rights. Wire: u32 LE. Bits 0 to 5 are defined; bits 6 to 31
/// are reserved and must be zero.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights(u32);

impl Rights {
    pub const SIZE: usize = 4;
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const MAP: Self = Self(1 << 2);
    pub const GRANT: Self = Self(1 << 3);
    pub const DERIVE: Self = Self(1 << 4);
    pub const REVOKE: Self = Self(1 << 5);
    /// Mask of every bit defined in v1.
    pub const DEFINED_MASK: u32 = (1 << 6) - 1;

    /// Fails with [`AbiError::ReservedBits`] if any bit 6 to 31 is set.
    pub const fn from_bits(bits: u32) -> Result<Self, AbiError> {
        if bits & !Self::DEFINED_MASK == 0 {
            Ok(Self(bits))
        } else {
            Err(AbiError::ReservedBits)
        }
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn to_bytes(&self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    pub const fn from_bytes(bytes: &[u8; 4]) -> Result<Self, AbiError> {
        Self::from_bits(get_u32(bytes, 0))
    }
}

wire_impl!(Rights, EnvelopeTag::Rights, 4);

impl From<caps::Rights> for Rights {
    fn from(rights: caps::Rights) -> Self {
        Self(rights.bits() as u32)
    }
}

impl TryFrom<Rights> for caps::Rights {
    type Error = AbiError;
    fn try_from(rights: Rights) -> Result<Self, AbiError> {
        let bits = u8::try_from(rights.0).map_err(|_| AbiError::ReservedBits)?;
        caps::Rights::from_bits(bits).ok_or(AbiError::ReservedBits)
    }
}

// ---------------------------------------------------------------------------
// Capability

/// A capability as data: which resource and which rights. Wire: resource
/// (8 bytes), rights u32 LE, reserved u32 (zero); 16 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability {
    resource: ResourceId,
    rights: Rights,
    reserved: u32,
}

impl Capability {
    pub const SIZE: usize = 16;

    pub const fn new(resource: ResourceId, rights: Rights) -> Self {
        Self {
            resource,
            rights,
            reserved: 0,
        }
    }

    pub const fn resource(self) -> ResourceId {
        self.resource
    }

    pub const fn rights(self) -> Rights {
        self.rights
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        put(&mut out, 0, &self.resource.to_bytes());
        put(&mut out, 8, &self.rights.to_bytes());
        // Bytes 12..16 reserved, written as zero.
        out
    }

    pub const fn from_bytes(bytes: &[u8; 16]) -> Result<Self, AbiError> {
        let resource = match ResourceId::from_bytes(&[
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]) {
            Ok(resource) => resource,
            Err(e) => return Err(e),
        };
        let rights = match Rights::from_bits(get_u32(bytes, 8)) {
            Ok(rights) => rights,
            Err(e) => return Err(e),
        };
        if get_u32(bytes, 12) != 0 {
            return Err(AbiError::ReservedNonZero);
        }
        Ok(Self::new(resource, rights))
    }
}

wire_impl!(Capability, EnvelopeTag::Capability, 16);

// ---------------------------------------------------------------------------
// MemoryRegion

/// A bounded memory extent in pages. Wire: base u64 LE, pages u32 LE,
/// reserved u32 (zero); 16 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base: u64,
    pub pages: u32,
    pub reserved: u32,
}

impl MemoryRegion {
    pub const SIZE: usize = 16;
    pub const EMPTY: Self = Self {
        base: 0,
        pages: 0,
        reserved: 0,
    };

    pub const fn new(base: u64, pages: u32) -> Self {
        Self {
            base,
            pages,
            reserved: 0,
        }
    }

    pub const fn base(self) -> u64 {
        self.base
    }

    pub const fn pages(self) -> u32 {
        self.pages
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        put(&mut out, 0, &self.base.to_le_bytes());
        put(&mut out, 8, &self.pages.to_le_bytes());
        // Bytes 12..16 reserved, written as zero.
        out
    }

    pub const fn from_bytes(bytes: &[u8; 16]) -> Result<Self, AbiError> {
        if get_u32(bytes, 12) != 0 {
            return Err(AbiError::ReservedNonZero);
        }
        Ok(Self::new(get_u64(bytes, 0), get_u32(bytes, 8)))
    }
}

wire_impl!(MemoryRegion, EnvelopeTag::MemoryRegion, 16);

// ---------------------------------------------------------------------------
// Message

/// Fixed-size typed IPC message. Wire (56 bytes): kind u32 LE at 0,
/// reserved u32 (zero) at 4, payload 3 x u64 LE at 8, region at 32,
/// object u64 LE at 48. Field order matches the typed IPC message.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    pub kind: u32,
    pub reserved: u32,
    pub payload: [u64; 3],
    pub region: MemoryRegion,
    pub object: ObjectId,
}

impl Message {
    pub const SIZE: usize = 56;
    pub const NEW: Self = Self {
        kind: 0,
        reserved: 0,
        payload: [0; 3],
        region: MemoryRegion::EMPTY,
        object: ObjectId(0),
    };

    pub const fn new(kind: u32, payload: [u64; 3], region: MemoryRegion, object: ObjectId) -> Self {
        Self {
            kind,
            reserved: 0,
            payload,
            region,
            object,
        }
    }

    pub const fn kind(self) -> u32 {
        self.kind
    }

    pub const fn payload(self) -> [u64; 3] {
        self.payload
    }

    pub const fn region(self) -> MemoryRegion {
        self.region
    }

    pub const fn object(self) -> ObjectId {
        self.object
    }

    pub fn to_bytes(&self) -> [u8; 56] {
        let mut out = [0u8; 56];
        put(&mut out, 0, &self.kind.to_le_bytes());
        // Bytes 4..8 reserved, written as zero.
        put(&mut out, 8, &self.payload[0].to_le_bytes());
        put(&mut out, 16, &self.payload[1].to_le_bytes());
        put(&mut out, 24, &self.payload[2].to_le_bytes());
        put(&mut out, 32, &self.region.to_bytes());
        put(&mut out, 48, &self.object.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8; 56]) -> Result<Self, AbiError> {
        if get_u32(bytes, 4) != 0 {
            return Err(AbiError::ReservedNonZero);
        }
        let region = MemoryRegion::decode(&bytes[32..48])?;
        Ok(Self::new(
            get_u32(bytes, 0),
            [get_u64(bytes, 8), get_u64(bytes, 16), get_u64(bytes, 24)],
            region,
            ObjectId(get_u64(bytes, 48)),
        ))
    }
}

wire_impl!(Message, EnvelopeTag::Message, 56);

// ---------------------------------------------------------------------------
// Envelope

/// Type tag in an envelope header. Discriminants are frozen and never reused;
/// 0 is invalid.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeTag {
    Handle = 1,
    TaskId = 2,
    ObjectId = 3,
    ChannelId = 4,
    DeviceId = 5,
    ResourceId = 6,
    Rights = 7,
    Capability = 8,
    MemoryRegion = 9,
    Message = 10,
}

impl EnvelopeTag {
    pub const fn from_u16(value: u16) -> Result<Self, AbiError> {
        match value {
            1 => Ok(Self::Handle),
            2 => Ok(Self::TaskId),
            3 => Ok(Self::ObjectId),
            4 => Ok(Self::ChannelId),
            5 => Ok(Self::DeviceId),
            6 => Ok(Self::ResourceId),
            7 => Ok(Self::Rights),
            8 => Ok(Self::Capability),
            9 => Ok(Self::MemoryRegion),
            10 => Ok(Self::Message),
            _ => Err(AbiError::UnknownTag),
        }
    }

    pub const fn to_u16(self) -> u16 {
        self as u16
    }
}

/// Write `value` as header (tag, [`ABI_VERSION`], payload length) followed by
/// its payload. Returns the number of bytes written.
pub fn encode_enveloped<T: Wire>(value: &T, out: &mut [u8]) -> Result<usize, AbiError> {
    let total = ENVELOPE_HEADER_SIZE + T::SIZE;
    let dst = out.get_mut(..total).ok_or(AbiError::BufferTooSmall)?;
    put(dst, 0, &T::TAG.to_u16().to_le_bytes());
    put(dst, 2, &ABI_VERSION.to_le_bytes());
    put(dst, 4, &(T::SIZE as u32).to_le_bytes());
    value.encode_into(&mut dst[ENVELOPE_HEADER_SIZE..])?;
    Ok(total)
}

/// Decode an enveloped `T`. Checks, in order: header present, version,
/// tag known, tag matches `T`, length field equals `T::SIZE`, buffer holds
/// exactly header plus payload, payload decodes.
pub fn decode_enveloped<T: Wire>(bytes: &[u8]) -> Result<T, AbiError> {
    if bytes.len() < ENVELOPE_HEADER_SIZE {
        return Err(AbiError::Truncated);
    }
    if get_u16(bytes, 2) != ABI_VERSION {
        return Err(AbiError::UnknownVersion);
    }
    if EnvelopeTag::from_u16(get_u16(bytes, 0))? != T::TAG {
        return Err(AbiError::TagMismatch);
    }
    if get_u32(bytes, 4) as usize != T::SIZE {
        return Err(AbiError::WrongLength);
    }
    T::decode(&bytes[ENVELOPE_HEADER_SIZE..])
}

// ---------------------------------------------------------------------------
// Layout assertions. The wire encoding is the contract; these pin the
// in-memory mirror so it cannot drift silently.

const _: () = {
    assert!(size_of::<Handle>() == Handle::SIZE);
    assert!(align_of::<Handle>() == 4);
    assert!(offset_of!(Handle, index) == 0);
    assert!(offset_of!(Handle, generation) == 4);

    assert!(size_of::<TaskId>() == TaskId::SIZE);
    assert!(size_of::<ObjectId>() == ObjectId::SIZE);
    assert!(size_of::<ChannelId>() == ChannelId::SIZE);
    assert!(size_of::<DeviceId>() == DeviceId::SIZE);

    assert!(size_of::<ResourceKind>() == 2);
    assert!(size_of::<ResourceId>() == ResourceId::SIZE);
    assert!(align_of::<ResourceId>() == 4);
    assert!(offset_of!(ResourceId, kind) == 0);
    assert!(offset_of!(ResourceId, reserved) == 2);
    assert!(offset_of!(ResourceId, id) == 4);

    assert!(size_of::<Rights>() == Rights::SIZE);

    assert!(size_of::<Capability>() == Capability::SIZE);
    assert!(align_of::<Capability>() == 4);
    assert!(offset_of!(Capability, resource) == 0);
    assert!(offset_of!(Capability, rights) == 8);
    assert!(offset_of!(Capability, reserved) == 12);

    assert!(size_of::<MemoryRegion>() == MemoryRegion::SIZE);
    assert!(align_of::<MemoryRegion>() == 8);
    assert!(offset_of!(MemoryRegion, base) == 0);
    assert!(offset_of!(MemoryRegion, pages) == 8);
    assert!(offset_of!(MemoryRegion, reserved) == 12);

    assert!(size_of::<Message>() == Message::SIZE);
    assert!(align_of::<Message>() == 8);
    assert!(offset_of!(Message, kind) == 0);
    assert!(offset_of!(Message, reserved) == 4);
    assert!(offset_of!(Message, payload) == 8);
    assert!(offset_of!(Message, region) == 32);
    assert!(offset_of!(Message, object) == 48);

    assert!(size_of::<EnvelopeTag>() == 2);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden round trip: encode gives exactly `golden`, decoding `golden`
    /// gives `value`, and re-encoding gives `golden` again. Also covers the
    /// envelope form and every truncation and one-byte extension.
    fn golden<T: Wire + Copy + PartialEq + core::fmt::Debug>(value: T, golden: &[u8]) {
        assert_eq!(golden.len(), T::SIZE);
        let mut buf = [0xAAu8; 64];
        assert_eq!(value.encode_into(&mut buf), Ok(T::SIZE));
        assert_eq!(&buf[..T::SIZE], golden);
        let decoded = T::decode(golden).expect("golden bytes decode");
        assert_eq!(decoded, value);
        let mut again = [0x55u8; 64];
        decoded.encode_into(&mut again).unwrap();
        assert_eq!(&again[..T::SIZE], golden);

        for len in 0..T::SIZE {
            assert_eq!(T::decode(&golden[..len]), Err(AbiError::Truncated));
        }
        let mut long = [0u8; 65];
        long[..T::SIZE].copy_from_slice(golden);
        assert_eq!(T::decode(&long[..T::SIZE + 1]), Err(AbiError::WrongLength));
        let mut small = [0u8; 64];
        assert_eq!(
            value.encode_into(&mut small[..T::SIZE - 1]),
            Err(AbiError::BufferTooSmall)
        );

        // Envelope: header golden bytes, then payload golden bytes.
        let mut env = [0u8; 72];
        let n = encode_enveloped(&value, &mut env).unwrap();
        assert_eq!(n, ENVELOPE_HEADER_SIZE + T::SIZE);
        assert_eq!(&env[0..2], &T::TAG.to_u16().to_le_bytes());
        assert_eq!(&env[2..4], &[1, 0]);
        assert_eq!(&env[4..8], &(T::SIZE as u32).to_le_bytes());
        assert_eq!(&env[8..n], golden);
        assert_eq!(decode_enveloped::<T>(&env[..n]), Ok(value));
        for len in 0..n {
            assert_eq!(
                decode_enveloped::<T>(&env[..len]),
                Err(AbiError::Truncated),
                "envelope truncated to {len}"
            );
        }
        assert_eq!(
            decode_enveloped::<T>(&env[..n + 1]),
            Err(AbiError::WrongLength)
        );
        assert_eq!(
            encode_enveloped(&value, &mut env[..n - 1]),
            Err(AbiError::BufferTooSmall)
        );
    }

    #[test]
    fn handle_golden() {
        let h = Handle::new(7, 0x0102_0304).unwrap();
        golden(h, &[0x07, 0, 0, 0, 0x04, 0x03, 0x02, 0x01]);
        assert_eq!(h.to_raw(), 0x0102_0304_0000_0007);
        assert_eq!(Handle::from_raw(0x0102_0304_0000_0007), Ok(h));
    }

    #[test]
    fn handle_raw_matches_syscall_packing() {
        // user.rs packs (generation << 32) | index into x0.
        let h = Handle::new(u32::MAX, u32::MAX).unwrap();
        assert_eq!(h.to_raw(), u64::MAX);
        let h = Handle::new(0, 1).unwrap();
        assert_eq!(h.to_raw(), 1 << 32);
        assert_eq!(Handle::from_raw(1 << 32), Ok(h));
    }

    #[test]
    fn handle_generation_zero_fails_closed() {
        assert_eq!(Handle::new(3, 0), Err(AbiError::InvalidHandle));
        assert_eq!(Handle::from_raw(0), Err(AbiError::InvalidHandle));
        assert_eq!(
            Handle::from_raw(0x0000_0000_FFFF_FFFF),
            Err(AbiError::InvalidHandle)
        );
        assert_eq!(
            Handle::decode(&[1, 0, 0, 0, 0, 0, 0, 0]),
            Err(AbiError::InvalidHandle)
        );
        let env = [1, 0, 1, 0, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            decode_enveloped::<Handle>(&env),
            Err(AbiError::InvalidHandle)
        );
        let forged = Handle {
            index: 0,
            generation: 0,
        };
        assert_eq!(
            Handle::from_raw(forged.to_raw()),
            Err(AbiError::InvalidHandle)
        );
    }

    #[test]
    fn handle_raw_register_encoding() {
        let mut table = caps::CapTable::<4>::new(1);
        let issued = table.insert(9, caps::Rights::READ).unwrap();
        let raw = issued.to_raw();
        assert_eq!(Handle::from_raw(raw), Ok(issued));
        assert_eq!(Handle::from_raw(0), Err(AbiError::InvalidHandle));
    }

    #[test]
    fn id_goldens() {
        golden(TaskId(0x1122_3344), &[0x44, 0x33, 0x22, 0x11]);
        golden(
            ObjectId(0x0102_0304_0506_0708),
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        );
        golden(ChannelId(0xA1B2_C3D4), &[0xD4, 0xC3, 0xB2, 0xA1]);
        golden(DeviceId(0x42), &[0x42, 0, 0, 0]);
    }

    #[test]
    fn resource_id_golden() {
        golden(
            ResourceId::new(ResourceKind::Channel, 0xBEEF),
            &[0x02, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0x00, 0x00],
        );
        let kinds = [
            (ResourceKind::Console, 1u16),
            (ResourceKind::Channel, 2),
            (ResourceKind::Object, 3),
            (ResourceKind::Device, 4),
            (ResourceKind::MemoryRegion, 5),
        ];
        for (kind, value) in kinds {
            assert_eq!(kind.to_u16(), value);
            assert_eq!(ResourceKind::from_u16(value), Ok(kind));
        }
    }

    #[test]
    fn resource_id_rejects_unknown_kind_and_reserved() {
        for kind in [0u16, 6, 0x00FF, 0xFFFF] {
            let [a, b] = kind.to_le_bytes();
            assert_eq!(
                ResourceId::decode(&[a, b, 0, 0, 1, 0, 0, 0]),
                Err(AbiError::UnknownDiscriminant)
            );
        }
        assert_eq!(
            ResourceId::decode(&[1, 0, 1, 0, 1, 0, 0, 0]),
            Err(AbiError::ReservedNonZero)
        );
        assert_eq!(
            ResourceId::decode(&[1, 0, 0, 0x80, 1, 0, 0, 0]),
            Err(AbiError::ReservedNonZero)
        );
    }

    #[test]
    fn rights_golden() {
        let rights = Rights::READ.union(Rights::WRITE).union(Rights::GRANT);
        golden(rights, &[0x0B, 0, 0, 0]);
        golden(Rights::NONE, &[0, 0, 0, 0]);
        golden(Rights::from_bits(0x3F).unwrap(), &[0x3F, 0, 0, 0]);
        assert_eq!(Rights::READ.bits(), caps::Rights::READ.bits() as u32);
        assert_eq!(Rights::WRITE.bits(), caps::Rights::WRITE.bits() as u32);
        assert_eq!(Rights::MAP.bits(), caps::Rights::MAP.bits() as u32);
        assert_eq!(Rights::GRANT.bits(), caps::Rights::GRANT.bits() as u32);
        assert_eq!(Rights::DERIVE.bits(), caps::Rights::DERIVE.bits() as u32);
        assert_eq!(Rights::REVOKE.bits(), caps::Rights::REVOKE.bits() as u32);
    }

    #[test]
    fn rights_reserved_bits_fail_closed() {
        for bit in 6..32 {
            let bits = 1u32 << bit;
            assert_eq!(Rights::from_bits(bits), Err(AbiError::ReservedBits));
            assert_eq!(
                Rights::decode(&bits.to_le_bytes()),
                Err(AbiError::ReservedBits)
            );
        }
    }

    #[test]
    fn rights_convert_with_caps_rights() {
        let kernel = caps::Rights::READ | caps::Rights::DERIVE;
        let wire = Rights::from(kernel);
        assert_eq!(wire.bits(), 0x11);
        assert_eq!(caps::Rights::try_from(wire), Ok(kernel));
    }

    #[test]
    fn capability_golden() {
        let cap = Capability::new(
            ResourceId::new(ResourceKind::Device, 0x1234_5678),
            Rights::READ.union(Rights::MAP).union(Rights::REVOKE),
        );
        golden(
            cap,
            &[
                0x04, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, // resource
                0x25, 0x00, 0x00, 0x00, // rights
                0x00, 0x00, 0x00, 0x00, // reserved
            ],
        );
    }

    #[test]
    fn capability_fails_closed() {
        let good = [4u8, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        assert!(Capability::decode(&good).is_ok());
        let mut bad = good;
        bad[15] = 1;
        assert_eq!(Capability::decode(&bad), Err(AbiError::ReservedNonZero));
        let mut bad = good;
        bad[8] = 0x40;
        assert_eq!(Capability::decode(&bad), Err(AbiError::ReservedBits));
        let mut bad = good;
        bad[11] = 0x80;
        assert_eq!(Capability::decode(&bad), Err(AbiError::ReservedBits));
        let mut bad = good;
        bad[0] = 0;
        assert_eq!(Capability::decode(&bad), Err(AbiError::UnknownDiscriminant));
        let mut bad = good;
        bad[3] = 1;
        assert_eq!(Capability::decode(&bad), Err(AbiError::ReservedNonZero));
    }

    #[test]
    fn memory_region_golden() {
        golden(
            MemoryRegion::new(0x4000_0000, 16),
            &[
                0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, // base
                0x10, 0x00, 0x00, 0x00, // pages
                0x00, 0x00, 0x00, 0x00, // reserved
            ],
        );
        let mut bad = MemoryRegion::new(1, 1).to_bytes();
        bad[12] = 1;
        assert_eq!(MemoryRegion::decode(&bad), Err(AbiError::ReservedNonZero));
    }

    fn sample_message() -> Message {
        Message::new(
            3,
            [1, 0x2222, u64::MAX],
            MemoryRegion::new(0x8000_1000, 2),
            ObjectId(0x0A0B_0C0D_0E0F_1011),
        )
    }

    const MESSAGE_GOLDEN: [u8; 56] = [
        0x03, 0x00, 0x00, 0x00, // kind
        0x00, 0x00, 0x00, 0x00, // reserved
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // payload[0]
        0x22, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // payload[1]
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // payload[2]
        0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, // region.base
        0x02, 0x00, 0x00, 0x00, // region.pages
        0x00, 0x00, 0x00, 0x00, // region reserved
        0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, // object
    ];

    #[test]
    fn message_golden() {
        golden(sample_message(), &MESSAGE_GOLDEN);
    }

    #[test]
    fn message_reserved_fields_fail_closed() {
        for at in [4usize, 7, 44, 47] {
            let mut bad = MESSAGE_GOLDEN;
            bad[at] = 1;
            assert_eq!(
                Message::decode(&bad),
                Err(AbiError::ReservedNonZero),
                "byte {at}"
            );
        }
    }

    #[test]
    fn envelope_golden() {
        let cap = Capability::new(ResourceId::new(ResourceKind::Console, 1), Rights::WRITE);
        let mut out = [0u8; 24];
        assert_eq!(encode_enveloped(&cap, &mut out), Ok(24));
        let expected = [
            0x08, 0x00, // tag: Capability
            0x01, 0x00, // version 1
            0x10, 0x00, 0x00, 0x00, // payload length 16
            0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // resource
            0x02, 0x00, 0x00, 0x00, // rights
            0x00, 0x00, 0x00, 0x00, // reserved
        ];
        assert_eq!(out, expected);
        assert_eq!(decode_enveloped::<Capability>(&expected), Ok(cap));
    }

    #[test]
    fn envelope_fails_closed() {
        let mut good = [0u8; 16];
        encode_enveloped(&Handle::new(2, 5).unwrap(), &mut good).unwrap();
        assert!(decode_enveloped::<Handle>(&good).is_ok());

        for version in [0u16, 2, 0x0100, 0xFFFF] {
            let mut bad = good;
            bad[2..4].copy_from_slice(&version.to_le_bytes());
            assert_eq!(
                decode_enveloped::<Handle>(&bad),
                Err(AbiError::UnknownVersion)
            );
        }
        for tag in [0u16, 11, 0xFFFF] {
            let mut bad = good;
            bad[0..2].copy_from_slice(&tag.to_le_bytes());
            assert_eq!(decode_enveloped::<Handle>(&bad), Err(AbiError::UnknownTag));
        }
        // A known tag for an 8-byte type that is not Handle.
        let mut bad = good;
        bad[0] = EnvelopeTag::ObjectId.to_u16() as u8;
        assert_eq!(decode_enveloped::<Handle>(&bad), Err(AbiError::TagMismatch));
        for len in [0u32, 7, 9, 16, u32::MAX] {
            let mut bad = good;
            bad[4..8].copy_from_slice(&len.to_le_bytes());
            assert_eq!(decode_enveloped::<Handle>(&bad), Err(AbiError::WrongLength));
        }
        let mut bad = good;
        bad[12] = 0;
        bad[13] = 0;
        bad[14] = 0;
        bad[15] = 0;
        assert_eq!(
            decode_enveloped::<Handle>(&bad),
            Err(AbiError::InvalidHandle)
        );
    }

    #[test]
    fn tags_are_distinct_and_round_trip() {
        let tags = [
            (EnvelopeTag::Handle, <Handle as Wire>::TAG),
            (EnvelopeTag::TaskId, <TaskId as Wire>::TAG),
            (EnvelopeTag::ObjectId, <ObjectId as Wire>::TAG),
            (EnvelopeTag::ChannelId, <ChannelId as Wire>::TAG),
            (EnvelopeTag::DeviceId, <DeviceId as Wire>::TAG),
            (EnvelopeTag::ResourceId, <ResourceId as Wire>::TAG),
            (EnvelopeTag::Rights, <Rights as Wire>::TAG),
            (EnvelopeTag::Capability, <Capability as Wire>::TAG),
            (EnvelopeTag::MemoryRegion, <MemoryRegion as Wire>::TAG),
            (EnvelopeTag::Message, <Message as Wire>::TAG),
        ];
        for (i, (tag, wire_tag)) in tags.iter().enumerate() {
            assert_eq!(tag, wire_tag);
            assert_eq!(tag.to_u16(), i as u16 + 1);
            assert_eq!(EnvelopeTag::from_u16(tag.to_u16()), Ok(*tag));
        }
    }
}
