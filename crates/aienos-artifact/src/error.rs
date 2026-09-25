/// Stable fail-closed reasons for Binary Artifact v0 parsing and validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ArtifactError {
    BadMagic = 1,
    UnsupportedVersion = 2,
    WrongTarget = 3,
    WrongAbi = 4,
    LengthOverflow = 5,
    Truncated = 6,
    WrongLength = 7,
    ReservedNonZero = 8,
    UnsupportedFlags = 9,
    SectionOverlap = 10,
    BadSection = 11,
    BadEntryPoint = 12,
    MalformedCapability = 13,
    ResourceLimit = 14,
    BadSignatureFormat = 15,
    DigestMismatch = 16,
    UntrustedSigner = 17,
    BadSignature = 18,
    RightsEscalation = 19,
}
