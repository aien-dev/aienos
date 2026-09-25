use aienos_crypto::sha256::{Digest, Sha256};

use crate::format::Artifact;

pub const ARTIFACT_ID_DOMAIN: &[u8] = b"AIENOS-ARTIFACT-V1\0";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArtifactId(pub Digest);

impl ArtifactId {
    pub const fn as_bytes(&self) -> &Digest {
        &self.0
    }
}

pub fn compute_artifact_id(artifact: &Artifact<'_>) -> ArtifactId {
    let mut hash = Sha256::new();
    hash.update(ARTIFACT_ID_DOMAIN);
    hash.update(artifact.unsigned_bytes);
    ArtifactId(hash.finalize())
}

pub fn artifact_id_from_unsigned_bytes(bytes: &[u8]) -> ArtifactId {
    let mut hash = Sha256::new();
    hash.update(ARTIFACT_ID_DOMAIN);
    hash.update(bytes);
    ArtifactId(hash.finalize())
}
