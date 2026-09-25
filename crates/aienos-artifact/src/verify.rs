//! Structural parsing and identity entry points shared by host tooling and
//! the kernel. Authentication is added in P2-3.

use crate::canonical::payload_digest;
use crate::error::ArtifactError;
use crate::format::{Artifact, MAX_ARTIFACT_SIZE};
use crate::id::{compute_artifact_id, ArtifactId};
use aienos_crypto::sha256::Digest;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentifiedArtifact<'a> {
    pub artifact: Artifact<'a>,
    pub artifact_id: ArtifactId,
    pub payload_digest: Digest,
}

pub fn parse_and_identify(bytes: &[u8]) -> Result<IdentifiedArtifact<'_>, ArtifactError> {
    if bytes.len() > MAX_ARTIFACT_SIZE {
        return Err(ArtifactError::ResourceLimit);
    }
    let artifact = Artifact::parse(bytes)?;
    Ok(IdentifiedArtifact {
        artifact_id: compute_artifact_id(&artifact),
        payload_digest: payload_digest(&artifact),
        artifact,
    })
}
