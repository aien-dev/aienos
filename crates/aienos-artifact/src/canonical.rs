use aienos_crypto::sha256::{hash, Digest, Sha256};

use crate::format::Artifact;

pub const REQUESTS_DOMAIN: &[u8] = b"AIENOS-ARTIFACT-CAP-REQUESTS-V1\0";
pub const GRANTS_DOMAIN: &[u8] = b"AIENOS-ADMISSION-CAP-GRANTS-V1\0";
pub const RESOURCES_DOMAIN: &[u8] = b"AIENOS-ARTIFACT-RESOURCES-V1\0";
pub const POLICY_DOMAIN: &[u8] = b"AIENOS-ADMISSION-POLICY-V1\0";
pub const MACHINE_ID_DOMAIN: &[u8] = b"AIENOS-MACHINE-ID-V1\0";
pub const VERIFIER_IDENTITY_DOMAIN: &[u8] = b"AIENOS-VERIFIER-IDENTITY-V1\0";

pub fn payload_digest(artifact: &Artifact<'_>) -> Digest {
    hash(artifact.payload)
}

pub fn requested_capability_digest(canonical_records: &[u8]) -> Digest {
    digest_domain(REQUESTS_DOMAIN, canonical_records)
}

pub fn granted_capability_digest(canonical_records: &[u8]) -> Digest {
    digest_domain(GRANTS_DOMAIN, canonical_records)
}

pub fn resource_envelope_digest(canonical_envelope: &[u8]) -> Digest {
    digest_domain(RESOURCES_DOMAIN, canonical_envelope)
}

pub fn policy_digest(canonical_policy: &[u8]) -> Digest {
    digest_domain(POLICY_DOMAIN, canonical_policy)
}

pub fn machine_id_digest(canonical_machine_id: &[u8]) -> Digest {
    digest_domain(MACHINE_ID_DOMAIN, canonical_machine_id)
}

pub fn verifier_identity_digest(build_identity: &[u8]) -> Digest {
    digest_domain(VERIFIER_IDENTITY_DOMAIN, build_identity)
}

fn digest_domain(domain: &[u8], canonical_bytes: &[u8]) -> Digest {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(canonical_bytes);
    digest.finalize()
}
