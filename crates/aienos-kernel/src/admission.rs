//! Deterministic policy evaluation for authenticated native artifacts.
//!
//! This module decides what a verified artifact may receive. It does not
//! reserve resources, allocate pages, create handles, or execute candidate
//! code; those are loader responsibilities.

use aienos_artifact::canonical::{
    granted_capability_digest, policy_digest, requested_capability_digest, resource_envelope_digest,
};
use aienos_artifact::capability::{
    CapabilityRequest, MAX_CAPABILITIES, RESOURCE_KIND_CHANNEL, RESOURCE_KIND_OBJECT,
};
use aienos_artifact::error::ArtifactError;
use aienos_artifact::format::{ABI_V1, MAX_PAYLOAD_SIZE, TARGET_AARCH64_LE};
use aienos_artifact::resource::{
    ResourceEnvelope, MAX_CODE_PAGES, MAX_CPU_TICKS, MAX_DATA_PAGES, MAX_ELAPSED_TICKS,
    MAX_IPC_BYTES, MAX_IPC_MESSAGES, MAX_STACK_PAGES, MAX_SYSCALLS, PAGE_SIZE,
};
use aienos_artifact::signature::{TrustTier, VerifiedArtifact};
use aienos_crypto::sha256::Digest;

use crate::abi::{ResourceId, ResourceKind};
use crate::caps::Rights;

pub const MAX_POLICY_RESOURCES: usize = 16;
pub const MAX_POLICY_SIGNERS: usize = 8;
pub const POLICY_HEADER_SIZE: usize = 64;
pub const POLICY_RECORD_SIZE: usize = 48;
pub const POLICY_SIGNER_SIZE: usize = 32;
const MAX_POLICY_BYTES: usize = POLICY_HEADER_SIZE
    + MAX_POLICY_RESOURCES * POLICY_RECORD_SIZE
    + MAX_POLICY_SIGNERS * POLICY_SIGNER_SIZE;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdmissionLimits {
    pub code_pages: u32,
    pub data_pages: u32,
    pub stack_pages: u32,
    pub max_capabilities: u32,
    pub ipc_messages: u32,
    pub ipc_bytes: u32,
    pub cpu_ticks: u64,
    pub elapsed_ticks: u64,
    pub syscall_count: u32,
}

impl AdmissionLimits {
    fn validate(self) -> Result<(), ArtifactError> {
        if self.code_pages > MAX_CODE_PAGES
            || self.data_pages > MAX_DATA_PAGES
            || self.stack_pages > MAX_STACK_PAGES
            || self.max_capabilities > MAX_CAPABILITIES as u32
            || self.ipc_messages > MAX_IPC_MESSAGES
            || self.ipc_bytes > MAX_IPC_BYTES
            || self.cpu_ticks > MAX_CPU_TICKS
            || self.elapsed_ticks > MAX_ELAPSED_TICKS
            || self.syscall_count > MAX_SYSCALLS
        {
            return Err(ArtifactError::ResourceLimit);
        }
        Ok(())
    }

    fn encode(self, out: &mut [u8]) {
        put_u32(out, 16, self.code_pages);
        put_u32(out, 20, self.data_pages);
        put_u32(out, 24, self.stack_pages);
        put_u32(out, 28, self.max_capabilities);
        put_u32(out, 32, self.ipc_messages);
        put_u32(out, 36, self.ipc_bytes);
        put_u64(out, 40, self.cpu_ticks);
        put_u64(out, 48, self.elapsed_ticks);
        put_u32(out, 56, self.syscall_count);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AvailableResources {
    pub code_pages: u32,
    pub data_pages: u32,
    pub stack_pages: u32,
    pub capability_slots: u32,
    pub ipc_messages: u32,
    pub ipc_bytes: u32,
    pub cpu_ticks: u64,
    pub elapsed_ticks: u64,
    pub syscall_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionPolicy {
    limits: AdmissionLimits,
    resource_rules: [CapabilityRequest; MAX_POLICY_RESOURCES],
    resource_count: u8,
    signer_fingerprints: [Digest; MAX_POLICY_SIGNERS],
    signer_count: u8,
}

impl AdmissionPolicy {
    pub fn new(limits: AdmissionLimits) -> Result<Self, ArtifactError> {
        limits.validate()?;
        Ok(Self {
            limits,
            resource_rules: [CapabilityRequest::default(); MAX_POLICY_RESOURCES],
            resource_count: 0,
            signer_fingerprints: [[0; 32]; MAX_POLICY_SIGNERS],
            signer_count: 0,
        })
    }

    pub fn add_resource_rule(&mut self, rule: CapabilityRequest) -> Result<(), ArtifactError> {
        rule.validate()?;
        let key = resource_key(&rule);
        let count = usize::from(self.resource_count);
        let mut insertion = count;
        for index in 0..count {
            let current = resource_key(&self.resource_rules[index]);
            if current == key {
                return Err(ArtifactError::MalformedCapability);
            }
            if current > key {
                insertion = index;
                break;
            }
        }
        if count == MAX_POLICY_RESOURCES {
            return Err(ArtifactError::ResourceLimit);
        }
        for index in (insertion..count).rev() {
            self.resource_rules[index + 1] = self.resource_rules[index];
        }
        self.resource_rules[insertion] = rule;
        self.resource_count += 1;
        Ok(())
    }

    pub fn allow_signer(&mut self, fingerprint: Digest) -> Result<(), ArtifactError> {
        let count = usize::from(self.signer_count);
        let mut insertion = count;
        for index in 0..count {
            match self.signer_fingerprints[index].cmp(&fingerprint) {
                core::cmp::Ordering::Equal => return Err(ArtifactError::UntrustedSigner),
                core::cmp::Ordering::Greater => {
                    insertion = index;
                    break;
                }
                core::cmp::Ordering::Less => {}
            }
        }
        if count == MAX_POLICY_SIGNERS {
            return Err(ArtifactError::ResourceLimit);
        }
        for index in (insertion..count).rev() {
            self.signer_fingerprints[index + 1] = self.signer_fingerprints[index];
        }
        self.signer_fingerprints[insertion] = fingerprint;
        self.signer_count += 1;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> ([u8; MAX_POLICY_BYTES], usize) {
        let mut bytes = [0u8; MAX_POLICY_BYTES];
        bytes[0..8].copy_from_slice(b"AIENPOL\0");
        put_u16(&mut bytes, 8, 0);
        put_u16(&mut bytes, 10, POLICY_HEADER_SIZE as u16);
        put_u16(&mut bytes, 12, POLICY_RECORD_SIZE as u16);
        put_u16(&mut bytes, 14, u16::from(self.resource_count));
        self.limits.encode(&mut bytes);
        put_u16(&mut bytes, 60, u16::from(self.signer_count));

        let mut offset = POLICY_HEADER_SIZE;
        for rule in &self.resource_rules[..usize::from(self.resource_count)] {
            bytes[offset..offset + POLICY_RECORD_SIZE].copy_from_slice(&rule.to_bytes());
            offset += POLICY_RECORD_SIZE;
        }
        for fingerprint in &self.signer_fingerprints[..usize::from(self.signer_count)] {
            bytes[offset..offset + POLICY_SIGNER_SIZE].copy_from_slice(fingerprint);
            offset += POLICY_SIGNER_SIZE;
        }
        (bytes, offset)
    }

    pub fn digest(&self) -> Digest {
        let (bytes, length) = self.canonical_bytes();
        policy_digest(&bytes[..length])
    }

    pub fn resource_rules(&self) -> &[CapabilityRequest] {
        &self.resource_rules[..usize::from(self.resource_count)]
    }

    pub fn evaluate(
        &self,
        verified: &VerifiedArtifact<'_>,
        available: AvailableResources,
    ) -> Result<GrantedAdmission, ArtifactError> {
        let identified = verified.identified();
        let artifact = &identified.artifact;
        if artifact.target_arch != TARGET_AARCH64_LE {
            return Err(ArtifactError::WrongTarget);
        }
        if artifact.abi_version != ABI_V1 {
            return Err(ArtifactError::WrongAbi);
        }
        if !self.contains_signer(verified.signer_fingerprint()) {
            return Err(ArtifactError::UntrustedSigner);
        }
        validate_entry(artifact.entry_offset, artifact.sections[0].file_length)?;
        if artifact.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ArtifactError::ResourceLimit);
        }
        let requested = artifact.resources;
        requested.validate(artifact.capabilities.len())?;
        check_resource_limits(requested, self.limits)?;
        check_available(requested, available)?;

        let mut grants = [None; MAX_CAPABILITIES];
        let mut grant_count = 0usize;
        let mut grant_bytes = [[0u8; POLICY_RECORD_SIZE]; MAX_CAPABILITIES];
        for request in artifact.capabilities.as_slice() {
            let Some(rule) = self.find_rule(request) else {
                continue;
            };
            let Some(grant) = intersect_request(request, rule)? else {
                continue;
            };
            if !grant.is_attenuation_of(request) {
                return Err(ArtifactError::RightsEscalation);
            }
            if !grant.is_attenuation_of(rule) {
                return Err(ArtifactError::RightsEscalation);
            }
            let resource_kind = match grant.resource_kind {
                RESOURCE_KIND_CHANNEL => ResourceKind::Channel,
                RESOURCE_KIND_OBJECT => ResourceKind::Object,
                _ => return Err(ArtifactError::MalformedCapability),
            };
            let right_bits =
                u8::try_from(grant.rights).map_err(|_| ArtifactError::RightsEscalation)?;
            let rights = Rights::from_bits(right_bits).ok_or(ArtifactError::MalformedCapability)?;
            grants[grant_count] = Some(GrantedCapability {
                resource: ResourceId::new(resource_kind, grant.resource_id),
                rights,
                bounds: grant,
            });
            grant_bytes[grant_count] = grant.to_bytes();
            grant_count += 1;
        }
        let mut canonical_grants = [0u8; MAX_CAPABILITIES * POLICY_RECORD_SIZE];
        for (index, record) in grant_bytes[..grant_count].iter().enumerate() {
            let offset = index * POLICY_RECORD_SIZE;
            canonical_grants[offset..offset + POLICY_RECORD_SIZE].copy_from_slice(record);
        }
        let policy_digest = self.digest();
        Ok(GrantedAdmission {
            artifact_id: identified.artifact_id,
            payload_digest: identified.payload_digest,
            signer_fingerprint: *verified.signer_fingerprint(),
            trust_tier: verified.trust_tier(),
            requested_capability_digest: requested_capability_digest(
                artifact.capability_request_bytes,
            ),
            granted_capability_digest: granted_capability_digest(
                &canonical_grants[..grant_count * POLICY_RECORD_SIZE],
            ),
            resource_envelope_digest: resource_envelope_digest(artifact.resource_envelope_bytes),
            policy_digest,
            resources: requested,
            entry_offset: artifact.entry_offset,
            grants,
            grant_count: grant_count as u8,
        })
    }

    fn contains_signer(&self, fingerprint: &Digest) -> bool {
        self.signer_fingerprints[..usize::from(self.signer_count)]
            .binary_search(fingerprint)
            .is_ok()
    }

    fn find_rule(&self, request: &CapabilityRequest) -> Option<&CapabilityRequest> {
        let key = resource_key(request);
        self.resource_rules()
            .binary_search_by_key(&key, resource_key)
            .ok()
            .map(|index| &self.resource_rules()[index])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantedCapability {
    pub resource: ResourceId,
    pub rights: Rights,
    /// Canonical bounds record retained for receipt and authority checks.
    pub bounds: CapabilityRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantedAdmission {
    pub artifact_id: aienos_artifact::ArtifactId,
    pub payload_digest: Digest,
    pub signer_fingerprint: Digest,
    pub trust_tier: TrustTier,
    pub requested_capability_digest: Digest,
    pub granted_capability_digest: Digest,
    pub resource_envelope_digest: Digest,
    pub policy_digest: Digest,
    pub resources: ResourceEnvelope,
    pub entry_offset: u32,
    grants: [Option<GrantedCapability>; MAX_CAPABILITIES],
    grant_count: u8,
}

impl GrantedAdmission {
    pub fn capabilities(&self) -> &[Option<GrantedCapability>] {
        &self.grants[..usize::from(self.grant_count)]
    }

    pub const fn capability_count(&self) -> usize {
        self.grant_count as usize
    }
}

fn validate_entry(entry: u32, code_length: u32) -> Result<(), ArtifactError> {
    if entry & 3 != 0 || entry.checked_add(4).ok_or(ArtifactError::LengthOverflow)? > code_length {
        return Err(ArtifactError::BadEntryPoint);
    }
    Ok(())
}

fn check_resource_limits(
    requested: ResourceEnvelope,
    limits: AdmissionLimits,
) -> Result<(), ArtifactError> {
    if requested.code_pages > limits.code_pages
        || requested.data_pages > limits.data_pages
        || requested.stack_pages > limits.stack_pages
        || u32::from(requested.max_capabilities) > limits.max_capabilities
        || requested.ipc_messages > limits.ipc_messages
        || requested.ipc_bytes > limits.ipc_bytes
        || requested.cpu_ticks > limits.cpu_ticks
        || requested.elapsed_ticks > limits.elapsed_ticks
        || requested.syscall_count > limits.syscall_count
    {
        return Err(ArtifactError::ResourceLimit);
    }
    requested
        .code_pages
        .checked_mul(PAGE_SIZE)
        .and_then(|_| requested.data_pages.checked_mul(PAGE_SIZE))
        .and_then(|_| requested.stack_pages.checked_mul(PAGE_SIZE))
        .ok_or(ArtifactError::LengthOverflow)?;
    Ok(())
}

fn check_available(
    requested: ResourceEnvelope,
    available: AvailableResources,
) -> Result<(), ArtifactError> {
    if requested.code_pages > available.code_pages
        || requested.data_pages > available.data_pages
        || requested.stack_pages > available.stack_pages
        || u32::from(requested.max_capabilities) > available.capability_slots
        || requested.ipc_messages > available.ipc_messages
        || requested.ipc_bytes > available.ipc_bytes
        || requested.cpu_ticks > available.cpu_ticks
        || requested.elapsed_ticks > available.elapsed_ticks
        || requested.syscall_count > available.syscall_count
    {
        return Err(ArtifactError::ResourceLimit);
    }
    Ok(())
}

fn intersect_request(
    request: &CapabilityRequest,
    policy: &CapabilityRequest,
) -> Result<Option<CapabilityRequest>, ArtifactError> {
    let rights = request.rights & policy.rights;
    if rights == 0 {
        return Ok(None);
    }
    let max_operations = request.max_operations.min(policy.max_operations);
    let max_bytes = request.max_bytes.min(policy.max_bytes);
    let (byte_offset, byte_length, bounded_max_bytes) = match request.bounds_kind {
        1 => {
            let request_end = request
                .byte_offset
                .checked_add(request.byte_length)
                .ok_or(ArtifactError::LengthOverflow)?;
            let policy_end = policy
                .byte_offset
                .checked_add(policy.byte_length)
                .ok_or(ArtifactError::LengthOverflow)?;
            let start = request.byte_offset.max(policy.byte_offset);
            let end = request_end.min(policy_end);
            if start >= end {
                return Ok(None);
            }
            let length = end - start;
            let bytes = max_bytes.min(length);
            (start, length, bytes)
        }
        2 => (0, 0, max_bytes),
        _ => return Err(ArtifactError::MalformedCapability),
    };
    if max_operations == 0 || bounded_max_bytes == 0 {
        return Ok(None);
    }
    let grant = CapabilityRequest {
        resource_kind: request.resource_kind,
        resource_id: request.resource_id,
        rights,
        bounds_kind: request.bounds_kind,
        max_operations,
        max_bytes: bounded_max_bytes,
        byte_offset,
        byte_length,
    };
    grant.validate()?;
    Ok(Some(grant))
}

fn resource_key(request: &CapabilityRequest) -> (u16, u32) {
    (request.resource_kind, request.resource_id)
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use aienos_artifact::capability::{CapabilityRequest, RIGHT_READ, RIGHT_WRITE};
    use aienos_artifact::error::ArtifactError;
    use aienos_artifact::signature::{
        ArtifactVerifier, ConfiguredArtifactVerifier, SignatureVerifier, TrustAnchorSet, TrustTier,
        TrustedSigner,
    };
    use aienos_crypto::sha256::{hash, Digest};

    use super::{
        AdmissionLimits, AdmissionPolicy, AvailableResources, POLICY_HEADER_SIZE,
        POLICY_RECORD_SIZE,
    };
    use crate::caps::{CapTable, Rights};

    const PUBLIC_KEY: [u8; 32] = [0x45; 32];

    struct TestAnchorSet;

    impl TrustAnchorSet for TestAnchorSet {
        fn find(&self, fingerprint: &Digest) -> Option<TrustedSigner> {
            (*fingerprint == hash(&PUBLIC_KEY)).then_some(TrustedSigner {
                public_key: PUBLIC_KEY,
                tier: TrustTier::Production,
            })
        }
    }

    struct TestSignatureVerifier;

    impl SignatureVerifier for TestSignatureVerifier {
        fn verify(&self, _key: &[u8; 32], message: &[u8], _signature: &[u8; 64]) -> bool {
            message.len() == aienos_artifact::signature::ARTIFACT_SIGNATURE_MESSAGE_SIZE
        }
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn signed_test_artifact(request: Option<CapabilityRequest>) -> Vec<u8> {
        let cap_count = usize::from(request.is_some());
        let cap_bytes = cap_count * POLICY_RECORD_SIZE;
        let resources_offset = 192 + cap_bytes;
        let payload_offset = (resources_offset + 48 + 15) & !15;
        let signature_offset = payload_offset + 8;
        let total_length = signature_offset + 100;
        let mut bytes = vec![0u8; total_length];
        bytes[0..8].copy_from_slice(b"AIENART\0");
        put_u16(&mut bytes, 8, 0);
        put_u16(&mut bytes, 10, 128);
        put_u16(&mut bytes, 12, 1);
        put_u16(&mut bytes, 14, 1);
        put_u32(&mut bytes, 20, total_length as u32);
        put_u32(&mut bytes, 24, 128);
        put_u16(&mut bytes, 28, 2);
        put_u16(&mut bytes, 30, 32);
        put_u16(&mut bytes, 32, 0);
        put_u32(&mut bytes, 40, 192);
        put_u16(&mut bytes, 44, cap_count as u16);
        put_u16(&mut bytes, 46, 48);
        put_u32(&mut bytes, 48, resources_offset as u32);
        put_u16(&mut bytes, 52, 48);
        put_u32(&mut bytes, 56, payload_offset as u32);
        put_u32(&mut bytes, 60, 8);
        put_u32(&mut bytes, 64, signature_offset as u32);
        put_u16(&mut bytes, 68, 100);
        put_u16(&mut bytes, 70, 1);

        put_u16(&mut bytes, 128, 1);
        put_u16(&mut bytes, 130, 5);
        put_u32(&mut bytes, 140, 4);
        put_u32(&mut bytes, 144, 4);
        put_u32(&mut bytes, 148, 4096);
        put_u16(&mut bytes, 160, 2);
        put_u16(&mut bytes, 162, 3);
        put_u32(&mut bytes, 168, 4);
        put_u32(&mut bytes, 172, 4);
        put_u32(&mut bytes, 176, 4096);
        put_u32(&mut bytes, 180, 4096);
        if let Some(request) = request {
            bytes[192..240].copy_from_slice(&request.to_bytes());
        }
        put_u32(&mut bytes, resources_offset, 1);
        put_u32(&mut bytes, resources_offset + 4, 1);
        put_u32(&mut bytes, resources_offset + 8, 1);
        put_u16(&mut bytes, resources_offset + 12, cap_count as u16);
        put_u64(&mut bytes, resources_offset + 24, 10);
        put_u64(&mut bytes, resources_offset + 32, 20);
        put_u32(&mut bytes, resources_offset + 40, 16);
        bytes[payload_offset..payload_offset + 4].copy_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
        bytes[payload_offset + 4..payload_offset + 8].copy_from_slice(b"DATA");
        put_u16(&mut bytes, signature_offset, 1);
        bytes[signature_offset + 4..signature_offset + 36].copy_from_slice(&hash(&PUBLIC_KEY));
        bytes
    }

    fn request(rights: u32) -> CapabilityRequest {
        CapabilityRequest {
            resource_kind: 3,
            resource_id: 7,
            rights,
            bounds_kind: 1,
            max_operations: 4,
            max_bytes: 4,
            byte_offset: 0,
            byte_length: 4,
        }
    }

    fn policy_with(rules: &[CapabilityRequest]) -> AdmissionPolicy {
        let mut policy = AdmissionPolicy::new(AdmissionLimits {
            code_pages: 1,
            data_pages: 1,
            stack_pages: 1,
            max_capabilities: 1,
            ipc_messages: 0,
            ipc_bytes: 0,
            cpu_ticks: 10,
            elapsed_ticks: 20,
            syscall_count: 16,
        })
        .unwrap();
        for rule in rules {
            policy.add_resource_rule(*rule).unwrap();
        }
        policy.allow_signer(hash(&PUBLIC_KEY)).unwrap();
        policy
    }

    fn available() -> AvailableResources {
        AvailableResources {
            code_pages: 1,
            data_pages: 1,
            stack_pages: 1,
            capability_slots: 1,
            ipc_messages: 0,
            ipc_bytes: 0,
            cpu_ticks: 10,
            elapsed_ticks: 20,
            syscall_count: 16,
        }
    }

    fn verified(bytes: &[u8]) -> aienos_artifact::signature::VerifiedArtifact<'_> {
        ConfiguredArtifactVerifier::new(&TestAnchorSet, TestSignatureVerifier)
            .verify(bytes)
            .unwrap()
    }

    #[test]
    fn read_is_granted_and_uses_the_existing_m3_rights_type() {
        let bytes = signed_test_artifact(Some(request(RIGHT_READ)));
        let candidate = verified(&bytes);
        let policy = policy_with(&[request(RIGHT_READ)]);
        let admission = policy.evaluate(&candidate, available()).unwrap();
        assert_eq!(admission.capability_count(), 1);
        let granted = admission.capabilities()[0].unwrap();
        assert_eq!(granted.resource.id(), 7);
        assert_eq!(granted.rights, Rights::READ);
        assert!(granted.bounds.is_attenuation_of(&request(RIGHT_READ)));

        let mut task_caps = CapTable::<2>::new(42);
        let handle = task_caps
            .insert(granted.resource.id(), granted.rights)
            .unwrap();
        assert_eq!(task_caps.lookup(handle, Rights::READ), Ok(7));
        assert_eq!(
            task_caps.lookup(handle, Rights::WRITE),
            Err(crate::caps::CapError::MissingRights)
        );
    }

    #[test]
    fn read_write_request_is_reduced_to_policy_read() {
        let bytes = signed_test_artifact(Some(request(RIGHT_READ | RIGHT_WRITE)));
        let candidate = verified(&bytes);
        let policy = policy_with(&[request(RIGHT_READ)]);
        let admission = policy.evaluate(&candidate, available()).unwrap();
        let granted = admission.capabilities()[0].unwrap();
        assert_eq!(granted.rights, Rights::READ);
        assert!(granted
            .bounds
            .is_attenuation_of(&request(RIGHT_READ | RIGHT_WRITE)));
    }

    #[test]
    fn unapproved_write_receives_no_capability() {
        let bytes = signed_test_artifact(Some(request(RIGHT_WRITE)));
        let candidate = verified(&bytes);
        let policy = policy_with(&[]);
        let admission = policy.evaluate(&candidate, available()).unwrap();
        assert_eq!(admission.capability_count(), 0);
        assert!(admission.capabilities().is_empty());
    }

    #[test]
    fn policy_reduces_object_range_and_operation_byte_budgets() {
        let bytes = signed_test_artifact(Some(request(RIGHT_READ)));
        let candidate = verified(&bytes);
        let narrow = CapabilityRequest {
            max_operations: 2,
            max_bytes: 2,
            byte_offset: 1,
            byte_length: 2,
            ..request(RIGHT_READ)
        };
        let policy = policy_with(&[narrow]);
        let admission = policy.evaluate(&candidate, available()).unwrap();
        let granted = admission.capabilities()[0].unwrap();
        assert_eq!(granted.bounds.max_operations, 2);
        assert_eq!(granted.bounds.max_bytes, 2);
        assert_eq!(granted.bounds.byte_offset, 1);
        assert_eq!(granted.bounds.byte_length, 2);
        assert!(granted.bounds.is_attenuation_of(&request(RIGHT_READ)));
    }

    #[test]
    fn policy_digest_is_canonical_and_binds_signer_allowlist() {
        let read = request(RIGHT_READ);
        let other_resource = CapabilityRequest {
            resource_id: 9,
            ..read
        };
        let forward = policy_with(&[read, other_resource]);
        let reverse = policy_with(&[other_resource, read]);
        assert_eq!(forward.digest(), reverse.digest());
        let (canonical, length) = forward.canonical_bytes();
        assert_eq!(length, POLICY_HEADER_SIZE + 2 * POLICY_RECORD_SIZE + 32);
        assert_eq!(&canonical[..8], b"AIENPOL\0");
        assert_eq!(u16::from_le_bytes([canonical[60], canonical[61]]), 1);
        assert_eq!(&canonical[62..64], &[0, 0]);
        let mut other_signer = AdmissionPolicy::new(forward.limits).unwrap();
        other_signer.add_resource_rule(read).unwrap();
        other_signer.add_resource_rule(other_resource).unwrap();
        other_signer.allow_signer([0x99; 32]).unwrap();
        assert_ne!(forward.digest(), other_signer.digest());
    }

    #[test]
    fn insufficient_resource_snapshot_rejects_before_authorization() {
        let bytes = signed_test_artifact(None);
        let candidate = verified(&bytes);
        let policy = policy_with(&[]);
        let mut insufficient = available();
        insufficient.stack_pages = 0;
        assert_eq!(
            policy.evaluate(&candidate, insufficient),
            Err(ArtifactError::ResourceLimit)
        );
    }

    #[test]
    fn verified_but_policy_untrusted_signer_is_rejected() {
        let bytes = signed_test_artifact(None);
        let candidate = verified(&bytes);
        let policy = AdmissionPolicy::new(AdmissionLimits {
            code_pages: 1,
            data_pages: 1,
            stack_pages: 1,
            max_capabilities: 1,
            ipc_messages: 0,
            ipc_bytes: 0,
            cpu_ticks: 10,
            elapsed_ticks: 20,
            syscall_count: 16,
        })
        .unwrap();
        assert_eq!(
            policy.evaluate(&candidate, available()),
            Err(ArtifactError::UntrustedSigner)
        );
    }
}
