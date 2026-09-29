//! Transactional handoff from authenticated artifact bytes to a private EL0
//! task image. Address-space and frame operations are supplied by the target
//! memory backend; the loader fixes their security-sensitive order.

use aienos_artifact::error::ArtifactError;
use aienos_artifact::format::Artifact;
use aienos_artifact::resource::PAGE_SIZE;
use aienos_artifact::signature::{ArtifactVerifier, TrustTier};

use crate::abi::Handle;
use crate::admission::{AdmissionPolicy, AvailableResources, GrantedAdmission};
use aienos_crypto::sha256::Digest;

pub const MAX_TASK_CODE_PAGES: u32 = 64;
pub const MAX_TASK_DATA_PAGES: u32 = 64;
pub const MAX_TASK_STACK_PAGES: u32 = 16;
pub const MAX_TASK_CAPABILITIES: usize = 16;
pub const TASK_PAGE_TABLE_FRAMES: u32 = 4;
pub const MAX_TASK_RESERVED_FRAMES: usize =
    (MAX_TASK_CODE_PAGES + MAX_TASK_DATA_PAGES + MAX_TASK_STACK_PAGES + TASK_PAGE_TABLE_FRAMES)
        as usize;

/// State transitions observable for audit and tests. No transition reaches a
/// runnable state until every verification, reservation, and mapping step has
/// succeeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateState {
    Received,
    Parsed,
    Verified,
    Authorized,
    Reserved,
    Mapped,
    CanaryRunning,
    CanaryPassed,
    Admitted,
    Rejected,
    Destroyed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskLayout {
    pub code_pages: u32,
    pub data_pages: u32,
    pub stack_pages: u32,
    pub code_bytes: u32,
    pub data_bytes: u32,
    pub data_memory_bytes: u32,
    pub entry_offset: u32,
}

impl TaskLayout {
    /// Count all private code/data/stack pages and the four translation-table
    /// pages used by the bounded v0 task window, checking before reservation.
    pub fn total_frames(self) -> Result<usize, ArtifactError> {
        let pages = self
            .code_pages
            .checked_add(self.data_pages)
            .and_then(|sum| sum.checked_add(self.stack_pages))
            .and_then(|sum| sum.checked_add(TASK_PAGE_TABLE_FRAMES))
            .ok_or(ArtifactError::LengthOverflow)?;
        let count = usize::try_from(pages).map_err(|_| ArtifactError::LengthOverflow)?;
        if count > MAX_TASK_RESERVED_FRAMES {
            return Err(ArtifactError::ResourceLimit);
        }
        Ok(count)
    }
}

impl TaskLayout {
    fn from_artifact(
        artifact: &Artifact<'_>,
        admission: &GrantedAdmission,
    ) -> Result<Self, ArtifactError> {
        let code = artifact.sections[0];
        let data = artifact.sections[1];
        let layout = Self {
            code_pages: admission.resources.code_pages,
            data_pages: admission.resources.data_pages,
            stack_pages: admission.resources.stack_pages,
            code_bytes: code.file_length,
            data_bytes: data.file_length,
            data_memory_bytes: data.memory_length,
            entry_offset: admission.entry_offset,
        };
        validate_layout(layout)?;
        Ok(layout)
    }
}

/// Backend contract for an all-or-nothing candidate task construction.
/// `reserve_all` must reserve code, data, stack, page-table, capability, and
/// scheduler slots as one atomic operation. `copy_and_hash_loaded` must hash
/// the bytes read back from the allocated private pages after copying and
/// deterministic zero-fill, not the source artifact slice.
pub trait TaskLoaderBackend {
    type Reservation;
    type AddressSpace: AddressSpaceLayout;
    type CapabilityTable;

    fn reserve_all(
        &mut self,
        admission: &GrantedAdmission,
        layout: TaskLayout,
    ) -> Result<Self::Reservation, ArtifactError>;

    /// Create a private, non-executable address space with code pages RW+NX,
    /// and data/stack pages RW+NX. Guard pages should be left unmapped.
    fn map_private_rw_nx(
        &mut self,
        reservation: &mut Self::Reservation,
        artifact: &Artifact<'_>,
        layout: TaskLayout,
    ) -> Result<Self::AddressSpace, ArtifactError>;

    /// Copy exact code and data payload bytes, zero-fill the remainder of the
    /// admitted data memory and stack, and hash bytes read from the mapped
    /// private pages using the artifact payload digest definition.
    fn copy_and_hash_loaded(
        &mut self,
        reservation: &mut Self::Reservation,
        address_space: &mut Self::AddressSpace,
        artifact: &Artifact<'_>,
        layout: TaskLayout,
    ) -> Result<Digest, ArtifactError>;

    /// Synchronize D/I caches, remove every writable alias to code pages, and
    /// transition code to EL0 RX while data and stack remain EL0 RW+NX.
    fn finalize_wx(
        &mut self,
        reservation: &mut Self::Reservation,
        address_space: &mut Self::AddressSpace,
        layout: TaskLayout,
    ) -> Result<(), ArtifactError>;

    /// Install exactly the policy-produced grants in the candidate's M3
    /// capability table. The returned handle array is in grant order.
    fn install_grants(
        &mut self,
        reservation: &mut Self::Reservation,
        admission: &GrantedAdmission,
    ) -> Result<
        (
            Self::CapabilityTable,
            [Option<Handle>; MAX_TASK_CAPABILITIES],
        ),
        ArtifactError,
    >;

    /// Reclaim all reserved pages, table slots, and any partially installed
    /// capability slots after any failed stage.
    fn abort(
        &mut self,
        reservation: Self::Reservation,
        address_space: Option<Self::AddressSpace>,
        capabilities: Option<Self::CapabilityTable>,
    );
}

/// Construct a task in a fixed order. The backend cannot be asked to map
/// pages until signature verification, policy evaluation, and full-envelope
/// resource reservation have all succeeded.
pub fn load_candidate<V, B>(
    bytes: &[u8],
    verifier: &V,
    policy: &AdmissionPolicy,
    available: AvailableResources,
    backend: &mut B,
) -> CandidateLoadResult<B>
where
    V: ArtifactVerifier,
    B: TaskLoaderBackend,
{
    // ArtifactVerifier performs bounded parse, canonical identity, trust
    // anchor lookup, and signature verification before returning this marker.
    let verified = verifier.verify(bytes)?;
    let admission = policy.evaluate(&verified, available)?;
    if admission.capability_count() > MAX_TASK_CAPABILITIES {
        return Err(ArtifactError::ResourceLimit);
    }
    let artifact = &verified.identified().artifact;
    let layout = TaskLayout::from_artifact(artifact, &admission)?;

    // Atomic reservation is deliberately the first backend operation.
    let mut reservation = backend.reserve_all(&admission, layout)?;
    let mut address_space = None;
    let mut capabilities = None;

    let result = (|| {
        let space = backend.map_private_rw_nx(&mut reservation, artifact, layout)?;
        address_space = Some(space);

        let Some(space) = address_space.as_mut() else {
            return Err(ArtifactError::BadSection);
        };

        let loaded_digest =
            backend.copy_and_hash_loaded(&mut reservation, space, artifact, layout)?;
        if loaded_digest != admission.payload_digest {
            return Err(ArtifactError::DigestMismatch);
        }

        backend.finalize_wx(&mut reservation, space, layout)?;

        let (cap_table, handles) = backend.install_grants(&mut reservation, &admission)?;
        capabilities = Some(cap_table);
        Ok(handles)
    })();

    let handles = match result {
        Ok(handles) => handles,
        Err(error) => {
            backend.abort(reservation, address_space, capabilities);
            return Err(error);
        }
    };

    let address_space = address_space.ok_or(ArtifactError::BadSection)?;
    let capabilities = capabilities.ok_or(ArtifactError::MalformedCapability)?;
    let entry_pc = address_space_entry(&address_space, layout.entry_offset);
    let user_stack = address_space_stack_top(&address_space, layout.stack_pages);
    Ok(LoadedTask {
        artifact_id: admission.artifact_id,
        payload_digest: admission.payload_digest,
        admission,
        address_space,
        capabilities,
        handles,
        entry_pc,
        user_stack,
        layout,
        state: CandidateState::Admitted,
        reservation: Some(reservation),
    })
}

/// The memory backend exposes the chosen task virtual addresses without
/// exposing artifact parsing or signature concepts to the scheduler.
pub trait AddressSpaceLayout {
    fn code_base(&self) -> u64;
    fn stack_top(&self, stack_pages: u32) -> u64;
}

fn address_space_entry<A: AddressSpaceLayout>(space: &A, offset: u32) -> u64 {
    space.code_base() + u64::from(offset)
}

fn address_space_stack_top<A: AddressSpaceLayout>(space: &A, stack_pages: u32) -> u64 {
    space.stack_top(stack_pages)
}

/// Fully verified and mapped task. The scheduler can consume `entry_pc` and
/// `user_stack`; it receives no parser or trust-anchor implementation.
pub struct LoadedTask<R, A, C> {
    pub artifact_id: aienos_artifact::ArtifactId,
    pub payload_digest: Digest,
    pub admission: GrantedAdmission,
    pub address_space: A,
    pub capabilities: C,
    pub handles: [Option<Handle>; MAX_TASK_CAPABILITIES],
    pub entry_pc: u64,
    pub user_stack: u64,
    pub layout: TaskLayout,
    pub state: CandidateState,
    reservation: Option<R>,
}

pub type CandidateLoadResult<B> = Result<
    LoadedTask<
        <B as TaskLoaderBackend>::Reservation,
        <B as TaskLoaderBackend>::AddressSpace,
        <B as TaskLoaderBackend>::CapabilityTable,
    >,
    ArtifactError,
>;

impl<R, A, C> LoadedTask<R, A, C> {
    /// Release a successfully constructed candidate after exit, fault,
    /// timeout, or canary failure. The backend revokes caps before frames.
    pub fn destroy<B>(mut self, backend: &mut B)
    where
        B: TaskLoaderBackend<Reservation = R, AddressSpace = A, CapabilityTable = C>,
    {
        self.state = CandidateState::Destroyed;
        if let Some(reservation) = self.reservation.take() {
            backend.abort(
                reservation,
                Some(self.address_space),
                Some(self.capabilities),
            );
        }
    }
}

fn validate_layout(layout: TaskLayout) -> Result<(), ArtifactError> {
    if layout.code_pages == 0
        || layout.code_pages > MAX_TASK_CODE_PAGES
        || layout.data_pages == 0
        || layout.data_pages > MAX_TASK_DATA_PAGES
        || layout.stack_pages == 0
        || layout.stack_pages > MAX_TASK_STACK_PAGES
    {
        return Err(ArtifactError::ResourceLimit);
    }
    let code_capacity = layout
        .code_pages
        .checked_mul(PAGE_SIZE)
        .ok_or(ArtifactError::LengthOverflow)?;
    let data_capacity = layout
        .data_pages
        .checked_mul(PAGE_SIZE)
        .ok_or(ArtifactError::LengthOverflow)?;
    let stack_capacity = layout
        .stack_pages
        .checked_mul(PAGE_SIZE)
        .ok_or(ArtifactError::LengthOverflow)?;
    if layout.code_bytes == 0
        || layout.code_bytes > code_capacity
        || layout.data_bytes == 0
        || layout.data_bytes > layout.data_memory_bytes
        || layout.data_memory_bytes > data_capacity
        || stack_capacity == 0
        || layout.entry_offset & 3 != 0
        || layout
            .entry_offset
            .checked_add(4)
            .is_none_or(|end| end > layout.code_bytes)
    {
        return Err(ArtifactError::BadEntryPoint);
    }
    Ok(())
}

/// Explicitly surfaced trust tier for boot receipts.
pub const fn qualification_label(tier: TrustTier) -> &'static str {
    match tier {
        TrustTier::Production => "PRODUCTION",
        TrustTier::Seed0bQualification => "SEED-0B QUALIFICATION — TEST ONLY",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_layout_checks_arithmetic_and_entry_bounds() {
        let valid = TaskLayout {
            code_pages: 1,
            data_pages: 1,
            stack_pages: 1,
            code_bytes: 4,
            data_bytes: 1,
            data_memory_bytes: 1,
            entry_offset: 0,
        };
        assert_eq!(validate_layout(valid), Ok(()));
        assert_eq!(valid.total_frames(), Ok(7));
        assert_eq!(
            validate_layout(TaskLayout {
                entry_offset: 4,
                ..valid
            }),
            Err(ArtifactError::BadEntryPoint)
        );
        assert_eq!(
            validate_layout(TaskLayout {
                code_pages: u32::MAX,
                ..valid
            }),
            Err(ArtifactError::ResourceLimit)
        );
        assert_eq!(
            validate_layout(TaskLayout {
                data_memory_bytes: u32::MAX,
                ..valid
            }),
            Err(ArtifactError::BadEntryPoint)
        );
    }

    #[test]
    fn qualification_tier_is_unambiguous() {
        assert_eq!(
            qualification_label(TrustTier::Seed0bQualification),
            "SEED-0B QUALIFICATION — TEST ONLY"
        );
    }
}
