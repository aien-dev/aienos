//! C binding for the 32-bit-generation Rust capability authority
//! (`aienos-capability`).
//!
//! This is NOT the native AIENOS capability ABI. The production ABI is the C
//! library in `native/capability` (`aienos_capability.h`): 64-bit
//! generations, `AienosCapRef` of 16 bytes, symbols `aienos_cap_*`. That is
//! the library omega links into the reaction world.
//!
//! This crate is a separate implementation with a different layout
//! (`AienosCapRef` of 8 bytes, 32-bit generation). So that a program built
//! against the C header can never resolve against this archive by accident,
//! every exported symbol carries its own versioned prefix, `aienos_cap32_*`,
//! and [`aienos_cap32_abi_layout`] reports the layout it was built with.
//! `scripts/test-cap-abi-isolation.sh` checks that the two archives share no
//! symbol and that a C caller of `aienos_cap_*` fails to link against this
//! one.
//!
//! The view pointer can validate. The admin pointer can change the table.
//! They share the table, and only the admin holds the office token.

use std::fs::File;
use std::io::Read;
use std::sync::{Arc, Mutex};

use aienos_capability::{
    AuthorityAdmin, AuthorityState, CapRef, Entry, Mint, ERR_IO, ERR_STATE, OK,
};

/// Capability reference in the 32-bit-generation Rust authority ABI
/// (8 bytes, align 4, generation at offset 4). NOT the native AIENOS
/// capability ABI, whose `AienosCapRef` is 16 bytes with a 64-bit
/// generation at offset 8.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AienosCapRef {
    pub cap_id: u32,
    pub generation: u32,
}

/// Table entry in the 32-bit-generation Rust authority ABI (64 bytes).
/// NOT the native AIENOS capability ABI (88 bytes there).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AienosCapEntry {
    pub cap_id: u32,
    pub generation: u32,
    pub state: u32,
    pub issuer: u32,
    pub subject: u32,
    pub rights: u32,
    pub resource: u64,
    pub epoch: u64,
    pub lease_expiry: u64,
    pub parent_id: u32,
    pub parent_generation: u32,
    pub minted_by_id: u32,
    pub minted_by_generation: u32,
}

/// Mint request in the 32-bit-generation Rust authority ABI (48 bytes).
/// NOT the native AIENOS capability ABI (64 bytes there).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AienosCapMint {
    pub issuer: u32,
    pub subject: u32,
    pub resource: u64,
    pub rights: u32,
    pub lease_ticks: u64,
    pub parent: AienosCapRef,
    pub authority: AienosCapRef,
}

/// Version of the `aienos_cap32_*` binary contract. Bump it, and the symbol
/// prefix, if any exported layout or signature changes.
pub const AIENOS_CAP32_ABI_VERSION: u32 = 1;

/// Width in bits of every generation field in this ABI.
pub const AIENOS_CAP32_GENERATION_BITS: u32 = 32;

/// Number of `u32` words [`aienos_cap32_abi_layout`] writes.
pub const AIENOS_CAP32_LAYOUT_WORDS: usize = 4;

const REF_SIZE: usize = 8;
const REF_ALIGN: usize = 4;
const REF_GENERATION_OFFSET: usize = 4;
const ENTRY_SIZE: usize = 64;
const MINT_SIZE: usize = 48;

const _: () = assert!(core::mem::size_of::<AienosCapRef>() == REF_SIZE);
const _: () = assert!(core::mem::align_of::<AienosCapRef>() == REF_ALIGN);
const _: () = assert!(core::mem::offset_of!(AienosCapRef, cap_id) == 0);
const _: () = assert!(core::mem::offset_of!(AienosCapRef, generation) == REF_GENERATION_OFFSET);
const _: () = assert!(core::mem::size_of::<u32>() * 8 == AIENOS_CAP32_GENERATION_BITS as usize);
const _: () = assert!(core::mem::size_of::<AienosCapEntry>() == ENTRY_SIZE);
const _: () = assert!(core::mem::align_of::<AienosCapEntry>() == 8);
const _: () = assert!(core::mem::offset_of!(AienosCapEntry, generation) == 4);
const _: () = assert!(core::mem::offset_of!(AienosCapEntry, resource) == 24);
const _: () = assert!(core::mem::offset_of!(AienosCapEntry, parent_generation) == 52);
const _: () = assert!(core::mem::offset_of!(AienosCapEntry, minted_by_generation) == 60);
const _: () = assert!(core::mem::size_of::<AienosCapMint>() == MINT_SIZE);
const _: () = assert!(core::mem::offset_of!(AienosCapMint, lease_ticks) == 24);
const _: () = assert!(core::mem::offset_of!(AienosCapMint, parent) == 32);
const _: () = assert!(core::mem::offset_of!(AienosCapMint, authority) == 40);

/// Report the layout this archive was built with, so a caller can refuse to
/// run against a different one. Writes, in order: size of `AienosCapRef`,
/// offset of its `generation`, size of that `generation` field, size of
/// `AienosCapEntry`. Returns [`AIENOS_CAP32_ABI_VERSION`], or 0 when `out`
/// is null.
///
/// # Safety
/// `out` is null or points to [`AIENOS_CAP32_LAYOUT_WORDS`] writable `u32`s.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_abi_layout(out: *mut u32) -> u32 {
    if out.is_null() {
        return 0;
    }
    let words: [u32; AIENOS_CAP32_LAYOUT_WORDS] = [
        REF_SIZE as u32,
        REF_GENERATION_OFFSET as u32,
        core::mem::size_of::<u32>() as u32,
        ENTRY_SIZE as u32,
    ];
    for (i, word) in words.iter().enumerate() {
        unsafe { *out.add(i) = *word };
    }
    AIENOS_CAP32_ABI_VERSION
}

pub struct AienosCapShared {
    state: Mutex<AuthorityState>,
    admin: Mutex<AuthorityAdmin>,
}

pub struct AienosCapAdmin {
    shared: Arc<AienosCapShared>,
}

pub struct AienosCapView {
    shared: Arc<AienosCapShared>,
}

fn fill_token(token: &mut [u8; 32]) -> bool {
    let mut file = match File::open("/dev/urandom") {
        Ok(file) => file,
        Err(_) => return false,
    };
    file.read_exact(token).is_ok()
}

fn to_ref(cap: AienosCapRef) -> CapRef {
    CapRef {
        cap_id: cap.cap_id,
        generation: cap.generation,
    }
}

fn from_ref(cap: CapRef) -> AienosCapRef {
    AienosCapRef {
        cap_id: cap.cap_id,
        generation: cap.generation,
    }
}

fn to_mint(request: AienosCapMint) -> Mint {
    Mint {
        issuer: request.issuer,
        subject: request.subject,
        resource: request.resource,
        rights: request.rights,
        lease_ticks: request.lease_ticks,
        parent: to_ref(request.parent),
        authority: to_ref(request.authority),
    }
}

fn from_entry(entry: Entry) -> AienosCapEntry {
    AienosCapEntry {
        cap_id: entry.cap_id,
        generation: entry.generation,
        state: entry.state,
        issuer: entry.issuer,
        subject: entry.subject,
        rights: entry.rights,
        resource: entry.resource,
        epoch: entry.epoch,
        lease_expiry: entry.lease_expiry,
        parent_id: entry.parent_id,
        parent_generation: entry.parent_generation,
        minted_by_id: entry.minted_by_id,
        minted_by_generation: entry.minted_by_generation,
    }
}

fn write_entry(out: *mut AienosCapEntry, entry: Entry) {
    if !out.is_null() {
        unsafe { *out = from_entry(entry) };
    }
}

fn write_ref(out: *mut AienosCapRef, cap: CapRef) {
    if !out.is_null() {
        unsafe { *out = from_ref(cap) };
    }
}

/// # Safety
/// `admin_out` and `view_out` must be writable pointers.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_start(
    admin_out: *mut *mut AienosCapAdmin,
    view_out: *mut *mut AienosCapView,
) -> i32 {
    if admin_out.is_null() || view_out.is_null() {
        return ERR_STATE;
    }
    let boot = match aienos_capability::take_boot_gen() {
        Ok(boot) => boot,
        Err(code) => return code,
    };
    let state = match AuthorityState::bootstrap(boot) {
        Ok(state) => state,
        Err(code) => return code,
    };
    let mut token = [0u8; 32];
    if !fill_token(&mut token) {
        return ERR_IO;
    }
    let shared = Arc::new(AienosCapShared {
        state: Mutex::new(state),
        admin: Mutex::new(AuthorityAdmin::new(token)),
    });
    let admin = Box::new(AienosCapAdmin {
        shared: Arc::clone(&shared),
    });
    let view = Box::new(AienosCapView { shared });
    unsafe {
        *admin_out = Box::into_raw(admin);
        *view_out = Box::into_raw(view);
    }
    OK
}

/// # Safety
/// Both pointers came from [`aienos_cap32_start`] and have not been stopped.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_stop(admin: *mut AienosCapAdmin, view: *mut AienosCapView) {
    if !admin.is_null() {
        drop(unsafe { Box::from_raw(admin) });
    }
    if !view.is_null() {
        drop(unsafe { Box::from_raw(view) });
    }
}

fn with_state<T>(shared: &AienosCapShared, f: impl FnOnce(&AuthorityState) -> T) -> T {
    let state = shared
        .state
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    f(&state)
}

fn with_state_mut<T>(shared: &AienosCapShared, f: impl FnOnce(&mut AuthorityState) -> T) -> T {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    f(&mut state)
}

/// # Safety
/// `admin` came from [`aienos_cap32_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_office(
    admin: *const AienosCapAdmin,
    out: *mut AienosCapRef,
) -> i32 {
    if admin.is_null() {
        return ERR_STATE;
    }
    let cap = with_state(&unsafe { &*admin }.shared, |state| state.office());
    write_ref(out, cap);
    OK
}

/// # Safety
/// `admin` came from [`aienos_cap32_start`]. `out` may be null.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_mint(
    admin: *mut AienosCapAdmin,
    request: *const AienosCapMint,
    out: *mut AienosCapRef,
) -> i32 {
    if admin.is_null() || request.is_null() {
        return ERR_STATE;
    }
    let request = unsafe { *request };
    let result = with_state_mut(&unsafe { &*admin }.shared, |state| {
        state.mint(to_mint(request))
    });
    match result {
        Ok(cap) => {
            write_ref(out, cap);
            OK
        }
        Err(code) => code,
    }
}

/// # Safety
/// `admin` came from [`aienos_cap32_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_revoke(
    admin: *mut AienosCapAdmin,
    authority: AienosCapRef,
    target: AienosCapRef,
) -> i32 {
    if admin.is_null() {
        return ERR_STATE;
    }
    with_state_mut(&unsafe { &*admin }.shared, |state| {
        state.revoke(to_ref(authority), to_ref(target))
    })
    .err()
    .unwrap_or(OK)
}

/// # Safety
/// `admin` came from [`aienos_cap32_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_reclaim(
    admin: *mut AienosCapAdmin,
    authority: AienosCapRef,
    cap_id: u32,
) -> i32 {
    if admin.is_null() {
        return ERR_STATE;
    }
    with_state_mut(&unsafe { &*admin }.shared, |state| {
        state.reclaim(to_ref(authority), cap_id)
    })
    .err()
    .unwrap_or(OK)
}

/// # Safety
/// `admin` came from [`aienos_cap32_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_advance_clock(
    admin: *mut AienosCapAdmin,
    authority: AienosCapRef,
    ticks: u64,
) -> i32 {
    if admin.is_null() {
        return ERR_STATE;
    }
    with_state_mut(&unsafe { &*admin }.shared, |state| {
        state.advance_clock(to_ref(authority), ticks)
    })
    .err()
    .unwrap_or(OK)
}

/// # Safety
/// `admin` came from [`aienos_cap32_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_bump_epoch(
    admin: *mut AienosCapAdmin,
    authority: AienosCapRef,
) -> i32 {
    if admin.is_null() {
        return ERR_STATE;
    }
    with_state_mut(&unsafe { &*admin }.shared, |state| {
        state.bump_epoch(to_ref(authority))
    })
    .err()
    .unwrap_or(OK)
}

/// # Safety
/// `admin` came from [`aienos_cap32_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_kill(admin: *mut AienosCapAdmin) -> i32 {
    if admin.is_null() {
        return ERR_STATE;
    }
    with_state_mut(&unsafe { &*admin }.shared, |state| state.kill_writer());
    OK
}

/// Replace the table with the next boot generation. The new table starts
/// above every generation the old one used (fix mirrored from the native
/// authority, b1fa747), so outstanding references fail against it even
/// after reclaims. The office token is replaced.
///
/// # Safety
/// `admin` came from [`aienos_cap32_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_restart(admin: *mut AienosCapAdmin) -> i32 {
    if admin.is_null() {
        return ERR_STATE;
    }
    let mut token = [0u8; 32];
    if !fill_token(&mut token) {
        return ERR_IO;
    }
    let shared = &unsafe { &*admin }.shared;
    let swapped = with_state_mut(shared, |slot| {
        let boot = aienos_capability::take_boot_gen_above(slot.generation_floor())?;
        *slot = AuthorityState::bootstrap(boot)?;
        Ok::<(), i32>(())
    });
    if let Err(code) = swapped {
        return code;
    }
    let mut admin_token = shared
        .admin
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    *admin_token = AuthorityAdmin::new(token);
    OK
}

/// # Safety
/// `view` came from [`aienos_cap32_start`]. `out` may be null.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_validate(
    view: *const AienosCapView,
    cap: AienosCapRef,
    subject: u32,
    resource: u64,
    rights: u32,
    out: *mut AienosCapEntry,
) -> i32 {
    if view.is_null() {
        return ERR_STATE;
    }
    let result = with_state(&unsafe { &*view }.shared, |state| {
        state.validate(to_ref(cap), subject, resource, rights)
    });
    match result {
        Ok(entry) => {
            write_entry(out, entry);
            OK
        }
        Err(code) => code,
    }
}

/// # Safety
/// `view` came from [`aienos_cap32_start`]. `out` may be null.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_inspect(
    view: *const AienosCapView,
    cap: AienosCapRef,
    out: *mut AienosCapEntry,
) -> i32 {
    if view.is_null() {
        return ERR_STATE;
    }
    let result = with_state(&unsafe { &*view }.shared, |state| {
        state.inspect(to_ref(cap))
    });
    match result {
        Ok(entry) => {
            write_entry(out, entry);
            OK
        }
        Err(code) => code,
    }
}

/// # Safety
/// `view` came from [`aienos_cap32_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_clock(view: *const AienosCapView) -> u64 {
    if view.is_null() {
        return 0;
    }
    with_state(&unsafe { &*view }.shared, |state| state.clock())
}

/// Cognition's mint attempt. The view has no office token, so this cannot
/// change the table no matter what reference or token bytes are supplied.
///
/// # Safety
/// `view` came from [`aienos_cap32_start`]. `token` may be null.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_cognition_mint(
    view: *const AienosCapView,
    _request: *const AienosCapMint,
    _token: *const u8,
) -> i32 {
    if view.is_null() {
        return ERR_STATE;
    }
    let _ = with_state(&unsafe { &*view }.shared, |state| state.clock());
    aienos_capability::ERR_UNAUTHORIZED
}

/// # Safety
/// `view` came from [`aienos_cap32_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_cognition_admin(
    view: *const AienosCapView,
    _op: u32,
    _authority: AienosCapRef,
    _target: AienosCapRef,
) -> i32 {
    if view.is_null() {
        return ERR_STATE;
    }
    aienos_capability::ERR_UNAUTHORIZED
}

/// # Safety
/// `out` may be null. When it is not, it must be writable.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_generation_advance(generation: u32, out: *mut u32) -> i32 {
    match aienos_capability::generation_advance(generation) {
        Ok(next) => {
            if !out.is_null() {
                unsafe { *out = next };
            }
            OK
        }
        Err(code) => code,
    }
}

/// # Safety
/// `admin` came from [`aienos_cap32_start`] and is the test harness, not cognition.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap32_force_generation(
    admin: *mut AienosCapAdmin,
    cap_id: u32,
    generation: u32,
) -> i32 {
    if admin.is_null() {
        return ERR_STATE;
    }
    with_state_mut(&unsafe { &*admin }.shared, |state| {
        state.set_generation_for_test(cap_id, generation)
    })
    .err()
    .unwrap_or(OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aienos_capability::{
        ERR_EXHAUSTED, ERR_REVOKED, ERR_STALE_GEN, ERR_SUBJECT, ERR_UNAUTHORIZED, RIGHT_READ,
    };
    use core::ptr;

    #[test]
    fn layout_matches_the_cap32_contract() {
        assert_eq!(core::mem::size_of::<AienosCapRef>(), 8);
        assert_eq!(core::mem::align_of::<AienosCapRef>(), 4);
        assert_eq!(core::mem::offset_of!(AienosCapRef, generation), 4);
        assert_eq!(core::mem::size_of::<AienosCapEntry>(), 64);
        assert_eq!(core::mem::size_of::<AienosCapMint>(), 48);
        let mut words = [0u32; AIENOS_CAP32_LAYOUT_WORDS];
        let version = unsafe { aienos_cap32_abi_layout(words.as_mut_ptr()) };
        assert_eq!(version, AIENOS_CAP32_ABI_VERSION);
        assert_eq!(version, 1);
        assert_eq!(words, [8, 4, 4, 64]);
        assert_eq!(unsafe { aienos_cap32_abi_layout(ptr::null_mut()) }, 0);
        // The native C ABI is 16 bytes with the generation at offset 8. A
        // caller that checks this report cannot mistake one for the other.
        assert_ne!(words[0], 16);
        assert_ne!(words[1], 8);
    }

    struct Auth {
        admin: *mut AienosCapAdmin,
        view: *mut AienosCapView,
    }

    impl Auth {
        fn start() -> Self {
            let mut admin = ptr::null_mut();
            let mut view = ptr::null_mut();
            assert_eq!(unsafe { aienos_cap32_start(&mut admin, &mut view) }, OK);
            Self { admin, view }
        }

        fn office(&self) -> AienosCapRef {
            let mut out = AienosCapRef {
                cap_id: 0,
                generation: 0,
            };
            assert_eq!(unsafe { aienos_cap32_office(self.admin, &mut out) }, OK);
            out
        }

        fn mint(&self, subject: u32, resource: u64) -> AienosCapRef {
            let request = AienosCapMint {
                issuer: 3,
                subject,
                resource,
                rights: RIGHT_READ,
                lease_ticks: 0,
                parent: AienosCapRef {
                    cap_id: aienos_capability::PARENT_NONE,
                    generation: 0,
                },
                authority: self.office(),
            };
            let mut out = AienosCapRef {
                cap_id: 0,
                generation: 0,
            };
            assert_eq!(
                unsafe { aienos_cap32_mint(self.admin, &request, &mut out) },
                OK
            );
            out
        }

        fn validate(&self, cap: AienosCapRef, subject: u32, resource: u64) -> i32 {
            unsafe {
                aienos_cap32_validate(
                    self.view,
                    cap,
                    subject,
                    resource,
                    RIGHT_READ,
                    ptr::null_mut(),
                )
            }
        }
    }

    impl Drop for Auth {
        fn drop(&mut self) {
            unsafe { aienos_cap32_stop(self.admin, self.view) };
        }
    }

    /// Mirror of the C test reclaimed_reference_stays_dead_after_restart
    /// (fix b1fa747): a reference minted after one reclaim must not validate
    /// again once the same slot is minted for the same subject and resource
    /// after a restart.
    #[test]
    fn reclaimed_reference_stays_dead_after_restart() {
        let a = Auth::start();
        let first = a.mint(1, 0x40);
        assert_eq!(
            unsafe { aienos_cap32_revoke(a.admin, a.office(), first) },
            OK
        );
        assert_eq!(
            unsafe { aienos_cap32_reclaim(a.admin, a.office(), first.cap_id) },
            OK
        );
        let second = a.mint(1, 0x40);
        assert_eq!(second.cap_id, first.cap_id);
        assert_eq!(second.generation, first.generation + 1);
        assert_eq!(unsafe { aienos_cap32_restart(a.admin) }, OK);
        let fresh = a.mint(1, 0x40);
        assert_eq!(fresh.cap_id, second.cap_id);
        assert!(fresh.generation > second.generation);
        assert_eq!(a.validate(second, 1, 0x40), ERR_STALE_GEN);
        assert_eq!(a.validate(first, 1, 0x40), ERR_STALE_GEN);
        assert_eq!(a.validate(fresh, 1, 0x40), OK);
    }

    /// Mirror of the C test generation_exhaustion_fails_closed.
    #[test]
    fn generation_exhaustion_fails_closed() {
        let mut next = 0u32;
        assert_eq!(
            unsafe { aienos_cap32_generation_advance(u32::MAX, &mut next) },
            ERR_EXHAUSTED
        );
        assert_eq!(
            unsafe { aienos_cap32_generation_advance(u32::MAX - 1, &mut next) },
            OK
        );
        assert_eq!(next, u32::MAX);
        let a = Auth::start();
        let cap = a.mint(1, 0x10);
        assert_eq!(unsafe { aienos_cap32_revoke(a.admin, a.office(), cap) }, OK);
        assert_eq!(
            unsafe { aienos_cap32_force_generation(a.admin, cap.cap_id, u32::MAX) },
            OK
        );
        assert_eq!(
            unsafe { aienos_cap32_reclaim(a.admin, a.office(), cap.cap_id) },
            ERR_EXHAUSTED
        );
        assert_eq!(a.validate(cap, 1, 0x10), ERR_STALE_GEN);
        let replacement = a.mint(1, 0x11);
        assert_ne!(replacement.cap_id, cap.cap_id);
        assert_eq!(
            unsafe { aienos_cap32_force_generation(a.admin, replacement.cap_id, 99) },
            ERR_STATE
        );
        // No start above an exhausted generation exists, so restart refuses
        // rather than reuse one, and the table is left as it was.
        assert_eq!(unsafe { aienos_cap32_restart(a.admin) }, ERR_EXHAUSTED);
        assert_eq!(a.validate(replacement, 1, 0x11), OK);
    }

    #[test]
    fn stale_and_unauthorized_use_is_refused() {
        let a = Auth::start();
        let cap = a.mint(1, 0x20);
        assert_eq!(a.validate(cap, 2, 0x20), ERR_SUBJECT);
        let before = unsafe { aienos_cap32_clock(a.view) };
        let request = AienosCapMint {
            issuer: 1,
            subject: 1,
            resource: 1,
            rights: RIGHT_READ,
            lease_ticks: 0,
            parent: AienosCapRef {
                cap_id: aienos_capability::PARENT_NONE,
                generation: 0,
            },
            authority: a.office(),
        };
        let guess = [0u8; 32];
        assert_eq!(
            unsafe { aienos_cap32_cognition_mint(a.view, &request, guess.as_ptr()) },
            ERR_UNAUTHORIZED
        );
        assert_eq!(
            unsafe { aienos_cap32_cognition_admin(a.view, 1, a.office(), cap) },
            ERR_UNAUTHORIZED
        );
        assert_eq!(unsafe { aienos_cap32_clock(a.view) }, before);
        // An ordinary reference cannot act as the office.
        let mut as_office = request;
        as_office.authority = cap;
        let mut out = AienosCapRef {
            cap_id: 0,
            generation: 0,
        };
        assert_eq!(
            unsafe { aienos_cap32_mint(a.admin, &as_office, &mut out) },
            ERR_UNAUTHORIZED
        );
        assert_eq!(
            unsafe { aienos_cap32_advance_clock(a.admin, cap, 1) },
            ERR_UNAUTHORIZED
        );
        assert_eq!(unsafe { aienos_cap32_revoke(a.admin, a.office(), cap) }, OK);
        assert_eq!(a.validate(cap, 1, 0x20), ERR_REVOKED);
        assert_eq!(
            unsafe { aienos_cap32_reclaim(a.admin, a.office(), cap.cap_id) },
            OK
        );
        assert_eq!(a.validate(cap, 1, 0x20), ERR_STALE_GEN);
        // Null handles fail closed.
        assert_eq!(
            unsafe {
                aienos_cap32_validate(ptr::null(), cap, 1, 0x20, RIGHT_READ, ptr::null_mut())
            },
            ERR_STATE
        );
    }
}
