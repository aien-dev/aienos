//! C binding used by the reaction world and by the Linux differential oracle.
//!
//! The view pointer can validate. The admin pointer can change the table.
//! They share the table, and only the admin holds the office token.

use std::fs::File;
use std::io::Read;
use std::sync::{Arc, Mutex};

use aienos_capability::{
    AuthorityAdmin, AuthorityState, CapRef, Entry, Mint, ERR_IO, ERR_STATE, OK,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AienosCapRef {
    pub cap_id: u32,
    pub generation: u32,
}

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
pub unsafe extern "C" fn aienos_cap_start(
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
/// Both pointers came from [`aienos_cap_start`] and have not been stopped.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_stop(admin: *mut AienosCapAdmin, view: *mut AienosCapView) {
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
/// `admin` came from [`aienos_cap_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_office(
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
/// `admin` came from [`aienos_cap_start`]. `out` may be null.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_mint(
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
/// `admin` came from [`aienos_cap_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_revoke(
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
/// `admin` came from [`aienos_cap_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_reclaim(
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
/// `admin` came from [`aienos_cap_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_advance_clock(
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
/// `admin` came from [`aienos_cap_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_bump_epoch(
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
/// `admin` came from [`aienos_cap_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_kill(admin: *mut AienosCapAdmin) -> i32 {
    if admin.is_null() {
        return ERR_STATE;
    }
    with_state_mut(&unsafe { &*admin }.shared, |state| state.kill_writer());
    OK
}

/// Replace the table with the next boot generation. Outstanding references
/// fail against the new table. The office token is replaced.
///
/// # Safety
/// `admin` came from [`aienos_cap_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_restart(admin: *mut AienosCapAdmin) -> i32 {
    if admin.is_null() {
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
    let shared = &unsafe { &*admin }.shared;
    with_state_mut(shared, |slot| *slot = state);
    let mut admin_token = shared
        .admin
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    *admin_token = AuthorityAdmin::new(token);
    OK
}

/// # Safety
/// `view` came from [`aienos_cap_start`]. `out` may be null.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_validate(
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
/// `view` came from [`aienos_cap_start`]. `out` may be null.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_inspect(
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
/// `view` came from [`aienos_cap_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_clock(view: *const AienosCapView) -> u64 {
    if view.is_null() {
        return 0;
    }
    with_state(&unsafe { &*view }.shared, |state| state.clock())
}

/// Cognition's mint attempt. The view has no office token, so this cannot
/// change the table no matter what reference or token bytes are supplied.
///
/// # Safety
/// `view` came from [`aienos_cap_start`]. `token` may be null.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_cognition_mint(
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
/// `view` came from [`aienos_cap_start`].
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_cognition_admin(
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
pub unsafe extern "C" fn aienos_cap_generation_advance(generation: u32, out: *mut u32) -> i32 {
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
/// `admin` came from [`aienos_cap_start`] and is the test harness, not cognition.
#[no_mangle]
pub unsafe extern "C" fn aienos_cap_force_generation(
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
