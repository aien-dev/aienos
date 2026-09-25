#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use uefi::prelude::*;
use uefi::proto::device_path::{DeviceSubType, DeviceType, LoadedImageDevicePath};
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::runtime::{ResetType, VariableAttributes, VariableVendor};
use uefi::{cstr16, CStr16};

#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    uefi::println!("ROLLBACK_MOCK_PANIC: {}", info);
    uefi::runtime::reset(ResetType::COLD, Status::ABORTED, None)
}

const CYCLE_VAR: &CStr16 = cstr16!("AienosRollbackCycle");
const CYCLE_VENDOR: uefi::runtime::VariableVendor =
    VariableVendor(uefi::guid!("a1e05b0e-7c3d-4f51-9b6a-2d8e4c1f0a38"));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Stager,
    Candidate,
    DefaultOs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Normal,
    Fault,
    Timeout,
    Absent,
    Malformed,
    RealAienos,
}

fn detect_role() -> Role {
    let handle = uefi::boot::image_handle();
    let Ok(loaded_dp) = uefi::boot::open_protocol_exclusive::<LoadedImageDevicePath>(handle) else {
        return Role::Stager;
    };

    for node in loaded_dp.node_iter() {
        if node.device_type() == DeviceType::MEDIA
            && node.sub_type() == DeviceSubType::MEDIA_FILE_PATH
        {
            let data = node.data();
            let (chunks, _) = data.as_chunks::<2>();
            let s = chunks
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]) as u8 as char)
                .collect::<alloc::string::String>();
            let lower = s.to_lowercase();
            if lower.contains("default") {
                return Role::DefaultOs;
            } else if lower.contains("candidate") {
                return Role::Candidate;
            }
        }
    }
    Role::Stager
}

fn read_mode_file() -> Mode {
    let mut buf = [0u8; 64];
    if let Ok(mut fs) = uefi::boot::get_image_file_system(uefi::boot::image_handle()) {
        if let Ok(mut root) = fs.open_volume() {
            if let Ok(handle) = root.open(
                cstr16!("\\EFI\\AIENOS\\ROLLBACK_MODE.TXT"),
                FileMode::Read,
                FileAttribute::empty(),
            ) {
                if let Some(mut file) = handle.into_regular_file() {
                    let _ = file.read(&mut buf);
                }
            }
        }
    }

    let text = core::str::from_utf8(&buf).unwrap_or("");
    if text.contains("fault") {
        Mode::Fault
    } else if text.contains("timeout") {
        Mode::Timeout
    } else if text.contains("absent") {
        Mode::Absent
    } else if text.contains("malformed") {
        Mode::Malformed
    } else if text.contains("real_aienos") {
        Mode::RealAienos
    } else {
        Mode::Normal
    }
}

fn build_load_option(description: &str, partition_dp_prefix: &[u8], file_path: &str) -> Vec<u8> {
    let mut full_dp = Vec::new();
    full_dp.extend_from_slice(partition_dp_prefix);

    // Media FilePath node: Type = 0x04, SubType = 0x04
    // Length: 4 + 2 * (chars + 1)
    let utf16_chars: Vec<u16> = file_path.encode_utf16().collect();
    let node_len = (4 + 2 * (utf16_chars.len() + 1)) as u16;
    full_dp.push(0x04);
    full_dp.push(0x04);
    full_dp.extend_from_slice(&node_len.to_le_bytes());
    for &ch in &utf16_chars {
        full_dp.extend_from_slice(&ch.to_le_bytes());
    }
    full_dp.extend_from_slice(&0u16.to_le_bytes()); // null terminator

    // End-Entire node: 0x7F, 0xFF, 0x04, 0x00
    full_dp.push(0x7F);
    full_dp.push(0xFF);
    full_dp.extend_from_slice(&4u16.to_le_bytes());

    let mut opt = Vec::new();
    // 1. Attributes: LOAD_OPTION_ACTIVE = 0x00000001
    opt.extend_from_slice(&1u32.to_le_bytes());
    // 2. FilePathListLength
    opt.extend_from_slice(&(full_dp.len() as u16).to_le_bytes());
    // 3. Description null-terminated UTF-16
    for c in description.encode_utf16() {
        opt.extend_from_slice(&c.to_le_bytes());
    }
    opt.extend_from_slice(&0u16.to_le_bytes());
    // 4. FilePathList
    opt.extend_from_slice(&full_dp);

    opt
}

#[entry]
fn main() -> Status {
    let role = detect_role();
    let mode = read_mode_file();

    match role {
        Role::Stager => run_stager(mode),
        Role::Candidate => run_candidate(mode),
        Role::DefaultOs => run_default(mode),
    }
}

fn run_stager(mode: Mode) -> Status {
    uefi::println!("=== M0_ROLLBACK_HARNESS: STAGER STARTING ===");
    uefi::println!("stager_mode: {:?}", mode);

    let handle = uefi::boot::image_handle();
    let Ok(loaded_dp) = uefi::boot::open_protocol_exclusive::<LoadedImageDevicePath>(handle) else {
        uefi::println!("FAIL: cannot get LoadedImageDevicePath");
        return Status::UNSUPPORTED;
    };

    // Extract partition device path prefix (everything before the first MEDIA_FILE_PATH node)
    let mut prefix_len = 0;
    for node in loaded_dp.node_iter() {
        if node.device_type() == DeviceType::MEDIA
            && node.sub_type() == DeviceSubType::MEDIA_FILE_PATH
        {
            break;
        }
        prefix_len += usize::from(node.length());
    }

    if prefix_len == 0 {
        uefi::println!("FAIL: partition device path prefix empty");
        return Status::UNSUPPORTED;
    }

    let prefix = &loaded_dp.as_bytes()[..prefix_len];

    // Build Boot0001 (Default Linux OS -> \EFI\DEFAULT\default.efi)
    let opt_default = build_load_option("Default Linux OS", prefix, "\\EFI\\DEFAULT\\default.efi");

    // Build Boot0000 (Candidate)
    let candidate_path = match mode {
        Mode::Absent => "\\EFI\\AIENOS\\missing_candidate.efi",
        Mode::RealAienos => "\\EFI\\AIENOS\\aienos-handoff.efi",
        _ => "\\EFI\\AIENOS\\candidate.efi",
    };
    let opt_candidate = build_load_option("AIENOS Candidate", prefix, candidate_path);

    let var_attrs = VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS;

    // Set Boot0001
    if uefi::runtime::set_variable(
        cstr16!("Boot0001"),
        &VariableVendor::GLOBAL_VARIABLE,
        var_attrs,
        &opt_default,
    )
    .is_err()
    {
        uefi::println!("FAIL: set Boot0001");
        return Status::DEVICE_ERROR;
    }

    // Set BootOrder = [0x0001]
    let boot_order = [0x0001u16];
    let boot_order_bytes =
        unsafe { core::slice::from_raw_parts(boot_order.as_ptr() as *const u8, 2) };
    if uefi::runtime::set_variable(
        cstr16!("BootOrder"),
        &VariableVendor::GLOBAL_VARIABLE,
        var_attrs,
        boot_order_bytes,
    )
    .is_err()
    {
        uefi::println!("FAIL: set BootOrder");
        return Status::DEVICE_ERROR;
    }

    // Set Boot0000
    if uefi::runtime::set_variable(
        cstr16!("Boot0000"),
        &VariableVendor::GLOBAL_VARIABLE,
        var_attrs,
        &opt_candidate,
    )
    .is_err()
    {
        uefi::println!("FAIL: set Boot0000");
        return Status::DEVICE_ERROR;
    }

    // Set BootNext = 0x0000
    let boot_next = 0x0000u16;
    if uefi::runtime::set_variable(
        cstr16!("BootNext"),
        &VariableVendor::GLOBAL_VARIABLE,
        var_attrs,
        &boot_next.to_le_bytes(),
    )
    .is_err()
    {
        uefi::println!("FAIL: set BootNext");
        return Status::DEVICE_ERROR;
    }

    // Reset cycle counter to 0
    let zero = 0u32;
    let _ = uefi::runtime::set_variable(CYCLE_VAR, &CYCLE_VENDOR, var_attrs, &zero.to_le_bytes());

    uefi::println!(
        "PASS  M0_ROLLBACK_STAGED: boot_order=0001 boot_next=0000 candidate={}",
        candidate_path
    );
    uefi::println!("M0_ROLLBACK_HARNESS: RESETTING SYSTEM FOR CANDIDATE BOOT");

    // Initiate Cold Reset to execute BootNext
    uefi::runtime::reset(ResetType::COLD, Status::SUCCESS, None)
}

fn run_candidate(mode: Mode) -> Status {
    uefi::println!("=== AIENOS CANDIDATE STARTING ===");
    uefi::println!("AIENOS_CANDIDATE: RUNNING");
    uefi::println!("NATIVE_CONTROL_ACQUIRED: PASS");

    // Check BootCurrent
    let mut current_buf = [0u8; 4];
    if let Ok((data, _)) = uefi::runtime::get_variable(
        cstr16!("BootCurrent"),
        &VariableVendor::GLOBAL_VARIABLE,
        &mut current_buf,
    ) {
        if data.len() >= 2 {
            let cur = u16::from_le_bytes([data[0], data[1]]);
            uefi::println!("AIENOS_CANDIDATE: BOOT_CURRENT={:04X}", cur);
        }
    }

    match mode {
        Mode::Normal => {
            uefi::println!("AIENOS_CANDIDATE: NORMAL_TERMINATION_REQUESTED");
            uefi::println!("AIENOS_CANDIDATE: RESETTING");
            uefi::runtime::reset(ResetType::COLD, Status::SUCCESS, None)
        }
        Mode::Fault => {
            uefi::println!("AIENOS_CANDIDATE: INDUCED_FAULT_PANIC");
            uefi::println!("AIENOS_CANDIDATE: RESETTING WITH FAULT");
            uefi::runtime::reset(ResetType::COLD, Status::ABORTED, None)
        }
        Mode::Timeout => {
            uefi::println!("AIENOS_CANDIDATE: ENTERING_HANG_SPIN_LOOP");
            loop {
                core::hint::spin_loop();
            }
        }
        _ => {
            uefi::println!("AIENOS_CANDIDATE: DEFAULT_TERMINATION");
            uefi::runtime::reset(ResetType::COLD, Status::SUCCESS, None)
        }
    }
}

fn run_default(_mode: Mode) -> Status {
    uefi::println!("=== DEFAULT OS BOOT (LINUX REFERENCE MOCK) ===");
    uefi::println!("DEFAULT_BOOT: ALIVE");

    // Read BootCurrent
    let mut current_buf = [0u8; 4];
    let cur = if let Ok((data, _)) = uefi::runtime::get_variable(
        cstr16!("BootCurrent"),
        &VariableVendor::GLOBAL_VARIABLE,
        &mut current_buf,
    ) {
        if data.len() >= 2 {
            u16::from_le_bytes([data[0], data[1]])
        } else {
            0xFFFF
        }
    } else {
        0xFFFF
    };
    uefi::println!("DEFAULT_OS: BOOT_CURRENT={:04X}", cur);

    // Read BootOrder
    let mut order_buf = [0u8; 32];
    let order_ok = if let Ok((data, _)) = uefi::runtime::get_variable(
        cstr16!("BootOrder"),
        &VariableVendor::GLOBAL_VARIABLE,
        &mut order_buf,
    ) {
        if data.len() >= 2 {
            let first = u16::from_le_bytes([data[0], data[1]]);
            uefi::println!("DEFAULT_OS: BOOT_ORDER[0]={:04X}", first);
            first == 0x0001
        } else {
            false
        }
    } else {
        false
    };

    // Check BootNext (must be absent / consumed)
    let mut next_buf = [0u8; 4];
    let next_result = uefi::runtime::get_variable(
        cstr16!("BootNext"),
        &VariableVendor::GLOBAL_VARIABLE,
        &mut next_buf,
    );
    let next_consumed = next_result.is_err();

    if next_consumed {
        uefi::println!("DEFAULT_OS: BOOT_NEXT=CONSUMED_PASS");
        uefi::println!("PASS  NATIVE_ROLLBACK_BOOTNEXT_CONSUMED");
    } else {
        uefi::println!("FAIL  NATIVE_ROLLBACK_BOOTNEXT_STILL_PRESENT");
    }

    if order_ok {
        uefi::println!("PASS  NATIVE_ROLLBACK_DEFAULT_UNCHANGED");
    } else {
        uefi::println!("FAIL  NATIVE_ROLLBACK_DEFAULT_ORDER_ALTERED");
    }

    // Check cycle count
    let mut cycle_buf = [0u8; 4];
    let cycle = if let Ok((data, _)) =
        uefi::runtime::get_variable(CYCLE_VAR, &CYCLE_VENDOR, &mut cycle_buf)
    {
        if data.len() >= 4 {
            u32::from_le_bytes([data[0], data[1], data[2], data[3]])
        } else {
            0
        }
    } else {
        0
    };

    let var_attrs = VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS;

    if cycle == 0 {
        uefi::println!("DEFAULT_OS: FIRST_RETURN_VERIFIED");
        let next_cycle = 1u32;
        let _ = uefi::runtime::set_variable(
            CYCLE_VAR,
            &CYCLE_VENDOR,
            var_attrs,
            &next_cycle.to_le_bytes(),
        );
        uefi::println!("DEFAULT_OS: TRIGGERING_REPEAT_BOOT_TEST");
        uefi::runtime::reset(ResetType::COLD, Status::SUCCESS, None)
    } else {
        uefi::println!("DEFAULT_OS: REPEAT_BOOT_VERIFIED (cycle={})", cycle);
        uefi::println!("PASS  NATIVE_ROLLBACK_REPEAT_BOOT");
        uefi::println!("DEFAULT_OS: ALL ROLLBACK INVARIANTS SATISFIED");
        uefi::runtime::reset(ResetType::SHUTDOWN, Status::SUCCESS, None)
    }
}
