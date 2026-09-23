#![no_std]
#![no_main]

use uefi::prelude::*;

#[entry]
fn main() -> Status {
    uefi::println!("{}", aienos_boot::FIRMWARE_BANNER);
    uefi::println!("firmware services: active");
    uefi::println!("kernel handoff: not implemented");
    Status::SUCCESS
}
