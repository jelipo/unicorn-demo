use std::borrow::{Borrow, BorrowMut};
use std::fs::File;

use unicorn_engine::{RegisterARM, SECOND_SCALE, Unicorn};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};

fn main() {
    let arm_code32 = 0b0000_0001_0010_1111_1111_1111_0001_0010u32.to_le_bytes();

    let mut unicorn = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN).expect("failed to initialize Unicorn instance");
    let emu = &mut unicorn;
    emu.mem_map(0x1000, 0x4000, Permission::ALL).expect("failed to map code page");

    emu.mem_write(0x1000, &arm_code32).unwrap();

    emu.reg_write(RegisterARM::R2, 0x1100).unwrap();

    let _ = emu.emu_start(0x1000, (0x1000 + arm_code32.len()) as u64, 10 * SECOND_SCALE, 1);


    let i = emu.reg_read(RegisterARM::R15).unwrap();
    println!("{:x}", i);
}

