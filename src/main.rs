use std::borrow::{Borrow, BorrowMut};
use std::fs::File;

use unicorn_engine::{RegisterARM, SECOND_SCALE, Unicorn};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};

fn main() {
    let test1 = test("dasda".to_string());


    let arm_code32: Vec<u8> = vec![0x17, 0x00, 0x40, 0xe2]; // sub r0, #23

    let mut unicorn = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN).expect("failed to initialize Unicorn instance");
    let emu = unicorn.borrow_mut();
    emu.mem_map(0x1000, 0x4000, Permission::ALL).expect("failed to map code page");
    emu.mem_write(0x1000, &arm_code32).expect("failed to write instructions");

    emu.reg_write(RegisterARM::R0, 123).expect("failed write R0");
    emu.reg_write(RegisterARM::R5, 1337).expect("failed write R5");

    let _ = emu.emu_start(0x1000, (0x1000 + arm_code32.len()) as u64, 10 * SECOND_SCALE, 1000);
    assert_eq!(emu.reg_read(RegisterARM::R0), Ok(100));
    assert_eq!(emu.reg_read(RegisterARM::R5), Ok(1337));
}

fn test<D: AsRef<[u8]>>(data: D) {
    let string = String::new();
    string.borrow()
    let data_ref = data.borrow();
    Borrow::borrow()
    let x1 = data_ref[0];
}