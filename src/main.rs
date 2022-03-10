mod run;

use std::borrow::{Borrow, BorrowMut};
use std::fs::File;

use unicorn_engine::{RegisterARM, SECOND_SCALE, Unicorn};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};
use crate::run::ArmEmu;

fn main() {
    let ops = vec![
        0b0000_0001_0010_1111_1111_1111_0001_0001u32, //BX,
        0b0000_0001_0010_1111_1111_1111_0001_0011u32, //BX
    ];
    let reg = vec![
        (RegisterARM::R0, 0x1008),
        (RegisterARM::R1, 0x1008),
        (RegisterARM::R2, 0x1008),
        (RegisterARM::R3, 0x1008),
        (RegisterARM::R4, 0x1008),
        (RegisterARM::R5, 0x1008),
    ];

    let emu = ArmEmu::new(ops);
    emu.run(&reg);
}

