use unicorn_engine::RegisterARM;

use crate::run::ArmEmu;

mod run;
mod op;


fn main() {
    let ops = vec![
        0b0000_0001_0010_1111_1111_1111_0001_0010u32, //BX,
    ];
    let reg = vec![
        (RegisterARM::R0, 0x3900),
        (RegisterARM::R1, 0x3900),
        (RegisterARM::R2, 0x3900),
        (RegisterARM::R3, 0x3900),
        (RegisterARM::R4, 0x3900),
        (RegisterARM::R5, 0x3900),
    ];

    let emu = ArmEmu::new(ops);
    emu.run(&reg);
}

