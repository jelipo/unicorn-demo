use unicorn_engine::RegisterARM::{R0, R1, R2, R3, R4, R5};

use crate::ArmEmu;

#[test]
pub fn test() {
    let ops = vec![
        0b0000_0001_0010_1111_1111_1111_0001_0011u32, //BX
    ];
    let reg = vec![
        (R0, 0x128),
        (R1, 0x128),
        (R2, 0x128),
        (R3, 0x128),
        (R4, 0x128),
        (R5, 0x128),
    ];

    let emu = ArmEmu::new(ops);
    emu.run(&reg);
}