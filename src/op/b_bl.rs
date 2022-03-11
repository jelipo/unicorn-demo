use unicorn_engine::RegisterARM::{R0, R1, R2, R3, R4, R5};

use crate::ArmEmu;

#[test]
pub fn test() {
    let ops = vec![
        0b0000_1011_1000_0000_0000_0000_0000_0001u32, //BX
    ];
    let reg = vec![];
    let emu = ArmEmu::new(ops);
    emu.run(&reg);
}