use unicorn_engine::RegisterARM;
use crate::ArmEmu;

#[test]
pub fn test_data_processor() {
    let ops = vec![
        0b0000_0010_1000_0001_0010_0010_0000_1111u32,
    ];
    let reg = vec![
        (RegisterARM::R1, 0b0),
        (RegisterARM::R2, 0b0),
    ];
    let emu = ArmEmu::new(ops);
    emu.run(&reg);
}

#[test]
pub fn test_data_processor2() {
    let ops = vec![
        0b0000_0000_1000_0001_0010_0100_0001_0011u32,
    ];
    let reg = vec![
        (RegisterARM::R1, 0b0),
        (RegisterARM::R2, 0b0),
        (RegisterARM::R3, 0b1111_1111_1111_1111_1111_1111_1111_1111),
        (RegisterARM::R4, 0b1111_1111_1111_1111_1111_1111_0000_0010),
    ];
    // ( R3_val << R4_val)
    let emu = ArmEmu::new(ops);
    emu.run(&reg);
}