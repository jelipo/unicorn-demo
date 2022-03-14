use unicorn_engine::RegisterARM;
use crate::ArmEmu;

#[test]
pub fn test_data_processor() {
    let ops = vec![
        0b0000_0010_1000_0001_0010_0010_0000_1111u32, //BX
    ];
    let reg = vec![
        (RegisterARM::R1, 0b0),
        (RegisterARM::R2, 0b0)

    ];
    let emu = ArmEmu::new(ops);
    emu.run(&reg);
}

#[test]
pub fn custom_demo() {
    let i = 0b0011_1111u32;
    println!("{:b}", i.rotate_right(28));
}