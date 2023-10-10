use crate::ArmEmu;

#[test]
pub fn test() {
    let ops = vec![
        0b1110_1011_0000_0000_0000_0000_1111_1111u32, //BL
    ];
    let reg = vec![];
    let emu = ArmEmu::new(ops);
    emu.run(&reg);
}