use unicorn_engine::{RegisterARM, SECOND_SCALE, Unicorn};
use unicorn_engine::RegisterARM::{LR, R0, R1, R10, R11, R12, R2, R3, R4, R5, R6, R7, R8, R9};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};

pub struct ArmEmu {
    arm_op: Vec<u32>,
}

impl ArmEmu {
    pub fn new(arm_op: Vec<u32>) -> ArmEmu {
        ArmEmu {
            arm_op
        }
    }

    pub fn run(self, set_regs: &[(RegisterARM, u32)]) {
        let mut unicorn = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN).unwrap();
        let emu = &mut unicorn;
        let addr_start = 0x0;
        emu.mem_map(addr_start, 0x4000, Permission::ALL).unwrap();
        let mut addr = addr_start;
        for op in &self.arm_op {
            let op_bytes = op.to_le_bytes();
            emu.mem_write(addr, &op_bytes).unwrap();
            addr += 4;
        }
        for (arm_reg, value) in set_regs {
            emu.reg_write(*arm_reg, *value as u64).unwrap();
        }
        let op_size = self.arm_op.len();

        print_emuinfo(emu);
        if let Err(e) = emu.emu_start(addr_start, addr_start + (op_size * 4) as u64, 10 * SECOND_SCALE, op_size) {
            println!("emu get a error:{:?}", e);
        }
        print_emuinfo(emu);
    }
}

fn print_emuinfo(emu: &mut Unicorn<()>) {
    println!(
        r"-----------------
R0 :{}  R1 :{}  R2 :{}  R3 :{}
R4 :{}  R5 :{}  R6 :{}  R7 :{}
R8 :{}  R9 :{}  R10:{}  R11:{}
R12:{}  R13:{}  LR :{}
PC  : {}    SP : {}
CPSR: {}
      NZCV_    _    _    _    _    _IFT _
-----------------
",
        reg_str(emu, R0), reg_str(emu, R1), reg_str(emu, R2), reg_str(emu, R3),
        reg_str(emu, R4), reg_str(emu, R5), reg_str(emu, R6), reg_str(emu, R7),
        reg_str(emu, R8), reg_str(emu, R9), reg_str(emu, R10), reg_str(emu, R11),
        reg_str(emu, R12), reg_str(emu, R12), reg_str(emu, LR),
        fmt_u32(emu.pc_read().unwrap() as u32), reg_str(emu, RegisterARM::SP),
        reg_str(emu, RegisterARM::CPSR),
    );
}

fn reg_str(emu: &mut Unicorn<()>, reg: RegisterARM) -> String {
    fmt_u32(read_reg(emu, reg))
}

fn read_reg(emu: &mut Unicorn<()>, reg: RegisterARM) -> u32 {
    emu.reg_read(reg).unwrap() as u32
}

fn fmt_u32(num: u32) -> String {
    let string = format!("{:032b}", num);
    let bytes = string.as_bytes();
    let mut new_bytes = vec![95u8; 39];
    new_bytes[0..4].clone_from_slice(&bytes[0..4]);
    new_bytes[5..9].clone_from_slice(&bytes[4..8]);
    new_bytes[10..14].clone_from_slice(&bytes[8..12]);
    new_bytes[15..19].clone_from_slice(&bytes[12..16]);
    new_bytes[20..24].clone_from_slice(&bytes[16..20]);
    new_bytes[25..29].clone_from_slice(&bytes[20..24]);
    new_bytes[30..34].clone_from_slice(&bytes[24..28]);
    new_bytes[35..39].clone_from_slice(&bytes[28..32]);
    String::from_utf8_lossy(&new_bytes).to_string()
}