use unicorn_engine::{RegisterARM, SECOND_SCALE, Unicorn};
use unicorn_engine::RegisterARM::{LR, R0, R1, R10, R11, R12, R2, R3, R4, R5, R6, R7, R8, R9};
use unicorn_engine::RegisterX86::R14;
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
R0 :{:032b}  R1 :{:032b}  R2 :{:032b}  R3 :{:032b}
R4 :{:032b}  R5 :{:032b}  R6 :{:032b}  R7 :{:032b}
R8 :{:032b}  R9 :{:032b}  R10:{:032b}  R11:{:032b}
R12:{:032b}  R13:{:032b}  LR :{:032b}
PC  : {:032b}
CSPR: {:032b}
SP  : {:032b}
-----------------
",
        read_reg(emu, R0), read_reg(emu, R1), read_reg(emu, R2), read_reg(emu, R3),
        read_reg(emu, R4), read_reg(emu, R5), read_reg(emu, R6), read_reg(emu, R7),
        read_reg(emu, R8), read_reg(emu, R9), read_reg(emu, R10), read_reg(emu, R11),
        read_reg(emu, R12), read_reg(emu, R12), read_reg(emu, LR),
        emu.pc_read().unwrap(), read_reg(emu, RegisterARM::CPSR), read_reg(emu, RegisterARM::SP)
    );
}

fn read_reg(emu: &mut Unicorn<()>, reg: RegisterARM) -> u32 {
    emu.reg_read(reg).unwrap() as u32
}