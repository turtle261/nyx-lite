pub use iced_x86::OpAccess;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, InstructionInfoFactory,
    NasmFormatter,
};
const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;

// slightly modifed from the iced_x86 example - note this function is incredibly poorly done from a performance perspective!
pub fn disassemble(addr: u64, bytes: &[u8]) -> Vec<String> {
    let wordsize = 64;
    let mut decoder = Decoder::with_ip(wordsize, bytes, addr, DecoderOptions::NONE);

    // Formatters: Masm*, Nasm*, Gas* (AT&T) and Intel* (XED).
    // For fastest code, see `SpecializedFormatter` which is ~3.3x faster. Use it if formatting
    // speed is more important than being able to re-assemble formatted instructions.
    let mut formatter = NasmFormatter::new();

    // Change some options, there are many more
    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);

    // Initialize this outside the loop because decode_out() writes to every field
    let mut instruction = Instruction::default();

    // The decoder also implements Iterator/IntoIterator so you could use a for loop:
    //      for instruction in &mut decoder { /* ... */ }
    // or collect():
    //      let instructions: Vec<_> = decoder.into_iter().collect();
    // but can_decode()/decode_out() is a little faster:
    let mut res = vec![];
    while decoder.can_decode() {
        // There's also a decode() method that returns an instruction but that also
        // means it copies an instruction (40 bytes):
        //     instruction = decoder.decode();
        decoder.decode_out(&mut instruction);

        let mut output = String::new();
        formatter.format(&instruction, &mut output);

        // Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
        let mut prefix = format!("{:016X} ", instruction.ip());
        let start_index = (instruction.ip() - addr) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
        for b in instr_bytes.iter() {
            prefix.push_str(&format!("{:02X}", b));
        }
        if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
            for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                prefix.push_str("  ");
            }
        }
        prefix.push_str(&output);
        res.push(prefix);
    }
    return res;
}

pub fn disassemble_print(addr: u64, bytes: &[u8]) {
    for line in disassemble(addr, bytes) {
        println!("{}", line);
    }
}

use iced_x86::Register;
use kvm_bindings::{kvm_regs, kvm_sregs};

fn get_register_value(reg: Register, regs: &kvm_regs, sregs: &kvm_sregs) -> u64 {
    match reg {
        Register::None => 0,
        // 64-bit general purpose registers
        Register::RAX => regs.rax,
        Register::RBX => regs.rbx,
        Register::RCX => regs.rcx,
        Register::RDX => regs.rdx,
        Register::RSI => regs.rsi,
        Register::RDI => regs.rdi,
        Register::RBP => regs.rbp,
        Register::RSP => regs.rsp,
        Register::R8 => regs.r8,
        Register::R9 => regs.r9,
        Register::R10 => regs.r10,
        Register::R11 => regs.r11,
        Register::R12 => regs.r12,
        Register::R13 => regs.r13,
        Register::R14 => regs.r14,
        Register::R15 => regs.r15,
        Register::RIP => regs.rip,

        // 32-bit variants
        Register::EAX => regs.rax as u32 as u64,
        Register::EBX => regs.rbx as u32 as u64,
        Register::ECX => regs.rcx as u32 as u64,
        Register::EDX => regs.rdx as u32 as u64,
        Register::ESI => regs.rsi as u32 as u64,
        Register::EDI => regs.rdi as u32 as u64,
        Register::EBP => regs.rbp as u32 as u64,
        Register::ESP => regs.rsp as u32 as u64,
        Register::R8D => regs.r8 as u32 as u64,
        Register::R9D => regs.r9 as u32 as u64,
        Register::R10D => regs.r10 as u32 as u64,
        Register::R11D => regs.r11 as u32 as u64,
        Register::R12D => regs.r12 as u32 as u64,
        Register::R13D => regs.r13 as u32 as u64,
        Register::R14D => regs.r14 as u32 as u64,
        Register::R15D => regs.r15 as u32 as u64,
        Register::EIP => regs.rip as u32 as u64,

        // 16-bit variants
        Register::AX => (regs.rax & 0xFFFF) as u64,
        Register::BX => (regs.rbx & 0xFFFF) as u64,
        Register::CX => (regs.rcx & 0xFFFF) as u64,
        Register::DX => (regs.rdx & 0xFFFF) as u64,
        Register::SI => (regs.rsi & 0xFFFF) as u64,
        Register::DI => (regs.rdi & 0xFFFF) as u64,
        Register::BP => (regs.rbp & 0xFFFF) as u64,
        Register::SP => (regs.rsp & 0xFFFF) as u64,
        Register::R8W => (regs.r8 & 0xFFFF) as u64,
        Register::R9W => (regs.r9 & 0xFFFF) as u64,
        Register::R10W => (regs.r10 & 0xFFFF) as u64,
        Register::R11W => (regs.r11 & 0xFFFF) as u64,
        Register::R12W => (regs.r12 & 0xFFFF) as u64,
        Register::R13W => (regs.r13 & 0xFFFF) as u64,
        Register::R14W => (regs.r14 & 0xFFFF) as u64,
        Register::R15W => (regs.r15 & 0xFFFF) as u64,

        // 8-bit variants (low)
        Register::AL => (regs.rax & 0xFF) as u64,
        Register::BL => (regs.rbx & 0xFF) as u64,
        Register::CL => (regs.rcx & 0xFF) as u64,
        Register::DL => (regs.rdx & 0xFF) as u64,
        Register::SIL => (regs.rsi & 0xFF) as u64,
        Register::DIL => (regs.rdi & 0xFF) as u64,
        Register::BPL => (regs.rbp & 0xFF) as u64,
        Register::SPL => (regs.rsp & 0xFF) as u64,
        Register::R8L => (regs.r8 & 0xFF) as u64,
        Register::R9L => (regs.r9 & 0xFF) as u64,
        Register::R10L => (regs.r10 & 0xFF) as u64,
        Register::R11L => (regs.r11 & 0xFF) as u64,
        Register::R12L => (regs.r12 & 0xFF) as u64,
        Register::R13L => (regs.r13 & 0xFF) as u64,
        Register::R14L => (regs.r14 & 0xFF) as u64,
        Register::R15L => (regs.r15 & 0xFF) as u64,

        // 8-bit variants (high)
        Register::AH => ((regs.rax >> 8) & 0xFF) as u64,
        Register::BH => ((regs.rbx >> 8) & 0xFF) as u64,
        Register::CH => ((regs.rcx >> 8) & 0xFF) as u64,
        Register::DH => ((regs.rdx >> 8) & 0xFF) as u64,
        // Segment registers
        Register::CS => sregs.cs.base,
        Register::DS => sregs.ds.base,
        Register::SS => sregs.ss.base,
        Register::ES => sregs.es.base,
        Register::FS => sregs.fs.base,
        Register::GS => sregs.gs.base,

        // Default case for unsupported registers
        reg => panic!("unhandled memory access with register {:?}", reg),
    }
}

// Assume this exists in your code
pub fn get_memory_accesses(
    instr: &Instruction,
    regs: &kvm_regs,
    sregs: &kvm_sregs,
) -> Vec<(u64, OpAccess)> {
    let mut factory = InstructionInfoFactory::new();
    let info = factory.info(instr);
    let page_size = crate::mem::PAGE_SIZE;
    let page_mask = !(page_size - 1);
    let mut accesses = Vec::new();
    for mem in info.used_memory().iter() {
        let base = get_register_value(mem.base(), regs, sregs) as i128;
        let index = get_register_value(mem.index(), regs, sregs) as i128;
        let scale = mem.scale() as i128;
        let displacement = mem.displacement() as i128;
        let segment = get_register_value(mem.segment(), regs, sregs) as i128;

        let addr = (segment + base + (index * scale) + displacement) as u64;
        let access = mem.access();
        accesses.push((addr, access));

        let size_bytes = mem.memory_size().size();
        if size_bytes == 0 {
            continue;
        }
        let end = addr.saturating_add(size_bytes as u64 - 1);
        let mut next_page = (addr & page_mask).saturating_add(page_size);
        while next_page <= end {
            accesses.push((next_page, access));
            next_page = next_page.saturating_add(page_size);
        }
    }
    accesses
}

pub fn disassemble_memory_accesses(
    data: &[u8],
    regs: &kvm_regs,
    sregs: &kvm_sregs,
) -> Vec<(u64, OpAccess)> {
    let mut decoder = Decoder::with_ip(64, data, regs.rip, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    if decoder.can_decode() {
        decoder.decode_out(&mut instruction);
    } else {
        return vec![];
    }
    return get_memory_accesses(&instruction, regs, sregs);
}

pub fn is_control_flow(addr: u64, bytes: &[u8]) -> bool {
    let mut decoder = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    if !decoder.can_decode() {
        return false;
    }
    decoder.decode_out(&mut instruction);
    !matches!(instruction.flow_control(), FlowControl::Next)
}
