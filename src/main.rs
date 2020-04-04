/*
 * x86-64 debugger
 * x86 -> x86 emulator with JIT
 * debug statements can be JIT'd inline
 */

use std::path::PathBuf;
use std::collections::HashMap;
use iced_x86::{Decoder, DecoderOptions, BlockEncoder, BlockEncoderOptions, Instruction, InstructionBlock, OpKind, FlowControl};

struct CodeRegionAllocator {
    _code_pages: mmap::MemoryMap,
    next_code_addr: u64,
}

impl CodeRegionAllocator {
    const LOCAL_MAX_SIZE: usize = 0x4000_0000; // half of signed int32 max
    const ADDR_BASE: u64 = 0x1_0000_0000;

    fn new() -> CodeRegionAllocator {
        let code_pages = mmap::MemoryMap::new(CodeRegionAllocator::LOCAL_MAX_SIZE, &[
            mmap::MapOption::MapReadable,
            mmap::MapOption::MapWritable,
            mmap::MapOption::MapExecutable,
            mmap::MapOption::MapAddr(CodeRegionAllocator::ADDR_BASE as *const u8),
        ]).unwrap();

        CodeRegionAllocator{
            next_code_addr: code_pages.data() as u64,
            _code_pages: code_pages,
        }
    }

    fn alloc_code(&mut self, size: usize) -> *mut u8 {
        let addr = self.next_code_addr;
        self.next_code_addr += size as u64;
        self.next_code_addr = (self.next_code_addr + 0xf) & !0xf;
        return addr as *mut u8;
    }
}

struct BasicBlock {
    source_address: u64,
    jit_address: u64,
    size: usize,
}

impl BasicBlock {
    fn contains(&self, address: u64) -> bool {
        return address >= self.source_address && address < self.source_address + self.size as u64;
    }

    fn call(&self) {
        let f: fn() = unsafe { std::mem::transmute(self.jit_address) };
        f();
    }
}

struct TranslatorState<'a> {
    binary: xmas_elf::ElfFile<'a>,

    bitness: u32,

    // quick reference to the text section
    text_section: xmas_elf::sections::SectionHeader<'a>,

    side_stack: mmap::MemoryMap,

    mapped_regions: Vec<mmap::MemoryMap>,

    allocator: CodeRegionAllocator,

    // map of program vaddr to JIT'd bb
    decoded_bbs: HashMap<u64, BasicBlock>,
}

impl<'a> TranslatorState<'a> {
    fn side_stack_rsp_loc(&self) -> u64 {
        return (self.side_stack.data() as u64) + self.side_stack.len() as u64 - 8;
    }

    fn new(contents: &'a Vec<u8>) -> Result<TranslatorState<'a>, &'static str> {
        let binary = match xmas_elf::ElfFile::new(contents) {
            Ok(b) => b,
            Err(_) => return Err("Failed to load ELF"),
        };

        let bitness = match binary.header.pt1.class.as_class() {
            xmas_elf::header::Class::ThirtyTwo => 32,
            xmas_elf::header::Class::SixtyFour => 64,
            _ => return Err("Invalid ELF class (bitness)"),
        };

        let text_section = match binary.find_section_by_name(".text") {
            Some(s) => s,
            None => return Err("Failed to look up .text section"),
        };

        let side_stack = mmap::MemoryMap::new(0x1000, &[
            mmap::MapOption::MapReadable,
            mmap::MapOption::MapWritable,
            mmap::MapOption::MapAddr(0x100_000 as *const u8), // pin this to a 32-bit mem addr so it can be xchg'd
        ]).unwrap();

        let ts = TranslatorState{
            binary,
            bitness,
            text_section,
            side_stack,
            mapped_regions: Vec::new(),
            allocator: CodeRegionAllocator::new(),
            decoded_bbs: HashMap::new(),
        };

        unsafe {
            // Write the address of the end of the stack region itself to where we're going to be
            // swapping RSP from/to
            (ts.side_stack_rsp_loc() as *mut u64).write(
                (ts.side_stack.data() as u64) + ts.side_stack.len() as u64 - 0x10
            );
        }

        return Ok(ts);
    }

    fn map_file(&mut self) -> Result<(), mmap::MapError> {
        for segment in self.binary.program_iter() {
            match segment.get_type() {
                Ok(xmas_elf::program::Type::Load) => (),
                _ => continue,
            }

            let map_addr = segment.virtual_addr() & !(segment.align() - 1);
            let mut map_ops = vec![
                mmap::MapOption::MapWritable,  // everything needs to be writable so we can copy data in
                mmap::MapOption::MapAddr(map_addr as *const u8),
            ];

            if segment.flags().is_read() {
                map_ops.push(mmap::MapOption::MapReadable);
            }
            if segment.flags().is_execute() {
                map_ops.push(mmap::MapOption::MapExecutable);
            }

            let alloc_result = mmap::MemoryMap::new(segment.mem_size() as usize, &map_ops);
            if alloc_result.is_err() {
                return Err(alloc_result.err().unwrap());
            }

            let allocation = alloc_result.unwrap();

            let bin_data = match segment {
                xmas_elf::program::ProgramHeader::Ph32(seg32) => seg32.raw_data(&self.binary),
                xmas_elf::program::ProgramHeader::Ph64(seg64) => seg64.raw_data(&self.binary),
            };

            let data_offset = segment.virtual_addr() - map_addr;

            unsafe {
                allocation.data().offset(data_offset as isize).copy_from(bin_data.as_ptr(), bin_data.len());
            }

            self.mapped_regions.push(allocation);
        }

        return Ok(());
    }

    fn is_decoded(&self, address: u64) -> bool {
        return self.get_bb_containing(address).is_some();
    }

    fn get_bb_containing(&self, address: u64) -> Option<&BasicBlock> {
        return self.decoded_bbs.values().find(|&bb| bb.contains(address));
    }

    fn encode_instrs(&self, block: InstructionBlock) -> Vec<u8> {
        return match BlockEncoder::encode(self.bitness, block, BlockEncoderOptions::NONE) {
            Err(err) => panic!("Couldn't encode instruction block: {}", err),
            Ok(result) => result.code_buffer,
        };
    }

    fn split_bb(&mut self, split_address: u64) -> &BasicBlock {
        let pre_bb_addr = self.get_bb_containing(split_address).unwrap().source_address;

        let post_bb = self.decode_at(split_address);
        let new_target_addr = post_bb.jit_address;

        let pre_bb = self.decoded_bbs.get_mut(&pre_bb_addr).unwrap();

        let split_offset = (pre_bb.source_address - split_address) as usize;
        let pre_bb_fallthrough_pc = pre_bb.jit_address + split_offset as u64;

        pre_bb.size = split_offset;
        let fallthrough_jump = self.encode_instrs(InstructionBlock::new(
            &[Instruction::with_branch(iced_x86::Code::Jmp_rel32_64, new_target_addr)],
            pre_bb_fallthrough_pc,
        ));

        unsafe {
            (pre_bb_fallthrough_pc as *mut u8).copy_from(fallthrough_jump.as_ptr(), fallthrough_jump.len());
        }

        return self.decoded_bbs.get(&split_address).unwrap();
    }

    fn generate_trampoline(&self, pc: u64, cb: fn(&mut [u64; 16])) -> Vec<Instruction> {
        let save_regs = [
            iced_x86::Register::RAX,
            iced_x86::Register::RBX,
            iced_x86::Register::RCX,
            iced_x86::Register::RDX,
            iced_x86::Register::RDI,
            iced_x86::Register::RSI,
            iced_x86::Register::RBP,
            iced_x86::Register::R8,
            iced_x86::Register::R9,
            iced_x86::Register::R10,
            iced_x86::Register::R11,
            iced_x86::Register::R12,
            iced_x86::Register::R13,
            iced_x86::Register::R14,
            iced_x86::Register::R15,
        ];

        let stack_swap = Instruction::with_mem_reg(
            iced_x86::Code::Xchg_rm64_r64,
            iced_x86::MemoryOperand::new(
                iced_x86::Register::None,
                iced_x86::Register::None,
                1,
                self.side_stack_rsp_loc() as i32,
                8,
                false,
                iced_x86::Register::None,
            ),
            iced_x86::Register::RSP,
        );

        let mut insns = vec![
            stack_swap,
        ];

        for reg in save_regs.iter() {
            insns.push(Instruction::with_reg(
                iced_x86::Code::Push_r64,
                *reg,
            ));
        }

        // push guest PC
        insns.extend(vec![
            Instruction::with_reg_u64(
                iced_x86::Code::Mov_r64_imm64,
                iced_x86::Register::RAX,
                pc,
            ),
            Instruction::with_reg(
                iced_x86::Code::Push_r64,
                iced_x86::Register::RAX,
            ),
        ]);

        insns.extend(vec![
            Instruction::with_reg_reg(
                iced_x86::Code::Mov_rm64_r64,
                iced_x86::Register::RDI,
                iced_x86::Register::RSP,
            ),
            Instruction::with_reg_u64(
                iced_x86::Code::Mov_r64_imm64,
                iced_x86::Register::RAX,
                cb as u64,
            ),
            // align stack - rust cbs will need it it 16-byte aligned for xmm stuff
            Instruction::with_reg_i32(
                iced_x86::Code::And_rm64_imm8,
                iced_x86::Register::RSP,
                -0x10,
            ),
            Instruction::with_reg(
                iced_x86::Code::Call_rm64,
                iced_x86::Register::RAX,
            ),
        ]);

        // add back over pc
        insns.extend(vec![
            Instruction::with_reg_i32(
                iced_x86::Code::Add_rm64_imm8,
                iced_x86::Register::RSP,
                8,
            ),
        ]);

        for reg in save_regs.iter().rev() {
            insns.push(Instruction::with_reg(
                iced_x86::Code::Pop_r64,
                *reg,
            ));
        }

        insns.push(stack_swap);

        return insns;
    }

    fn rewrite_instr(&mut self, instr: Instruction) -> (Vec<Instruction>, bool) {
        let mut mem_access_ops: Vec<u32> = Vec::with_capacity(5);

        for op_idx in 0..instr.op_count() {
            if instr.op_kind(op_idx) == OpKind::Memory && (
                    instr.memory_base() != iced_x86::Register::None || 
                    instr.memory_index() != iced_x86::Register::None) {
                mem_access_ops.push(op_idx);
            }
        }

        let is_non_branch_instr = match (instr.flow_control(), instr.code()) {
            (FlowControl::Next, _) => true,
            (_, iced_x86::Code::Syscall) => true,
            _ => false,
        };

        let mut instrs: Vec<Instruction> = Vec::new();

        let mut info_factory = iced_x86::InstructionInfoFactory::new();
        let info = info_factory.info(&instr);

        for mem_op_idx in mem_access_ops.iter() {
            // rewrite the mem load(s)/store(s)
            println!("Rewriting mem load/store in {} op {}", instr, mem_op_idx);
            match info.op_access(*mem_op_idx) {
                iced_x86::OpAccess::Write => (),  // TODO: check for SMC
                _ => (),
            }
            instrs.extend(self.generate_trampoline(instr.ip(), |regs: &mut [u64; 16]| {
                println!("regs: {:?}", regs);
            }));
        }

        instrs.push(instr);

        if is_non_branch_instr {
            if mem_access_ops.len() == 0 {
                // instr can be directly lifted
                println!("Lifting {} directly", instr);
            }

            return (instrs, true);
        }

        let (needs_translate_stub, branch_type, decode_next) = match (instr.code(), instr.flow_control()) {
            (_, FlowControl::UnconditionalBranch) => (false, iced_x86::Code::Jmp_rel32_64, false),
            (_, FlowControl::ConditionalBranch) => (false, instr.code(), true),
            (_, FlowControl::Call) => (false, iced_x86::Code::Call_rel32_64, false),
            _ => {
                panic!("Unhandled control flow change instruction {:?}", instr.flow_control());
            }
        };

        let guest_target = instr.near_branch_target();
        if let Some(bb) = self.decoded_bbs.get(&guest_target) {
            println!("Target of {} ({:#x}) already decoded, adding trampoline", instr, guest_target);
            instrs.push(Instruction::with_branch(branch_type, bb.jit_address));
        } else if self.is_decoded(guest_target) {
            // jump into existing BB, but not the beginning.
            // split the existing BB at the target point and re-decode
            let new_bb = self.split_bb(guest_target);
            instrs.push(Instruction::with_branch(branch_type, new_bb.jit_address));
        } else {
            // new code, preallocate a target code region and create the jump to it
            println!("Decoding target of {} ({:#x})", instr, guest_target);
            let target_bb = self.decode_at(guest_target);
            instrs.push(Instruction::with_branch(branch_type, target_bb.jit_address));
        }

        return (instrs, decode_next);
    }

    fn decode_at(&mut self, address: u64) -> &BasicBlock {
        println!("Decoding at {:#x}", address);

        let text: &[u8] = unsafe { std::slice::from_raw_parts(self.text_section.address() as *const u8, self.text_section.size() as usize) };
        let mut decoder = Decoder::new(self.bitness, text, DecoderOptions::NONE);
        decoder.set_position((address - self.text_section.address()) as usize);
        decoder.set_ip(address);

        let mut bb_instrs: Vec<Instruction> = Vec::new();

        loop {
            let instr = decoder.decode();
            if decoder.invalid_no_more_bytes() {
                break;
            }

            // If we've decoded down into an existing BB, setup a trampoline to it
            // and break out
            if let Some(existing_bb) = self.decoded_bbs.get(&instr.ip()) {
                bb_instrs.push(Instruction::with_branch(iced_x86::Code::Jmp_rel32_64, existing_bb.jit_address));
                break;
            }

            let (rewritten_instrs, decode_next) = self.rewrite_instr(instr);

            bb_instrs.extend(rewritten_instrs);

            if !decode_next {
                // This is the end of the BB
                break;
            }
        }

        let rewritten_bytes = self.encode_instrs(InstructionBlock::new(
            &bb_instrs,
            address,
        ));
        let new_code_region = self.allocator.alloc_code(rewritten_bytes.len());

        unsafe {
            new_code_region.copy_from(rewritten_bytes.as_ptr(), rewritten_bytes.len());
        }

        let bb = BasicBlock{
            source_address: address,
            jit_address: new_code_region as u64,
            size: rewritten_bytes.len(),
        };

        return self.decoded_bbs.entry(address).or_insert(bb);
    }

    fn decode(&mut self) {
        self.decode_at(self.binary.header.pt2.entry_point());
    }

    fn run(&self) {
        let entry_bb = self.decoded_bbs.get(&self.binary.header.pt2.entry_point()).unwrap();
        entry_bb.call();
    }
}

fn main() {
    let args = clap::App::new("DBIdbg")
        .version("0.0.0")
        .author("Nick Gregory <kallsyms>")
        .about("Fast, programmable Linux debugger")
        .arg(clap::Arg::with_name("file")
                 .help("Executable to debug")
                 .required(true)
                 .index(1))
        .get_matches();

    let bin_path = PathBuf::from(args.value_of("file").unwrap());
    let contents = std::fs::read(bin_path).expect("Unable to read file");

    let mut translator: TranslatorState = TranslatorState::new(&contents).unwrap();
    let map_result = translator.map_file();
    if map_result.is_err() {
        panic!(map_result.err().unwrap());
    }

    println!("Decoding from entrypoint");
    translator.decode();

    // debug output all of our rewritten blocks
    println!("Rewritten entrypoint:");
    for (_, bb) in translator.decoded_bbs.iter() {
        let code: &[u8] = unsafe { std::slice::from_raw_parts(bb.jit_address as *const u8, bb.size) };
        let mut decoder = Decoder::new(translator.bitness, code, DecoderOptions::NONE);
        decoder.set_ip(bb.jit_address);

        while decoder.can_decode() {
            let instr = decoder.decode();
            println!("{}", instr);
        }
    }

    translator.run();
}
