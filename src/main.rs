mod elf;
use elf::*;
use capstone::prelude::*;

fn main() {
    let mut elf = ELF::new("test");
    match elf.analyse() {
        Ok(_) => println!("elf analyse finished"),
        Err(e) => {
            eprintln!("{}", e);
        }
    }
    //let symbol = elf.get_symbol();

    elf.analyse_sections();
    elf.analyse_symbol_name();
    elf.analyse_excutable_code();

    let symbol = elf.get_symbol();
    let section = elf.get_section();

    //elf.analyse_excutable_code();
    /*
    let (code, address) = match elf.get_excutable_segment_bytes_as_ref() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{}", e);
            panic!("error");
        }
    };
    */

    let code_block = elf.get_code_blocks();
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode32)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("failed to initialize capstone");

    let mut code_block: Vec<_> = code_block.into_iter().collect();
    code_block = code_block[..].to_vec();
    code_block.sort_by_key(|x| x.0);

    let mut instructions = Vec::new();
    for code in code_block {
        let insns = cs.disasm_all(&code.1, *code.0 as u64).expect("failed to disassemble");
        for insn in insns.as_ref() {
            instructions.push(insn.clone());

            /* 
            let detail = cs.insn_detail(&insn).expect("failed to get instruction detail");
            let arch_detail = detail.arch_detail();
            let oprands = arch_detail.operands();
            
            //println!("{}", insn);
            if let Some(op) = &insn.mnemonic() {
                if let Some(operands) = &insn.op_str() {
                    if let Some(section) = &section.get(&(insn.address() as usize)) {
                        println!("\n{}: ", section);
                    }
                    if let Some(label) = &symbol.get(&(insn.address() as usize)) {
                        println!("\n0x{:<08x} <{}>: ", insn.address(), label);
                    }

                    if(detail.groups().iter().any(|&x| x == InsnGroupId(2))) {
                        let call_address = &oprands[0];
                        if let arch::ArchOperand::X86Operand(oprand) = call_address 
                        { 
                            if let arch::x86::X86OperandType::Imm(addr) = oprand.op_type
                            {
                                if let Some(label) = symbol.get(&(addr as usize))
                                {
                                    println!("\t0x{:<08x} {:<8} {}<{}>", insn.address(), op, operands, label); 
                                }
                            }
                        }

                    } else {
                        println!("\t0x{:<08x} {:<8} {}", insn.address(), op, operands); 
                    }
                }
            }
            */
        }
    }

    let mut i = 0;
    
    for insn in &instructions {
        //println!("{:x}", insn.address());
        //println!("{}:{}", instructions.len(), i);    
        i += 1;
        let detail = cs.insn_detail(&insn).expect("failed to get instruction detail");
        let arch_detail = detail.arch_detail();
        let operands = arch_detail.operands();

        if let Some(op) = &insn.mnemonic() {
            if let Some(oprands) = &insn.op_str() {
                if let Some(section) = section.get(&(insn.address() as usize)) {
                    println!("\n{}: ", section);
                }
                if let Some(label) = symbol.get(&(insn.address() as usize)) {
                    println!("\n0x{:<08x} <{}>:", insn.address(), label);
                }
                if detail.groups().iter().any(|&x| x == InsnGroupId(2)) {
                    let call_address = &operands[0];
                    if let arch::ArchOperand::X86Operand(oprand) = call_address 
                    { 
                        if let arch::x86::X86OperandType::Imm(addr) = oprand.op_type
                        {
                            if let Some(label) = symbol.get(&(addr as usize))
                            {
                                println!("\t0x{:<08x} {:<8} {}<{}>", insn.address(), op, oprands, label); 
                            }
                        }
                    }

                } else {
                    println!("\t0x{:<08x} {:<8} {}", insn.address(), op, oprands); 
                }
            }
        }
    }

    /*
    for insn in instructions {
        let detail = cs.insn_detail(&insn).expect("failed to get instruction detail");
        let arch_detail = detail.arch_detail();
        let oprands = arch_detail.operands();
    
        //println!("{}", insn);
        //println!("{:?}", insn.id());
        if let Some(op) = &insn.mnemonic() {
            if let Some(oprands) = &insn.op_str() {
                if let Some(section) = section.get(&(insn.address() as usize)) {
                    println!("\n{}: ", section);
                }
                if let Some(label) = symbol.get(&(insn.address() as usize)) {
                    println!("\n0x{:<08x} <{}>:", insn.address(), label);
                }
                println!("\t0x{:<08x} {:<8}{}", insn.address(), op, oprands);
            }
        }
    }
    */
}

fn group_names(cs: &Capstone, regs: &[InsnGroupId]) -> Vec<String> {
    let names: Vec<String> = regs.iter().map(|&x| cs.group_name(x).unwrap()).collect();
    names
}
