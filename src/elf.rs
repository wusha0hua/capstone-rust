use capstone::prelude::*;
use std::{io::Read, fs::File, convert::*, collections::HashMap};

#[derive(Debug, Clone)]
pub struct ELF {
    elf_bytes: Vec<u8>,
    elf_header: Elf32Ehdr,
    section_header_tables: Vec<Elf32Shdr>,
    section_bytes: HashMap<usize, Vec<u8>>,
    section_index_to_name: HashMap<usize, String>,
    section_addr_to_name: HashMap<usize, String>,
    program_header_tables: Vec<Elf32Phdr>,

    symbol_tables: Vec::<Elf32Sym>,
    symbol_addr_to_name: HashMap<usize, String>,
    symbol_index: usize,

    dynsym_tables: Vec<Elf32Sym>,
    dynsym_addr_to_name: HashMap<usize, String>,
    dynsym_index: usize,


    strtab_bytes: HashMap<usize, Vec<u8>>,

    code_block: HashMap<usize, Vec<u8>>,

    base: usize,
}

#[derive(Debug, Clone)]
pub struct Code {
    address: usize,
    label: Option<String>,
    code: Vec<u8>,
}

impl ELF {
    pub fn new(file_path: &str) -> Self {
        let mut fin = File::open(file_path).unwrap();
        let mut elf_bytes = Vec::<u8>::new();
        
        fin.read_to_end(&mut elf_bytes).unwrap();
        ELF {
            elf_bytes,
            elf_header: Elf32Ehdr::new(),
            section_header_tables: Vec::new(),
            section_bytes: HashMap::new(),
            section_index_to_name: HashMap::new(),
            section_addr_to_name: HashMap::new(),
            program_header_tables: Vec::new(),

            symbol_tables: Vec::new(),
            symbol_addr_to_name: HashMap::new(),
            symbol_index: 0,

            dynsym_tables: Vec::new(),
            dynsym_addr_to_name: HashMap::new(),
            dynsym_index: 0,

            strtab_bytes: HashMap::new(),

            code_block: HashMap::new(),

            base: 0,
        }
    } 

    pub fn analyse(&mut self) -> Result<u8, &str> {
        self.elf_header = Elf32Ehdr::from(self.elf_bytes.as_slice());   
        //println!("{:#?}", self.elf_header);
        ELF::check_elf_header(&self.elf_header)?;
        
        if self.elf_bytes.len() < self.elf_header.e_shoff as usize || self.elf_bytes.len() < self.elf_header.e_shoff as usize+ self.elf_header.e_shentsize as usize * self.elf_header.e_shnum as usize {
            return Err("failed to get section header table");
        }

        for i in 0..self.elf_header.e_shnum {
            let start = self.elf_header.e_shoff as usize + i as usize * self.elf_header.e_shentsize as usize;
            let end = start + self.elf_header.e_shentsize as usize;
            self.section_header_tables.push(Elf32Shdr::from(&self.elf_bytes[start..end])); 
        }

        /*
        for i in 0..self.elf_header.e_shnum as usize {
            println!("{:#?}", self.section_header_tables[i]);
        }
        */

        self.base = self.elf_header.e_entry as usize;
        
        for i in 0..self.elf_header.e_shnum as usize {
            let section = &self.section_header_tables[i];
            let offset = section.sh_offset as usize;
            let size = section.sh_size as usize;
            
            self.section_bytes.insert(offset, (&self.elf_bytes[offset..offset+size]).to_vec());
        }

        let shstrndx = self.elf_header.e_shstrndx;
        let shstrtab = self.section_header_tables[shstrndx as usize].clone();
        let shstr_offset = shstrtab.sh_offset as usize;
        let shstr_size = shstrtab.sh_size as usize;
        let shstrtab_bytes = (&self.elf_bytes[shstr_offset..shstr_offset + shstr_size]).to_vec();
        for i in 0..self.elf_header.e_shnum as usize {
            let section = &self.section_header_tables[i];
            let offset = section.sh_offset as usize;
            let name_index = section.sh_name as usize;
            let mut name_str = String::new();
            let mut index = name_index;
            while shstrtab_bytes[index] != 0 {
                name_str.push(shstrtab_bytes[index] as char);
                index += 1;
            }
            self.section_index_to_name.insert(name_index, name_str.clone());
            self.section_addr_to_name.insert(offset, name_str);
        }

        let phentsize = self.elf_header.e_phentsize as usize;
        let phoff = self.elf_header.e_phoff as usize;
        for i in 0..self.elf_header.e_phnum as usize {
            let start = phoff + i * phentsize;
            let end = start + (i + 1) * phentsize;
            self.program_header_tables.push(Elf32Phdr::from(&self.elf_bytes[start..end]));
        }

        Ok(0)
    }

    pub fn analyse_sections(&mut self) {
        for i in 0..self.elf_header.e_shnum as usize{
            let section = &self.section_header_tables[i];
            let name = section.sh_name as usize;
            let size = section.sh_size as usize;
            let offset = section.sh_offset as usize;
            let vaddr = section.sh_addr as usize;
            match section.sh_type as usize{
                SHT_STRTAB => {
                    let bytes = &self.elf_bytes[offset..offset + size].to_vec();
                    self.strtab_bytes.insert(i, bytes.clone());
                    if &self.section_index_to_name[&name] == ".strtab" {
                        self.symbol_index = i;
                    } else if &self.section_index_to_name[&name] == ".dynstr" {
                        self.dynsym_index = i;
                    }
                }

                SHT_SYMTAB => {
                    let bytes = &self.elf_bytes[offset..offset + size].to_vec();
                    let num = size / ELF32_SYM_TABLE_SIZE;
                    for i in 0..num {
                        let start = i * ELF32_SYM_TABLE_SIZE;
                        let end = start + ELF32_SYM_TABLE_SIZE;
                        let sym_bytes = &bytes[start..end];
                        self.symbol_tables.push(Elf32Sym::from(sym_bytes));
                        //println!("{}", self.symbol_tables[i].st_shndx)
                    }

                }

                SHT_DYNSYM => {
                    let bytes = &self.elf_bytes[offset..offset + size].to_vec();
                    let num = size / ELF32_SYM_TABLE_SIZE;
                    for i in 0..num {
                        let start = i * ELF32_SYM_TABLE_SIZE;
                        let end = start + ELF32_SYM_TABLE_SIZE;
                        let sym_bytes = &bytes[start..end];
                        self.dynsym_tables.push(Elf32Sym::from(sym_bytes));
                    }
                }

                _ => {}
            }
        }
    }

    pub fn analyse_symbol_name(&mut self) {
        let bytes = &self.strtab_bytes[&self.symbol_index];
        for sym in &self.symbol_tables {
            let name_index = sym.st_name;
            let vaddr = sym.st_value as usize;
            let mut name_str = String::new();
            let mut i = name_index as usize;
            while bytes[i] != 0 {
                name_str.push(bytes[i] as char);
                i += 1;
            }
            self.symbol_addr_to_name.insert(vaddr, name_str);
        } 

        let bytes = &self.strtab_bytes[&self.dynsym_index];
        for dynsym in &self.dynsym_tables {
            let name_index = dynsym.st_name;
            let vaddr = dynsym.st_value as usize;
            let mut name_str = String::new();
            let mut i = name_index as usize;
            while bytes[i] != 0 {
                name_str.push(bytes[i] as char);
                i += 1;
            }
            println!("{}: {} {}",name_index, name_str, vaddr);
            self.dynsym_addr_to_name.insert(vaddr, name_str);
        }
        println!("{:#?}", self.dynsym_addr_to_name);
    }

    pub fn analyse_excutable_code(&mut self) {
        for segment in &self.program_header_tables {
            if segment.p_type as usize == PT_LOAD && (segment.p_flags as usize & PF_X) != 0 {
                let offset = segment.p_offset as usize;
                let size = segment.p_filesz as usize;
                for section in &self.section_header_tables {
                    let shoff = section.sh_offset as usize;
                    let shsize = section.sh_size as usize;
                    let shflag = section.sh_offset as usize;
                    //println!("{} {} {} {} {}", offset, size, shoff, shsize, shflag & (1 << 2));
                    if shoff >= offset && shoff < offset + size {
                        let mut code = Vec::<u8>::new();
                        code = self.elf_bytes[shoff..shoff + shsize].to_vec();
                        self.code_block.insert(shoff, code);
                    } 
                }
            } 
        }

    }

    pub fn get_base_address(&self) -> usize {
        self.base
    }

    pub fn get_symbol(&self) -> &HashMap<usize, String>{
        &self.symbol_addr_to_name
    }

    pub fn get_section(&self) -> &HashMap<usize, String> {
        &self.section_addr_to_name
    }

    pub fn get_code_blocks(&self) -> &HashMap<usize, Vec<u8>> {
        &self.code_block
    }

    fn check_elf_header(elf_header: &Elf32Ehdr) -> Result<u8, &str> {
        if &elf_header.e_ident[0..4] != &[0x7f, 'E' as u8, 'L' as u8, 'F' as u8] {
            return Err("not an elf file");
        }
        if elf_header.e_ident[4] != 1 {
            return Err("not an 32 bit elf file"); 
        }
        Ok(0)
    }


}



#[derive(Debug, Clone)]
struct Elf32Ehdr {
    e_ident: [u8; 16],	/* Magic number and other info */
    e_type: u16,			/* Object file u8 */
    e_machine: u16,		/* Architecture */
    e_version: u32,		/* Object file version */
    e_entry: u32,	/* Entry point virtual address */
    e_phoff: u32,		/* Program header table file offset */
    e_shoff: u32,		/* Section header table file offset */
    e_flags: u32,		/* Processor-specific flags */
    e_ehsize: u16,		/* ELF header size in bytes */
    e_phentsize: u16,		/* Program header table entry size */
    e_phnum: u16,		/* Program header table entry count */
    e_shentsize: u16,		/* Section header table entry size */
    e_shnum: u16,		/* Section header table entry count */
    e_shstrndx: u16,		/* Section header string table index */
}

const ELF32_HEADER_SIZE: usize = 52;

#[derive(Debug, Clone)]
struct Elf32Shdr{
	sh_name: u32,		/* Section name (string tbl index) */
	sh_type: u32,		/* Section u8 */
	sh_flags: u32,		/* Section flags */
	sh_addr: u32,		/* Section virtual addr at execution */
	sh_offset: u32,		/* Section file offset */
	sh_size: u32,		/* Section size in bytes */
	sh_link: u32,		/* Link to another section */
	sh_info: u32,		/* Additional section information */
	sh_addralign: u32,		/* Section alignment */
	sh_entsize: u32,		/* Entry size if section holds table */
}
const ELF32_SECTION_HEADER_TABLE_SIZE: usize = 40;


#[derive(Debug, Clone)]
struct Elf32Sym {
    st_name: u32,		/* Symbol name (string tbl index) */
	st_value: u32,		/* Symbol value */
	st_size: u32,		/* Symbol size */
	st_info: u8,		/* Symbol u8 and binding */
	st_other: u8,		/* Symbol visibility */
	st_shndx: u16,		/* Section index */
}
const ELF32_SYM_TABLE_SIZE: usize = 16;

/*
#[derive(Debug)]
struct Elf32Rel {
	r_offset: u32,		/* Address */
	r_info: u32,			/* Relocation u8 and symbol index */
}

#[derive(Debug)]
struct Elf32Rela {
	r_offset: u32,		/* Address */
	r_info: u32,			/* Relocation u8 and symbol index */
    r_addend: i32,		/* Addend */
}
*/
#[derive(Debug, Clone)]
struct Elf32Phdr {
	p_type: u32,			/* Segment u8 */
	p_offset: u32,		/* Segment file offset */
	p_vaddr: u32,		/* Segment virtual address */
	p_paddr: u32,		/* Segment physical address */
	p_filesz: u32,		/* Segment size in file */
	p_memsz: u32,		/* Segment size in memory */
	p_flags: u32,		/* Segment flags */
	p_align: u32,		/* Segment alignment */
}

#[derive(Debug, Clone)]
struct Elf32Dyn {
  d_tag: i32,			/* Dynamic entry u8 */
  d_un: u32,
}



impl Elf32Ehdr {
    pub fn new() -> Self {
        Elf32Ehdr {
            e_ident: [0; 16],	
            e_type: 0,			
            e_machine: 0,		
            e_version: 0,		        
            e_entry: 0,
            e_phoff: 0,		
            e_shoff: 0,		
            e_flags: 0,		
            e_ehsize: 0,		
            e_phentsize: 0,	
            e_phnum: 0,		
            e_shentsize: 0,	
            e_shnum: 0,		
            e_shstrndx: 0,	
        }
    }
}


impl From<&[u8]> for Elf32Ehdr {
    fn from(item: &[u8]) -> Self {
        Elf32Ehdr {
            e_ident: clone_into_array(&item[0..16]),	
            e_type: u16::from_le_bytes(clone_into_array(&item[16..18])),			
            e_machine: u16::from_le_bytes(clone_into_array(&item[18..20])),		
            e_version: u32::from_le_bytes(clone_into_array(&item[20..24])),		        
            e_entry: u32::from_le_bytes(clone_into_array(&item[24..28])),
            e_phoff: u32::from_le_bytes(clone_into_array(&item[28..32])),		
            e_shoff: u32::from_le_bytes(clone_into_array(&item[32..36])),		
            e_flags: u32::from_le_bytes(clone_into_array(&item[36..40])),		
            e_ehsize: u16::from_le_bytes(clone_into_array(&item[40..42])),		
            e_phentsize: u16::from_le_bytes(clone_into_array(&item[42..44])),	
            e_phnum: u16::from_le_bytes(clone_into_array(&item[44..46])),		
            e_shentsize: u16::from_le_bytes(clone_into_array(&item[46..48])),	
            e_shnum: u16::from_le_bytes(clone_into_array(&item[48..50])),		
            e_shstrndx: u16::from_le_bytes(clone_into_array(&item[50..52])),	
        } 
    } 
}

impl From<&[u8]> for Elf32Shdr {
    fn from(item: &[u8]) -> Self {
        Elf32Shdr {
            sh_name: u32::from_le_bytes(clone_into_array(&item[0..4])),		
        	sh_type: u32::from_le_bytes(clone_into_array(&item[4..8])),	
        	sh_flags: u32::from_le_bytes(clone_into_array(&item[8..12])),	
        	sh_addr: u32::from_le_bytes(clone_into_array(&item[12..16])),	
        	sh_offset: u32::from_le_bytes(clone_into_array(&item[16..20])),	
        	sh_size: u32::from_le_bytes(clone_into_array(&item[20..24])),	
        	sh_link: u32::from_le_bytes(clone_into_array(&item[24..28])),	
        	sh_info: u32::from_le_bytes(clone_into_array(&item[28..32])),	
        	sh_addralign: u32::from_le_bytes(clone_into_array(&item[32..36])),	
        	sh_entsize: u32::from_le_bytes(clone_into_array(&item[36..40])),	
        }
    }
}

impl From<&[u8]> for Elf32Phdr {
    fn from(item: &[u8]) -> Self {
        Elf32Phdr {
        	p_type: u32::from_le_bytes(clone_into_array(&item[0..4])),		
        	p_offset: u32::from_le_bytes(clone_into_array(&item[4..8])),	
        	p_vaddr: u32::from_le_bytes(clone_into_array(&item[8..12])),	
        	p_paddr: u32::from_le_bytes(clone_into_array(&item[12..16])),	
        	p_filesz: u32::from_le_bytes(clone_into_array(&item[16..20])),	
        	p_memsz: u32::from_le_bytes(clone_into_array(&item[20..24])),	
        	p_flags: u32::from_le_bytes(clone_into_array(&item[24..28])),	
        	p_align: u32::from_le_bytes(clone_into_array(&item[28..32])),	
        }
    }
}

impl From<&[u8]> for Elf32Sym {
    fn from(item: &[u8]) -> Self {
        Elf32Sym {
            st_name: u32::from_le_bytes(clone_into_array(&item[0..4])),		
        	st_value: u32::from_le_bytes(clone_into_array(&item[4..8])),		
        	st_size: u32::from_le_bytes(clone_into_array(&item[8..12])),		
        	st_info: u8::from_le_bytes(clone_into_array(&item[12..13])),		
        	st_other: u8::from_le_bytes(clone_into_array(&item[13..14])),		
        	st_shndx: u16::from_le_bytes(clone_into_array(&item[14..16])),		
        }
    }
}

fn clone_into_array<A, T>(slice: &[T]) -> A 
where
    A: Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}


const PT_LOAD: usize = 1;

const PF_X: usize = 1 << 0;

const SHT_SYMTAB: usize = 2;
const SHT_STRTAB: usize = 3;
const SHT_DYNSYM: usize = 11;

const SHF_EXECINSTR: usize = 1 << 2;
