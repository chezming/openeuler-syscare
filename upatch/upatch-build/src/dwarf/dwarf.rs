use std::borrow::{Cow, Borrow};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::ffi::{OsString, OsStr};
use std::os::unix::ffi::OsStrExt;

use log::*;
use gimli::{constants, Reader};
use object::{Object, ObjectSection, ObjectSymbol};
use typed_arena::Arena;

use super::Relocate;
use super::Result;
use crate::tool::*;

type RelocationMap = HashMap<usize, object::Relocation>;

#[allow(non_snake_case)]
pub struct DwarfCompileUnit {
    pub DW_AT_producer: String,
    pub DW_AT_comp_dir: PathBuf,
    pub DW_AT_name: PathBuf,
}

impl DwarfCompileUnit{
    pub fn new() -> Self{
        Self {
            DW_AT_producer: String::new(),
            DW_AT_comp_dir: PathBuf::new(),
            DW_AT_name: PathBuf::new(),
        }
    }

    pub fn get_source(&self) -> PathBuf {
        self.DW_AT_comp_dir.join(&self.DW_AT_name)
    }

    pub fn get_compiler_version(&self) -> String {
        self.DW_AT_producer.clone()
    }
}

pub struct Dwarf {}

impl Dwarf{
    pub fn new() -> Self{
        Self {}
    }

    pub fn file_in_binary<P: AsRef<Path>>(&self, dir_str: P, binary: P) -> io::Result<Vec<DwarfCompileUnit>> {
        let path = self.find_binary(dir_str, binary)?;
        self.file_in_obj(path)
    }

    pub fn file_in_obj<P: AsRef<Path>>(&self, elf: P) -> io::Result<Vec<DwarfCompileUnit>> {
        // use mmap here, but depend on some devices
        let elf = elf.as_ref();
        let file = std::fs::File::open(elf)?;
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        match object::File::parse(&*mmap) {
            Ok(object) => {
                let endian = if object.is_little_endian() {
                    gimli::RunTimeEndian::Little
                } else {
                    gimli::RunTimeEndian::Big
                };
                match self.get_files(&object, endian) {
                    Ok(res) => Ok(res),
                    Err(e) => Err(io::Error::new(io::ErrorKind::NotFound, e.to_string())),
                }
            },
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
        }
    }
}

impl Dwarf {
    fn find_binary<P: AsRef<Path>>(&self, dir_str: P, binary: P) -> io::Result<String> {
        let dir_str = dir_str.as_ref();
        let binary = binary.as_ref();
        let arr = find_files(dir_str, binary, false, true)?;
        match arr.len() {
            0 => Err(io::Error::new(io::ErrorKind::NotFound, format!("{} don't have {}", dir_str.display(), binary.display()))),
            1 => Ok(stringtify(&arr[0])),
            _ => Err(io::Error::new(io::ErrorKind::NotFound, format!("{} have {} {}", dir_str.display(), arr.len(), binary.display()))),
        }
    }

    fn add_relocations(&self, relocations: &mut RelocationMap, file: &object::File, section: &object::Section) {
        for (offset64, mut relocation) in section.relocations() {
            let offset = offset64 as usize;
            if offset as u64 != offset64 {
                continue;
            }
            let offset = offset as usize;
            match relocation.kind() {
                object::RelocationKind::Absolute => {
                    match relocation.target() {
                        object::RelocationTarget::Symbol(symbol_idx) => {
                            match file.symbol_by_index(symbol_idx) {
                                Ok(symbol) => {
                                    let addend = symbol.address().wrapping_add(relocation.addend() as u64);
                                    relocation.set_addend(addend as i64);
                                }
                                Err(_) => {
                                    trace!( "Relocation with invalid symbol for section {} at offset 0x{:08x}",
                                        section.name().unwrap(),
                                        offset
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                    if relocations.insert(offset, relocation).is_some() {
                        trace!("Multiple relocations for section {} at offset 0x{:08x}",
                            section.name().unwrap(),
                            offset
                        );
                    }
                }
                _ => {
                    trace!( "Unsupported relocation for section {} at offset 0x{:08x}",
                        section.name().unwrap(),
                        offset
                    );
                }
            }
        }
    }

    fn load_file_section<'input, 'arena, Endian: gimli::Endianity> (
        &self,
        id: gimli::SectionId,
        file: &object::File<'input>,
        endian: Endian,
        arena_data: &'arena Arena<Cow<'input, [u8]>>,
        arena_relocations: &'arena Arena<RelocationMap>,
    ) -> Result<Relocate<'arena, gimli::EndianSlice<'arena, Endian>>> {
        let mut relocations = RelocationMap::default();
        let name = Some(id.name());
        let data = match name.and_then(|name| file.section_by_name(&name)) {
            Some(ref section) => {
                // DWO sections never have relocations, so don't bother.
                self.add_relocations(&mut relocations, file, section);
                section.uncompressed_data()?
            }
            // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
            None => Cow::Owned(Vec::with_capacity(1)),
        };
        let data_ref = (*arena_data.alloc(data)).borrow();
        let reader = gimli::EndianSlice::new(data_ref, endian);
        let section = reader;
        let relocations = (*arena_relocations.alloc(relocations)).borrow();
        Ok(Relocate {relocations, section, reader})
    }

    fn get_files(&self, file: &object::File, endian: gimli::RunTimeEndian) -> Result<Vec<DwarfCompileUnit>> {
        let arena_data = Arena::new();
        let arena_relocations = Arena::new();

        // Load a section and return as `Cow<[u8]>`.
        let mut load_section = |id: gimli::SectionId| -> Result<_> {
            self.load_file_section(id, file, endian, &arena_data, &arena_relocations)
        };

        let dwarf = gimli::Dwarf::load(&mut load_section)?;

        self.__get_files(&dwarf)
    }

 
    fn __get_files<R: Reader>(&self, dwarf: &gimli::Dwarf<R>) -> Result<Vec<DwarfCompileUnit>> {
        let mut result = Vec::new();
        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs()? {
                if entry.tag() != constants::DW_TAG_compile_unit{
                    break;
                }
                // Iterate over the attributes in the DIE.
                let mut attrs = entry.attrs();
                let mut element = DwarfCompileUnit::new();
                while let Some(attr) = attrs.next()? {
                    match attr.name() {
                        constants::DW_AT_comp_dir => {
                            element.DW_AT_comp_dir.push(&self.attr_value(&attr, &dwarf));
                        },
                        constants::DW_AT_name => {
                            element.DW_AT_name.push(&self.attr_value(&attr, &dwarf));
                        },
                        constants::DW_AT_producer => {
                            element.DW_AT_producer.push_str(&self.attr_value(&attr, &dwarf).to_string_lossy());
                        }
                        _ => continue,
                    }
                }
                result.push(element);
            }
        }
        Ok(result)
    }

    fn attr_value<R: Reader>(&self, attr: &gimli::Attribute<R>, dwarf: &gimli::Dwarf<R>) -> OsString {
        let value = attr.value();
        match value {
            gimli::AttributeValue::DebugLineStrRef(offset) => {
                if let Ok(s) = dwarf.debug_line_str.get_str(offset) {
                    OsStr::from_bytes(&s.to_slice().ok().unwrap_or_default()).to_os_string()
                } else {
                    OsString::default()
                }
            }
            gimli::AttributeValue::DebugStrRef(offset) => {
                if let Ok(s) = dwarf.debug_str.get_str(offset) {
                    OsStr::from_bytes(&s.to_slice().ok().unwrap_or_default()).to_os_string()
                } else {
                    OsString::default()
                }
            }
            _ =>  OsString::default()
        }
    }
}