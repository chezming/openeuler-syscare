use std::ffi::OsStr;
use std::os::unix::prelude::OsStrExt;

use memmap2::Mmap;

use super::super::{Endian, ReadInteger, SymbolRead, OperateRead};

#[derive(Debug)]
pub struct SymbolHeader<'a> {
    mmap: Mmap,
    endian: Endian,
    strtab: &'a Mmap,
    name: &'a OsStr,
}

impl<'a> SymbolHeader<'a> {
    pub fn from(mmap: Mmap, endian: Endian, strtab: &'a Mmap) -> Self {
        Self {
            mmap,
            endian,
            strtab,
            name: OsStr::new(""),
        }
    }

    pub fn get_st_name(&mut self) -> &OsStr {
        match self.name.is_empty() {
            false => self.name.clone(),
            true => {
                let name_offset = self.get_st_name_offset() as usize;
                self.name = self.read_to_os_string(name_offset);
                self.name
            }
        }
    }

}

impl SymbolRead for SymbolHeader<'_> {}

impl<'a> SymbolHeader<'a> {
    fn read_to_os_string(&self, offset: usize) -> &'a OsStr {
        let mut end = offset;
        loop {
            let data = self.strtab[end];
            match data {
                0 => break,
                _ => (),
            };
            end += 1;
        }
        OsStr::from_bytes(&self.strtab[offset..end])
    }
}

impl OperateRead for SymbolHeader<'_> {
    fn get<T: ReadInteger<T>>(&self, start: usize) -> T {
        self.endian.read_integer::<T>(&self.mmap[start..(start + std::mem::size_of::<T>())])
    }
}