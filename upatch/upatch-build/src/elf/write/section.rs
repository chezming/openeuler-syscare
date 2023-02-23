use memmap2::MmapMut;

use super::super::{Endian, ReadInteger, SectionRead, OperateRead, OperateWrite};

#[derive(Debug)]
pub struct SectionHeader {
    mmap: MmapMut,
    endian: Endian,
}

impl SectionHeader {
    pub fn from(mmap: MmapMut, endian: Endian) -> Self {
        Self {
            mmap,
            endian,
        }
    }
}

impl SectionRead for SectionHeader {}

impl OperateRead for SectionHeader {
    fn get<T: ReadInteger<T>>(&self, start: usize) -> T {
        self.endian.read_integer::<T>(&self.mmap[start..(start + std::mem::size_of::<T>())])
    }
}

impl OperateWrite for SectionHeader {
    fn set<T: ReadInteger<T>>(&mut self, start: usize, data: T) {
        let vec = self.endian.write_integer::<T>(data);
        for i in 0..vec.len() {
            self.mmap[start + i] = vec[i];
        }
    }
}