// SPDX-License-Identifier: Mulan PSL v2
/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
 * upatch-build is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *         http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use memmap2::MmapMut;

use super::super::{Endian, HeaderRead, HeaderWrite, OperateRead, OperateWrite, ReadInteger};

#[derive(Debug)]
pub struct Header {
    mmap: MmapMut,
    endian: Endian,
}

impl Header {
    pub fn from(mmap: MmapMut, endian: Endian) -> Self {
        Self { mmap, endian }
    }
}

impl HeaderRead for Header {}

impl HeaderWrite for Header {}

impl OperateRead for Header {
    fn get<T: ReadInteger<T>>(&self, start: usize) -> T {
        self.endian
            .read_integer::<T>(&self.mmap[start..(start + std::mem::size_of::<T>())])
    }
}

impl OperateWrite for Header {
    fn set<T: ReadInteger<T>>(&mut self, start: usize, data: T) {
        let vec = self.endian.write_integer::<T>(data);
        for (i, _) in vec.iter().enumerate() {
            self.mmap[start + i] = vec[i];
        }
    }
}
