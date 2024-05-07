// SPDX-License-Identifier: Mulan PSL v2
/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
 * syscared is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *         http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use std::{
    ffi::OsStr,
    ffi::OsString,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use object::{NativeFile, Object, ObjectSection};

use syscare_abi::PatchEntity;
use syscare_common::util::os_str::OsStrExt;
use syscare_common::fs;

use super::PatchInfoExt;

#[derive(Debug)]
pub struct KernelPatchExt {
    pub patch_file: PathBuf,
    pub sys_file: PathBuf,
    pub module_name: String,
    pub symbols: Vec<KernelPatchSymbol>,
}

mod ffi {
    use std::os::raw::{c_char, c_long, c_ulong};

    use object::Pod;

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    /// Corresponds to `struct kpatch_patch_func` defined in `kpatch-patch.h`
    pub struct KpatchFunction {
        pub new_addr: c_ulong,
        pub new_size: c_ulong,
        pub old_addr: c_ulong,
        pub old_size: c_ulong,
        pub sympos: u64,
        pub name: *const c_char,
        pub obj_name: *const c_char,
        pub ref_name: *const c_char,
        pub ref_offset: c_long,
    }

    pub const KPATCH_FUNC_SIZE: usize = std::mem::size_of::<KpatchFunction>();
    pub const KPATCH_FUNC_NAME_OFFSET: usize = 40;
    pub const KPATCH_OBJECT_NAME_OFFSET: usize = 48;

    /*
     * SAFETY: This struct is
     * - #[repr(C)]
     * - have no invalid byte values
     * - have no padding
     */
    unsafe impl Pod for KpatchFunction {}

    pub enum KpatchRelocation {
        NewAddr = 0,
        Name = 1,
        ObjName = 2,
    }

    impl From<usize> for KpatchRelocation {
        fn from(value: usize) -> Self {
            match value {
                0 => KpatchRelocation::NewAddr,
                1 => KpatchRelocation::Name,
                2 => KpatchRelocation::ObjName,
                _ => unreachable!(),
            }
        }
    }

    pub const KPATCH_FUNC_RELA_TYPE_NUM: usize = 3;
}

use ffi::*;

const KPATCH_FUNCS_SECTION: &str = ".kpatch.funcs";
const KPATCH_STRINGS_SECTION: &str = ".kpatch.strings";

impl KernelPatchExt {
    #[inline]
    fn resolve_patch_file(patch: &mut KernelPatchExt) -> Result<()> {
        let patch_file =
            fs::MappedFile::open(&patch.patch_file).context("Failed to map patch file")?;
        let patch_elf = NativeFile::parse(patch_file.as_bytes()).context("Invalid patch format")?;

        // Read sections
        let function_section = patch_elf
            .section_by_name(KPATCH_FUNCS_SECTION)
            .with_context(|| format!("Cannot find section '{}'", KPATCH_FUNCS_SECTION))?;
        let string_section = patch_elf
            .section_by_name(KPATCH_STRINGS_SECTION)
            .with_context(|| format!("Cannot find section '{}'", KPATCH_STRINGS_SECTION))?;
        let function_data = function_section
            .data()
            .with_context(|| format!("Failed to read section '{}'", KPATCH_FUNCS_SECTION))?;
        let string_data = string_section
            .data()
            .with_context(|| format!("Failed to read section '{}'", KPATCH_FUNCS_SECTION))?;

        // Resolve patch functions
        let patch_symbols = &mut patch.symbols;
        let patch_functions = object::slice_from_bytes::<KpatchFunction>(
            function_data,
            function_data.len() / KPATCH_FUNC_SIZE,
        )
        .map(|(f, _)| f)
        .map_err(|_| anyhow!("Invalid data format"))
        .context("Failed to resolve patch functions")?;

        for function in patch_functions {
            patch_symbols.push(KernelPatchSymbol {
                name: OsString::new(),
                target: OsString::new(),
                old_addr: function.old_addr,
                old_size: function.old_size,
                new_addr: function.new_addr,
                new_size: function.new_size,
            });
        }

        // Relocate patch functions
        for (index, (offset, relocation)) in function_section.relocations().enumerate() {
            match KpatchRelocation::from(index % KPATCH_FUNC_RELA_TYPE_NUM) {
                KpatchRelocation::Name => {
                    let symbol_index =
                        (offset as usize - KPATCH_FUNC_NAME_OFFSET) / KPATCH_FUNC_SIZE;
                    let patch_symbol = patch_symbols
                        .get_mut(symbol_index)
                        .context("Failed to find patch symbol")?;

                    let name_offset = relocation.addend() as usize;
                    let mut name_bytes = &string_data[name_offset..];
                    let string_end = name_bytes
                        .iter()
                        .position(|b| b == &b'\0')
                        .context("Failed to find termination char")?;
                    name_bytes = &name_bytes[..string_end];

                    patch_symbol.name = OsString::from_vec(name_bytes.to_vec());
                }
                KpatchRelocation::ObjName => {
                    let symbol_index =
                        (offset as usize - KPATCH_OBJECT_NAME_OFFSET) / KPATCH_FUNC_SIZE;
                    let patch_symbol = patch_symbols
                        .get_mut(symbol_index)
                        .context("Failed to find patch symbol")?;

                    let name_offset = relocation.addend() as usize;
                    let mut name_bytes = &string_data[name_offset..];
                    let string_end = name_bytes
                        .iter()
                        .position(|b| b == &b'\0')
                        .context("Failed to find termination char")?;
                    name_bytes = &name_bytes[..string_end];

                    patch_symbol.target = OsString::from_vec(name_bytes.to_vec());
                }
                _ => {}
            };
        }

        Ok(())
    }
}



impl KernelPatchExt {
    pub fn new<P: AsRef<Path>>(patch_root: P, patch_entity: &PatchEntity) -> Self {
        const KPATCH_SUFFIX: &str = ".ko";
        const KPATCH_MGNT_DIR: &str = "/sys/kernel/livepatch";
        const KPATCH_MGNT_FILE_NAME: &str = "enabled";

        let patch_name = patch_entity
            .patch_name
            .strip_suffix(KPATCH_SUFFIX)
            .map(OsStr::to_string_lossy)
            .unwrap_or_else(|| patch_entity.patch_name.to_string_lossy());
        let patch_sys_name = patch_name.replace('-', "_").replace('.', "_");
        let patch_file_name = format!("{}{}", patch_name, KPATCH_SUFFIX);
        let module_name = patch_sys_name.to_owned();
      //  let symbols :Vec<KernelPatchSymbol> =Vec::new();


        let mut kernel_patch_ext = KernelPatchExt  {
            patch_file: patch_root.as_ref().join(patch_file_name),
            sys_file: PathBuf::from(KPATCH_MGNT_DIR)
                .join(patch_sys_name)
                .join(KPATCH_MGNT_FILE_NAME),
            module_name:module_name,
            symbols:Vec::new(),
        };
        Self::resolve_patch_file(&mut kernel_patch_ext).context("Failed to resolve patch elf").unwrap();
        
       kernel_patch_ext
    }
}

impl<'a> From<&'a PatchInfoExt> for &'a KernelPatchExt {
    fn from(ext: &'a PatchInfoExt) -> Self {
        match ext {
            PatchInfoExt::KernelPatch(ext) => ext,
            _ => panic!("Cannot convert user patch ext into kernel patch ext"),
        }
    }
}



/// Kernel patch symbol definition
#[derive(Clone)]
pub struct KernelPatchSymbol {
    pub name: OsString,
    pub target: OsString,
    pub old_addr: u64,
    pub old_size: u64,
    pub new_addr: u64,
    pub new_size: u64,
}

impl std::fmt::Debug for KernelPatchSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelPatchSymbol")
            .field("name", &self.name)
            .field("target", &self.target)
            .field("old_addr", &format!("{:#x}", self.old_addr))
            .field("old_size", &format!("{:#x}", self.old_size))
            .field("new_addr", &format!("{:#x}", self.new_addr))
            .field("new_size", &format!("{:#x}", self.new_size))
            .finish()
    }
}

impl std::fmt::Display for KernelPatchSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
             f,
             "name: {}, target: {}, old_addr: {:#x}, old_size: {:#x}, new_addr: {:#x}, new_size: {:#x}",
             self.name.to_string_lossy(),
             self.target.to_string_lossy(),
             self.old_addr,
             self.old_size,
             self.new_addr,
             self.new_size,
         )
    }
}
