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

use std::{ffi::CString, os::unix::prelude::OsStrExt, path::Path};

use anyhow::{Context, Result};

use nix::libc::{c_char, c_int, pid_t, size_t};
use syscare_abi::PatchStatus;

pub trait ToCString {
    fn to_cstring(&self) -> Result<CString>;
}

impl ToCString for Path {
    /// Converts a `Path` to an owned [`CString`].
    fn to_cstring(&self) -> Result<CString> {
        CString::new(self.as_os_str().as_bytes()).context("FFI failure")
    }
}

impl ToCString for str {
    /// Converts a `str` to an owned [`CString`].
    fn to_cstring(&self) -> Result<CString> {
        CString::new(self.as_bytes()).context("FFI failure")
    }
}

#[repr(C)]
pub enum UpatchStatus {
    NotApplied = 1,
    Deactived = 2,
    Active = 3,
    Invalid = 4,
}

impl From<UpatchStatus> for PatchStatus {
    fn from(status: UpatchStatus) -> Self {
        match status {
            UpatchStatus::NotApplied => PatchStatus::NotApplied,
            UpatchStatus::Deactived => PatchStatus::Deactived,
            UpatchStatus::Active => PatchStatus::Actived,
            UpatchStatus::Invalid => PatchStatus::Unknown,
        }
    }
}

extern "C" {
    pub fn upatch_status(uuid: *const c_char) -> UpatchStatus;

    pub fn upatch_check(
        target_elf: *const c_char,
        patch_file: *const c_char,
        err_msg: *mut c_char,
        max_len: size_t,
    ) -> c_int;

    pub fn upatch_load(
        uuid: *const c_char,
        target_elf: *const c_char,
        patch_file: *const c_char,
        force: bool,
    ) -> c_int;

    pub fn upatch_remove(uuid: *const c_char) -> c_int;

    pub fn upatch_active(uuid: *const c_char, pid_list: *const pid_t, list_len: size_t) -> c_int;

    pub fn upatch_deactive(uuid: *const c_char, pid_list: *const pid_t, list_len: size_t) -> c_int;
}
