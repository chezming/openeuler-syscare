use std::{path::PathBuf, ffi::OsString};

use crate::patch::PatchFile;

pub struct UserPatchBuilderArguments {
    pub name:                String,
    pub work_dir:            PathBuf,
    pub elf_name:            String,
    pub debug_source:        PathBuf,
    pub debuginfo:           PathBuf,
    pub build_source_cmd:    OsString,
    pub build_patch_cmd:     OsString,
    pub output_dir:          PathBuf,
    pub skip_compiler_check: bool,
    pub verbose:             bool,
    pub patch_list:          Vec<PatchFile>,
}
