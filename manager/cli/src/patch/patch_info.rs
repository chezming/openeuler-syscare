use std::ffi::OsString;
use std::path::PathBuf;
use std::collections::HashMap;

use log::log;
use serde::{Serialize, Deserialize};

use super::package_info::PackageInfo;

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(Clone, Copy)]
pub enum PatchType {
    UserPatch,
    KernelPatch,
}

impl std::fmt::Display for PatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

#[derive(Serialize, Deserialize)]
#[derive(Clone)]
pub struct PatchFile {
    name:   String,
    path:   PathBuf,
    digest: String,
}

#[derive(Serialize, Deserialize)]
#[derive(Clone)]
pub struct PatchInfo {
    pub name:        String,
    pub version:     u32,
    pub release:     String,
    pub arch:        String,
    pub kind:        PatchType,
    pub target:      PackageInfo,
    pub target_elfs: HashMap<OsString, PathBuf>,
    pub license:     String,
    pub description: String,
    pub incremental: bool,
    pub builder:     String,
    pub patches:     Vec<PatchFile>,
}

impl PatchInfo {
    pub fn print_log(&self, level: log::Level) {
        const PATCH_FLAG_NONE: &str = "(none)";

        let target_elfs = match self.target_elfs.is_empty() {
            false => {
                let mut str = String::new();
                for (elf_name, _) in self.target_elfs.iter() {
                    str.push_str(&format!("{}, ", elf_name.to_string_lossy()));
                }
                str.pop();
                str.pop();
                str
            },
            true => {
                PATCH_FLAG_NONE.to_owned()
            },
        };

        log!(level, "name:        {}", self.name);
        log!(level, "version:     {}", self.version);
        log!(level, "release:     {}", self.release);
        log!(level, "arch:        {}", self.arch);
        log!(level, "type:        {}", self.kind);
        log!(level, "target:      {}", self.target.short_name());
        log!(level, "target_elfs: {}", target_elfs);
        log!(level, "license:     {}", self.license);
        log!(level, "description: {}", self.description);
        log!(level, "builder:     {}", self.builder);
        log!(level, "");
        log!(level, "patch list:");
        for patch_file in &self.patches {
            log!(level, "{} {}", patch_file.name, patch_file.digest);
        }
    }
}
