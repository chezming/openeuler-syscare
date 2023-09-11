use std::path::PathBuf;

use syscare_abi::PatchFile;

pub struct KernelPatchBuilderArguments {
    pub build_root: PathBuf,
    pub patch_uuid: String,
    pub patch_name: String,
    pub source_dir: PathBuf,
    pub config: PathBuf,
    pub vmlinux: PathBuf,
    pub jobs: usize,
    pub output_dir: PathBuf,
    pub debug: bool,
    pub skip_compiler_check: bool,
    pub patch_list: Vec<PatchFile>,
}
