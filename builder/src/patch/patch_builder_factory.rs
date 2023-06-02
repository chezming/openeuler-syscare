use crate::cli::CliWorkDir;

use super::{PatchType, PatchBuilder};

use super::user_patch::UserPatchBuilder;
use super::kernel_patch::KernelPatchBuilder;

pub struct PatchBuilderFactory;

impl PatchBuilderFactory {
    pub fn get_builder(patch_type: PatchType, workdir: &CliWorkDir) -> Box<dyn PatchBuilder + '_> {
        match patch_type {
            PatchType::KernelPatch => Box::new(KernelPatchBuilder::new(workdir)),
            PatchType::UserPatch   => Box::new(UserPatchBuilder::new(workdir)),
        }
    }
}
