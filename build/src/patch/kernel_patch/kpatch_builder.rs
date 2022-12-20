use crate::constants::*;
use crate::log::debug;

use crate::cli::{CliWorkDir, CliArguments};
use crate::package::RpmHelper;
use crate::patch::{PatchInfo, PatchFile};
use crate::patch::{PatchBuilder, PatchBuilderArgumentsParser, PatchBuilderArguments};

use super::kpatch_helper::KernelPatchHelper;
use super::kpatch_builder_args::KernelPatchBuilderArguments;

pub struct KernelPatchBuilder;

impl KernelPatchBuilder {
    pub fn new() -> Self {
        Self {}
    }

    fn parse_arg_list<'a>(&self, args: &'a KernelPatchBuilderArguments) -> Vec<&'a str> {
        let mut arg_list = vec![
            "--name",      args.patch_name.as_str(),
            "--sourcedir", args.source_dir.as_str(),
            "--config",    args.config.as_str(),
            "--vmlinux",   args.vmlinux.as_str(),
            "--jobs",      Box::leak(Box::new(args.jobs.to_string())),
            "--output",    args.output_dir.as_str(),
            "--skip-cleanup",
        ];
        if args.skip_compiler_check {
            arg_list.push("--skip-compiler-check");
        }
        arg_list.append(&mut args.patch_list.iter().map(PatchFile::get_path).collect());

        arg_list
    }

    fn parse_env_list<'a>(&'a self, args: &'a KernelPatchBuilderArguments) -> Vec<(&str, &str)> {
        vec![
            ("CACHEDIR",           args.build_root.as_str()),
            ("NO_PROFILING_CALLS", "yes"),
            ("DISABLE_AFTER_LOAD", "yes"),
            ("KEEP_JUMP_LABEL",    "yes")
        ]
    }
}

impl PatchBuilderArgumentsParser for KernelPatchBuilder {
    fn parse_args(patch_info: &PatchInfo, workdir: &CliWorkDir, args: &CliArguments) -> std::io::Result<PatchBuilderArguments> {
        let patch_build_root = workdir.patch_root().build_root_dir();
        let patch_output_dir = workdir.patch_root().output_dir();

        let source_pkg_dir = workdir.package_root().source_pkg_dir();
        let debug_pkg_dir  = workdir.package_root().debug_pkg_dir();

        let source_pkg_build_root = RpmHelper::find_build_root(source_pkg_dir)?;
        let source_pkg_build_dir  = source_pkg_build_root.build_dir();

        let kernel_source_dir = RpmHelper::find_source_directory(source_pkg_build_dir, patch_info)?;
        debug!("source directory: '{}'", kernel_source_dir);

        KernelPatchHelper::generate_defconfig(&kernel_source_dir)?;
        let kernel_config = KernelPatchHelper::find_kernel_config(&kernel_source_dir)?;
        debug!("kernel config: '{}'", kernel_config);

        let debuginfo_file = KernelPatchHelper::find_debuginfo_file(debug_pkg_dir)?;
        debug!("debuginfo file: '{}'", debuginfo_file);

        let builder_args = KernelPatchBuilderArguments {
            build_root:          patch_build_root.to_owned(),
            patch_name:          patch_info.get_name().to_owned(),
            source_dir:          kernel_source_dir,
            config:              kernel_config,
            vmlinux:             debuginfo_file,
            jobs:                args.kjobs,
            output_dir:          patch_output_dir.to_owned(),
            skip_compiler_check: args.skip_compiler_check,
            patch_list:          patch_info.get_file_list().to_owned(),
        };

        Ok(PatchBuilderArguments::KernelPatch(builder_args))
    }
}

impl PatchBuilder for KernelPatchBuilder {
    fn build_patch(&self, args: PatchBuilderArguments) -> std::io::Result<()> {
        match args {
            PatchBuilderArguments::KernelPatch(kargs) => {
                let exit_status = KPATCH_BUILD.execve(
                    self.parse_arg_list(&kargs),
                    self.parse_env_list(&kargs)
                )?;

                let exit_code = exit_status.exit_code();
                if exit_code != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        format!("Process '{}' exited unsuccessfully, exit_code={}", KPATCH_BUILD, exit_code),
                    ));
                }
                Ok(())
            },
            _ => unreachable!(),
        }
    }
}
