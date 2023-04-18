use std::ffi::OsString;

use common::util::os_str::OsStringExt;
use common::util::ext_cmd::{ExternCommand, ExternCommandArgs};
use common::util::fs;

use crate::cli::{CliWorkDir, CliArguments};
use crate::package::RpmHelper;
use crate::patch::{PatchInfo, PatchBuilder, PatchBuilderArguments};

use super::upatch_builder_args::UserPatchBuilderArguments;

pub struct UserPatchBuilder<'a> {
    workdir: &'a CliWorkDir
}

impl<'a> UserPatchBuilder<'a> {
    pub fn new(workdir: &'a CliWorkDir) -> Self {
        Self { workdir }
    }

    fn parse_cmd_args(&self, args: &UserPatchBuilderArguments) -> ExternCommandArgs {
        let mut cmd_args = ExternCommandArgs::new()
            .arg("--work-dir")
            .arg(&args.work_dir)
            .arg("--debug-source")
            .arg(&args.debug_source)
            .arg("--elf-dir")
            .arg(&args.elf_dir)
            .arg("--build-source-cmd")
            .arg(&args.build_source_cmd)
            .arg("--build-patch-cmd")
            .arg(&args.build_patch_cmd)
            .arg("--output-dir")
            .arg(&args.output_dir);

        for relation in &args.elf_relations {
            cmd_args = cmd_args
                .arg("--elf-path")
                .arg(OsString::from("*").concat(&relation.elf))
                .arg("--debug-info")
                .arg(&relation.debuginfo)
        }

        if args.skip_compiler_check {
            cmd_args = cmd_args.arg("--skip-compiler-check");
        }
        if args.verbose {
            cmd_args = cmd_args.arg("--verbose");
        }
        cmd_args = cmd_args.args(args.patch_list.iter().map(|patch| &patch.path));

        cmd_args
    }
}

impl PatchBuilder for UserPatchBuilder<'_> {
    fn parse_builder_args(&self, patch_info: &PatchInfo, args: &CliArguments) -> std::io::Result<PatchBuilderArguments> {
        let source_pkg_dir = self.workdir.package.source.as_path();
        let debug_pkg_dir  = self.workdir.package.debug.as_path();

        let pkg_build_root    = RpmHelper::find_build_root(source_pkg_dir)?;
        let pkg_spec_dir      = pkg_build_root.specs.as_path();
        let pkg_build_dir     = pkg_build_root.build.as_path();
        let pkg_buildroot_dir = pkg_build_root.build_root.as_path();
        let pkg_spec_file     = RpmHelper::find_spec_file(pkg_spec_dir)?;

        let target_pkg    = &patch_info.target;
        let work_dir      = self.workdir.patch.build.as_path();
        let source_dir    = RpmHelper::find_build_source(pkg_build_dir, patch_info)?;
        let debuginfos    = RpmHelper::find_debuginfo(debug_pkg_dir)?;
        let elf_relations = RpmHelper::parse_elf_relations(debuginfos, debug_pkg_dir, target_pkg)?;
        let output_dir    = self.workdir.patch.output.as_path();

        let build_original_cmd = OsString::from("rpmbuild")
            .concat(" --define '_topdir ")
            .concat(&pkg_build_root)
            .concat("' -bc ")
            .concat("--nodebuginfo ")
            .concat("--noclean ")
            .concat(&pkg_spec_file);

        let build_patched_cmd = OsString::from("rpmbuild")
            .concat(" --define '__brp_strip %{nil}'")
            .concat(" --define '_topdir ")
            .concat(&pkg_build_root)
            .concat("' -bb ")
            .concat("--noprep ")
            .concat("--nocheck ")
            .concat("--nodebuginfo ")
            .concat("--noclean ")
            .concat(&pkg_spec_file);

        let builder_args = UserPatchBuilderArguments {
            work_dir:            work_dir.to_path_buf(),
            debug_source:        source_dir,
            elf_dir:             pkg_buildroot_dir.to_path_buf(),
            elf_relations:       elf_relations,
            build_source_cmd:    build_original_cmd,
            build_patch_cmd:     build_patched_cmd,
            output_dir:          output_dir.to_path_buf(),
            skip_compiler_check: args.skip_compiler_check,
            verbose:             args.verbose,
            patch_list:          patch_info.patches.to_owned(),
        };

        Ok(PatchBuilderArguments::UserPatch(builder_args))
    }

    fn build_patch(&self, args: &PatchBuilderArguments) -> std::io::Result<()> {
        const UPATCH_BUILD: ExternCommand = ExternCommand::new("/usr/libexec/syscare/upatch-build");

        match args {
            PatchBuilderArguments::UserPatch(uargs) => {
                UPATCH_BUILD.execvp(
                    self.parse_cmd_args(uargs)
                )?.check_exit_code()
            },
            PatchBuilderArguments::KernelPatch(_) => unreachable!(),
        }
    }

    fn write_patch_info(&self, patch_info: &mut PatchInfo, args: &PatchBuilderArguments) -> std::io::Result<()> {
        match args {
            PatchBuilderArguments::UserPatch(uargs) => {
                /*
                 * We assume that upatch-build generated patch file is named same as original elf file.
                 * Thus, we can filter all elf names by existing patch file, which is the patch binary.
                 */
                let elf_map = uargs.elf_relations.iter().filter_map(|elf_relation| {
                    let elf_name = fs::file_name(&elf_relation.elf);
                    let elf_path = elf_relation.elf.to_path_buf();

                    fs::find_file(&uargs.output_dir, &elf_name, fs::FindOptions { fuzz: false, recursive: false }).map(|_| {
                        (elf_name, elf_path)
                    }).ok()
                });
                patch_info.target_elfs.extend(elf_map);

                Ok(())
            },
            PatchBuilderArguments::KernelPatch(_) => unreachable!(),
        }
    }
}
