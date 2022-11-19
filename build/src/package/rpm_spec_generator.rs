use std::io::{Write, LineWriter};

use crate::constants::*;
use crate::util::fs;

use crate::patch::PatchInfo;

pub struct RpmSpecGenerator;

impl RpmSpecGenerator {
    #[inline(always)]
    fn get_patch_name(patch_info: &PatchInfo) -> &str {
        patch_info.get_patch().get_name()
    }

    #[inline(always)]
    fn parse_pkg_name(patch_info: &PatchInfo) -> String {
        let patch_target = patch_info.get_target();
        let patch_name   = Self::get_patch_name(patch_info);

        format!("{}-{}-{}", patch_target, PKG_FLAG_PATCH_PKG, patch_name)
    }

    #[inline(always)]
    fn parse_build_requires(patch_info: &PatchInfo) -> String {
        let patch_target = patch_info.get_target();

        format!("{} = {}-{}",
            patch_target.get_name(),
            patch_target.get_version(),
            patch_target.get_release()
        )
    }

    #[inline(always)]
    fn write_patch_info<W>(mut writer: W, patch_info: &PatchInfo, source_dir: &str) -> std::io::Result<()>
    where
        W: Write
    {
        let pkg_file_list = fs::list_all_files(source_dir, true)?
            .into_iter()
            .map(fs::file_name)
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        let pkg_install_path = format!("{}/{}", PATCH_INSTALL_PATH, Self::get_patch_name(patch_info));

        writeln!(writer, "Name:     {}", Self::parse_pkg_name(patch_info))?;
        writeln!(writer, "Version:  {}", patch_info.get_patch().get_version())?;
        writeln!(writer, "Release:  {}", patch_info.get_patch().get_release())?;
        writeln!(writer, "Group:    {}", PKG_SPEC_TAG_VALUE_GROUP)?;
        writeln!(writer, "License:  {}", patch_info.get_license())?;
        writeln!(writer, "Summary:  {}", patch_info.get_summary())?;
        writeln!(writer, "Requires: {}", Self::parse_build_requires(patch_info))?;
        let mut file_index = 0usize;
        for file_name in &pkg_file_list {
            writeln!(writer, "Source{}: {}", file_index, file_name)?;
            file_index += 1;
        }
        writeln!(writer)?;

        writeln!(writer, "%description")?;
        writeln!(writer, "{}", patch_info)?;
        writeln!(writer)?;

        writeln!(writer, "%prep")?;
        writeln!(writer, "cp -a %{{_sourcedir}}/* %{{_builddir}}")?;
        writeln!(writer)?;

        writeln!(writer, "%build")?;
        writeln!(writer)?;

        writeln!(writer, "%install")?;
        writeln!(writer, "install -m {} -d %{{buildroot}}{}", PATCH_DIR_PERMISSION, pkg_install_path)?;
        for file_name in &pkg_file_list {
            writeln!(writer, "install -m {} %{{_builddir}}/{} %{{buildroot}}{}", PATCH_FILE_PERMISSION, file_name, pkg_install_path)?;
        }
        writeln!(writer)?;

        writeln!(writer, "%files")?;
        writeln!(writer, "{}", pkg_install_path)?;
        writeln!(writer)?;

        writeln!(writer, "%changelog")?;
        writeln!(writer)?;

        writer.flush()
    }

    pub fn generate_from_patch_info(patch_info: &PatchInfo, source_dir: &str, output_dir: &str) -> std::io::Result<String> {
        fs::check_dir(source_dir)?;
        fs::check_dir(output_dir)?;

        let patch_name = Self::get_patch_name(patch_info);
        let pkg_spec_path = format!("{}/{}.spec", output_dir, patch_name);
        let writer = LineWriter::new(
            std::fs::File::create(&pkg_spec_path)?
        );

        Self::write_patch_info(writer, patch_info, source_dir)?;

        Ok(pkg_spec_path)
    }
}
