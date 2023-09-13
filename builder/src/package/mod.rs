use std::path::{Path, PathBuf};

use anyhow::Result;

use syscare_abi::PackageInfo;

mod build_root;
mod elf_relation;
mod pkg_builder;
mod rpm;
mod spec_builder;
mod spec_writer;
mod tar;

pub use build_root::PackageBuildRoot;
pub use elf_relation::ElfRelation;
pub use pkg_builder::{PackageBuilder, PackageBuilderFactory};
use rpm::RpmPackage;
pub use spec_builder::{PackageSpecBuilder, PackageSpecBuilderFactory};
pub use spec_writer::{PackageSpecWriter, PackageSpecWriterFactory};
pub use tar::TarPackage;

const DEBUGINFO_FILE_EXT: &str = "debug";
const DEBUGINFO_INSTALL_DIR: &str = "usr/lib/debug";

trait Package {
    fn extension(&self) -> &'static str;
    fn parse_package_info(&self, pkg_path: &Path) -> Result<PackageInfo>;
    fn query_package_files(&self, pkg_path: &Path) -> Result<Vec<PathBuf>>;
    fn parse_elf_relations(
        &self,
        package: &PackageInfo,
        debuginfo_root: &Path,
    ) -> Result<Vec<ElfRelation>>;
    fn extract_package(&self, pkg_path: &Path, output_dir: &Path) -> Result<()>;
    fn find_build_root(&self, directory: &Path) -> Result<PackageBuildRoot>;
    fn find_spec_file(&self, directory: &Path) -> Result<PathBuf>;
    fn find_source_directory(&self, directory: &Path, package_name: &str) -> Result<PathBuf>;
}

#[derive(Debug, Clone, Copy)]
pub enum PackageFormat {
    RpmPackage,
}

pub struct PackageImpl {
    format: PackageFormat,
    inner: Box<dyn Package + Send + Sync>,
}

impl PackageImpl {
    pub fn new(pkg_format: PackageFormat) -> Self {
        match pkg_format {
            PackageFormat::RpmPackage => Self {
                format: pkg_format,
                inner: Box::new(RpmPackage),
            },
        }
    }

    pub fn format(&self) -> PackageFormat {
        self.format
    }

    pub fn extension(&self) -> &'static str {
        self.inner.extension()
    }

    pub fn parse_package_info<P: AsRef<Path>>(&self, pkg_path: P) -> Result<PackageInfo> {
        self.inner.parse_package_info(pkg_path.as_ref())
    }

    pub fn query_package_files<P: AsRef<Path>>(&self, pkg_path: P) -> Result<Vec<PathBuf>> {
        self.inner.query_package_files(pkg_path.as_ref())
    }

    pub fn parse_elf_relations<P: AsRef<Path>>(
        &self,
        package: &PackageInfo,
        debuginfo_pkg_root: P,
    ) -> Result<Vec<ElfRelation>> {
        self.inner
            .parse_elf_relations(package, debuginfo_pkg_root.as_ref())
    }

    pub fn extract_package<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        pkg_path: P,
        output_dir: Q,
    ) -> Result<()> {
        self.inner
            .extract_package(pkg_path.as_ref(), output_dir.as_ref())
    }

    pub fn find_build_root<P: AsRef<Path>>(&self, directory: P) -> Result<PackageBuildRoot> {
        self.inner.find_build_root(directory.as_ref())
    }

    pub fn find_spec_file<P: AsRef<Path>>(&self, directory: P) -> Result<PathBuf> {
        self.inner.find_spec_file(directory.as_ref())
    }

    pub fn find_source_directory<P: AsRef<Path>>(
        &self,
        directory: P,
        package_name: &str,
    ) -> Result<PathBuf> {
        self.inner
            .find_source_directory(directory.as_ref(), package_name)
    }
}
