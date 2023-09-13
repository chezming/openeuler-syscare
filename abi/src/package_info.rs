use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum PackageType {
    SourcePackage,
    BinaryPackage,
}

impl std::fmt::Display for PackageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub kind: PackageType,
    pub arch: String,
    pub epoch: String,
    pub version: String,
    pub release: String,
    pub license: String,
    pub source_pkg: String,
}

impl PackageInfo {
    pub fn short_name(&self) -> String {
        format!("{}-{}-{}", self.name, self.version, self.release)
    }

    pub fn full_name(&self) -> String {
        format!(
            "{}-{}-{}.{}",
            self.name, self.version, self.release, self.arch
        )
    }

    pub fn is_source_of(&self, pkg_info: &PackageInfo) -> bool {
        (self.kind == PackageType::SourcePackage)
            && (pkg_info.kind == PackageType::BinaryPackage)
            && (self.source_pkg == pkg_info.source_pkg)
    }
}

impl std::fmt::Display for PackageInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "------------------------------")?;
        match self.kind {
            PackageType::SourcePackage => writeln!(f, "Source Package")?,
            PackageType::BinaryPackage => writeln!(f, "Debuginfo Package")?,
        }
        writeln!(f, "------------------------------")?;
        writeln!(f, "name:    {}", self.name)?;
        writeln!(f, "type:    {}", self.kind)?;
        writeln!(f, "arch:    {}", self.arch)?;
        writeln!(f, "epoch:   {}", self.epoch)?;
        writeln!(f, "version: {}", self.version)?;
        writeln!(f, "release: {}", self.release)?;
        writeln!(f, "license: {}", self.license)?;
        write!(f, "------------------------------")?;

        Ok(())
    }
}
