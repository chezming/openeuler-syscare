use std::ffi::OsString;
use std::path::PathBuf;
use std::fs::File;
use std::io::BufReader;

use crate::util::fs;
use crate::util::os_str::OsStrSplit;
use crate::util::raw_line::RawLines;

pub struct Mounts {
    lines: RawLines<BufReader<File>>,
}

impl Mounts {
    pub fn new() -> std::io::Result<Self> {
        const MOUNT_INFO: &str = "/proc/self/mountinfo";
        Ok(Self {
            lines: RawLines::from(BufReader::new(fs::open_file(MOUNT_INFO)?))
        })
    }
}

impl Iterator for Mounts {
    type Item = MountRecord;

    fn next(&mut self) -> Option<Self::Item> {
        self.lines.next()
            .and_then(Result::ok)
            .and_then(|s| MountRecord::try_from(s).ok())
    }
}

type MountRecordParseError = ();

#[derive(Debug)]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct MountRecord {
    pub source:     OsString,
    pub target:     PathBuf,
    pub filesystem: OsString,
    pub options:    OsString,
}

impl TryFrom<OsString> for MountRecord {
    type Error = MountRecordParseError;

    fn try_from(s: OsString) -> Result<Self, Self::Error> {
        if s.len() == 0 {
            return Err(());
        }

        let record = s.split(' ').collect::<Vec<_>>();
        if record.len() != 11 {
            return Err(());
        }

        Ok(Self {
            source:     OsString::from(record[9]),
            target:     PathBuf::from(record[4]),
            filesystem: OsString::from(record[8]),
            options:    OsString::from(record[10]),
        })
    }
}

impl std::fmt::Display for MountRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}, {}, {}, {}",
            self.target.display(),
            self.source.to_string_lossy(),
            self.filesystem.to_string_lossy(),
            self.options.to_string_lossy()
        ))
    }
}
