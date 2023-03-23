use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::fs::{Metadata, Permissions, ReadDir, File, FileType};

use super::os_str::OsStrExt;

trait RewriteError {
    fn rewrite_err(self, err_msg: String) -> Self;
}

impl<T> RewriteError for std::io::Result<T> {
    #[inline]
    fn rewrite_err(self, err_msg: String) -> Self {
        self.map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("{}, {}", err_msg, e.to_string().to_lowercase())
            )
        })
    }
}

/* std::fs functions */
#[inline]
pub fn read<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<u8>> {
    std::fs::read(path.as_ref()).rewrite_err(
        format!("Cannot read \"{}\"",
            path.as_ref().display()
        )
    )
}

#[inline]
pub fn read_to_string<P: AsRef<Path>>(path: P) -> std::io::Result<String> {
    std::fs::read_to_string(path.as_ref()).rewrite_err(
        format!("Cannot read \"{}\"",
            path.as_ref().display()
        )
    )
}

#[inline]
pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> std::io::Result<()> {
    std::fs::write(path.as_ref(), contents).rewrite_err(
        format!("Cannot write \"{}\"",
            path.as_ref().display()
        )
    )
}

#[inline]
pub fn remove_file<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    std::fs::remove_file(path.as_ref()).rewrite_err(
        format!("Cannot remove \"{}\"",
            path.as_ref().display()
        )
    )
}

#[inline]
pub fn metadata<P: AsRef<Path>>(path: P) -> std::io::Result<Metadata> {
    std::fs::metadata(path.as_ref()).rewrite_err(
        format!("Cannot access \"{}\"", path.as_ref().display())
    )
}

#[inline]
pub fn symlink_metadata<P: AsRef<Path>>(path: P) -> std::io::Result<Metadata> {
    std::fs::symlink_metadata(path.as_ref()).rewrite_err(
        format!("Cannot access \"{}\"", path.as_ref().display())
    )
}

#[inline]
pub fn rename<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> std::io::Result<()> {
    std::fs::rename(&from, &to).rewrite_err(
        format!("Cannot rename \"{}\" to \"{}\"",
            from.as_ref().display(),
            to.as_ref().display()
        )
    )
}

#[inline]
pub fn copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> std::io::Result<u64> {
    std::fs::copy(&from, &to).rewrite_err(
        format!("Cannot copy \"{}\" to \"{}\"",
            from.as_ref().display(),
            to.as_ref().display()
        )
    )
}

#[inline]
pub fn hard_link<P: AsRef<Path>, Q: AsRef<Path>>(original: P, link: Q) -> std::io::Result<()> {
    std::fs::hard_link(original.as_ref(), link.as_ref()).rewrite_err(
        format!("Cannot link \"{}\" to \"{}\"",
            original.as_ref().display(),
            link.as_ref().display()
        )
    )
}

#[inline]
pub fn soft_link<P: AsRef<Path>, Q: AsRef<Path>>(original: P, link: Q) -> std::io::Result<()> {
    // std::fs::soft_link() is deprecated, use std::os::unix::fs::symlink instead
    std::os::unix::fs::symlink(original.as_ref(), link.as_ref()).rewrite_err(
        format!("Cannot link \"{}\" to \"{}\"",
            original.as_ref().display(),
            link.as_ref().display()
        )
    )
}

#[inline]
pub fn read_link<P: AsRef<Path>>(path: P) -> std::io::Result<PathBuf> {
    std::fs::read_link(path.as_ref()).rewrite_err(
        format!("Cannot read symbol link \"{}\"",
            path.as_ref().display(),
        )
    )
}

#[inline]
pub fn canonicalize<P: AsRef<Path>>(path: P) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(path.as_ref()).rewrite_err(
        format!("Cannot canonicalize \"{}\"",
            path.as_ref().display(),
        )
    )
}

#[inline]
pub fn create_dir<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    std::fs::create_dir(path.as_ref()).rewrite_err(
        format!("Cannot create directory \"{}\"",
            path.as_ref().display(),
        )
    )
}

#[inline]
pub fn create_dir_all<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    std::fs::create_dir_all(path.as_ref()).rewrite_err(
        format!("Cannot create directory \"{}\"",
            path.as_ref().display(),
        )
    )
}

#[inline]
pub fn remove_dir<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    std::fs::remove_dir(path.as_ref()).rewrite_err(
        format!("Cannot remove directory \"{}\"",
            path.as_ref().display(),
        )
    )
}

#[inline]
pub fn remove_dir_all<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    std::fs::remove_dir_all(path.as_ref()).rewrite_err(
        format!("Cannot remove directory \"{}\"",
            path.as_ref().display(),
        )
    )
}

#[inline]
pub fn read_dir<P: AsRef<Path>>(path: P) -> std::io::Result<ReadDir> {
    std::fs::read_dir(path.as_ref()).rewrite_err(
        format!("Cannot read directory \"{}\"",
            path.as_ref().display(),
        )
    )
}

#[inline]
pub fn set_permissions<P: AsRef<Path>>(path: P, perm: Permissions) -> std::io::Result<()> {
    std::fs::set_permissions(path.as_ref(), perm).rewrite_err(
        format!("Cannot set permission to \"{}\"",
            path.as_ref().display(),
        )
    )
}

/* Extended functions */
pub fn create_file<P: AsRef<Path>>(path: P) -> std::io::Result<File> {
    std::fs::File::create(&path).rewrite_err(
        format!("Cannot create file \"{}\"",
            path.as_ref().display(),
        )
    )
}

pub fn open_file<P: AsRef<Path>>(path: P) -> std::io::Result<File> {
    std::fs::File::open(&path).rewrite_err(
        format!("Cannot open file \"{}\"",
            path.as_ref().display(),
        )
    )
}

pub fn file_name<P: AsRef<Path>>(path: P) -> OsString {
    path.as_ref()
        .file_name()
        .map(OsStr::to_os_string)
        .unwrap_or_default()
}

pub fn file_ext<P: AsRef<Path>>(path: P) -> OsString {
    path.as_ref()
        .extension()
        .map(OsStr::to_os_string)
        .unwrap_or_default()
}

#[derive(Clone, Copy)]
pub struct TraverseOptions {
    pub recursive: bool
}

pub fn traverse<P, F>(directory: P, options: TraverseOptions, predicate: F) -> std::io::Result<Vec<PathBuf>>
where
    P: AsRef<Path>,
    F: Fn(&FileType, &Path) -> bool + Copy
{
    let mut results = Vec::new();
    let mut subdirs = Vec::new();

    for dir_entry in read_dir(directory)? {
        let entry     = dir_entry?;
        let file_type = entry.file_type()?;
        let file_path = entry.path();

        if predicate(&file_type, &file_path) {
            results.push(file_path.clone());
        }
        if options.recursive && file_type.is_dir() {
            subdirs.push(file_path);
        }
    }

    for subdir in subdirs {
        results.extend(traverse(subdir, options, predicate)?);
    }

    Ok(results)
}

pub fn list_dirs<P>(directory: P, options: TraverseOptions) -> std::io::Result<Vec<PathBuf>>
where
    P: AsRef<Path>,
{
    traverse(directory, options, |file_type, _| file_type.is_dir())?
        .into_iter()
        .map(canonicalize)
        .collect()
}

pub fn list_files<P>(directory: P, options: TraverseOptions) -> std::io::Result<Vec<PathBuf>>
where
    P: AsRef<Path>,
{
    traverse(directory, options, |file_type, _| file_type.is_file())?
        .into_iter()
        .map(canonicalize)
        .collect()
}

pub fn list_files_by_ext<P, S>(directory: P, ext: S, options: TraverseOptions) -> std::io::Result<Vec<PathBuf>>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>,
{
    traverse(directory, options,
        |file_type, file_path| {
            if !file_type.is_file() {
                return false;
            }
            return file_path.extension()
                .map(|s| s == ext.as_ref())
                .unwrap_or(false);
        }
    )?.into_iter().map(canonicalize).collect()
}

pub fn list_symlinks<P>(directory: P, options: TraverseOptions) -> std::io::Result<Vec<PathBuf>>
where
    P: AsRef<Path>,
{
    traverse(directory, options, |file_type, _| file_type.is_symlink())
}

#[derive(Clone, Copy)]
pub struct FindOptions {
    pub fuzz: bool,
    pub recursive: bool,
}

pub fn find<P, F>(directory: P, options: FindOptions, predicate: F)  -> std::io::Result<Option<PathBuf>>
where
    P: AsRef<Path>,
    F: Fn(&FileType, &Path) -> bool + Copy
{
    let mut subdirs = Vec::new();

    for dir_entry in read_dir(directory)? {
        let entry     = dir_entry?;
        let file_type = entry.file_type()?;
        let file_path = entry.path();

        if predicate(&file_type, &file_path) {
            return Ok(Some(file_path));
        }
        if options.recursive && file_type.is_dir() {
            subdirs.push(file_path);
        }
    }

    for subdir in subdirs {
        if let Some(path) = find(subdir, options, predicate)? {
            return Ok(Some(path));
        }
    }

    Ok(None)
}

pub fn find_dir<P, S>(directory: P, name: S, options: FindOptions,) -> std::io::Result<PathBuf>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>,
{
    let result = find(&directory, options,
        |file_type, file_path| -> bool {
            if !file_type.is_dir() {
                return false;
            }
            if let Some(file_name) = file_path.file_name() {
                if file_name == name.as_ref() {
                    return true;
                }
                else if options.fuzz && file_name.contains(&name) {
                    return true;
                }
            }
            return false;
        }
    )?;

    result.ok_or(
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Cannot find directory \"{}\" from \"{}\"",
                name.as_ref().to_string_lossy(),
                directory.as_ref().display()
            )
       )
    )
}

pub fn find_file<P, S>(directory: P, name: S, options: FindOptions) -> std::io::Result<PathBuf>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>,
{
    let result = find(&directory, options,
        |file_type, file_path| -> bool {
            if !file_type.is_file() {
                return false;
            }
            if let Some(file_name) = file_path.file_name() {
                if file_name == name.as_ref() {
                    return true;
                }
                else if options.fuzz && file_name.contains(&name) {
                    return true;
                }
            }
            return false;
        }
    )?;

    result.ok_or(
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Cannot find file \"{}\" from \"{}\"",
                name.as_ref().to_string_lossy(),
                directory.as_ref().display()
            )
       )
    )
}

pub fn find_file_by_ext<P, S>(directory: P, ext: S, options: FindOptions) -> std::io::Result<PathBuf>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>,
{
    let result = find(&directory, options,
        |file_type: &FileType, file_path: &Path| -> bool {
            if !file_type.is_file() {
                return false;
            }
            if let Some(file_name) = file_path.extension() {
                if file_name == ext.as_ref() {
                    return true;
                }
            }
            return false;
        }
    )?;

    result.ok_or(
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Cannot find file \"*.{}\" from \"{}\"",
                ext.as_ref().to_string_lossy(),
                directory.as_ref().display()
            )
       )
    )
}

pub fn find_symlink<P, S>(directory: P, name: S, options: FindOptions) -> std::io::Result<PathBuf>
where
    P: AsRef<Path>,
    S: AsRef<OsStr>,
{
    let result = find(&directory, options,
        |file_type, file_path| -> bool {
            if !file_type.is_symlink() {
                return false;
            }
            if let Some(file_name) = file_path.file_name() {
                if file_name == name.as_ref() {
                    return true;
                }
                else if options.fuzz && file_name.contains(&name) {
                    return true;
                }
            }
            return false;
        }
    )?;

    result.ok_or(
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Cannot find symlink \"{}\" from \"{}\"",
                name.as_ref().to_string_lossy(),
                directory.as_ref().display()
            )
       )
    )
}

pub fn copy_dir_contents<P: AsRef<Path>, Q: AsRef<Path>>(src_dir: P, dst_dir: Q) -> std::io::Result<()> {
    for src_file in list_files(src_dir, TraverseOptions { recursive: true })? {
        let dst_file = dst_dir.as_ref().join(src_file.file_name().unwrap_or_default());

        copy(src_file, dst_file)?;
    }

    Ok(())
}

pub fn sync() {
    unsafe { libc::sync() }
}
