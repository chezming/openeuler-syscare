use std::{path::PathBuf, ffi::OsString};

use log::{debug, info};

use crate::os::{Mounts, KExec};
use crate::util::{sys, fs};
use crate::util::os_str::OsStrConcat;

pub struct BootManager;

impl BootManager {
    pub fn sync_mount_points() -> std::io::Result<()> {
        for mount in Mounts::new()? {
            let mount_point = mount.target.as_path();
            let metadata    = fs::metadata(mount_point)?;

            if metadata.is_file() || metadata.is_dir() {
                if let Err(_) = fs::fsync(mount_point) {
                    debug!("Skipped \"{}\"", mount_point.display());
                    continue;
                }
            }
        }
        fs::sync();

        Ok(())
    }

    pub fn load_kernel() -> std::io::Result<()> {
        const BOOT_DIR_NAME:       &str = "/boot";
        const KERNEL_PREFIX:       &str = "vmlinuz-";
        const INITRAMFS_PREFIX:    &str = "initramfs-";
        const INITRAMFS_EXTENSION: &str = ".img";

        let kernel_version = sys::get_kernel_version()?;
        info!("Kernel version:  {}", kernel_version.to_string_lossy());

        let boot_dir = PathBuf::from(BOOT_DIR_NAME);
        let kernel = fs::find_file(
            &boot_dir,
            OsString::from(KERNEL_PREFIX).concat(&kernel_version),
            false,
            false
        )?;
        let initramfs = fs::find_file(
            &boot_dir,
            OsString::from(INITRAMFS_PREFIX).concat(&kernel_version).concat(INITRAMFS_EXTENSION),
            false,
            false
        )?;

        info!("Using kernel:    {}", kernel.display());
        info!("Using initramfs: {}", initramfs.display());
        KExec::load_kernel(kernel, initramfs)?;

        Ok(())
    }

    pub fn reboot() -> std::io::Result<()> {
        KExec::exec_kernel()?;

        Ok(())
    }
}