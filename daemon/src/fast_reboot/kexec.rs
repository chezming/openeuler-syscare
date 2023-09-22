use std::ffi::OsString;
use std::path::Path;

use anyhow::{ensure, Result};

use lazy_static::lazy_static;
use syscare_common::util::{
    ext_cmd::{ExternCommand, ExternCommandArgs},
    os_str::OsStringExt,
};

lazy_static! {
    static ref KEXEC: ExternCommand = ExternCommand::new("kexec");
    static ref SYSTEMCTL: ExternCommand = ExternCommand::new("systemctl");
}

pub fn load<P, Q>(kernel: P, initramfs: Q) -> Result<()>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let exit_status = KEXEC.execvp(
        ExternCommandArgs::new()
            .arg("--load")
            .arg(kernel.as_ref())
            .arg(OsString::from("--initrd=").concat(initramfs.as_ref()))
            .arg("--reuse-cmdline"),
    )?;
    ensure!(
        exit_status.exit_code() == 0,
        format!("{}", exit_status.stderr().to_string_lossy())
    );
    Ok(())
}

pub fn unload() -> Result<()> {
    let exit_status = KEXEC.execvp(ExternCommandArgs::new().arg("--unload"))?;
    ensure!(
        exit_status.exit_code() == 0,
        format!("{}", exit_status.stderr().to_string_lossy())
    );
    Ok(())
}

pub fn systemd_exec() -> Result<()> {
    let exit_status = SYSTEMCTL.execvp(ExternCommandArgs::new().arg("kexec"))?;
    ensure!(
        exit_status.exit_code() == 0,
        format!("{}", exit_status.stderr().to_string_lossy())
    );
    Ok(())
}

pub fn force_exec() -> Result<()> {
    let exit_status = KEXEC.execvp(ExternCommandArgs::new().arg("--exec"))?;
    ensure!(
        exit_status.exit_code() == 0,
        format!("{}", exit_status.stderr().to_string_lossy())
    );
    Ok(())
}
