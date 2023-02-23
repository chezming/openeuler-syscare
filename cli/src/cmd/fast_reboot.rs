use log::{debug, info};

use crate::boot::BootManager;

use super::CommandExecutor;

pub struct FastRebootCommandExecutor;

impl CommandExecutor for FastRebootCommandExecutor {
    fn invoke(&self, _args: &[String]) -> std::io::Result<i32> {
        debug!("Handle Command \"fast-reboot\"");

        info!("Preparing for reboot");
        BootManager::load_kernel()?;

        info!("Syncing mount points");
        BootManager::sync_mount_points()?;

        info!("Rebooting system");
        BootManager::reboot()?;

        debug!("Command \"fast-reboot\" done");
        Ok(0)
    }
}
