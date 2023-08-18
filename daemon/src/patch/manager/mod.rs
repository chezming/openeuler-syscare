use std::{
    collections::HashMap,
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use parking_lot::RwLock;

use syscare_abi::{PatchStatus, PatchType};
use syscare_common::util::{fs, serde};

mod info_ext;
mod kernel_patch_driver;
mod patch;
mod patch_driver;
mod user_patch_driver;

use kernel_patch_driver::KernelPatchDriver;
pub use patch::Patch;
use patch_driver::PatchDriver;
use user_patch_driver::UserPatchDriver;

const PATCH_INSTALL_DIR: &str = "patches";
const PATCH_STATUS_FILE: &str = "patch_status";

type Transition = (PatchStatus, PatchStatus);
type TransitionAction = &'static (dyn Fn(&PatchManager, &Patch) -> Result<()> + Sync);

const PATCH_APPLY: TransitionAction = &PatchManager::driver_apply_patch;
const PATCH_REMOVE: TransitionAction = &PatchManager::driver_remove_patch;
const PATCH_ACTIVE: TransitionAction = &PatchManager::driver_active_patch;
const PATCH_DEACTIVE: TransitionAction = &PatchManager::driver_deactive_patch;
const PATCH_ACCEPT: TransitionAction = &PatchManager::do_patch_accept;
const PATCH_DECLINE: TransitionAction = &PatchManager::do_patch_decline;

lazy_static! {
    static ref DRIVER_MAP: IndexMap<PatchType, Box<dyn PatchDriver>> = IndexMap::from([
        (
            PatchType::KernelPatch,
            Box::new(KernelPatchDriver) as Box<dyn PatchDriver>
        ),
        (
            PatchType::UserPatch,
            Box::new(UserPatchDriver) as Box<dyn PatchDriver>
        ),
    ]);
    static ref TRANSITION_MAP: IndexMap<Transition, Vec<TransitionAction>> = IndexMap::from([
        (
            (PatchStatus::NotApplied, PatchStatus::Deactived),
            vec![PATCH_APPLY]
        ),
        (
            (PatchStatus::NotApplied, PatchStatus::Actived),
            vec![PATCH_APPLY, PATCH_ACTIVE]
        ),
        (
            (PatchStatus::NotApplied, PatchStatus::Accepted),
            vec![PATCH_APPLY, PATCH_ACTIVE, PATCH_ACCEPT]
        ),
        (
            (PatchStatus::Deactived, PatchStatus::NotApplied),
            vec![PATCH_REMOVE]
        ),
        (
            (PatchStatus::Deactived, PatchStatus::Actived),
            vec![PATCH_ACTIVE]
        ),
        (
            (PatchStatus::Deactived, PatchStatus::Accepted),
            vec![PATCH_ACTIVE, PATCH_ACCEPT]
        ),
        (
            (PatchStatus::Actived, PatchStatus::NotApplied),
            vec![PATCH_DEACTIVE, PATCH_REMOVE]
        ),
        (
            (PatchStatus::Actived, PatchStatus::Deactived),
            vec![PATCH_DEACTIVE]
        ),
        (
            (PatchStatus::Actived, PatchStatus::Accepted),
            vec![PATCH_ACCEPT]
        ),
        (
            (PatchStatus::Accepted, PatchStatus::NotApplied),
            vec![PATCH_DECLINE, PATCH_DEACTIVE, PATCH_REMOVE]
        ),
        (
            (PatchStatus::Accepted, PatchStatus::Deactived),
            vec![PATCH_DECLINE, PATCH_DEACTIVE]
        ),
        (
            (PatchStatus::Accepted, PatchStatus::Actived),
            vec![PATCH_DECLINE]
        ),
    ]);
}

struct PatchEntry {
    patch: Arc<Patch>,
    status: PatchStatus,
}

pub struct PatchManager {
    patch_root: RwLock<PathBuf>,
    entry_map: RwLock<IndexMap<String, PatchEntry>>,
}

impl PatchManager {
    pub fn new() -> Self {
        Self {
            patch_root: Default::default(),
            entry_map: Default::default(),
        }
    }

    pub fn initialize<P: AsRef<Path>>(&self, patch_root: P) -> Result<()> {
        *self.patch_root.write() = patch_root.as_ref().to_path_buf();

        self.rescan()
    }

    pub fn match_patch(&self, identifier: String) -> Result<Vec<Arc<Patch>>> {
        debug!("Matching patch by \"{}\"...", identifier);
        let match_result = match self.find_patch_by_uuid(&identifier) {
            Ok(patch) => vec![patch],
            Err(_) => self.find_patch_by_name(&identifier)?,
        };

        for patch in &match_result {
            debug!("Matched \"{}\"", patch)
        }
        debug!("Found {} patch(es)", match_result.len());

        Ok(match_result)
    }

    pub fn get_patch_list(&self) -> Vec<Arc<Patch>> {
        self.entry_map
            .read()
            .values()
            .map(|entry| entry.patch.clone())
            .collect::<Vec<_>>()
    }

    pub fn get_patch_status(&self, patch: &Patch) -> Result<PatchStatus> {
        let mut status = self
            .entry_map
            .read()
            .get(&patch.uuid)
            .with_context(|| format!("Cannot find patch \"{}\"", patch))?
            .status;
        if status == PatchStatus::Unknown {
            status = self.driver_get_patch_status(patch)?;
            self.set_patch_status(patch, status)
                .with_context(|| format!("Failed to set patch \"{}\" status", patch))?;
        }

        Ok(status)
    }

    pub fn set_patch_status(&self, patch: &Patch, value: PatchStatus) -> Result<()> {
        if value == PatchStatus::Unknown {
            bail!("Cannot set patch {} status to {}", patch, value);
        }
        self.entry_map
            .write()
            .get_mut(&patch.uuid)
            .with_context(|| format!("Cannot find patch \"{}\"", patch))?
            .status = value;

        Ok(())
    }

    pub fn apply_patch(&self, patch: &Patch) -> Result<PatchStatus> {
        info!("Apply patch \"{}\"", patch);
        self.do_status_transition(patch, PatchStatus::Actived)
    }

    pub fn remove_patch(&self, patch: &Patch) -> Result<PatchStatus> {
        info!("Remove patch \"{}\"", patch);
        self.do_status_transition(patch, PatchStatus::NotApplied)
    }

    pub fn active_patch(&self, patch: &Patch) -> Result<PatchStatus> {
        info!("Active patch \"{}\"", patch);
        let current_status = self.get_patch_status(patch)?;
        let target_status = PatchStatus::Actived;

        if current_status == PatchStatus::NotApplied {
            bail!("Patch \"{}\" is not applied", patch);
        }
        self.do_status_transition(patch, target_status)
    }

    pub fn deactive_patch(&self, patch: &Patch) -> Result<PatchStatus> {
        info!("Deactive patch \"{}\"", patch);
        let current_status = self.get_patch_status(patch)?;
        let target_status = PatchStatus::Deactived;

        if current_status == PatchStatus::NotApplied {
            bail!("Patch \"{}\" is not applied", patch);
        }
        self.do_status_transition(patch, target_status)
    }

    pub fn accept_patch(&self, patch: &Patch) -> Result<PatchStatus> {
        info!("Accept patch \"{}\"", patch);
        let current_status = self.get_patch_status(patch)?;
        let target_status = PatchStatus::Accepted;

        if current_status != PatchStatus::Actived {
            bail!("Patch \"{}\" is not actived", patch);
        }
        self.do_status_transition(patch, target_status)
    }

    pub fn save_patch_status(&self) -> Result<()> {
        info!("Saving all patch status...");

        debug!("Updating all patch status...");
        for patch in self.get_patch_list() {
            debug!("Update patch \"{}\" status", patch);
            self.get_patch_status(&patch)?;
        }

        let mut status_map = HashMap::new();
        let entry_map = self.entry_map.read();
        for (uuid, entry) in entry_map.iter() {
            status_map.insert(uuid, entry.status);
        }

        debug!("Writing patch status file");
        let status_file = self.patch_root.read().join(PATCH_STATUS_FILE);
        serde::serialize(&status_map, status_file).context("Failed to write patch status file")?;

        info!("All patch status were saved");
        Ok(())
    }

    pub fn restore_patch_status(&self, accepted_only: bool) -> Result<()> {
        debug!("Reading patch status from file...");
        let status_file = self.patch_root.read().join(PATCH_STATUS_FILE);
        let read_result = serde::deserialize::<HashMap<String, PatchStatus>, _>(status_file);
        let status_map = match read_result {
            Ok(map) => map,
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!("Cannot find patch status file");
                return Ok(());
            }
            Err(_) => {
                bail!("Failed to read patch status");
            }
        };

        /*
         * To ensure that we won't load multiple patches for same target at the same time,
         * we take a sort operation of the status to make sure do REMOVE operation at first
         */
        info!("Restoring all patch status...");
        let mut restore_list = status_map
            .into_iter()
            .filter_map(|(uuid, status)| match self.find_patch_by_uuid(&uuid) {
                Ok(patch) => {
                    if accepted_only && (status != PatchStatus::Accepted) {
                        info!(
                            "Skipped patch \"{}\", status is not \"{}\"",
                            patch,
                            PatchStatus::Accepted
                        );
                        return None;
                    }
                    Some((patch, status))
                }
                Err(e) => {
                    error!("{:?}", e);
                    None
                }
            })
            .collect::<Vec<_>>();
        restore_list.sort_by(|(lhs_patch, lhs_status), (rhs_patch, rhs_status)| {
            match lhs_status.cmp(rhs_status) {
                std::cmp::Ordering::Less => std::cmp::Ordering::Less,
                std::cmp::Ordering::Equal => lhs_patch.cmp(rhs_patch),
                std::cmp::Ordering::Greater => std::cmp::Ordering::Greater,
            }
        });

        for (patch, target_status) in restore_list {
            debug!(
                "Restore patch \"{}\" status to \"{}\"",
                patch, target_status
            );
            self.do_status_transition(&patch, target_status)?;
        }
        info!("All patch status were restored");

        Ok(())
    }

    pub fn rescan(&self) -> Result<()> {
        let patch_install_dir = self.patch_root.read().join(PATCH_INSTALL_DIR);
        let mut entry_map = self.entry_map.write();

        // Add new patches
        for (uuid, entry) in Self::scan_patches(patch_install_dir)? {
            if !entry_map.contains_key(&uuid) {
                entry_map.insert(uuid, entry);
            }
        }
        // Sort patches by its entity name
        entry_map.sort_by(|_, lhs_entry, _, rhs_entry| {
            lhs_entry
                .patch
                .entity_name
                .cmp(&rhs_entry.patch.entity_name)
        });

        Ok(())
    }

    pub(super) fn do_status_transition(
        &self,
        patch: &Patch,
        status: PatchStatus,
    ) -> Result<PatchStatus> {
        let current_status = self.get_patch_status(patch)?;
        let target_status = status;
        if current_status == target_status {
            debug!(
                "Patch \"{}\": Current status is already \"{}\"",
                patch, target_status,
            );
            return Ok(target_status);
        }

        match TRANSITION_MAP.get(&(current_status, target_status)) {
            Some(action_list) => {
                debug!(
                    "Patch \"{}\": Switching status from \"{}\" to \"{}\"",
                    patch, current_status, status
                );
                for action in action_list {
                    action(self, patch)?;
                }
            }
            None => {
                warn!(
                    "Patch \"{}\": Ignored invalid status transition from \"{}\" to \"{}\"",
                    patch, current_status, status
                );
            }
        }

        let new_status = self.get_patch_status(patch)?;
        if new_status != status {
            bail!("Patch \"{}\" does not reached \"{}\" status", patch, status);
        }

        Ok(new_status)
    }
}

impl PatchManager {
    fn scan_patches<P: AsRef<Path>>(directory: P) -> Result<Vec<(String, PatchEntry)>> {
        const TRAVERSE_OPTION: fs::TraverseOptions = fs::TraverseOptions { recursive: false };

        let mut patch_list = Vec::new();

        info!(
            "Scanning patches from \"{}\"...",
            directory.as_ref().display()
        );
        for patch_root in fs::list_dirs(directory, TRAVERSE_OPTION)? {
            let read_result = Patch::read_from(&patch_root).with_context(|| {
                format!(
                    "Failed to load patch metadata from \"{}\"",
                    patch_root.display()
                )
            });
            match read_result {
                Ok(patches) => {
                    for patch in patches {
                        debug!("Detected patch \"{}\"", patch);
                        patch_list.push((
                            patch.uuid.clone(),
                            PatchEntry {
                                patch: Arc::new(patch),
                                status: PatchStatus::Unknown,
                            },
                        ));
                    }
                }
                Err(e) => error!("{:?}", e),
            }
        }
        info!("Found {} patch(es)", patch_list.len());

        Ok(patch_list)
    }

    fn find_patch_by_uuid(&self, uuid: &str) -> Result<Arc<Patch>> {
        self.entry_map
            .read()
            .get(uuid)
            .map(|entry| entry.patch.clone())
            .with_context(|| format!("Cannot find patch by uuid {{{}}}", uuid))
    }

    fn find_patch_by_name(&self, identifier: &str) -> Result<Vec<Arc<Patch>>> {
        let match_result = self
            .entry_map
            .read()
            .values()
            .filter_map(|entry| {
                let patch = &entry.patch;
                let is_matched = (identifier == patch.entity_name)
                    || (identifier == patch.patch_name)
                    || (identifier == patch.target_name);
                match is_matched {
                    true => Some(patch.clone()),
                    false => None,
                }
            })
            .collect::<Vec<_>>();

        if match_result.is_empty() {
            bail!("Cannot match any patch of \"{}\"", identifier);
        }
        Ok(match_result)
    }
}

impl PatchManager {
    fn call_driver<T, U>(&self, patch: &Patch, driver_action: T) -> Result<U>
    where
        T: FnOnce(&'static dyn PatchDriver, &Patch) -> Result<U>,
    {
        let patch_type = patch.kind();
        let driver = DRIVER_MAP
            .get(&patch_type)
            .map(Box::deref)
            .with_context(|| format!("Failed to get driver of {}", patch_type))?;

        driver_action(driver, patch)
    }

    fn driver_get_patch_status(&self, patch: &Patch) -> Result<PatchStatus> {
        self.call_driver(patch, PatchDriver::status)
            .with_context(|| format!("Driver: Failed to get patch \"{}\" status", patch))
    }

    fn driver_apply_patch(&self, patch: &Patch) -> Result<()> {
        self.call_driver(patch, PatchDriver::check)
            .with_context(|| format!("Driver: Patch \"{}\" check failed", patch))?;

        self.call_driver(patch, PatchDriver::apply)
            .with_context(|| format!("Driver: Failed to apply patch \"{}\"", patch))?;

        self.set_patch_status(patch, PatchStatus::Deactived)
    }

    fn driver_remove_patch(&self, patch: &Patch) -> Result<()> {
        self.call_driver(patch, PatchDriver::remove)
            .with_context(|| format!("Driver: Failed to remove patch \"{}\"", patch))?;

        self.set_patch_status(patch, PatchStatus::NotApplied)
    }

    fn driver_active_patch(&self, patch: &Patch) -> Result<()> {
        self.call_driver(patch, PatchDriver::active)
            .with_context(|| format!("Driver: Failed to active patch \"{}\"", patch))?;

        self.set_patch_status(patch, PatchStatus::Actived)
    }

    fn driver_deactive_patch(&self, patch: &Patch) -> Result<()> {
        self.call_driver(patch, PatchDriver::deactive)
            .with_context(|| format!("Driver: Failed to deactive patch \"{}\"", patch))?;

        self.set_patch_status(patch, PatchStatus::Deactived)
    }

    fn do_patch_accept(&self, patch: &Patch) -> Result<()> {
        self.set_patch_status(patch, PatchStatus::Accepted)
    }

    fn do_patch_decline(&self, patch: &Patch) -> Result<()> {
        self.set_patch_status(patch, PatchStatus::Actived)
    }
}
