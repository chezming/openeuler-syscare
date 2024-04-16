// SPDX-License-Identifier: Mulan PSL v2
/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
 * syscared is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *         http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use std::{
    ffi::OsStr,
    fmt::Write,
    os::linux::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, ensure, Context, Result};
use indexmap::{indexset, IndexMap, IndexSet};
use log::{debug, info, warn};
use parking_lot::RwLock;
use uuid::Uuid;

use syscare_abi::PatchStatus;
use syscare_common::{fs, util::digest};

use crate::patch::{driver::upatch::entity::PatchEntity, entity::UserPatch};

mod entity;
mod monitor;
mod sys;
mod target;

use monitor::UserPatchMonitor;
use target::PatchTarget;

pub struct UserPatchDriver {
    status_map: IndexMap<Uuid, PatchStatus>,
    target_map: Arc<RwLock<IndexMap<PathBuf, PatchTarget>>>,
    monitor: UserPatchMonitor,
}

impl UserPatchDriver {
    pub fn new() -> Result<Self> {
        let status_map = IndexMap::new();
        let target_map = Arc::new(RwLock::new(IndexMap::new()));
        let monitor = UserPatchMonitor::new(target_map.clone(), Self::patch_new_process)?;
        let instance = Self {
            status_map,
            target_map,
            monitor,
        };

        Ok(instance)
    }
}

impl UserPatchDriver {
    #[inline]
    fn get_patch_status(&self, uuid: &Uuid) -> PatchStatus {
        self.status_map
            .get(uuid)
            .copied()
            .unwrap_or(PatchStatus::NotApplied)
    }

    #[inline]
    fn set_patch_status(&mut self, uuid: &Uuid, value: PatchStatus) {
        *self.status_map.entry(*uuid).or_default() = value;
    }

    fn remove_patch_status(&mut self, uuid: &Uuid) {
        self.status_map.remove(uuid);
    }
}

impl UserPatchDriver {
    fn add_patch_target(&mut self, patch: &UserPatch) {
        let target_elf = patch.target_elf.as_path();
        let mut target_map = self.target_map.write();

        if !target_map.contains_key(target_elf) {
            target_map.insert(target_elf.to_path_buf(), PatchTarget::default());
        }
    }

    fn remove_patch_target(&mut self, patch: &UserPatch) {
        let target_elf = patch.target_elf.as_path();
        let mut target_map = self.target_map.write();

        if let Some(target) = target_map.get_mut(target_elf) {
            if !target.is_patched() {
                target_map.remove(target_elf);
            }
        }
    }
}

impl UserPatchDriver {
    fn check_consistency(patch: &UserPatch) -> Result<()> {
        let real_checksum = digest::file(&patch.patch_file)?;
        debug!("Target checksum: '{}'", patch.checksum);
        debug!("Expected checksum: '{}'", real_checksum);

        ensure!(
            patch.checksum == real_checksum,
            "Upatch: Patch consistency check failed",
        );
        Ok(())
    }

    fn check_compatiblity(_patch: &UserPatch) -> Result<()> {
        Ok(())
    }

    pub fn check_conflict_functions(&self, patch: &UserPatch) -> Result<()> {
        let conflict_patches = match self.target_map.read().get(&patch.target_elf) {
            Some(target) => target
                .get_conflicts(&patch.functions)
                .into_iter()
                .map(|record| record.uuid)
                .collect(),
            None => indexset! {},
        };

        ensure!(conflict_patches.is_empty(), {
            let mut err_msg = String::new();

            writeln!(&mut err_msg, "Upatch: Patch is conflicted with")?;
            for uuid in conflict_patches.into_iter() {
                writeln!(&mut err_msg, "* Patch '{}'", uuid)?;
            }
            err_msg.pop();

            err_msg
        });
        Ok(())
    }

    pub fn check_override_functions(&self, patch: &UserPatch) -> Result<()> {
        let override_patches = match self.target_map.read().get(&patch.target_elf) {
            Some(target) => target
                .get_overrides(&patch.uuid, &patch.functions)
                .into_iter()
                .map(|record| record.uuid)
                .collect(),
            None => indexset! {},
        };

        ensure!(override_patches.is_empty(), {
            let mut err_msg = String::new();

            writeln!(&mut err_msg, "Upatch: Patch is overrided by")?;
            for uuid in override_patches.into_iter() {
                writeln!(&mut err_msg, "* Patch '{}'", uuid)?;
            }
            err_msg.pop();

            err_msg
        });

        Ok(())
    }
}

impl UserPatchDriver {
    #[inline]
    fn parse_process_id(proc_path: &Path) -> Option<i32> {
        proc_path
            .file_name()
            .and_then(OsStr::to_str)
            .map(str::parse)
            .and_then(Result::ok)
    }

    fn find_target_process<P: AsRef<Path>>(target_elf: P) -> Result<IndexSet<i32>> {
        let mut target_pids = IndexSet::new();
        let target_path = target_elf.as_ref();
        let target_inode = target_path.metadata()?.st_ino();

        for proc_path in fs::list_dirs("/proc", fs::TraverseOptions { recursive: false })? {
            let pid = match Self::parse_process_id(&proc_path) {
                Some(pid) => pid,
                None => continue,
            };
            let exec_path = match fs::read_link(format!("/proc/{}/exe", pid)) {
                Ok(file_path) => file_path,
                Err(_) => continue,
            };
            // Try to match binary path
            if exec_path == target_path {
                target_pids.insert(pid);
                continue;
            }
            // Try to match mapped files
            let map_files = fs::list_symlinks(
                format!("/proc/{}/map_files", pid),
                fs::TraverseOptions { recursive: false },
            )?;
            for mapped_file in map_files {
                if let Ok(mapped_inode) = mapped_file
                    .read_link()
                    .and_then(|file_path| Ok(file_path.metadata()?.st_ino()))
                {
                    if mapped_inode == target_inode {
                        target_pids.insert(pid);
                        break;
                    }
                };
            }
        }

        Ok(target_pids)
    }

    fn patch_new_process(
        target_map: Arc<RwLock<IndexMap<PathBuf, PatchTarget>>>,
        target_elf: &Path,
    ) {
        let process_list = match Self::find_target_process(target_elf) {
            Ok(pids) => pids,
            Err(_) => return,
        };

        let mut target_map = target_map.write();
        let patch_target = match target_map.get_mut(target_elf) {
            Some(target) => target,
            None => return,
        };

        for (patch_uuid, patch_entity) in patch_target.all_patches() {
            patch_entity.clean_dead_process(&process_list);

            // Active patch
            let need_actived = patch_entity.need_actived(&process_list);
            if !need_actived.is_empty() {
                debug!(
                    "Upatch: Activating patch '{}' ({}) for process {:?}",
                    patch_uuid,
                    target_elf.display(),
                    need_actived,
                );
            }

            let ignore_list = patch_entity.need_ignored(&process_list);
            for pid in need_actived {
                if ignore_list.contains(&pid) {
                    continue;
                }
                match sys::active_patch(patch_uuid, pid, target_elf, &patch_entity.patch_file) {
                    Ok(_) => patch_entity.add_process(pid),
                    Err(e) => {
                        warn!(
                            "Upatch: Failed to active patch '{}' for process {}, {}",
                            patch_uuid,
                            pid,
                            e.to_string().to_lowercase(),
                        );
                        patch_entity.ignore_process(pid)
                    }
                }
            }
        }
    }
}

impl UserPatchDriver {
    pub fn status(&self, patch: &UserPatch) -> Result<PatchStatus> {
        Ok(self.get_patch_status(&patch.uuid))
    }

    pub fn check(&self, patch: &UserPatch) -> Result<()> {
        Self::check_consistency(patch)?;
        Self::check_compatiblity(patch)?;

        Ok(())
    }

    pub fn apply(&mut self, patch: &UserPatch) -> Result<()> {
        info!(
            "Upatch: Applying patch '{}' ({})",
            patch.uuid,
            patch.patch_file.display()
        );

        self.add_patch_target(patch);
        self.set_patch_status(&patch.uuid, PatchStatus::Deactived);

        Ok(())
    }

    pub fn remove(&mut self, patch: &UserPatch) -> Result<()> {
        info!(
            "Upatch: Removing patch '{}' ({})",
            patch.uuid,
            patch.patch_file.display()
        );

        self.remove_patch_target(patch);
        self.remove_patch_status(&patch.uuid);

        Ok(())
    }

    pub fn active(&mut self, patch: &UserPatch) -> Result<()> {
        let patch_uuid = &patch.uuid;
        let patch_file = patch.patch_file.as_path();
        let patch_functions = patch.functions.as_slice();
        let target_elf = patch.target_elf.as_path();

        let process_list = Self::find_target_process(target_elf)?;

        let mut target_map = self.target_map.write();
        let patch_target = target_map
            .get_mut(target_elf)
            .context("Upatch: Cannot find patch target")?;
        let mut patch_entity = match patch_target.get_patch(patch_uuid) {
            Some(_) => bail!("Upatch: Patch is already exist"),
            None => PatchEntity::new(patch_file.to_path_buf()),
        };

        // Active patch
        info!(
            "Upatch: Activating patch '{}' ({}) for {}",
            patch_uuid,
            patch_file.display(),
            target_elf.display(),
        );
        let mut results = Vec::new();
        for pid in patch_entity.need_actived(&process_list) {
            let result = sys::active_patch(patch_uuid, pid, target_elf, patch_file);
            match result {
                Ok(_) => patch_entity.add_process(pid),
                Err(_) => patch_entity.ignore_process(pid),
            }
            results.push((pid, result));
        }

        // Check results, return error if all process fails
        match results.iter().any(|(_, result)| result.is_ok()) {
            true => {
                for (pid, result) in &results {
                    if let Err(e) = result {
                        warn!(
                            "Upatch: Failed to active patch '{}' for process {}, {}",
                            patch_uuid,
                            pid,
                            e.to_string().to_lowercase(),
                        );
                    }
                }
            }
            false => {
                let mut err_msg = String::new();

                writeln!(err_msg, "Upatch: Failed to active patch")?;
                for (pid, result) in &results {
                    if let Err(e) = result {
                        writeln!(err_msg, "* Process {}: {}", pid, e)?;
                    }
                }
                bail!(err_msg);
            }
        }

        // If target is no patched before, start watching it
        let need_start_watch = !patch_target.is_patched();

        // Apply patch to target
        patch_target.add_patch(*patch_uuid, patch_entity);
        patch_target.add_functions(*patch_uuid, patch_functions);

        // Drop the lock
        drop(target_map);

        if need_start_watch {
            self.monitor.watch_file(target_elf)?;
        }
        self.set_patch_status(patch_uuid, PatchStatus::Actived);

        Ok(())
    }

    pub fn deactive(&mut self, patch: &UserPatch) -> Result<()> {
        let patch_uuid = &patch.uuid;
        let patch_file = patch.patch_file.as_path();
        let patch_functions = patch.functions.as_slice();
        let target_elf = patch.target_elf.as_path();

        let process_list = Self::find_target_process(target_elf)?;

        let mut target_map = self.target_map.write();
        let patch_target = target_map
            .get_mut(target_elf)
            .context("Upatch: Cannot find patch target")?;
        let patch_entity = patch_target
            .get_patch(patch_uuid)
            .context("Upatch: Cannot find patch entity")?;

        // Remove dead process
        patch_entity.clean_dead_process(&process_list);

        // Deactive patch
        info!(
            "Upatch: Deactivating patch '{}' ({}) for {}",
            patch_uuid,
            patch_file.display(),
            target_elf.display(),
        );
        let mut results = Vec::new();
        let ignore_list = patch_entity.need_ignored(&process_list);
        for pid in patch_entity.need_deactived(&process_list) {
            if ignore_list.contains(&pid) {
                continue;
            }
            let result = sys::deactive_patch(patch_uuid, pid, target_elf, patch_file);
            if result.is_ok() {
                patch_entity.remove_process(pid)
            }
            results.push((pid, result));
        }

        // Check results, return error if any process failes
        match results.iter().any(|(_, result)| result.is_err()) {
            true => {
                let mut err_msg = String::new();

                writeln!(err_msg, "Upatch: Failed to deactive patch")?;
                for (pid, result) in &results {
                    if let Err(e) = result {
                        writeln!(err_msg, "* Process {}: {}", pid, e)?;
                    }
                }
                bail!(err_msg)
            }
            false => {
                for (pid, result) in &results {
                    if let Err(e) = result {
                        warn!(
                            "Upatch: Failed to deactive patch '{}' for process {}, {}",
                            patch_uuid,
                            pid,
                            e.to_string().to_lowercase(),
                        );
                    }
                }
            }
        }

        // Remove patch functions from target
        patch_target.remove_patch(patch_uuid);
        patch_target.remove_functions(patch_uuid, patch_functions);

        // If target is no longer patched, stop watching it
        let need_stop_watch = !patch_target.is_patched();

        drop(target_map);

        if need_stop_watch {
            self.monitor.ignore_file(target_elf)?;
        }
        self.set_patch_status(patch_uuid, PatchStatus::Deactived);

        Ok(())
    }
}
