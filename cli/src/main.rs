// SPDX-License-Identifier: Mulan PSL v2
/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
 * syscare is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *         http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use std::{process::exit, rc::Rc};

use anyhow::Result;
use log::{debug, error, LevelFilter};

mod args;
mod executor;
mod logger;
mod rpc;

use args::Arguments;
use executor::{build::BuildCommandExecutor, patch::PatchCommandExecutor, CommandExecutor};
use logger::Logger;
use rpc::{RpcProxy, RpcRemote};
use syscare_common::os;

const CLI_UMASK: u32 = 0o077;

const SOCKET_FILE_NAME: &str = "syscared.sock";
const PATCH_OP_LOCK_NAME: &str = "patch_op.lock";

struct SyscareCLI {
    args: Arguments,
}

impl SyscareCLI {
    fn start_and_run() -> Result<()> {
        os::umask::set_umask(CLI_UMASK);

        let instance = Self {
            args: Arguments::new()?,
        };
        Logger::initialize(match instance.args.verbose {
            true => LevelFilter::Debug,
            false => LevelFilter::Info,
        })?;
        debug!("Start with {:#?}", instance.args);

        debug!("Initializing remote procedure call client...");
        let socket_file = instance.args.work_dir.join(SOCKET_FILE_NAME);
        let remote = Rc::new(RpcRemote::new(socket_file));

        debug!("Initializing remote procedure calls...");
        let patch_proxy = RpcProxy::new(remote);

        debug!("Initializing command executors...");
        let patch_lock_file = instance.args.work_dir.join(PATCH_OP_LOCK_NAME);
        let executors = vec![
            Box::new(BuildCommandExecutor) as Box<dyn CommandExecutor>,
            Box::new(PatchCommandExecutor::new(patch_proxy, patch_lock_file))
                as Box<dyn CommandExecutor>,
        ];

        let command = instance.args.command;
        debug!("Invoking command: {:#?}", command);
        for executor in &executors {
            executor.invoke(&command)?;
        }
        debug!("Done");

        Ok(())
    }
}

fn main() {
    let exit_code = match SyscareCLI::start_and_run() {
        Ok(_) => 0,
        Err(e) => {
            match Logger::is_inited() {
                false => {
                    eprintln!("Error: {:?}", e)
                }
                true => {
                    error!("Error: {:?}", e);
                }
            }
            1
        }
    };
    exit(exit_code);
}
