use std::{process::exit, rc::Rc};

use anyhow::Result;
use log::{debug, error, LevelFilter};

mod args;
mod executor;
mod flock;
mod logger;
mod rpc;

use args::Arguments;
use executor::{build::BuildCommandExecutor, patch::PatchCommandExecutor, CommandExecutor};
use logger::Logger;
use rpc::{RpcProxy, RpcRemote};

pub const CLI_NAME: &str = env!("CARGO_PKG_NAME");
pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CLI_ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

struct SyscareCLI {
    args: Arguments,
}

impl SyscareCLI {
    fn start_and_run() -> Result<()> {
        let instance = Self {
            args: Arguments::new()?,
        };
        Logger::initialize(match instance.args.verbose {
            true => LevelFilter::Debug,
            false => LevelFilter::Info,
        })?;
        debug!("Start with {:#?}", instance.args);

        debug!("Initializing remote procedure call client...");
        let remote = Rc::new(RpcRemote::new(&instance.args.socket_file));

        debug!("Initializing remote procedure calls...");
        let patch_proxy = RpcProxy::new(remote);

        debug!("Initializing command executors...");
        let executors = vec![
            Box::new(BuildCommandExecutor) as Box<dyn CommandExecutor>,
            Box::new(PatchCommandExecutor::new(patch_proxy)) as Box<dyn CommandExecutor>,
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
