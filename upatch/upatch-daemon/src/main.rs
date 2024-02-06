use std::{
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    path::Path,
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{ensure, Context, Result};
use daemonize::Daemonize;
use jsonrpc_core::IoHandler;
use jsonrpc_ipc_server::{Server, ServerBuilder};
use log::{error, info, LevelFilter};
use signal_hook::consts::TERM_SIGNALS;

use syscare_common::os;

mod args;
mod hijacker;
mod logger;
mod rpc;

use args::Arguments;
use logger::Logger;
use rpc::{Skeleton, SkeletonImpl};

const DAEMON_NAME: &str = env!("CARGO_PKG_NAME");
const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");
const DAEMON_ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

const DAEMON_UMASK: u32 = 0o077;
const DAEMON_PARK_TIME: u64 = 100;

const CONFIG_FILE_NAME: &str = "upatchd.yaml";
const PID_FILE_NAME: &str = "upatchd.pid";
const SOCKET_FILE_NAME: &str = "upatchd.sock";

const WORK_DIR_PERMISSION: u32 = 0o755;
const SOCKET_FILE_PERMISSION: u32 = 0o666;

struct Daemon {
    args: Arguments,
    term_flag: Arc<AtomicBool>,
}

impl Daemon {
    fn new() -> Result<Self> {
        const ROOT_UID: u32 = 0;

        os::umask::set_umask(DAEMON_UMASK);

        let instance = Self {
            args: Arguments::new()?,
            term_flag: Arc::new(AtomicBool::new(false)),
        };

        ensure!(
            os::user::id() == ROOT_UID,
            "This command has to be run with superuser privileges (under the root user on most systems)."
        );

        Ok(instance)
    }

    fn prepare_directory<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let dir_path = path.as_ref();
        if !dir_path.exists() {
            fs::create_dir_all(dir_path).with_context(|| {
                format!("Failed to create directory \"{}\"", dir_path.display())
            })?;
        }
        Ok(())
    }

    fn prepare_environment(&self) -> Result<()> {
        self.prepare_directory(&self.args.config_dir)?;

        self.prepare_directory(&self.args.work_dir)?;
        fs::set_permissions(
            &self.args.work_dir,
            Permissions::from_mode(WORK_DIR_PERMISSION),
        )?;

        self.prepare_directory(&self.args.log_dir)?;

        Ok(())
    }

    fn daemonize(&self) -> Result<()> {
        if !self.args.daemon {
            return Ok(());
        }

        let pid_file = self.args.work_dir.join(PID_FILE_NAME);
        Daemonize::new()
            .umask(DAEMON_UMASK)
            .working_directory(&self.args.work_dir)
            .pid_file(pid_file)
            .start()
            .context("Daemonize failed")
    }

    fn initialize_logger(&self) -> Result<()> {
        let max_level = self.args.log_level;
        let stdout_level = match self.args.daemon {
            true => LevelFilter::Off,
            false => max_level,
        };
        Logger::initialize(&self.args.log_dir, max_level, stdout_level)?;

        Ok(())
    }

    fn initialize_skeleton(&self) -> Result<IoHandler> {
        let mut io_handler = IoHandler::new();

        let config_file = self.args.config_dir.join(CONFIG_FILE_NAME);
        io_handler.extend_with(SkeletonImpl::new(config_file)?.to_delegate());

        Ok(io_handler)
    }

    fn initialize_signal_handler(&self) -> Result<()> {
        for signal in TERM_SIGNALS {
            signal_hook::flag::register(*signal, self.term_flag.clone())
                .with_context(|| format!("Failed to register handler for signal {}", signal))?;
        }

        Ok(())
    }

    fn start_rpc_server(&self, io_handler: IoHandler) -> Result<Server> {
        let socket_file = self.args.work_dir.join(SOCKET_FILE_NAME);
        let builder = ServerBuilder::new(io_handler).set_client_buffer_size(1);
        let server = builder.start(
            socket_file
                .to_str()
                .context("Failed to convert socket path to string")?,
        )?;

        fs::set_permissions(&socket_file, Permissions::from_mode(SOCKET_FILE_PERMISSION))?;

        Ok(server)
    }

    fn start_and_run() -> Result<()> {
        let instance = Self::new()?;

        info!("Preparing environment...");
        instance.prepare_environment()?;
        instance.initialize_logger()?;

        info!("============================");
        info!("Upatch Daemon - {}", DAEMON_VERSION);
        info!("============================");
        info!("Start with {:#?}", instance.args);
        instance.daemonize()?;

        info!("Initializing signal handler...");
        instance
            .initialize_signal_handler()
            .context("Failed to initialize signal handler")?;

        info!("Initializing skeleton...");
        let io_handler = instance
            .initialize_skeleton()
            .context("Failed to initialize skeleton")?;

        info!("Starting remote procedure call server...");
        let server = instance
            .start_rpc_server(io_handler)
            .context("Failed to create remote procedure call server")?;

        info!("Daemon is running...");
        while !instance.term_flag.load(Ordering::Relaxed) {
            std::thread::park_timeout(Duration::from_millis(DAEMON_PARK_TIME));
        }

        info!("Shutting down...");
        server.close();

        Ok(())
    }
}

pub fn main() {
    let exit_code = match Daemon::start_and_run() {
        Ok(_) => {
            info!("Daemon exited");
            0
        }
        Err(e) => {
            match Logger::is_inited() {
                false => {
                    eprintln!("Error: {:?}", e)
                }
                true => {
                    error!("{:?}", e);
                    error!("Daemon exited unsuccessfully");
                }
            }
            -1
        }
    };
    process::exit(exit_code);
}
