use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use log::{Level, log};

use crate::cmd::*;

use super::Result;
use super::Error;
use super::LINK_LOG;

const COMPILER_CMD_ENV: &str = "UPATCH_CMD";
const ASSEMBLER_DIR_ENV: &str = "UPATCH_AS_OUTPUT";
const LINK_PATH_ENV: &str = "UPATCH_LINK_OUTPUT";
const BUILD_SHELL: &str ="build.sh";

pub struct Project {
    project_dir: PathBuf,
}

impl Project {
    pub fn new<P: AsRef<Path>>(project_dir: P) -> Self {
        Self {
            project_dir: project_dir.as_ref().to_path_buf()
        }
    }

    pub fn build<P: AsRef<Path>>(&self, cmd: &str, assembler_output: P, build_command: String) -> Result<()> {
        let assembler_output = assembler_output.as_ref();
        let link_output = assembler_output.join(LINK_LOG);
        let command_shell_path = assembler_output.join(BUILD_SHELL);
        let mut command_shell = File::create(&command_shell_path)?;
        command_shell.write_all(build_command.as_ref())?;
        let args_list = ExternCommandArgs::new().arg(command_shell_path);
        let envs_list = ExternCommandEnvs::new().env(COMPILER_CMD_ENV, cmd)
            .env(ASSEMBLER_DIR_ENV, assembler_output)
            .env(LINK_PATH_ENV, link_output);
        let output = ExternCommand::new("sh").execve(args_list, envs_list, &self.project_dir)?;
        if !output.exit_status().success() {
            return Err(Error::Project(format!("build project error {}: {:?}", output.exit_code(), output.stderr())))
        };
        Ok(())
    }

    pub fn patch_all<P: AsRef<Path>>(&self, patches: &Vec<P>, level: Level) -> Result<()> {
        for patch in patches {
            log!(level, "Patching file: {:?}", patch.as_ref());
            let file = match File::open(&patch) {
                Ok(file) => file,
                Err(e) => return Err(Error::Project(format!("open {:?} error: {}", patch.as_ref(), e))),
            };
            let args_list = ExternCommandArgs::new().args(["-N", "-p1"]);
            if let Err(e) = self.patch(file, args_list, level) {
                return Err(Error::Project(format!("patch file {:?} {}", patch.as_ref(), e)));
            }
        }
        Ok(())
    }

    pub fn unpatch_all<P: AsRef<Path>>(&self, patches: &Vec<P>, level: Level) -> Result<()> {
        for patch in patches.iter().rev() {
            log!(level, "Patching file: {:?}", patch.as_ref());
            let file = match File::open(&patch) {
                Ok(file) => file,
                Err(e) => return Err(Error::Project(format!("open {:?} error: {}", patch.as_ref(), e))),
            };
            let args_list = ExternCommandArgs::new().args(["-N", "-p1", "-R"]);
            if let Err(e) = self.patch(file, args_list, level) {
                return Err(Error::Project(format!("unpatch file {:?} {}", patch.as_ref(), e)));
            }
        }
        Ok(())
    }
}

impl Project {
    fn patch(&self, file: File, args_list: ExternCommandArgs, level: Level) -> Result<()> {
        let output = ExternCommand::new("patch").execvp_stdio_level(args_list, &self.project_dir, file, level)?;
        if !output.exit_status().success() {
            return Err(Error::Project(format!("error {}: {:?}", output.exit_code(), output.stderr())));
        };
        Ok(())
    }
}
