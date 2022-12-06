use std::fmt::Display;
use std::env;
use std::path::Path;
use std::process::exit;

use crate::tool::*;

use super::Result;
use super::Error;

pub struct Arg {
    pub work_dir: String,
    pub source: String,
    pub build_source_command: String,
    pub build_patch_command: String,
    pub debug_info: String,
    pub compiler_file: String,
    pub elf_name: String,
    pub output: String,
    pub patch_name: String,
    pub diff_file: Vec<String>,
    program: String,
    pub skip_compiler_check: bool,
    pub verbose: bool,
}

impl Arg {
    fn usage(&self) {
        println!("Usage: {} [options] --debug-source <DEBUG_SOURCE> --build-source-cmd <BUILD_SOURCE_CMD> --debug-info <DEBUG_INFO> --elf-name <ELF_NAME> <PATCHES>", self.program);
        println!("      -h|--help:                  options message");
        println!("      -w|--work-dir:              Specify work directory, default ~/.upatch/");
        println!("                                  will delete the work_dir when building upatch, use a empty directory");
        println!("      -s|--debug-source:          Specify source directory");
        println!("                                  will modify the debug_source when building upatch, use a copy");
        println!("      -b|--build-source-cmd:      Specify build source command");
        println!("      -bp|--build-patch-cmd:      Specify build patched command, default --build-source-cmd");
        println!("      -i|--debug-info:            Specify debug info");
        println!("      -c|--compiler:              Specify compiler, default gcc");
        println!("      -e|--elf-name:              Specify running file name");
        println!("      -o|--output-dir:            Specify output directory, default --work-dir");
        println!("      -n|--name:                  Specify output name, default --elf-name");
        println!("      --skip-compiler-check:      Specify skip check compiler");
        println!("      -v|--verbose:               Specify show debug information");
        println!("      -V|--version:               Specify show version information");
    }

    fn check(&mut self) -> Result<()>  {
        if self.source.is_empty() ||
            self.debug_info.is_empty() ||
            self.diff_file.is_empty() ||
            self.elf_name.is_empty() ||
            self.build_source_command.is_empty() {
            self.usage();
            return Err(Error::InvalidInput(format!("no input files")));
        }
        if self.build_patch_command.is_empty() {
            self.build_patch_command = self.build_source_command.clone();
        }
        Ok(())
    }
}

impl Arg {
    pub fn new() -> Self {
        Self {
            work_dir: String::new(),
            source: String::new(),
            build_source_command: String::new(),
            build_patch_command: String::new(),
            debug_info: String::new(),
            elf_name: String::new(),
            compiler_file: String::new(),
            output: String::new(),
            patch_name: String::new(),
            diff_file: Vec::new(),
            program: String::new(),
            skip_compiler_check: false,
            verbose: false,
        }
    }

    pub fn read(&mut self) -> Result<()> {
        let args: Vec<String> = env::args().collect();
        self.program.push_str(&args[0]);
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-w" | "--work-dir" => {
                    i += 1;
                    if !Path::new(&args[i]).is_dir() {
                        self.usage();
                        return Err(Error::InvalidInput(format!("workdir {} is not a directory", &args[i])));
                    }
                    self.work_dir.push_str(stringtify(realpath(&args[i])?).as_str());
                },
                "-s" | "--debug-source" => {
                    i += 1;
                    if !Path::new(&args[i]).is_dir() {
                        self.usage();
                        return Err(Error::InvalidInput(format!("debugsource {} is not a directory", &args[i])));
                    }
                    self.source.push_str(stringtify(realpath(&args[i])?).as_str());
                },
                "-b" | "--build-source-cmd" => {
                    i += 1;
                    self.build_source_command.push_str(&args[i]);
                },
                "-bp" | "--build-patch-cmd" => {
                    i += 1;
                    self.build_patch_command.push_str(&args[i]);
                },
                "-i" | "--debug-info" => {
                    i += 1;
                    if !Path::new(&args[i]).is_file() {
                        self.usage();
                        return Err(Error::InvalidInput(format!("debuginfo {} is not a file", &args[i])));
                    }
                    self.debug_info.push_str(stringtify(realpath(&args[i])?).as_str());
                },
                "-e" | "--elf-name" => {
                    i += 1;
                    self.elf_name.push_str(&args[i]);
                },
                "-c" | "--compiler" => {
                    i += 1;
                    if !Path::new(&args[i]).is_file() {
                        self.usage();
                        return Err(Error::InvalidInput(format!("compiler {} is not a file", &args[i])));
                    }
                    self.compiler_file.push_str(stringtify(realpath(&args[i])?).as_str());
                },
                "-o" | "--output-dir" => {
                    i += 1;
                    if !Path::new(&args[i]).is_dir() {
                        self.usage();
                        return Err(Error::InvalidInput(format!("output {} is not a file", &args[i])));
                    }
                    self.output.push_str(stringtify(realpath(&args[i])?).as_str());
                },
                "-n" | "--name" => {
                    i += 1;
                    self.patch_name.push_str(&args[i]);
                },
                "-h" | "--help" => {
                    self.usage();
                    exit(0);
                },
                "--skip-compiler-check" => {
                    self.skip_compiler_check = true;
                },
                "-v" | "--verbose" => {
                    self.verbose = true;
                },
                "-V" | "--version" => {
                    println!("{}", env!("CARGO_PKG_VERSION"));
                    exit(0);
                },
                _ => {
                    if !Path::new(&args[i]).is_file() {
                        self.usage();
                        return Err(Error::InvalidInput(format!("patch {} is not a file", args[i])));
                    }
                    self.diff_file.push(stringtify(realpath(&args[i])?));
                },
            }
            i += 1;
        }
        self.check()
    }
}

impl Display for Arg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "work_dir: {}, source: {}, build source command: {}, build patch command: {}, debug info: {}, compiler file: {}, elf_name{}, output: {}, patch_name{}, diff files: {:?}, skip_compiler_check: {}",
            self.work_dir,
            self.source,
            self.build_source_command,
            self.build_patch_command,
            self.debug_info,
            self.compiler_file,
            self.elf_name,
            self.output,
            self.patch_name,
            self.diff_file,
            self.skip_compiler_check,
            )
    }
}