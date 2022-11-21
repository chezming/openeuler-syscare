use std::{path::Path, env};
use std::process::Command;
use std::collections::HashMap;
use std::fs::{self, OpenOptions, File};
use std::io::{self, Read};

use walkdir::WalkDir;

use super::Arg;
use crate::dwarf::{Dwarf, DwarfCompileUnit};
use super::Compiler;
use super::Project;
use super::Result;
use super::Error;
use super::{stringtify, find_file};

pub const UPATCH_DEV_NAME: &str = "upatch";
const SYSTEM_MOUDLES: &str = "/proc/modules";
const CMD_SOURCE_ENTER: &str = "SE";
const CMD_PATCHED_ENTER: &str = "PE";
const SUPPORT_TOOL: &str = "upatch-diff";
const SYSTEM_TOOL_DIR: &str = "/usr/libexec/syscare";

pub struct UpatchBuild {
    cache_dir: String,
    source_dir: String,
    patch_dir: String,
    output_dir: String,
    log_file: String,
    args: Arg,
    tool_file: String,
}

impl UpatchBuild {
    pub fn new() -> Self {
        Self {
            cache_dir: String::new(),
            source_dir: String::new(),
            patch_dir: String::new(),
            output_dir: String::new(),
            log_file: String::new(),
            args: Arg::new(),
            tool_file: String::new(),
        }
    }

    pub fn run(&mut self) -> Result<()> {
        self.args.read()?;

        // create .upatch directory
        self.create_dir()?;

        if self.args.patch_name.is_empty() {
            self.args.patch_name.push_str(&self.args.elf_name);
        }
        if self.args.output.is_empty() {
            self.args.output.push_str(&self.cache_dir);
        }

        // check mod
        self.check_mod()?;

        // find create-diff-object
        self.search_tool()?;

        // check compiler
        let mut compiler = Compiler::new(self.args.compiler_file.clone());
        compiler.analyze()?;
        if !self.args.skip_compiler_check {
            compiler.check_version(&self.cache_dir, &self.args.debug_info)?;
        }

        // copy source
        let project_name = &Path::new(&self.args.source).file_name().unwrap();

        // hack compiler
        println!("Hacking compiler");
        compiler.hack()?;

        // build source
        println!("Building original {}", project_name.to_str().unwrap());
        let project = Project::new(self.args.source.clone());
        project.build(CMD_SOURCE_ENTER, &self.source_dir, self.args.build_source_command.clone())?;

        // build patch
        for patch in &self.args.diff_file {
            println!("Patching file: {}", &patch);
            project.patch(patch.clone())?;
        }

        println!("Building patched {}", project_name.to_str().unwrap());
        project.build(CMD_PATCHED_ENTER, &self.patch_dir, self.args.build_patch_command.clone())?;

        // unhack compiler
        println!("Unhacking compiler");
        compiler.unhack()?;

        println!("Detecting changed objects");
        // correlate obj name
        let mut source_obj: HashMap<String, String> = HashMap::new();
        let mut patch_obj: HashMap<String, String> = HashMap::new();
        let dwarf = Dwarf::new();

        self.correlate_obj(&dwarf, self.args.source.as_str(), &self.source_dir, &mut source_obj)?;
        self.correlate_obj(&dwarf, self.args.source.as_str(), &self.patch_dir, &mut patch_obj)?;

        // choose the binary's obj to create upatch file
        let binary_obj = dwarf.file_in_binary(self.args.source.clone(), self.args.elf_name.clone())?;
        self.correlate_diff(&source_obj, &patch_obj, &binary_obj)?;

        // ld patchs
        let output_file = &format!("{}/{}", &self.args.output, &self.args.patch_name);
        compiler.linker(&self.output_dir, output_file)?;
        println!("Building patch: {}", output_file);
        Ok(())
    }
}

impl UpatchBuild {
    fn create_dir(&mut self) -> Result<()> {
        #![allow(deprecated)]
        if self.args.work_dir.is_empty(){
            // home_dir() don't support BSD system
            self.cache_dir.push_str(&format!("{}/{}", env::home_dir().unwrap().to_str().unwrap(), ".upatch"));
        }
        else{
            self.cache_dir.push_str(&self.args.work_dir);
        }

        self.source_dir.push_str(&format!("{}/{}", &self.cache_dir, "source"));
        self.patch_dir.push_str(&format!("{}/{}", &self.cache_dir, "patch"));
        self.output_dir.push_str(&format!("{}/{}", &self.cache_dir, "output"));
        self.log_file.push_str(&format!("{}/{}", &self.cache_dir, "buildlog"));

        if Path::new(&self.cache_dir).is_dir() {
            fs::remove_dir_all(self.cache_dir.clone())?;
        }

        fs::create_dir_all(self.cache_dir.clone())?;
        fs::create_dir(self.source_dir.clone())?;
        fs::create_dir(self.patch_dir.clone())?;
        fs::create_dir(self.output_dir.clone())?;
        File::create(&self.log_file)?;
        Ok(())
    }

    fn check_mod(&self) -> Result<()> {
        let mut file = File::open(SYSTEM_MOUDLES)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        match contents.find(UPATCH_DEV_NAME) {
            Some(_) => Ok(()),
            None => Err(Error::Mod(format!("can't found upatch mod in system"))),
        }
    }

    fn correlate_obj(&self, dwarf: &Dwarf, comp_dir: &str, dir: &str, map: &mut HashMap<String, String>) -> Result<()> {
        let arr = WalkDir::new(dir).into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file() && (stringtify(e.path().extension().unwrap_or_default()) == "o"))
                .collect::<Vec<_>>();
        for obj in arr {       
            let name = obj.path().to_str().unwrap_or_default().to_string(); 
            let result = dwarf.file_in_obj(name.clone())?;
            if result.len() == 1 && result[0].DW_AT_comp_dir.find(comp_dir) != None{
                map.insert(result[0].get_source(), name.clone());
            }
        }
        Ok(())
    }

    fn correlate_diff(&self, source_obj: &HashMap<String, String>, patch_obj: &HashMap<String, String>, binary_obj: &Vec<DwarfCompileUnit>) -> Result<()> {
        // TODO can print changed function
        for path in binary_obj {
            let source_name = path.get_source();
            match &patch_obj.get(&source_name) {
                Some(patch) => {
                    let output_dir =  self.output_dir.clone() + "/" + Path::new(patch).file_name().unwrap().to_str().unwrap();
                    match &source_obj.get(&source_name) {
                        Some(source) => {
                            let output = Command::new(&self.tool_file)
                                        .args(["-s", &source, "-p", &patch, "-o", &output_dir, "-r", &self.args.debug_info])
                                        .stdout(OpenOptions::new().append(true).write(true).open(&self.log_file)?)
                                        .stderr(OpenOptions::new().append(true).write(true).open(&self.log_file)?)
                                        .output()?;
                            if !output.status.success(){
                                return Err(Error::Diff(format!("{}: please look {} for detail.", output.status, &self.log_file)));
                            }
                        },
                        None => { fs::copy(&patch, output_dir)?; },
                    };
                },
                None => {},
            };
        }
        Ok(())
    }

    fn search_tool(&mut self) -> Result<()> {
        match find_file("./", SUPPORT_TOOL, false, false) {
            Err(_) => {
                let system_tool_str = format!("{}/{}", SYSTEM_TOOL_DIR, SUPPORT_TOOL);
                if !Path::new(&system_tool_str).is_file() {
                    return Err(io::Error::new(io::ErrorKind::NotFound, format!("can't find supporting tools: {}", &system_tool_str)).into());
                }
                self.tool_file.push_str(&system_tool_str);
            },
            Ok(path) => self.tool_file.push_str(stringtify(path).as_str()),
        };
        Ok(())
    }
}
