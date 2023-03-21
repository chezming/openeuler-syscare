use clap::Subcommand;

#[derive(Debug)]
#[derive(Subcommand)]
pub enum Command {
    /// Build a new patch
    #[command(
        disable_help_flag(true),
        subcommand_precedence_over_arg(true),
        allow_hyphen_values(true)
    )]
    Build {
        args: Vec<String>
    },
    /// Show patch detail info
    Info {
        /// Patch identifier, typically would be "<TARGET_NAME>/<PATCH_NAME>"
        identifier: String
    },
    /// Show patch target info
    Target {
        /// Patch identifier, typically would be "<TARGET_NAME>/<PATCH_NAME>"
        identifier: String
    },
    /// Show patch status
    Status {
        /// Patch identifier, typically would be "<TARGET_NAME>/<PATCH_NAME>"
        identifier: String
    },
    /// List all installed patches
    List,
    /// Apply a patch
    Apply {
        /// Patch identifier, typically would be "<TARGET_NAME>/<PATCH_NAME>"
        identifier: String
    },
    /// Remove a patch
    Remove {
        /// Patch identifier, typically would be "<TARGET_NAME>/<PATCH_NAME>"
        identifier: String
    },
    /// Activate a patch
    Active {
        /// Patch identifier, typically would be "<TARGET_NAME>/<PATCH_NAME>"
        identifier: String
    },
    /// Deactive a patch
    Deactive {
        /// Patch identifier, typically would be "<TARGET_NAME>/<PATCH_NAME>"
        identifier: String
    },
    /// Save all patch status
    Save,
    /// Restore all patch status
    Restore,
    /// Reboot the system
    Reboot {
        /// Target kernel name
        #[arg(short, long)]
        target: Option<String>,
        #[arg(short, long, default_value="false")]
        /// Skip all checks, force reboot
        force: bool,
    },
}

pub enum CommandArguments {
    None,
    CommandLineArguments(Vec<String>),
    PatchOperationArguments(String),
    RebootArguments(Option<String>, bool),
}

pub trait CommandExecutor {
    fn invoke(&self, args: &CommandArguments) -> std::io::Result<i32>;
}
