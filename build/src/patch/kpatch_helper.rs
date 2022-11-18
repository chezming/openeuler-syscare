use crate::constants::*;
use crate::util::fs;

pub struct KernelPatchHelper;

impl KernelPatchHelper {
    pub fn find_source_directory(directory: &str) -> std::io::Result<String> {
        fs::check_dir(directory)?;

        let source_dir = fs::find_directory(
            directory,
            KERNEL_SOURCE_DIR_PREFIX,
            true,
            true
        )?;

        Ok(fs::stringtify(source_dir))
    }

    pub fn find_kernel_config(directory: &str) -> std::io::Result<String> {
        fs::check_dir(directory)?;

        let config_file_path = fs::find_file(
            directory,
            KERNEL_CONFIG_NAME,
            false,
            true
        )?;

        Ok(fs::stringtify(config_file_path))
    }

    pub fn generate_defconfig(source_dir: &str) -> std::io::Result<String> {
        fs::check_dir(source_dir)?;

        println!("Using '{}' as default config", KERNEL_DEFCONFIG_NAME);

        let exit_status = MAKE.execvp(["-C", source_dir, KERNEL_DEFCONFIG_NAME])?;

        let exit_code = exit_status.exit_code();
        if exit_code != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("Process '{}' exited unsuccessfully, exit code: {}", MAKE, exit_code),
            ));
        }

        let config_file_path = fs::find_file(
            source_dir,
            KERNEL_CONFIG_NAME,
            false,
            true
        )?;

        Ok(fs::stringtify(config_file_path))
    }

    pub fn write_kernel_config(kconfig_path: &str, output_dir: &str) -> std::io::Result<()> {
        fs::check_file(kconfig_path)?;
        fs::check_dir(output_dir)?;

        let dst_path = format!("{}/{}", output_dir, KERNEL_CONFIG_NAME);
        if *kconfig_path == dst_path {
            return Ok(());
        }
        std::fs::copy(kconfig_path, dst_path)?;

        Ok(())
    }

    pub fn build_kernel(source_dir: &str, jobs: usize) -> std::io::Result<String> {
        fs::check_dir(source_dir)?;

        {
            let exit_status = MAKE.execvp(["-C", source_dir, "clean"])?;

            let exit_code = exit_status.exit_code();
            if exit_code != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    format!("Process '{}' exited unsuccessfully, exit code: {}", MAKE, exit_code),
                ));
            }
        }

        {
            let exit_status = MAKE.execvp([
                "-C", source_dir,
                "-j", jobs.to_string().as_str()
            ])?;

            let exit_code = exit_status.exit_code();
            if exit_code != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    format!("Process '{}' exited unsuccessfully, exit code: {}", MAKE, exit_code),
                ));
            }
        }

        let kernel_file_path = fs::find_file(
            &source_dir,
            KERNEL_FILE_NAME,
            false,
            true
        )?;

        Ok(fs::stringtify(kernel_file_path))
    }
}
