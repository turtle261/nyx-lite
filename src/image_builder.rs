use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImageBuilderError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("command `{0}` failed with status {1}")]
    CommandFailed(String, std::process::ExitStatus),
    #[error("command `{0}` returned empty output")]
    CommandEmptyOutput(String),
    #[error("root directory is empty or missing: {0}")]
    MissingRootDir(PathBuf),
}

#[derive(Debug, Clone)]
pub struct RootfsBuilder {
    work_dir: PathBuf,
}

impl RootfsBuilder {
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            work_dir: work_dir.into(),
        }
    }

    pub fn build_from_dockerfile(
        &self,
        dockerfile: &Path,
        context_dir: &Path,
        output_img: &Path,
        size_mib: Option<u64>,
    ) -> Result<(), ImageBuilderError> {
        let tag = format!("nyx-lite-rootfs-{}", unique_id());
        run_status(
            Command::new("docker")
                .arg("build")
                .arg("-f")
                .arg(dockerfile)
                .arg("-t")
                .arg(&tag)
                .arg(context_dir)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit()),
        )?;
        let _image_guard = DockerImageGuard::new(tag.clone());

        let container_id = run_output(
            Command::new("docker")
                .arg("create")
                .arg(&tag)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?;
        let _container_guard = DockerContainerGuard::new(container_id.clone());

        let temp_root = TempDir::new_in(&self.work_dir, "nyx-lite-rootfs")?;
        let tar_path = temp_root.path().join("rootfs.tar");
        run_status(
            Command::new("docker")
                .arg("export")
                .arg("-o")
                .arg(&tar_path)
                .arg(&container_id)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit()),
        )?;

        let root_dir = temp_root.path().join("root");
        fs::create_dir_all(&root_dir)?;
        run_status(
            Command::new("tar")
                .arg("-xf")
                .arg(&tar_path)
                .arg("-C")
                .arg(&root_dir)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit()),
        )?;

        self.build_from_rootdir(&root_dir, output_img, size_mib)
    }

    pub fn build_from_rootdir(
        &self,
        root_dir: &Path,
        output_img: &Path,
        size_mib: Option<u64>,
    ) -> Result<(), ImageBuilderError> {
        if !root_dir.is_dir() {
            return Err(ImageBuilderError::MissingRootDir(root_dir.to_path_buf()));
        }

        let estimated_mib = size_mib.unwrap_or_else(|| {
            let bytes = dir_size(root_dir).unwrap_or(0);
            estimate_mib(bytes)
        });

        if let Some(parent) = output_img.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = File::create(output_img)?;
        file.set_len(estimated_mib.saturating_mul(1024 * 1024))?;
        drop(file);

        run_status(
            Command::new("mke2fs")
                .arg("-t")
                .arg("ext4")
                .arg("-F")
                .arg("-L")
                .arg("rootfs")
                .arg("-d")
                .arg(root_dir)
                .arg(output_img)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit()),
        )
    }
}

fn estimate_mib(bytes: u64) -> u64 {
    let extra = bytes / 10;
    let extra = extra.max(64 * 1024 * 1024);
    let total = bytes.saturating_add(extra);
    let mib = (total + (1024 * 1024 - 1)) / (1024 * 1024);
    mib.max(256)
}

fn dir_size(root: &Path) -> io::Result<u64> {
    let mut total: u64 = 0;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            total = total.saturating_add(dir_size(&path)?);
        } else {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

fn run_status(command: &mut Command) -> Result<(), ImageBuilderError> {
    let name = format!("{:?}", command);
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(ImageBuilderError::CommandFailed(name, status))
    }
}

fn run_output(command: &mut Command) -> Result<String, ImageBuilderError> {
    let name = format!("{:?}", command);
    let output = command.output()?;
    if !output.status.success() {
        return Err(ImageBuilderError::CommandFailed(name, output.status));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        Err(ImageBuilderError::CommandEmptyOutput(name))
    } else {
        Ok(stdout)
    }
}

fn unique_id() -> String {
    let pid = std::process::id();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{pid}-{now}")
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new_in(base: &Path, prefix: &str) -> Result<Self, ImageBuilderError> {
        let mut path = base.to_path_buf();
        path.push(format!("{prefix}-{}", unique_id()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct DockerContainerGuard {
    id: String,
}

impl DockerContainerGuard {
    fn new(id: String) -> Self {
        Self { id }
    }
}

impl Drop for DockerContainerGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .arg("rm")
            .arg("-f")
            .arg(&self.id)
            .status();
    }
}

struct DockerImageGuard {
    tag: String,
}

impl DockerImageGuard {
    fn new(tag: String) -> Self {
        Self { tag }
    }
}

impl Drop for DockerImageGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .arg("rmi")
            .arg("-f")
            .arg(&self.tag)
            .status();
    }
}
