use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use nyx_lite::image_builder::RootfsBuilder;

fn cmd_exists(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn unique_tmp_dir(prefix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let pid = std::process::id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    p.push(format!("{prefix}-{pid}-{now}"));
    p
}

fn ext4_has_magic(path: &Path) -> bool {
    // ext4 superblock starts at offset 1024; s_magic is at offset 0x38 within superblock.
    // So magic is at absolute offset 1024 + 0x38 = 1080 (0x438) and should be 0xEF53.
    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = vec![0u8; 1082];
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    let magic_lo = buf[1080];
    let magic_hi = buf[1081];
    u16::from_le_bytes([magic_lo, magic_hi]) == 0xEF53
}

#[test]
fn docker_rootfs_builder_smoke_test() {
    if std::env::var("NYX_TEST_DOCKER").ok().as_deref() != Some("1") {
        eprintln!("skipping docker rootfs builder test (set NYX_TEST_DOCKER=1 to enable)");
        return;
    }

    if !cmd_exists("docker") {
        eprintln!("skipping: docker not available");
        return;
    }
    if !cmd_exists("tar") {
        eprintln!("skipping: tar not available");
        return;
    }
    // RootfsBuilder uses mke2fs (not mkfs.ext4).
    if !cmd_exists("mke2fs") {
        eprintln!("skipping: mke2fs not available");
        return;
    }

    let work_dir = unique_tmp_dir("nyx-lite-rootfs-test");
    fs::create_dir_all(&work_dir).expect("create work dir");

    let docker_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vm_image/dockerimage");
    let dockerfile = docker_dir.join("Dockerfile");

    let out_img = work_dir.join("rootfs.ext4");
    let builder = RootfsBuilder::new(&work_dir);

    builder
        .build_from_dockerfile(&dockerfile, &docker_dir, &out_img, Some(512))
        .expect("build_from_dockerfile should succeed");

    let md = fs::metadata(&out_img).expect("rootfs image should exist");
    assert!(md.len() > 0, "rootfs image should be non-empty");
    assert!(
        ext4_has_magic(&out_img),
        "rootfs image should look like ext4"
    );

    // Cleanup best-effort.
    let _ = fs::remove_file(&out_img);
    let _ = fs::remove_dir_all(&work_dir);
}
