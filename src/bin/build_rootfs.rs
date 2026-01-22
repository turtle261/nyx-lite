use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use nyx_lite::image_builder::RootfsBuilder;

fn usage() -> ! {
    eprintln!(
        "Usage: build_rootfs <dockerfile> <context_dir> <output_img> [--size-mib N] [--work-dir DIR]"
    );
    std::process::exit(2);
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);

    let dockerfile = args.next().unwrap_or_else(|| usage());
    let context_dir = args.next().unwrap_or_else(|| usage());
    let output_img = args.next().unwrap_or_else(|| usage());

    let mut size_mib: Option<u64> = None;
    let mut work_dir: Option<PathBuf> = None;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--size-mib" => {
                let v = args.next().unwrap_or_else(|| usage());
                size_mib = Some(v.parse().context("--size-mib must be an integer")?);
            }
            "--work-dir" => {
                let v = args.next().unwrap_or_else(|| usage());
                work_dir = Some(PathBuf::from(v));
            }
            "-h" | "--help" => usage(),
            other => bail!("Unknown argument: {other}"),
        }
    }

    let dockerfile = PathBuf::from(dockerfile);
    let context_dir = PathBuf::from(context_dir);
    let output_img = PathBuf::from(output_img);

    let work_dir = work_dir.unwrap_or_else(|| {
        output_img
            .parent()
            .map(|p| p.join(".rootfs_work"))
            .unwrap_or_else(|| std::env::temp_dir().join("nyx-lite-rootfs-work"))
    });

    std::fs::create_dir_all(&work_dir).context("create work dir")?;

    let builder = RootfsBuilder::new(&work_dir);
    builder
        .build_from_dockerfile(&dockerfile, &context_dir, &output_img, size_mib)
        .with_context(|| {
            format!(
                "build_from_dockerfile dockerfile={} context_dir={} output_img={}",
                dockerfile.display(),
                context_dir.display(),
                output_img.display()
            )
        })?;

    println!("{}", output_img.display());
    Ok(())
}
