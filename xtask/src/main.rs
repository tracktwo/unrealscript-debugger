use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

type DynError = Box<dyn std::error::Error>;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn try_main() -> Result<(), DynError> {
    let task = env::args().nth(1);
    match task.as_deref() {
        Some("dist") => dist()?,
        _ => print_help(),
    }

    Ok(())
}

fn print_help() {
    eprintln!(
        "Tasks:

dist        builds application and creates release package
"
    );
}

fn dist() -> Result<(), DynError> {
    let _ = fs::remove_dir_all(dist_dir());
    fs::create_dir(dist_dir())?;

    dist_binaries()?;
    Ok(())
}

fn dist_binaries() -> Result<(), DynError> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let targets = ["x86_64-pc-windows-msvc", "i686-pc-windows-msvc"];

    for t in targets {
        let status = Command::new(cargo.as_str())
            .current_dir(project_root())
            .args(["build", "--release", "--target", t])
            .status()?;

        if !status.success() {
            Err("cargo build failed")?;
        }

        fs::create_dir(dist_dir().join(t))?;

        fs::copy(
            project_root().join(format!(
                "target/{t}/release/unrealscript-debugger-adapter.exe"
            )),
            dist_dir().join(format!("{t}/unrealscript-debugger-adapter.exe")),
        )?;

        fs::copy(
            project_root().join(format!("target/{t}/release/interface.dll")),
            dist_dir().join(format!("{t}/DebuggerInterface.dll")),
        )?;
    }

    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
}

fn dist_dir() -> PathBuf {
    project_root().join("target/dist")
}
