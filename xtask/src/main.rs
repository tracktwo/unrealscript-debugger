use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use fs_extra::{copy_items, dir::CopyOptions};

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
        Some("dist") => dist(env::args().nth(2))?,
        _ => print_help(),
    }

    Ok(())
}

fn print_help() {
    eprintln!(
        "Tasks:

dist <version>     builds application and creates release package
"
    );
}

fn dist(version: Option<String>) -> Result<(), DynError> {
    let version = version.ok_or("Usage: dist <version>")?;
    let _ = fs::remove_dir_all(dist_dir());
    let _ = fs::remove_dir_all(extensions_dir());
    fs::create_dir(dist_dir())?;
    fs::create_dir(extensions_dir())?;
    dist_binaries()?;
    dist_extensions(&version)?;
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
            project_root().join(adapter_binary(t)),
            dist_dir().join(format!("{t}/adapter.exe")),
        )?;

        fs::copy(
            project_root().join(interface_binary(t)),
            dist_dir().join(format!("{t}/DebuggerInterface.dll")),
        )?;
    }

    Ok(())
}

fn dist_extensions(version: &str) -> Result<(), DynError> {
    dist_vscode_extension(version)
}

fn dist_vscode_extension(version: &str) -> Result<(), DynError> {
    let vscode_dir = project_root().join("extensions/vscode");
    let target_dir = extensions_dir().join("vscode");

    // Copy the vscode source dir into the dist
    let opts = CopyOptions::new().overwrite(true);
    copy_items(&[vscode_dir], extensions_dir(), &opts)?;

    // Install node modules
    let status = Command::new("npm.cmd")
        .current_dir(&target_dir)
        .args(["install"])
        .status()?;

    if !status.success() {
        Err("npm install failed.")?;
    }

    // Compile extension
    let status = Command::new("npm.cmd")
        .current_dir(&target_dir)
        .args(["run", "compile"])
        .status()?;

    if !status.success() {
        Err("npm compile failed.")?;
    }

    // Copy binaries
    fs::create_dir_all(target_dir.join("bin/win32"))?;
    fs::create_dir_all(target_dir.join("bin/win64"))?;
    fs::copy(
        project_root().join(adapter_binary("x86_64-pc-windows-msvc")),
        target_dir.join("bin/win64/adapter.exe"),
    )?;

    fs::copy(
        project_root().join(interface_binary("x86_64-pc-windows-msvc")),
        target_dir.join("bin/win64/DebuggerInterface.dll"),
    )?;

    fs::copy(
        project_root().join(interface_binary("i686-pc-windows-msvc")),
        target_dir.join("bin/win32/DebuggerInterface.dll"),
    )?;

    fs::copy(project_root().join("LICENSE"), target_dir.join("LICENSE"))?;

    // Create the package
    let status = Command::new("vsce.cmd")
        .current_dir(&target_dir)
        .args(["package", "-o", dist_dir().to_str().unwrap(), version])
        .status()?;

    if !status.success() {
        Err("vscode package creation failed.")?;
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

fn extensions_dir() -> PathBuf {
    project_root().join("target/extensions")
}

fn adapter_binary(target: &str) -> String {
    format!("target/{target}/release/adapter.exe")
}

fn interface_binary(target: &str) -> String {
    format!("target/{target}/release/interface.dll")
}
