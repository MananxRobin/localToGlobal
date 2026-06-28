use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
struct DownloadAsset {
    name: &'static str,
    url: String,
    archive: bool,
}

pub fn ensure_cloudflared(verbose: bool) -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("LTG_CLOUDFLARED_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            validate_cloudflared(&path)?;
            return Ok(path);
        }
        return Err(format!(
            "LTG_CLOUDFLARED_PATH points to {}, but that file does not exist",
            path.display()
        ));
    }

    if let Some(path) = command_path("cloudflared") {
        validate_cloudflared(&path)?;
        return Ok(path);
    }

    let managed = managed_cloudflared_path()?;
    if managed.is_file() {
        validate_cloudflared(&managed)?;
        return Ok(managed);
    }

    let asset = cloudflared_asset()?;
    if verbose {
        println!("cloudflared not found; installing managed copy...");
        println!("Downloading {}", asset.name);
    }
    download_cloudflared(&asset, &managed)?;
    validate_cloudflared(&managed)?;
    Ok(managed)
}

pub fn command_path(command: &str) -> Option<PathBuf> {
    let candidate = Path::new(command);
    if candidate.components().count() > 1 && candidate.is_file() {
        return Some(candidate.to_path_buf());
    }

    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(binary_name(command));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub fn managed_bin_dir() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("LTG_DATA_HOME") {
        return Ok(PathBuf::from(path).join("bin"));
    }
    if let Some(path) = env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(path).join("localtoglobal").join("bin"));
    }
    let home = env::var_os("HOME").ok_or_else(|| {
        "HOME is not set; cannot choose a directory for managed dependencies".to_string()
    })?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("localtoglobal")
        .join("bin"))
}

fn managed_cloudflared_path() -> Result<PathBuf, String> {
    Ok(managed_bin_dir()?.join(binary_name("cloudflared")))
}

fn binary_name(command: &str) -> String {
    if cfg!(windows) {
        format!("{}.exe", command)
    } else {
        command.to_string()
    }
}

fn cloudflared_asset() -> Result<DownloadAsset, String> {
    cloudflared_asset_for(env::consts::OS, env::consts::ARCH).ok_or_else(|| {
        format!(
            "automatic cloudflared install is not supported on {} {}; install cloudflared manually or set LTG_CLOUDFLARED_PATH",
            env::consts::OS,
            env::consts::ARCH
        )
    })
}

fn cloudflared_asset_for(os: &str, arch: &str) -> Option<DownloadAsset> {
    let (name, archive) = match (os, arch) {
        ("macos", "x86_64") => ("cloudflared-darwin-amd64.tgz", true),
        ("macos", "aarch64") => ("cloudflared-darwin-arm64.tgz", true),
        ("linux", "x86_64") => ("cloudflared-linux-amd64", false),
        ("linux", "aarch64") => ("cloudflared-linux-arm64", false),
        _ => return None,
    };
    Some(DownloadAsset {
        name,
        url: format!(
            "https://github.com/cloudflare/cloudflared/releases/latest/download/{}",
            name
        ),
        archive,
    })
}

fn download_cloudflared(asset: &DownloadAsset, destination: &Path) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("invalid cloudflared destination {}", destination.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create {}: {}", parent.display(), err))?;

    if command_path("curl").is_none() {
        return Err("curl is required to download managed cloudflared".to_string());
    }

    let download_path = parent.join(format!(".{}.download", asset.name));
    let status = Command::new("curl")
        .arg("-fL")
        .arg("--retry")
        .arg("3")
        .arg("--connect-timeout")
        .arg("20")
        .arg("-o")
        .arg(&download_path)
        .arg(&asset.url)
        .status()
        .map_err(|err| format!("failed to run curl: {}", err))?;
    if !status.success() {
        let _ = fs::remove_file(&download_path);
        return Err(format!("failed to download {}", asset.url));
    }

    if asset.archive {
        if command_path("tar").is_none() {
            let _ = fs::remove_file(&download_path);
            return Err("tar is required to unpack cloudflared on macOS".to_string());
        }
        let extract_dir = parent.join(format!(".cloudflared-{}", unix_timestamp()));
        fs::create_dir_all(&extract_dir)
            .map_err(|err| format!("failed to create {}: {}", extract_dir.display(), err))?;
        let status = Command::new("tar")
            .arg("-xzf")
            .arg(&download_path)
            .arg("-C")
            .arg(&extract_dir)
            .status()
            .map_err(|err| format!("failed to run tar: {}", err))?;
        if !status.success() {
            let _ = fs::remove_file(&download_path);
            let _ = fs::remove_dir_all(&extract_dir);
            return Err(format!("failed to unpack {}", download_path.display()));
        }
        let unpacked = find_file_named(&extract_dir, "cloudflared").ok_or_else(|| {
            "cloudflared archive did not contain a cloudflared binary".to_string()
        })?;
        install_file(&unpacked, destination)?;
        let _ = fs::remove_file(&download_path);
        let _ = fs::remove_dir_all(&extract_dir);
    } else {
        install_file(&download_path, destination)?;
        let _ = fs::remove_file(&download_path);
    }

    mark_executable(destination)?;
    Ok(())
}

fn install_file(source: &Path, destination: &Path) -> Result<(), String> {
    if destination.exists() {
        fs::remove_file(destination)
            .map_err(|err| format!("failed to replace {}: {}", destination.display(), err))?;
    }
    fs::copy(source, destination).map_err(|err| {
        format!(
            "failed to install {} to {}: {}",
            source.display(),
            destination.display(),
            err
        )
    })?;
    Ok(())
}

fn find_file_named(root: &Path, name: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && path
                .file_name()
                .and_then(|value| value.to_str())
                .map(|value| value == name)
                .unwrap_or(false)
        {
            return Some(path);
        }
        if path.is_dir() {
            if let Some(found) = find_file_named(&path, name) {
                return Some(found);
            }
        }
    }
    None
}

#[cfg(unix)]
fn mark_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|err| format!("failed to inspect {}: {}", path.display(), err))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)
        .map_err(|err| format!("failed to chmod {}: {}", path.display(), err))
}

#[cfg(not(unix))]
fn mark_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn validate_cloudflared(path: &Path) -> Result<(), String> {
    let output = Command::new(path)
        .arg("--version")
        .output()
        .map_err(|err| format!("failed to run {} --version: {}", path.display(), err))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{} exists but did not run successfully",
            path.display()
        ))
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_supported_cloudflared_assets() {
        assert_eq!(
            cloudflared_asset_for("macos", "aarch64").unwrap().name,
            "cloudflared-darwin-arm64.tgz"
        );
        assert_eq!(
            cloudflared_asset_for("macos", "x86_64").unwrap().name,
            "cloudflared-darwin-amd64.tgz"
        );
        assert_eq!(
            cloudflared_asset_for("linux", "aarch64").unwrap().name,
            "cloudflared-linux-arm64"
        );
        assert_eq!(
            cloudflared_asset_for("linux", "x86_64").unwrap().name,
            "cloudflared-linux-amd64"
        );
    }
}
