//! "Mit Windows starten" (ADR 0017): BridgeControll starts at login and then starts the nodes marked for autostart.
//! Off by default.
//!
//! - **Windows**: a small `.cmd` file in the user's Startup folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\
//!   Startup\BridgeControll2.cmd`). A registry `Run` entry would need the `winreg` crate and could not be built and
//!   tested here; the file needs only the standard library, is visible to the user and easy to remove.
//! - **Linux**: an XDG autostart entry (`~/.config/autostart/bridgecontroll2.desktop`).
//! - **macOS**: not offered yet.
//!
//! The entry runs this program with `--autostart` (no browser window; nodes with autostart start) and the app folder
//! if it is not the default one. Paths with quotes, `%` or line ends are refused (they could break out of the
//! command line of the entry). The `.cmd` file is UTF-8 and switches the console to code page 65001 first (review 8:
//! `cmd` reads a batch file in the console's OEM code page - a path with `ü` or `é` was garbled); `^`, `&` and other
//! `cmd` specials are harmless inside the double quotes, `!` too (no delayed expansion).

use std::path::{Path, PathBuf};

/// File name of the Windows entry.
const WINDOWS_FILE: &str = "BridgeControll2.cmd";
/// File name of the XDG entry.
const XDG_FILE: &str = "bridgecontroll2.desktop";

/// Where autostart entries of this system go (`None`: not supported here).
#[must_use]
pub fn system_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA").map(|appdata| {
            PathBuf::from(appdata).join("Microsoft").join("Windows").join("Start Menu").join("Programs").join("Startup")
        })
    } else if cfg!(target_os = "macos") {
        None
    } else {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
        Some(config.join("autostart"))
    }
}

/// The entry file in `dir`.
#[must_use]
pub fn entry_path(dir: &Path) -> PathBuf {
    dir.join(if cfg!(windows) { WINDOWS_FILE } else { XDG_FILE })
}

/// Whether the entry exists in `dir`.
#[must_use]
pub fn is_enabled(dir: &Path) -> bool {
    entry_path(dir).is_file()
}

/// Writes or removes the entry in `dir`. `app_dir`: passed with `--data` when it is not the default folder.
pub fn set(dir: &Path, enabled: bool, exe: &Path, app_dir: Option<&Path>) -> Result<(), String> {
    let path = entry_path(dir);
    if !enabled {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("Autostart-Eintrag {} nicht entfernbar: {error}", path.display())),
        };
    }
    let content = entry_content(exe, app_dir)?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    crate::config::write_private(&path, content.as_bytes())
}

/// The content of the entry for this system.
pub fn entry_content(exe: &Path, app_dir: Option<&Path>) -> Result<String, String> {
    let exe = safe(exe)?;
    let data = match app_dir {
        Some(dir) => format!(" --data \"{}\"", safe(dir)?),
        None => String::new(),
    };
    Ok(if cfg!(windows) {
        windows_cmd(&exe, &data)
    } else {
        format!(
            "[Desktop Entry]\nType=Application\nName=BridgeControll\nComment=Bridge 4 / BridgeNet\nExec=\"{exe}\" \
             --autostart{data}\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n"
        )
    })
}

/// The `.cmd` file: code page UTF-8 first, then the program in quotes (also built on other systems, for the tests).
fn windows_cmd(exe: &str, data: &str) -> String {
    format!("@chcp 65001>nul\r\n@echo off\r\nstart \"\" \"{exe}\" --autostart{data}\r\n")
}

/// A path as text that can sit between double quotes in a command line (no quotes, `%`, `$`, backticks, `\`-escapes
/// on Unix or control characters).
fn safe(path: &Path) -> Result<String, String> {
    let text = path.to_str().ok_or("Pfad ist kein gültiger Text")?;
    let bad = |c: char| c == '"' || c == '%' || c.is_control() || (!cfg!(windows) && matches!(c, '$' | '`' | '\\'));
    if text.is_empty() || text.chars().any(bad) || !path.is_absolute() {
        return Err(format!("Pfad {text:?} eignet sich nicht für den Autostart"));
    }
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_and_off() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let startup = dir.path().join("autostart");
        let exe = dir.path().join("bridgecontroll");
        assert!(!is_enabled(&startup));
        set(&startup, true, &exe, None)?;
        assert!(is_enabled(&startup));
        let content = std::fs::read_to_string(entry_path(&startup)).map_err(|e| e.to_string())?;
        assert!(content.contains("--autostart") && content.contains(exe.to_str().unwrap_or("?")), "{content}");
        set(&startup, true, &exe, Some(&dir.path().join("app")))?;
        let content = std::fs::read_to_string(entry_path(&startup)).map_err(|e| e.to_string())?;
        assert!(content.contains("--data"), "{content}");
        set(&startup, false, &exe, None)?;
        assert!(!is_enabled(&startup));
        set(&startup, false, &exe, None)?; // twice is fine
        Ok(())
    }

    /// Review 8, finding 9: the Windows entry switches to UTF-8 before anything else, and paths with non-ASCII
    /// letters and `cmd` specials (`^ & ( ) !`) stay inside one pair of quotes, byte for byte.
    #[test]
    fn windows_entry_is_utf8_and_quoted() {
        let exe = r"C:\Users\Jürgen & Zoë\AppData\Local\Programs\Bridge (neu)^1!\bridgecontroll.exe";
        let data = r#" --data "D:\Dätä\Bridge""#;
        let text = windows_cmd(exe, data);
        assert!(text.starts_with("@chcp 65001>nul\r\n"), "{text}");
        assert_eq!(
            text,
            format!("@chcp 65001>nul\r\n@echo off\r\nstart \"\" \"{exe}\" --autostart --data \"D:\\Dätä\\Bridge\"\r\n")
        );
        assert!(text.lines().all(|line| line.matches('"').count() % 2 == 0), "quotes balanced on every line");
        assert!(text.contains("Jürgen & Zoë") && text.is_char_boundary(text.len()), "UTF-8, unchanged");
    }

    #[test]
    fn dangerous_paths_are_refused() {
        let base = std::env::temp_dir();
        let unix_only: &[&str] = if cfg!(windows) { &[] } else { &["a$(x)b", "a`x`b"] };
        for bad in ["a\"b", "a%PATH%b", "a\nb"].iter().chain(unix_only) {
            assert!(entry_content(&base.join(bad), None).is_err(), "{bad:?}");
        }
        assert!(entry_content(Path::new("relative/exe"), None).is_err(), "relative");
        assert!(entry_content(&base.join("ok"), Some(&base.join("da\"ta"))).is_err());
    }
}
