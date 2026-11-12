//! The start menu entry "BridgeControll" (Paddy, 12.11.2026): typing "BridgeControll" in the Windows search opens this
//! program (Bridge 4), while the old BridgeControll of Bridge 3 stays usable as "BridgeControll 3".
//!
//! - **Windows**: a shortcut `BridgeControll.lnk` in the user's start menu (`%APPDATA%\Microsoft\Windows\Start Menu\
//!   Programs`) to this program, with the Bridge 4 icon (`bridgecontroll4.ico`, written into the app folder). Made
//!   with the shell's own `WScript.Shell` object through PowerShell (like the Bridge 3 build script) - no extra crate,
//!   no registry. The script is passed as `-EncodedCommand` (UTF-16LE, Base64): no quoting of the command line; paths
//!   go into single-quoted PowerShell strings (`'` doubled), control characters are refused.
//! - **"Übernehmen"** (the button) also renames a desktop shortcut `BridgeControll.lnk` that points to another program
//!   (Bridge 3's `BUILD_EXE.bat` made one) to `BridgeControll 3.lnk` - it keeps working, the search finds both apart.
//!   Never without the button, never if `BridgeControll 3.lnk` exists already.
//! - At the first start the entry is made if there is none (nothing on the desktop is touched then).
//! - **Linux**: an XDG entry `bridgecontroll.desktop` in `~/.local/share/applications` (icon next to it in the app
//!   folder). **macOS**: not offered.

use std::path::{Path, PathBuf};

use base64::Engine as _;

/// Name of the entry (what the search finds).
pub const ENTRY_NAME: &str = "BridgeControll";
/// The Bridge 3 desktop shortcut gets this name.
pub const OLD_NAME: &str = "BridgeControll 3";
/// The icon of the entry, built into the program.
pub const ICON_ICO: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/logo/bridgecontroll4.ico"));
/// The icon for Linux desktops.
pub const ICON_SVG: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/logo/bridge4-app-icon.svg"));
/// File name of the icon in the app folder.
const ICON_FILE_WINDOWS: &str = "bridgecontroll4.ico";
const ICON_FILE_XDG: &str = "bridgecontroll4.svg";
/// File name of the XDG entry.
const XDG_FILE: &str = "bridgecontroll.desktop";

/// Where start menu entries of this user go (`None`: not offered here).
#[must_use]
pub fn system_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(|appdata| PathBuf::from(appdata).join("Microsoft").join("Windows").join("Start Menu").join("Programs"))
    } else if cfg!(target_os = "macos") {
        None
    } else {
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("share")))?;
        Some(data.join("applications"))
    }
}

/// The entry file in `dir`.
fn entry_path(dir: &Path) -> PathBuf {
    if cfg!(windows) { dir.join(format!("{ENTRY_NAME}.lnk")) } else { dir.join(XDG_FILE) }
}

/// Whether the entry exists in `dir`.
#[must_use]
pub fn exists(dir: &Path) -> bool {
    entry_path(dir).is_file()
}

/// A path as a single-quoted PowerShell string (`'` doubled); control characters are refused.
pub fn ps_quote(path: &Path) -> Result<String, String> {
    let text = path.to_str().ok_or("Pfad ist kein gültiger Text")?;
    if text.is_empty() || text.chars().any(char::is_control) || !path.is_absolute() {
        return Err(format!("Pfad {text:?} eignet sich nicht für den Startmenü-Eintrag"));
    }
    Ok(format!("'{}'", text.replace('\'', "''")))
}

/// The PowerShell script for Windows: the shortcut in `menu` to `exe` with `icon`; with `rename_old`, a desktop
/// shortcut `BridgeControll.lnk` to another program becomes `BridgeControll 3.lnk`. Prints `renamed` if it did.
pub fn windows_script(menu: &Path, exe: &Path, icon: &Path, rename_old: bool) -> Result<String, String> {
    let link = ps_quote(&entry_path(menu))?;
    let menu_dir = ps_quote(menu)?;
    let target = ps_quote(exe)?;
    let work = ps_quote(exe.parent().ok_or("Programm ohne Ordner")?)?;
    let icon = ps_quote(icon)?;
    let mut script = format!(
        "$ErrorActionPreference = 'Stop'\n\
         $W = New-Object -ComObject WScript.Shell\n\
         New-Item -ItemType Directory -Force -Path {menu_dir} | Out-Null\n\
         $l = $W.CreateShortcut({link})\n\
         $l.TargetPath = {target}\n\
         $l.WorkingDirectory = {work}\n\
         $l.IconLocation = {icon} + ',0'\n\
         $l.Description = 'BridgeControll - Bridge 4'\n\
         $l.Save()\n"
    );
    if rename_old {
        script.push_str(&format!(
            "$desk = [Environment]::GetFolderPath('Desktop')\n\
             $old = Join-Path $desk '{ENTRY_NAME}.lnk'\n\
             $new = Join-Path $desk '{OLD_NAME}.lnk'\n\
             if ((Test-Path -LiteralPath $old) -and -not (Test-Path -LiteralPath $new)) {{\n\
             \x20 $t = $W.CreateShortcut($old).TargetPath\n\
             \x20 if ($t -and ($t -ine {target})) {{ Rename-Item -LiteralPath $old -NewName '{OLD_NAME}.lnk'; 'renamed' }}\n\
             }}\n"
        ));
    }
    Ok(script)
}

/// The script as PowerShell's `-EncodedCommand` (UTF-16LE, Base64).
#[must_use]
pub fn encoded(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The XDG entry for Linux desktops.
pub fn xdg_entry(exe: &Path, icon: &Path) -> Result<String, String> {
    let text = |path: &Path| {
        let text = path.to_str().ok_or("Pfad ist kein gültiger Text")?.to_owned();
        let bad = |c: char| c == '"' || c == '`' || c == '$' || c == '\\' || c == '%' || c.is_control();
        if text.is_empty() || text.chars().any(bad) || !path.is_absolute() {
            return Err(format!("Pfad {text:?} eignet sich nicht für den Startmenü-Eintrag"));
        }
        Ok::<_, String>(text)
    };
    Ok(format!(
        "[Desktop Entry]\nType=Application\nName={ENTRY_NAME}\nComment=Bridge 4 / BridgeNet\nExec=\"{}\"\nIcon={}\n\
         Terminal=false\nCategories=Network;\n",
        text(exe)?,
        text(icon)?
    ))
}

/// What [`set`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
    /// Where the entry is.
    pub entry: PathBuf,
    /// The Bridge 3 desktop shortcut was renamed to "BridgeControll 3".
    pub renamed_old: bool,
}

/// Makes (or renews) the entry in `menu` for `exe`; the icon goes into `app_dir`. `rename_old`: see the module.
pub fn set(menu: &Path, app_dir: &Path, exe: &Path, rename_old: bool) -> Result<Done, String> {
    std::fs::create_dir_all(app_dir).map_err(|e| format!("{}: {e}", app_dir.display()))?;
    if cfg!(windows) {
        let icon = app_dir.join(ICON_FILE_WINDOWS);
        std::fs::write(&icon, ICON_ICO).map_err(|e| format!("{}: {e}", icon.display()))?;
        let script = windows_script(menu, exe, &icon, rename_old)?;
        let output = powershell(&encoded(&script))?;
        Ok(Done { entry: entry_path(menu), renamed_old: output.lines().any(|line| line.trim() == "renamed") })
    } else {
        let icon = app_dir.join(ICON_FILE_XDG);
        std::fs::write(&icon, ICON_SVG).map_err(|e| format!("{}: {e}", icon.display()))?;
        let content = xdg_entry(exe, &icon)?;
        std::fs::create_dir_all(menu).map_err(|e| format!("{}: {e}", menu.display()))?;
        let path = entry_path(menu);
        crate::config::write_private(&path, content.as_bytes())?;
        Ok(Done { entry: path, renamed_old: false })
    }
}

/// Runs PowerShell with an encoded script (no window); its standard output, or the error it printed.
fn powershell(encoded: &str) -> Result<String, String> {
    let mut command = std::process::Command::new("powershell.exe");
    command
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded])
        .stdin(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let output = command.output().map_err(|e| format!("PowerShell nicht startbar: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let error = String::from_utf8_lossy(&output.stderr);
        Err(format!("Startmenü-Eintrag nicht angelegt: {}", error.lines().next().unwrap_or("unbekannter Fehler")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abs(path: &str) -> PathBuf {
        if cfg!(windows) { PathBuf::from(format!("C:\\{path}")) } else { PathBuf::from(format!("/{path}")) }
    }

    #[test]
    fn powershell_strings_cannot_break_out() -> Result<(), String> {
        assert_eq!(ps_quote(&abs("Users/O'Neil/x.exe"))?.matches("''").count(), 1);
        assert!(ps_quote(&abs("a\nb")).is_err(), "control characters");
        assert!(ps_quote(Path::new("relativ.exe")).is_err());
        let script = windows_script(&abs("menu"), &abs("Bridge Test/O'Neil/bridgecontroll.exe"), &abs("i.ico"), true)?;
        // Every single quote of the path is doubled: an odd run of quotes would end the string.
        for line in script.lines().filter(|line| line.contains("Neil")) {
            assert!(line.contains("O''Neil") && !line.contains("O'Neil"), "{line}");
        }
        assert!(
            script.contains("Rename-Item") && script.contains("-ine"),
            "renames only a shortcut to another program"
        );
        assert!(!windows_script(&abs("menu"), &abs("x.exe"), &abs("i.ico"), false)?.contains("Rename-Item"));
        Ok(())
    }

    #[test]
    fn encoded_is_utf16_base64() {
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded("ü'x")).unwrap_or_default();
        assert_eq!(decoded, vec![0xFC, 0, b'\'', 0, b'x', 0]);
    }

    #[test]
    fn xdg_entry_refuses_shell_specials() -> Result<(), String> {
        let entry = xdg_entry(&abs("opt/bc/bridgecontroll"), &abs("data/icon.svg"))?;
        assert!(entry.contains("Name=BridgeControll\n") && entry.contains("Exec=\""));
        for bad in ["opt/b\"c", "opt/$HOME", "opt/`x`", "opt/a%b"] {
            assert!(xdg_entry(&abs(bad), &abs("i.svg")).is_err(), "{bad}");
        }
        Ok(())
    }

    #[cfg(not(windows))]
    #[test]
    fn linux_entry_is_written() -> Result<(), String> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let (menu, app) = (dir.path().join("applications"), dir.path().join("app"));
        assert!(!exists(&menu));
        let done = set(&menu, &app, &abs("opt/bc/bridgecontroll"), true)?;
        assert!(exists(&menu) && !done.renamed_old);
        assert_eq!(std::fs::read(app.join(ICON_FILE_XDG)).map_err(|e| e.to_string())?, ICON_SVG);
        Ok(())
    }

    #[test]
    fn the_icon_is_an_ico() {
        assert_eq!(&ICON_ICO[..4], &[0, 0, 1, 0], "ICO header");
    }
}
