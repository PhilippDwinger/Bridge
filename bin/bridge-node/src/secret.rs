//! Reading the 24 words of the master key for `net rescue` (docs/06 §10) without leaving copies behind.
//!
//! - Never through std's global standard-input buffer (`std::io::stdin()` keeps what it read there for the life of
//!   the process): on a Unix terminal the words are read from the terminal device itself (`/dev/tty`), otherwise -
//!   and on Windows always - from a private duplicate of the standard input handle. Windows never opens the console
//!   `CONIN$` (review 6, finding 7): in Git Bash/MSYS (mintty) standard input is a pipe that std reports as a
//!   terminal, while `CONIN$` belongs to a hidden console nobody types into - the command hung.
//! - Byte by byte, up to the line end, into one buffer of at most 1 KiB that never grows (no stray copy on a
//!   reallocation) and is wiped on drop - no hidden buffer in between.
//! - Unix terminal: the echo is off while typing (the line end is still shown). The old terminal settings come back
//!   on every way out: the line was read, reading failed, or a signal came (Ctrl+C, Ctrl+\, Ctrl+Z, `SIGTERM`,
//!   `SIGHUP` - the input is cancelled and the program ends with code 130). The signal handlers stay for the rest of
//!   the command and end it the same way (a handled signal no longer stops the process by itself).
//! - Windows: the console (or mintty) shows what is typed - switching its echo off needs the console API, which only
//!   `unsafe` code could call here (forbidden); docs/06 §10 says so. The prompt is shown when standard input is a
//!   terminal.

use std::io::{self, IsTerminal, Read};

use zeroize::Zeroizing;

/// Longest line read (the 24 words are at most about 220 characters).
pub(crate) const MAX_LINE: usize = 1024;

/// Reads one line (without the line end, at most [`MAX_LINE`] bytes) from `source`, byte by byte into a buffer that
/// never grows and is wiped on drop. End of input ends the line; a longer line is an error.
pub(crate) fn read_line(mut source: impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_LINE));
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match source.read(&mut byte[..]) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) if line.len() >= MAX_LINE => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "longer than 1 KiB"));
            }
            Ok(_) => line.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop(); // Windows line end (the byte stays in the buffer and is wiped with it)
    }
    Ok(line)
}

/// Reads the secret line - always past std's buffer: on Unix from the terminal (echo off, after showing `prompt` on
/// standard error) if standard input is one; otherwise, and on Windows always, from a private duplicate of the
/// standard input handle (Windows: after showing `prompt` if standard input is a terminal).
pub(crate) async fn read_secret_line(prompt: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    #[cfg(not(windows))]
    if io::stdin().is_terminal() {
        return terminal::read(prompt).await;
    }
    #[cfg(windows)]
    if io::stdin().is_terminal() {
        eprintln!("{prompt}");
    }
    let input = duplicate_stdin().map_err(|e| format!("Standard-Eingabe nicht lesbar: {e}"))?;
    blocking_read(input).await
}

async fn blocking_read(source: std::fs::File) -> Result<Zeroizing<Vec<u8>>, String> {
    tokio::task::spawn_blocking(move || read_line(source))
        .await
        .map_err(|_| "Lesen abgebrochen".to_owned())?
        .map_err(|e| format!("Wörter nicht lesbar: {e}"))
}

/// A private handle to standard input: reads from it never go through std's global buffer.
fn duplicate_stdin() -> io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(std::fs::File::from(io::stdin().as_fd().try_clone_to_owned()?))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        Ok(std::fs::File::from(io::stdin().as_handle().try_clone_to_owned()?))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::new(io::ErrorKind::Unsupported, "no standard input handle on this system"))
    }
}

#[cfg(unix)]
mod terminal {
    use std::fs::{File, OpenOptions};

    use rustix::termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr};
    use tokio::signal::unix::{Signal, SignalKind, signal};
    use zeroize::Zeroizing;

    /// Puts the saved terminal settings back when dropped.
    struct Restore {
        tty: File,
        saved: Termios,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = tcsetattr(&self.tty, OptionalActions::Now, &self.saved);
        }
    }

    /// The signals that end the input (and, afterwards, the command).
    struct Signals([Signal; 5]);

    impl Signals {
        fn new() -> std::io::Result<Self> {
            let stop = SignalKind::from_raw(rustix::process::Signal::TSTP.as_raw());
            Ok(Self([
                signal(SignalKind::interrupt())?,
                signal(SignalKind::quit())?,
                signal(stop)?,
                signal(SignalKind::terminate())?,
                signal(SignalKind::hangup())?,
            ]))
        }

        /// Waits for any of them.
        async fn any(&mut self) {
            let [a, b, c, d, e] = &mut self.0;
            tokio::select! {
                _ = a.recv() => {}
                _ = b.recv() => {}
                _ = c.recv() => {}
                _ = d.recv() => {}
                _ = e.recv() => {}
            }
        }
    }

    /// Switches the echo of `/dev/tty` off, shows `prompt` and reads the line; the terminal is restored on every way
    /// out.
    pub(super) async fn read(prompt: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let unreadable = |e: std::io::Error| format!("Terminal nicht lesbar: {e}");
        let tty = OpenOptions::new().read(true).write(true).open("/dev/tty").map_err(unreadable)?;
        // The handlers first: from the moment the echo is off, a signal can no longer end the program unrestored.
        let mut signals = Signals::new().map_err(|e| format!("Signale: {e}"))?;
        let saved = tcgetattr(&tty).map_err(|e| unreadable(e.into()))?;
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        quiet.local_modes.insert(LocalModes::ECHONL);
        let restore = Restore { tty: tty.try_clone().map_err(unreadable)?, saved };
        // `Flush`: anything typed before the prompt (and shown) is dropped, not taken as part of the words.
        tcsetattr(&tty, OptionalActions::Flush, &quiet).map_err(|e| unreadable(e.into()))?;
        eprintln!("{prompt}");
        let reading = tokio::task::spawn_blocking(move || super::read_line(tty));
        tokio::select! {
            read = reading => {
                drop(restore);
                // A handled signal does not end the process by itself any more: end the command on the next one.
                tokio::spawn(async move {
                    signals.any().await;
                    std::process::exit(130);
                });
                read.map_err(|_| "Lesen abgebrochen".to_owned())?.map_err(|e| format!("Wörter nicht lesbar: {e}"))
            }
            () = signals.any() => {
                drop(restore);
                eprintln!("\nAbgebrochen (die Anzeige im Terminal ist wieder an).");
                std::process::exit(130);
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod terminal {
    use zeroize::Zeroizing;

    pub(super) async fn read(_prompt: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        Err("Auf diesem System können die Wörter nicht sicher gelesen werden.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source that hands out its bytes one call at a time, with an interruption in between.
    struct Slow<'a> {
        bytes: &'a [u8],
        interrupted: bool,
    }

    impl Read for Slow<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "signal"));
            }
            let Some((first, rest)) = self.bytes.split_first() else { return Ok(0) };
            match buf.first_mut() {
                Some(slot) => *slot = *first,
                None => return Ok(0),
            }
            self.bytes = rest;
            Ok(1)
        }
    }

    #[test]
    fn reads_exactly_one_line_into_a_buffer_that_never_grows() -> io::Result<()> {
        let mut source = Slow { bytes: b"abandon art\r\nrest", interrupted: false };
        let line = read_line(&mut source)?;
        assert_eq!(line.as_slice(), b"abandon art");
        assert_eq!(line.capacity(), MAX_LINE, "no reallocation");
        assert_eq!(source.bytes, b"rest", "nothing read past the line end");
        assert_eq!(read_line(&b"no line end"[..])?.as_slice(), b"no line end");
        assert!(read_line(&b""[..])?.is_empty());
        let exactly = vec![b'a'; MAX_LINE];
        assert_eq!(read_line(&exactly[..])?.len(), MAX_LINE);
        let too_long = vec![b'a'; MAX_LINE + 1];
        assert_eq!(
            read_line(&too_long[..]).map(|line| line.len()).map_err(|e| e.kind()),
            Err(io::ErrorKind::InvalidData)
        );
        Ok(())
    }
}
