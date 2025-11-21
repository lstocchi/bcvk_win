use std::process::Command;
use std::io::{Read, Seek};

use color_eyre::eyre::{Context, Result, eyre};


/// Helpers intended for [`std::process::Command`].
pub trait CommandRun {
    /// Execute the child process.
    fn run(&mut self) -> Result<()>;

    /// Execute the child process and capture its output. This uses `run` internally
    /// and will return an error if the child process exits abnormally.
    fn run_get_output(&mut self) -> Result<Box<dyn std::io::BufRead>>;

    /// Execute the child process and capture its output as a string.
    fn run_get_string(&mut self) -> Result<String>;

    /// Execute the child process, parsing its stdout as JSON. This uses `run` internally
    /// and will return an error if the child process exits abnormally.
    fn run_and_parse_json<T: serde::de::DeserializeOwned>(&mut self) -> Result<T>;
}

/// Helpers intended for [`std::process::ExitStatus`].
pub trait ExitStatusExt {
    /// If the exit status signals it was not successful, return an error.
    /// Note that we intentionally *don't* include the command string
    /// in the output; we leave it to the caller to add that if they want,
    /// as it may be verbose.
    fn check_status(&mut self, stderr: std::fs::File) -> Result<()>;
}

impl ExitStatusExt for std::process::ExitStatus {
    fn check_status(&mut self, stderr: std::fs::File) -> Result<()> {
        let stderr_buf = last_utf8_content_from_file(stderr);
        if self.success() {
            return Ok(());
        }
        Err(eyre!(format!("Subprocess failed: {self:?}\n{stderr_buf}")))
    }
}

fn last_utf8_content_from_file(mut f: std::fs::File) -> String {
    // u16 since we truncate to just the trailing bytes here
    // to avoid pathological error messages
    const MAX_STDERR_BYTES: u16 = 1024;
    let size = f
        .metadata()
        .map_err(|e| {
            tracing::warn!("failed to fstat: {e}");
        })
        .map(|m| m.len().try_into().unwrap_or(u16::MAX))
        .unwrap_or(0);
    let size = size.min(MAX_STDERR_BYTES);
    let seek_offset = -(size as i32);
    let mut stderr_buf = Vec::with_capacity(size.into());
    // We should never fail to seek()+read() really, but let's be conservative
    let r = match f
        .seek(std::io::SeekFrom::End(seek_offset.into()))
        .and_then(|_| f.read_to_end(&mut stderr_buf))
    {
        Ok(_) => String::from_utf8_lossy(&stderr_buf),
        Err(e) => {
            tracing::warn!("failed seek+read: {e}");
            "<failed to read stderr>".into()
        }
    };
    (&*r).to_owned()
}

impl CommandRun for Command {
    /// Synchronously execute the child, and return an error if the child exited unsuccessfully.
    fn run(&mut self) -> Result<()> {
        let stderr = tempfile::tempfile()?;
        self.stderr(stderr.try_clone()?);
        tracing::trace!("exec: {self:?}");
        self.status()?.check_status(stderr)
    }

    fn run_get_output(&mut self) -> Result<Box<dyn std::io::BufRead>> {
        let mut stdout = tempfile::tempfile()?;
        self.stdout(stdout.try_clone()?);
        self.run()?;
        stdout.seek(std::io::SeekFrom::Start(0)).context("seek")?;
        Ok(Box::new(std::io::BufReader::new(stdout)))
    }

    fn run_get_string(&mut self) -> Result<String> {
        let mut s = String::new();
        let mut o = self.run_get_output()?;
        o.read_to_string(&mut s)?;
        Ok(s)
    }

    /// Synchronously execute the child, and parse its stdout as JSON.
    fn run_and_parse_json<T: serde::de::DeserializeOwned>(&mut self) -> Result<T> {
        let output = self.run_get_output()?;
        serde_json::from_reader(output).map_err(Into::into)
    }
}