use std::process::Command;

/// Implementation of CommandRunExt for non-Linux platforms
/// This was taken from bootc_utils::CommandRunExt on Linux
///
/// This provides a basic implementation that works for simple cases.
/// For full functionality, non-Linux specific implementations should be added.
pub trait CommandRunExt {
    fn run_and_parse_json<T: serde::de::DeserializeOwned>(
        &mut self,
    ) -> Result<T, Box<dyn std::error::Error + Send + Sync>>;
}

impl CommandRunExt for Command {
    fn run_and_parse_json<T: serde::de::DeserializeOwned>(
        &mut self,
    ) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        let output = self.output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Command failed: {}", stderr).into());
        }
        let json_str = String::from_utf8(output.stdout)?;
        let parsed: T = serde_json::from_str(&json_str)?;
        Ok(parsed)
    }
}
