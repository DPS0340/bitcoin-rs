use std::path::Path;

use anyhow::{Context as _, Result};
use bitcoin_rs_node::UserConfig;

/// Reports malformed syntax or field values without retaining operator input.
fn sanitized_parse_error(text: &str, error: &toml::de::Error) -> anyhow::Error {
    // Serde messages and key context can contain credentials even after TOML's
    // source excerpt is removed. Keep only the value-independent location.
    match error.span().map(|span| line_column(text, span.start)) {
        Some((line, column)) => {
            anyhow::anyhow!("invalid TOML syntax or field value at line {line}, column {column}")
        }
        None => anyhow::anyhow!("invalid TOML syntax or field value"),
    }
}

/// Translates a byte offset into one-based line and character-column numbers.
fn line_column(text: &str, byte_index: usize) -> (usize, usize) {
    let byte_index = byte_index.min(text.len());
    let mut line = 1;
    let mut line_start = 0;
    for (index, byte) in text.bytes().take(byte_index).enumerate() {
        if byte == b'\n' {
            line += 1;
            line_start = index + 1;
        }
    }
    let column = text
        .get(line_start..byte_index)
        .map_or(byte_index - line_start, |line| line.chars().count())
        + 1;
    (line, column)
}

/// Resolves the TOML layer from a configuration file.
pub(crate) fn user_config_from_path(path: &Path) -> Result<UserConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read TOML config {}", path.display()))?;
    toml::from_str(&text)
        .map_err(|error| sanitized_parse_error(&text, &error))
        .with_context(|| format!("failed to parse TOML config {}", path.display()))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    #[test]
    fn malformed_toml_error_omits_secret_source_but_keeps_diagnostics() -> Result<()> {
        const SECRET_TEST_SENTINEL: &str = "rpc-password-test-sentinel";

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("node.toml");
        for input in [
            format!("rpc_password = \"{SECRET_TEST_SENTINEL}\\q\"\n"),
            "rpc_password = 867530912345\n".to_owned(),
            format!("{SECRET_TEST_SENTINEL} = true\n"),
        ] {
            std::fs::write(&path, input)?;
            let error = match super::user_config_from_path(&path) {
                Ok(_) => panic!("malformed TOML must be rejected"),
                Err(error) => error,
            };
            for rendered in [format!("{error:#}"), format!("{error:?}")] {
                assert!(!rendered.contains(SECRET_TEST_SENTINEL));
                assert!(!rendered.contains("867530912345"));
                assert!(rendered.contains("line 1, column"));
            }
        }
        Ok(())
    }
}
