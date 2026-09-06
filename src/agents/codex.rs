//! Surgical edits to Codex's managed root keys and provider table.
use super::AgentError;

const BANNER: &str = "# CLIProxyAPI Configuration for Codex CLI";

pub fn managed(model: &str, url: &str, effort: &str) -> Result<String, AgentError> {
    if model.is_empty() || effort.is_empty() {
        return Err(AgentError::Invalid);
    }
    let quote = |value: &str| serde_json::to_string(value).map_err(|_| AgentError::Invalid);
    Ok(format!(
        "{BANNER}\nmodel_provider = \"cliproxyapi\"\nmodel = {}\nmodel_reasoning_effort = {}\n\n[model_providers.cliproxyapi]\nname = \"cliproxyapi\"\nbase_url = {}\nwire_api = \"responses\"\n",
        quote(model)?,
        quote(effort)?,
        quote(url)?
    ))
}

pub fn merge(existing: &str, fragment: &str) -> Result<String, AgentError> {
    let cleaned = remove(existing)?;
    let mut scanner = Scanner::default();
    let lines: Vec<_> = cleaned.lines().collect();
    let split = lines
        .iter()
        .position(|line| scanner.structural(line) && line.trim_start().starts_with('['))
        .unwrap_or(lines.len());
    let (managed_top, managed_section) = fragment
        .split_once("[model_providers.cliproxyapi]")
        .ok_or(AgentError::Invalid)?;
    let output = format!(
        "{}\n{}\n[model_providers.cliproxyapi]{}\n{}\n",
        managed_top.trim_end(),
        lines[..split].join("\n"),
        managed_section.trim_end(),
        lines[split..].join("\n")
    );
    let _: toml::Value = toml::from_str(&output).map_err(|_| AgentError::Invalid)?;
    Ok(output)
}

pub fn remove(existing: &str) -> Result<String, AgentError> {
    let _: toml::Value = toml::from_str(existing).map_err(|_| AgentError::Invalid)?;
    let mut scanner = Scanner::default();
    let mut in_section = false;
    let mut skip = false;
    let mut output = Vec::new();
    for line in existing.lines() {
        let structural = scanner.structural(line);
        let trimmed = line.trim();
        if structural && trimmed.starts_with('[') {
            in_section = true;
            // Parsing a probe also recognizes quoted table names without guessing syntax.
            let probe: toml::Value = toml::from_str(&format!("{trimmed}\n__quotio_probe = true\n"))
                .map_err(|_| AgentError::Invalid)?;
            skip = probe
                .get("model_providers")
                .and_then(|v| v.get("cliproxyapi"))
                .is_some();
        }
        if skip {
            continue;
        }
        if structural && !in_section {
            if trimmed == BANNER {
                continue;
            }
            if let Some((key, _)) = trimmed.split_once('=') {
                let key = key.trim().trim_matches(['\'', '"']);
                if matches!(key, "model_provider" | "model" | "model_reasoning_effort") {
                    continue;
                }
            }
        }
        output.push(line);
    }
    Ok(output.join("\n") + "\n")
}

#[derive(Default)]
struct Scanner {
    multiline: Option<u8>,
    array_depth: usize,
}
impl Scanner {
    fn structural(&mut self, line: &str) -> bool {
        let structural = self.multiline.is_none() && self.array_depth == 0;
        let bytes = line.as_bytes();
        let mut index = 0;
        // Section headers are not array values.
        if structural && line.trim_start().starts_with('[') {
            return true;
        }
        while index < bytes.len() {
            let byte = bytes[index];
            if let Some(quote) = self.multiline {
                if quote == b'"' && byte == b'\\' {
                    index += 2;
                    continue;
                }
                if bytes.get(index..index + 3) == Some(&[quote, quote, quote]) {
                    self.multiline = None;
                    index += 3;
                } else {
                    index += 1;
                }
            } else if byte == b'#' {
                break;
            } else if byte == b'"' || byte == b'\'' {
                if bytes.get(index..index + 3) == Some(&[byte, byte, byte]) {
                    self.multiline = Some(byte);
                    index += 3;
                } else {
                    index += 1;
                    while index < bytes.len() {
                        if byte == b'"' && bytes[index] == b'\\' {
                            index += 2;
                            continue;
                        }
                        if bytes[index] == byte {
                            index += 1;
                            break;
                        }
                        index += 1;
                    }
                }
            } else {
                if byte == b'[' {
                    self.array_depth += 1;
                }
                if byte == b']' {
                    self.array_depth = self.array_depth.saturating_sub(1);
                }
                index += 1;
            }
        }
        structural
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_comments_multiline_content_profiles_and_custom_effort() {
        let existing = r#"# user comment
model = "old"
model_provider = "cliproxyapi"
note = '''
model = "inside string"
[model_providers.cliproxyapi]
'''
[model_providers.cliproxyapi]
base_url = "old"
[profiles.work]
model = "keep"
[tools]
enabled = true
"#;
        let output = merge(
            existing,
            &managed("model\"quote", "http://127.0.0.1:8317/v1", "future-effort").unwrap(),
        )
        .unwrap();
        assert!(output.contains("# user comment"));
        assert!(output.contains("model = \"inside string\""));
        let value: toml::Value = toml::from_str(&output).unwrap();
        assert_eq!(value["profiles"]["work"]["model"].as_str(), Some("keep"));
        assert_eq!(value["model"].as_str(), Some("model\"quote"));
        assert_eq!(
            value["model_reasoning_effort"].as_str(),
            Some("future-effort")
        );
        assert_eq!(
            merge(
                &output,
                &managed("model\"quote", "http://127.0.0.1:8317/v1", "future-effort").unwrap()
            )
            .unwrap()
            .matches("model_provider =")
            .count(),
            1
        );
    }
    #[test]
    fn rejects_invalid_toml_instead_of_overwriting_user_content() {
        assert!(merge("broken = [", &managed("model", "url", "high").unwrap()).is_err());
    }
}
