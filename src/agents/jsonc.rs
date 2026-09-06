//! Lossless edits to JSON-with-comments objects; untouched text is retained verbatim.
use super::AgentError;
use serde_json::{Map, Value};

struct Field {
    key: String,
    start: usize,
    node: Node,
    comma: Option<usize>,
}
struct Node {
    start: usize,
    end: usize,
    value: Value,
    fields: Vec<Field>,
}
struct Parser<'a> {
    source: &'a str,
    cursor: usize,
}
impl<'a> Parser<'a> {
    fn skip(&mut self) -> Result<(), AgentError> {
        let bytes = self.source.as_bytes();
        loop {
            while bytes.get(self.cursor).is_some_and(u8::is_ascii_whitespace) {
                self.cursor += 1;
            }
            if bytes.get(self.cursor..self.cursor + 2) == Some(b"//") {
                while bytes.get(self.cursor).is_some_and(|b| *b != b'\n') {
                    self.cursor += 1;
                }
            } else if bytes.get(self.cursor..self.cursor + 2) == Some(b"/*") {
                let end = self.source[self.cursor + 2..]
                    .find("*/")
                    .ok_or(AgentError::Invalid)?;
                self.cursor += end + 4;
            } else {
                return Ok(());
            }
        }
    }
    fn byte(&self) -> Option<u8> {
        self.source.as_bytes().get(self.cursor).copied()
    }
    fn consume(&mut self, byte: u8) -> Result<(), AgentError> {
        self.skip()?;
        if self.byte() != Some(byte) {
            return Err(AgentError::Invalid);
        }
        self.cursor += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<String, AgentError> {
        self.skip()?;
        let start = self.cursor;
        self.consume(b'"')?;
        loop {
            match self.byte() {
                None => return Err(AgentError::Invalid),
                Some(b'\\') => {
                    self.cursor += 2;
                }
                Some(b'"') => {
                    self.cursor += 1;
                    break;
                }
                _ => self.cursor += 1,
            }
        }
        serde_json::from_str(&self.source[start..self.cursor]).map_err(|_| AgentError::Invalid)
    }
    fn node(&mut self, depth: usize) -> Result<Node, AgentError> {
        if depth > 128 {
            return Err(AgentError::TooLarge);
        }
        self.skip()?;
        let start = self.cursor;
        let mut fields = Vec::new();
        let value = match self.byte() {
            Some(b'{') => {
                self.cursor += 1;
                self.skip()?;
                let mut object = Map::new();
                while self.byte() != Some(b'}') {
                    self.skip()?;
                    let field_start = self.cursor;
                    let key = self.string()?;
                    if object.contains_key(&key) {
                        return Err(AgentError::Invalid);
                    }
                    self.consume(b':')?;
                    let node = self.node(depth + 1)?;
                    self.skip()?;
                    let comma = if self.byte() == Some(b',') {
                        let at = self.cursor;
                        self.cursor += 1;
                        self.skip()?;
                        Some(at)
                    } else if self.byte() == Some(b'}') {
                        None
                    } else {
                        return Err(AgentError::Invalid);
                    };
                    object.insert(key.clone(), node.value.clone());
                    fields.push(Field {
                        key,
                        start: field_start,
                        node,
                        comma,
                    });
                }
                self.consume(b'}')?;
                Value::Object(object)
            }
            Some(b'[') => {
                self.cursor += 1;
                self.skip()?;
                let mut values = Vec::new();
                while self.byte() != Some(b']') {
                    values.push(self.node(depth + 1)?.value);
                    self.skip()?;
                    if self.byte() == Some(b',') {
                        self.cursor += 1;
                        self.skip()?;
                    } else if self.byte() != Some(b']') {
                        return Err(AgentError::Invalid);
                    }
                }
                self.consume(b']')?;
                Value::Array(values)
            }
            Some(b'"') => Value::String(self.string()?),
            Some(_) => {
                while self.byte().is_some_and(|b| {
                    !b.is_ascii_whitespace() && !matches!(b, b',' | b'}' | b']' | b'/')
                }) {
                    self.cursor += 1;
                }
                if start == self.cursor {
                    return Err(AgentError::Invalid);
                }
                serde_json::from_str(&self.source[start..self.cursor])
                    .map_err(|_| AgentError::Invalid)?
            }
            None => return Err(AgentError::Invalid),
        };
        Ok(Node {
            start,
            end: self.cursor,
            value,
            fields,
        })
    }
}
fn document(source: &str) -> Result<Node, AgentError> {
    if source.len() > 8 * 1024 * 1024 {
        return Err(AgentError::TooLarge);
    }
    let mut parser = Parser { source, cursor: 0 };
    let node = parser.node(0)?;
    parser.skip()?;
    if parser.cursor != source.len() || !node.value.is_object() {
        return Err(AgentError::Invalid);
    }
    Ok(node)
}
pub fn parse(source: &str) -> Result<Value, AgentError> {
    Ok(document(source)?.value)
}

pub fn edit(source: &str, path: &[&str], value: Option<&Value>) -> Result<String, AgentError> {
    if path.is_empty() {
        return Err(AgentError::Invalid);
    }
    let root = document(source)?;
    let result = edit_node(source, &root, path, value)?;
    document(&result)?;
    Ok(result)
}
fn edit_node(
    source: &str,
    node: &Node,
    path: &[&str],
    value: Option<&Value>,
) -> Result<String, AgentError> {
    if !node.value.is_object() {
        return Err(AgentError::Invalid);
    }
    if let Some((index, field)) = node
        .fields
        .iter()
        .enumerate()
        .find(|(_, f)| f.key == path[0])
    {
        if path.len() > 1 {
            return edit_node(source, &field.node, &path[1..], value);
        }
        if let Some(value) = value {
            let encoded = serde_json::to_string_pretty(value).map_err(|_| AgentError::Invalid)?;
            return Ok(format!(
                "{}{}{}",
                &source[..field.node.start],
                encoded,
                &source[field.node.end..]
            ));
        }
        let mut result = source.to_string();
        if let Some(comma) = field.comma {
            result.replace_range(comma..comma + 1, "");
            result.replace_range(field.start..field.node.end, "");
        } else {
            result.replace_range(field.start..field.node.end, "");
            if index > 0
                && let Some(comma) = node.fields[index - 1].comma
            {
                result.replace_range(comma..comma + 1, "");
            }
        }
        return Ok(result);
    }
    let Some(value) = value else {
        return Ok(source.into());
    };
    let mut value = value.clone();
    for key in path[1..].iter().rev() {
        value = Value::Object([(key.to_string(), value)].into_iter().collect());
    }
    let key = serde_json::to_string(path[0]).map_err(|_| AgentError::Invalid)?;
    let value = serde_json::to_string_pretty(&value).map_err(|_| AgentError::Invalid)?;
    let comma = if node
        .fields
        .last()
        .is_some_and(|field| field.comma.is_none())
    {
        ","
    } else {
        ""
    };
    let insertion = node.end - 1;
    // Insert a missing comma at the previous value rather than after a line comment.
    let mut result = source.to_string();
    result.insert_str(insertion, &format!("\n{key}: {value}\n"));
    if !comma.is_empty() {
        result.insert(node.fields.last().unwrap().node.end, ',');
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn merging_and_removing_keep_comments_other_providers_and_trailing_commas() {
        let source = "{\n// keep header\n\"provider\": {\n\"user\": {\"url\": \"https://test//x\"}, // keep user comment\n},\n\"theme\": \"dark\",\n}";
        let edited = edit(
            source,
            &["provider", "quotio"],
            Some(&json!({"options":{"apiKey":"fixture"}})),
        )
        .unwrap();
        assert!(edited.contains("// keep header"));
        assert!(edited.contains("// keep user comment"));
        assert_eq!(
            parse(&edited).unwrap()["provider"]["user"],
            parse(source).unwrap()["provider"]["user"]
        );
        let removed = edit(&edited, &["provider", "quotio"], None).unwrap();
        assert_eq!(parse(&removed).unwrap(), parse(source).unwrap());
        assert!(removed.contains("// keep user comment"));
    }
    #[test]
    fn invalid_duplicates_or_non_object_providers_fail_closed() {
        for source in [
            "{\"x\":1,\"x\":2}",
            "{/*unfinished",
            "[]",
            "{\"provider\":[]}",
        ] {
            assert!(edit(source, &["provider", "quotio"], Some(&json!({}))).is_err());
        }
        let source = "{\"x\":1 // trailing comment\n}";
        assert_eq!(
            parse(&edit(source, &["provider", "quotio"], Some(&json!({}))).unwrap()).unwrap()["x"],
            1
        );
    }
}
