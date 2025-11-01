//! Response file expansion utilities
//!
//! This module provides utilities to expand response files (arguments starting with @)
//! into their constituent tokens. Response files allow toolchains to pass arguments
//! via files rather than command lines, which is useful for very long argument lists.
//!
//! # Example
//! ```no_run
//! // If args.rsp contains: -O2 -Wall "my file.c"
//! // Then @args.rsp will be expanded to: ["-O2", "-Wall", "my file.c"]
//! ```

use std::fs;
use std::io;

/// Expands a single response file token into its constituent arguments
///
/// If the token starts with '@', this function reads the file at the path
/// and tokenizes its contents. Handles quoted strings and basic escaping.
///
/// # Arguments
/// * `token` - A potential response file token (e.g., "@args.rsp")
///
/// # Returns
/// * `Some(Vec<String>)` - If the token was a response file and was successfully expanded
/// * `None` - If the token is not a response file or cannot be expanded
#[must_use]
pub fn expand_response_file(token: &str) -> Option<Vec<String>> {
    if !token.starts_with('@') {
        return None;
    }

    let path = &token[1..];
    match fs::read_to_string(path) {
        Ok(content) => Some(tokenize_response_file(&content)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // File not found - return None to let caller handle it
            None
        }
        Err(_) => {
            // Other I/O errors - return None to let caller handle it
            None
        }
    }
}

/// Tokenizes the content of a response file into individual arguments
///
/// Handles:
/// - Whitespace separation (spaces, tabs, newlines, carriage returns)
/// - Double-quoted strings (preserves spaces within quotes)
/// - Backslash escaping
///
/// # Arguments
/// * `content` - The text content of a response file
///
/// # Returns
/// A vector of tokenized arguments
fn tokenize_response_file(content: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current_token = String::new();
    let mut in_quotes = false;
    let mut escape_next = false;

    for ch in content.chars() {
        if escape_next {
            current_token.push(ch);
            escape_next = false;
            continue;
        }

        match ch {
            '\\' => {
                escape_next = true;
            }
            '"' => {
                in_quotes = !in_quotes;
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current_token.is_empty() {
                    tokens.push(current_token.clone());
                    current_token.clear();
                }
            }
            c => {
                current_token.push(c);
            }
        }
    }

    if !current_token.is_empty() {
        tokens.push(current_token);
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_simple() {
        let content = "-O2 -Wall -DFOO=bar";
        let tokens = tokenize_response_file(content);
        assert_eq!(tokens, vec!["-O2", "-Wall", "-DFOO=bar"]);
    }

    #[test]
    fn test_tokenize_quoted_strings() {
        let content = r#"-I"my dir" -DSTR="hello world""#;
        let tokens = tokenize_response_file(content);
        // Quotes are removed and content preserved
        assert_eq!(tokens, vec!["-Imy dir", "-DSTR=hello world"]);
    }

    #[test]
    fn test_tokenize_multiline() {
        let content = "-O2\n-Wall\r\n-DFOO";
        let tokens = tokenize_response_file(content);
        assert_eq!(tokens, vec!["-O2", "-Wall", "-DFOO"]);
    }

    #[test]
    fn test_tokenize_escaped_quotes() {
        let content = r#"test \"quoted\" value"#;
        let tokens = tokenize_response_file(content);
        // Escaped quotes in the raw string become regular quotes when parsed
        assert_eq!(tokens, vec!["test", r#""quoted""#, "value"]);
    }

    #[test]
    fn test_expand_response_file_not_response() {
        let result = expand_response_file("-O2");
        assert_eq!(result, None);
    }

    #[test]
    fn test_expand_response_file_nonexistent() {
        let result = expand_response_file("@/nonexistent/path/to/file.rsp");
        assert_eq!(result, None);
    }
}
