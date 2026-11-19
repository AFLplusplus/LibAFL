//! Response file (`@file`) expansion for compiler/archiver command lines.
//!
//! Many toolchains (MSVC, GNU `ld`/`ar`, and Clang/GCC) support passing extra
//! command-line arguments via a "response file": an argument of the form
//! `@path/to/file` whose contents are read and tokenized into additional
//! arguments, spliced in place of the `@file` token. Build systems that emit
//! very long argument lists (for example, one object file per line) commonly
//! rely on this to avoid hitting OS command-line length limits.
//!
//! `libafl_cc`'s per-[`crate::Configuration`] argument rewriting (renaming
//! `foo.o` to `foo.coverage.o`, for example) walks the argument list
//! directly, so any filenames hidden behind an `@file` token were invisible
//! to it and never got rewritten. This module expands `@file` tokens before
//! that rewriting happens, so the rest of the pipeline only ever sees
//! literal arguments.

use std::{fs, path::Path};

use crate::Error;

/// Maximum recursion depth for nested `@file` references, guarding against
/// cycles (`a.rsp` containing `@a.rsp`) or pathological chains.
const MAX_RESPONSE_FILE_DEPTH: usize = 16;

/// Expand any `@file` (response file) arguments in `args`, returning a
/// flattened argument list with no response-file tokens remaining.
///
/// A bare `@` (no filename following it) and any token starting with `@`
/// that does not point at a readable file are passed through unchanged --
/// this matches Clang/GCC/`ar`'s behavior of only treating `@` specially
/// when it resolves to an existing file, and avoids misinterpreting other
/// arguments that happen to start with `@`.
pub fn expand_response_files<S: AsRef<str>>(args: &[S]) -> Result<Vec<String>, Error> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        expand_one(arg.as_ref(), &mut out, 0)?;
    }
    Ok(out)
}

fn expand_one(arg: &str, out: &mut Vec<String>, depth: usize) -> Result<(), Error> {
    let Some(file_path) = arg.strip_prefix('@') else {
        out.push(arg.to_string());
        return Ok(());
    };

    if file_path.is_empty() || !Path::new(file_path).is_file() {
        // Not a real response file reference -- leave it alone.
        out.push(arg.to_string());
        return Ok(());
    }

    if depth >= MAX_RESPONSE_FILE_DEPTH {
        return Err(Error::InvalidArguments(format!(
            "Response file nesting exceeded {MAX_RESPONSE_FILE_DEPTH} levels while expanding \
             '{arg}' -- possible cyclic @file reference"
        )));
    }

    let contents = fs::read_to_string(file_path).map_err(Error::Io)?;
    for token in tokenize(&contents) {
        expand_one(&token, out, depth + 1)?;
    }
    Ok(())
}

/// Tokenize the contents of a response file into individual arguments.
///
/// Response files are whitespace-separated (including newlines), support
/// both single- and double-quoted segments (so paths containing spaces
/// survive), and support backslash-escaping of the following character --
/// the common subset of GNU and MSVC response file conventions.
fn tokenize(contents: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;
    let mut chars = contents.chars().peekable();

    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == '\\' && chars.peek().is_some_and(|&n| n == q || n == '\\') {
                    current.push(chars.next().unwrap());
                } else if c == q {
                    quote = None;
                } else {
                    current.push(c);
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    in_token = true;
                }
                '\\' if chars.peek().is_some() => {
                    current.push(chars.next().unwrap());
                    in_token = true;
                }
                c if c.is_whitespace() => {
                    if in_token {
                        tokens.push(core::mem::take(&mut current));
                        in_token = false;
                    }
                }
                c => {
                    current.push(c);
                    in_token = true;
                }
            },
        }
    }
    if in_token || !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    /// Minimal scoped temp-file helper so these tests don't need an extra
    /// dev-dependency. Writes `contents` to a fresh path under the OS temp
    /// dir and removes it on drop.
    struct ScratchFile {
        path: std::path::PathBuf,
    }

    impl ScratchFile {
        fn new(contents: &str) -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "libafl_cc_response_file_test_{}_{unique}.rsp",
                std::process::id()
            ));
            fs::write(&path, contents).unwrap();
            Self { path }
        }

        fn at_arg(&self) -> String {
            format!("@{}", self.path.display())
        }
    }

    impl Drop for ScratchFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    #[test]
    fn tokenize_basic() {
        assert_eq!(
            tokenize("-o foo.o -c bar.c"),
            vec!["-o", "foo.o", "-c", "bar.c"]
        );
    }

    #[test]
    fn tokenize_quoted_with_space() {
        assert_eq!(
            tokenize(r#"-o "my file.o" -c bar.c"#),
            vec!["-o", "my file.o", "-c", "bar.c"]
        );
    }

    #[test]
    fn tokenize_escaped_space() {
        assert_eq!(tokenize(r"-o my\ file.o"), vec!["-o", "my file.o"]);
    }

    #[test]
    fn tokenize_multiline() {
        assert_eq!(
            tokenize("-o foo.o\n-c bar.c\n"),
            vec!["-o", "foo.o", "-c", "bar.c"]
        );
    }

    #[test]
    fn non_response_file_arg_untouched() {
        let args = vec!["@this-file-does-not-exist.rsp".to_string()];
        let expanded = expand_response_files(&args).unwrap();
        assert_eq!(expanded, args);
    }

    #[test]
    fn expands_real_response_file() {
        let file = ScratchFile::new("-o foo.o -c bar.c\n");
        let args = vec!["-c".to_string(), file.at_arg()];
        let expanded = expand_response_files(&args).unwrap();
        assert_eq!(expanded, vec!["-c", "-o", "foo.o", "-c", "bar.c"]);
    }

    #[test]
    fn rejects_cyclic_response_file() {
        let file = ScratchFile::new(""); // placeholder path, filled in below
        fs::write(&file.path, file.at_arg()).unwrap();

        let args = vec![file.at_arg()];
        assert!(expand_response_files(&args).is_err());
    }
}
