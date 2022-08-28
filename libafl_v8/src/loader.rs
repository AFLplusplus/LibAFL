//! Loader stubs to be used to resolve JavaScript dependencies

use std::{fs::read_to_string, path::Path, pin::Pin};

use deno_ast::{MediaType, ParseParams, SourceTextInfo};
use deno_core::{
    anyhow::bail, futures::FutureExt, url::Url, ModuleLoader, ModuleSource, ModuleSourceFuture,
    ModuleSpecifier, ModuleType,
};
use import_map::ImportMapWithDiagnostics;
use libafl::Error;

/// Loader which loads dependencies in vendored deno environments.
#[derive(Debug)]
pub struct VendoredLoader {
    import_map: ImportMapWithDiagnostics,
}

impl VendoredLoader {
    /// Create a new vendored loader with a path to the vendor/import_map.json.
    pub fn new<P: AsRef<Path>>(map_path: P) -> Result<Self, Error> {
        let json = read_to_string(map_path.as_ref())?;
        let url = match Url::from_file_path(map_path.as_ref()) {
            Ok(u) => u,
            Err(_) => {
                return Err(Error::illegal_argument(format!(
                    "Path was not found or was not absolute: {}",
                    map_path.as_ref().to_str().unwrap()
                )))
            }
        };
        if let Ok(import_map) = import_map::parse_from_json(&url, &json) {
            Ok(Self { import_map })
        } else {
            Err(Error::illegal_state(
                "Couldn't parse the provided import map",
            ))
        }
    }

    fn read_file_specifier(module_specifier: ModuleSpecifier) -> Pin<Box<ModuleSourceFuture>> {
        if let Ok(path) = module_specifier.to_file_path() {
            async move {
                // Section surrounded by SNIP below is taken from: https://github.com/denoland/deno/blob/94d369ebc65a55bd9fbf378a765c8ed88a4efe2c/core/examples/ts_module_loader.rs#L51-L88
                // License text available at: ../LICENSE-DENO
                // Copyright 2018-2022 the Deno authors. All rights reserved. MIT license.
                // ---- SNIP ----
                let media_type = MediaType::from(&path);
                let (module_type, should_transpile) = match MediaType::from(&path) {
                    MediaType::JavaScript | MediaType::Mjs | MediaType::Cjs => {
                        (ModuleType::JavaScript, false)
                    }
                    MediaType::Jsx => (ModuleType::JavaScript, true),
                    MediaType::TypeScript
                    | MediaType::Mts
                    | MediaType::Cts
                    | MediaType::Dts
                    | MediaType::Dmts
                    | MediaType::Dcts
                    | MediaType::Tsx => (ModuleType::JavaScript, true),
                    MediaType::Json => (ModuleType::Json, false),
                    _ => bail!("Unknown extension {:?}", path.extension()),
                };

                let code = read_to_string(&path)?;
                let code = if should_transpile {
                    let parsed = deno_ast::parse_module(ParseParams {
                        specifier: module_specifier.to_string(),
                        text_info: SourceTextInfo::from_string(code),
                        media_type,
                        capture_tokens: false,
                        scope_analysis: false,
                        maybe_syntax: None,
                    })?;
                    parsed.transpile(&Default::default())?.text
                } else {
                    code
                };
                let module = ModuleSource {
                    code: code.into_bytes().into_boxed_slice(),
                    module_type,
                    module_url_specified: module_specifier.to_string(),
                    module_url_found: module_specifier.to_string(),
                };
                Ok(module)
                // ---- SNIP ----
            }
            .boxed_local()
        } else {
            unimplemented!("File URL couldn't be parsed")
        }
    }
}

impl ModuleLoader for VendoredLoader {
    fn resolve(
        &self,
        specifier: &str,
        referrer: &str,
        _is_main: bool,
    ) -> Result<ModuleSpecifier, deno_core::anyhow::Error> {
        let referrer = deno_core::resolve_url_or_path(referrer)?;
        Ok(self.import_map.import_map.resolve(specifier, &referrer)?)
    }

    fn load(
        &self,
        module_specifier: &ModuleSpecifier,
        _maybe_referrer: Option<ModuleSpecifier>,
        _is_dyn_import: bool,
    ) -> Pin<Box<ModuleSourceFuture>> {
        let module_specifier = module_specifier.clone();
        if module_specifier.scheme() == "file" {
            Self::read_file_specifier(module_specifier)
        } else {
            unimplemented!("Not attempting to resolve non-file module specifiers")
        }
    }
}
