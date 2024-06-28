//! Derives for `LibAFL`

#![no_std]
#![forbid(unexpected_cfgs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(
    clippy::unreadable_literal,
    clippy::type_repetition_in_bounds,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::used_underscore_binding,
    clippy::ptr_as_ptr,
    clippy::missing_panics_doc,
    clippy::missing_docs_in_private_items,
    clippy::module_name_repetitions,
    clippy::unreadable_literal
)]
#![cfg_attr(not(test), warn(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    //unused_results
))]
#![cfg_attr(test, deny(
    missing_debug_implementations,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_must_use,
    //unused_results
))]
#![cfg_attr(
    test,
    deny(
        bad_style,
        dead_code,
        improper_ctypes,
        non_shorthand_field_patterns,
        no_mangle_generic_items,
        overflowing_literals,
        path_statements,
        patterns_in_fns_without_body,
        unconditional_recursion,
        unused,
        unused_allocation,
        unused_comparisons,
        unused_parens,
        while_true
    )
)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data::Struct, DeriveInput, Fields::Named, PathArguments, Type};

/// Derive macro to implement `SerdeAny`, to use a type in a `SerdeAnyMap`
#[proc_macro_derive(SerdeAny)]
pub fn libafl_serdeany_derive(input: TokenStream) -> TokenStream {
    let name = parse_macro_input!(input as DeriveInput).ident;
    TokenStream::from(quote! {
        libafl_bolts::impl_serdeany!(#name);
    })
}

/// Display macro to implement `Display` for a struct where all fields implement `Display`.
/// The result is the concatenation of all fields display.
/// Specifically handled cases:
/// Options: Some => inner type display None => "".
/// Vec: inner type display concatenated with spaces.
/// Generics or other more or less exotic stuff are not supported.
#[proc_macro_derive(Display)]
pub fn libafl_display(input: TokenStream) -> TokenStream {
    // TODO a bit of refactoring
    let DeriveInput { ident, data, .. } = parse_macro_input!(input as DeriveInput);

    if let Struct(s) = data {
        if let Named(fields) = s.fields {
            let vec_fields = fields
                .named
                .iter()
                .filter(|it| libafl_display_type(&it.ty) == TyVec)
                .map(|it| &it.ident);
            let options_fields = fields
                .named
                .iter()
                .filter(|it| libafl_display_type(&it.ty) == TyOption)
                .map(|it| &it.ident);
            let other_fields = fields
                .named
                .iter()
                .filter(|it| libafl_display_type(&it.ty) == TyOther)
                .map(|it| &it.ident);

            let other_fields_fmt = " {}".repeat(other_fields.clone().count());
            return TokenStream::from(quote! {
                impl core::fmt::Display for #ident {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        // TyVec
                        #( for e in &self.#vec_fields {
                            write!(f, " {}", e)?;
                        } )*

                        // TyOption
                        #( if let Some(opt) = &self.#options_fields {
                            write!(f, " {}", opt)?;
                        } )*

                        // TyOther
                        write!(f, #other_fields_fmt, #(self.#other_fields), *)?;

                        Ok(())
                    }
                }
            });
        }
    }
    panic!("Only structs are supported");
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, PartialEq, Eq)]
enum LibaflDisplayFieldType {
    TyOption,
    TyVec,
    TyOther,
}
use LibaflDisplayFieldType::{TyOption, TyOther, TyVec};

fn libafl_display_type(ty: &Type) -> LibaflDisplayFieldType {
    if let Type::Path(type_path) = ty {
        if type_path.qself.is_none() && type_path.path.segments.len() == 1 {
            let segment = &type_path.path.segments[0];
            if segment.ident == "Option" {
                if let PathArguments::AngleBracketed(ref generic_args) = segment.arguments {
                    if generic_args.args.len() == 1 {
                        return TyOption;
                    }
                }
            } else if segment.ident == "Vec" {
                if let PathArguments::AngleBracketed(ref generic_args) = segment.arguments {
                    if generic_args.args.len() == 1 {
                        return TyVec;
                    }
                }
            }
        }
    }
    TyOther
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;
    use LibaflDisplayFieldType::{TyOption, TyOther, TyVec};

    use super::*;

    #[test]
    fn libafl_display_type_works() {
        let ty: Type = parse_quote!(Option<(String, i8)>);
        assert!(libafl_display_type(&ty) == TyOption);

        let ty: Type = parse_quote!(Vec<u8>);
        assert!(libafl_display_type(&ty) == TyVec);

        let ty: Type = parse_quote!(Optionsus<u8>);
        assert!(libafl_display_type(&ty) == TyOther);
    }
}
