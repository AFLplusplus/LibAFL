//! Derives for `LibAFL`

#![no_std]
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
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{format_ident, quote};
use syn::{
    parse_macro_input,
    punctuated::Punctuated,
    token::Comma,
    Data::Struct,
    DeriveInput, Error, Field,
    Fields::{Named, Unit, Unnamed},
    GenericArgument, Ident, PathArguments, PathSegment, Type,
};

/// Derive macro to implement `SerdeAny`, to use a type in a `SerdeAnyMap`
#[proc_macro_derive(SerdeAny)]
pub fn libafl_serdeany_derive(input: TokenStream) -> TokenStream {
    let name = parse_macro_input!(input as DeriveInput).ident;
    TokenStream::from(quote! {
        libafl_bolts::impl_serdeany!(#name);
    })
}

/// A derive macro to implement `Display`
///
/// Derive macro to implement [`core::fmt::Display`] for a struct where all fields implement `Display`.
/// The result is the space separated concatenation of all fields' display.
/// Order of declaration is preserved.
/// Specifically handled cases:
/// Options: Some => inner type display None => "".
/// Vec: inner type display space separated concatenation.
/// Generics and other more or less exotic stuff are not supported.
///
/// # Examples
///
/// ```rust
/// use libafl_derive;
///
/// #[derive(libafl_derive::Display)]
/// struct MyStruct {
///     foo: String,
///     bar: Option<u32>,
/// }
/// ```
///
/// The above code will expand to:
///
/// ```rust
/// struct MyStruct {
///     foo: String,
///     bar: Option<u32>,
/// }
///
/// impl core::fmt::Display for MyStruct {
///     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
///         f.write_fmt(format_args!(" {0}", self.foo))?;
///         if let Some(opt) = &self.bar {
///             f.write_fmt(format_args!(" {0}", opt))?;
///         }
///         Ok(())
///     }
/// }
/// ```
///
/// # Panics
/// Panics for any non-structs.
#[proc_macro_derive(Display)]
pub fn libafl_display(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input as DeriveInput);

    if let Struct(s) = data {
        if let Named(fields) = s.fields {
            let fields_fmt = fields.named.iter().map(libafl_display_field_by_type);

            return quote! {
                impl core::fmt::Display for #ident {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        #(#fields_fmt)*
                        Ok(())
                    }
                }
            }
            .into();
        }
    }
    panic!("Only structs are supported");
}

fn libafl_display_field_by_type(it: &Field) -> proc_macro2::TokenStream {
    let fmt = " {}";
    let ident = &it.ident;
    if let Type::Path(type_path) = &it.ty {
        if type_path.qself.is_none() && type_path.path.segments.len() == 1 {
            let segment = &type_path.path.segments[0];
            if segment.ident == "Option" {
                return quote! {
                    if let Some(opt) = &self.#ident {
                        write!(f, #fmt, opt)?;
                    }
                };
            } else if segment.ident == "Vec" {
                return quote! {
                    for e in &self.#ident {
                        write!(f, #fmt, e)?;
                    }
                };
            }
        }
    }
    quote! {
        write!(f, #fmt, self.#ident)?;
    }
}

/// TODO
#[proc_macro_derive(HasHavocMutators)]
pub fn derive_has_mutator_bytes(input: TokenStream) -> TokenStream {
    let input_ast = parse_macro_input!(input as DeriveInput);

    let struct_name = input_ast.ident.clone();

    let fields = match extract_fields(input_ast) {
        Ok(f) => f,
        Err(e) => return e.into_compile_error().into(),
    };

    let (getter_methods, mutator_merge_call) = match create_functions_on_fields(&fields) {
        Ok(e) => e,
        Err(e) => return e.into_compile_error().into(),
    };

    // required to be able to use it from within libafl — used for testing
    let libafl_source = match crate_name("libafl").expect("Could not figure out current crate") {
        FoundCrate::Itself => quote! { crate },
        FoundCrate::Name(_) => quote! { libafl },
    };

    // Generate the impl block
    let expanded = quote! {
        use #libafl_source::{inputs::MutVecInput, mutators::{Mutator, mapped_havoc_mutations}};
        use libafl_bolts::tuples::{Merge, NamedTuple, tuple_list};

        impl #struct_name {
            #getter_methods
        }

        impl HasHavocMutators for #struct_name {
            fn havoc_mutators<MT: NamedTuple>() -> MT {
                #mutator_merge_call
            }
        }
    };

    TokenStream::from(expanded)
}

fn extract_fields(ast: DeriveInput) -> Result<Punctuated<Field, Comma>, Error> {
    match &ast.data {
        Struct(data_struct) => match &data_struct.fields {
            Named(fields_named) => Ok(fields_named.named.clone()),
            Unnamed(fields_unnamed) => Ok(fields_unnamed.unnamed.clone()),
            Unit => Err(Error::new_spanned(
                ast,
                "HasHavocMutators can not be derived for unit structs",
            )),
        },
        _ => Err(Error::new_spanned(
            ast,
            "HasHavocMutators can only be derived for structs",
        )),
    }
}

fn create_functions_on_fields(
    fields: &Punctuated<Field, Comma>,
) -> Result<(proc_macro2::TokenStream, proc_macro2::TokenStream), Error> {
    let functions_res = fields.iter().map(|field| match field.ty.clone() {
        Type::Path(type_path) => {
            let segment = type_path.path.segments.last().unwrap();
            if let Some(tokens) = create_functions_on_type(segment, field.ident.as_ref().unwrap()) {
                return Ok(tokens);
            }

            Err(Error::new_spanned(
                segment.ident.clone(),
                "HasHavocMutators does not support struct parts of this type",
            ))
        }
        _ => Err(Error::new_spanned(
            field,
            "HasHavocMutators can only be derived for structs",
        )),
    });

    // check if any fields could not be parsed into functions, combine the errors and return them
    if let Some(errors) = functions_res
        .clone()
        .filter(Result::is_err)
        .map(Result::unwrap_err)
        .reduce(|mut acc, e| {
            acc.combine(e);
            acc
        })
    {
        return Err(errors);
    }

    Ok(functions_res.map(Result::unwrap).fold(
        (quote! {}, quote! { tuple_list!() }),
        |(acc1, acc2), (e1, e2)| {
            (
                quote! {
                    #acc1
                    #e1
                },
                quote! { #acc2.merge(#e2) },
            )
        },
    ))
}

fn create_functions_on_type(
    segment: &PathSegment,
    field_name: &Ident,
) -> Option<(proc_macro2::TokenStream, proc_macro2::TokenStream)> {
    if segment.ident == "Vec" {
        if let PathArguments::AngleBracketed(args) = &segment.arguments {
            if let Some(GenericArgument::Type(Type::Path(arg_type))) = args.args.first() {
                let arg_ident = &arg_type.path.segments.last().unwrap().ident;
                if arg_ident == "u8" {
                    let mutable_method_name = format_ident!("{}_mut", field_name);
                    let immutable_method_name = field_name;
                    return Some((
                        quote! {
                            pub fn #mutable_method_name(&mut self) -> MutVecInput<'_> {
                                (&mut self.#field_name).into()
                            }
                            pub fn #immutable_method_name(&self) -> &[u8] {
                                &self.#field_name
                            }
                        },
                        quote! { mapped_havoc_mutations(Self::#mutable_method_name, Self::#immutable_method_name) },
                    ));
                }
            }
        }
    }
    None
}
