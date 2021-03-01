extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(SerdeAny)]
pub fn libafl_serdeany_derive(input: TokenStream) -> TokenStream {
    let name = parse_macro_input!(input as DeriveInput).ident;
    TokenStream::from(quote! {
        libafl::impl_serdeany!(#name);
    })
}
