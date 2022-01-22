//! Custom derive macros for the rust-bitcoin project.
//!

extern crate proc_macro;
extern crate syn;
extern crate quote;

use proc_macro::TokenStream;
use syn::{parse_macro_input, Data, DeriveInput, Fields};
use quote::quote;

#[proc_macro_derive(Encodable)]
pub fn encodable_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let ident = input.ident;
    let data = input.data;

    let fields = match data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(_) => &data.fields,
                Fields::Unnamed(_) | Fields::Unit => {
                    panic!("Encodable only implemented for named structs");
                }
            }
        }
        Data::Enum(_) | Data::Union(_) => panic!("Encodable only implemented for structs"),
    };

    let consensus_encode_fields = fields.iter().map(|f| {
        let ident = f.ident.clone().unwrap();
        quote! {
            len += self.#ident.consensus_encode(&mut s)?;
        }
    });

    let gen = quote! {
        impl Encodable for #ident {
            fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
                let mut len = 0;
                #(#consensus_encode_fields)*
                Ok(len)
            }
        }
    };
    gen.into()
}

#[proc_macro_derive(Decodable)]
pub fn decodable_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let ident = input.ident;
    let data = input.data;

    let fields = match data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(_) => &data.fields,
                Fields::Unnamed(_) | Fields::Unit => {
                    panic!("Decodable only implemented for named structs");
                }
            }
        }
        Data::Enum(_) | Data::Union(_) => panic!("Decodable only implemented for structs"),
    };

    let consensus_decode_fields = fields.iter().map(|f| {
        let ident = f.ident.clone().unwrap();
        quote! {
            #ident: Decodable::consensus_decode(&mut d)?
        }
    });

    let gen = quote! {
        impl Decodable for #ident {
            fn consensus_decode<D: io::Read>(d: D) -> Result<#ident, encode::Error> {
                let mut d = d.take(MAX_VEC_SIZE as u64);
                Ok(#ident {
                    #(#consensus_decode_fields),*
                })
            }
        }
    };
    gen.into()
}
