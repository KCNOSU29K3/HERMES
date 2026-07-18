use convert_case::ccase;
use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{Data, Field, Fields};
use syn::{GenericArgument, Ident, PathArguments, Type, Variant, parse_macro_input};

fn get_inner_type<'a>(dtype: &'a Type, target: &str) -> Option<&'a Type> {
    if let Type::Path(tp) = dtype {
        let segment = tp.path.segments.last()?;
        if segment.ident == target
            && let PathArguments::AngleBracketed(args) = &segment.arguments
            && let Some(GenericArgument::Type(inner)) = args.args.first()
        {
            return Some(inner);
        }
    }
    None
}

fn convert_field_to_param_and_init(field: &Field) -> (TokenStream, TokenStream) {
    let name = field.ident.as_ref().unwrap();
    let mut dtype = &field.ty;
    let mut is_option = false;
    let mut is_boxed = false;

    if let Some(inner) = get_inner_type(dtype, "Option") {
        is_option = true;
        dtype = inner;
    }

    if let Some(inner) = get_inner_type(dtype, "Box") {
        is_boxed = true;
        dtype = inner;
    }

    let signature_type = if is_option {
        quote! { Option<#dtype> }
    } else {
        quote! { #dtype }
    };

    let init = match (is_option, is_boxed) {
        (true, true) => quote! { #name: #name.map(Box::new) },
        (false, true) => quote! {#name: Box::new(#name) },
        _ => quote! { #name },
    };
    (signature_type, init)
}

fn variant_constructor(variant: &Variant) -> TokenStream {
    let variant_ident = &variant.ident;
    let fn_name = Ident::new(
        &ccase!(pascal -> snake, &variant_ident.to_string()),
        variant_ident.span(),
    );

    match &variant.fields {
        Fields::Named(fields) => {
            let (sig_types, inits): (Vec<_>, Vec<_>) = fields
                .named
                .iter()
                .map(convert_field_to_param_and_init)
                .collect::<Vec<_>>()
                .into_iter()
                .unzip();

            let args = fields.named.iter().map(|f| f.ident.as_ref().unwrap());

            quote! {
                pub fn #fn_name(#(#args: #sig_types),*) -> Self {
                    Self::#variant_ident {
                        #(#inits),*
                    }
                }
            }
        }
        Fields::Unnamed(fields) => {
            let (sig_types, inits): (Vec<_>, Vec<_>) = fields
                .unnamed
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    let ident = Ident::new(&format!("arg_{i}"), f.span());
                    let fake_field = Field {
                        ident: Some(ident.clone()),
                        ..f.clone()
                    };
                    convert_field_to_param_and_init(&fake_field)
                })
                .collect::<Vec<_>>()
                .into_iter()
                .unzip();

            let args: Vec<_> = (0..sig_types.len())
                .map(|i| syn::Ident::new(&format!("arg_{i}"), variant_ident.span()))
                .collect();

            quote! {
                pub fn #fn_name(#(#args: #sig_types),*) -> Self {
                    Self::#variant_ident(#(#inits),*)
                }
            }
        }
        Fields::Unit => {
            quote! {
                pub fn #fn_name() -> Self {
                    Self::#variant_ident
                }
            }
        }
    }
}

#[proc_macro_derive(New)]
/// Derive module that auto-implements the function `new()`.
///
/// When used on structs, implements a singular new function that takes
/// the arguments provided. If arguments are wrapped in Arc or Box, the macro
/// automatically generates code to Box and/or Arc wrap the provided data.
///
/// When used on structs
pub fn derive_new(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(item as syn::DeriveInput);

    let struct_identifier = input.ident;

    match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields) => {
                let (sig_types, inits): (Vec<_>, Vec<_>) = fields
                    .named
                    .iter()
                    .map(convert_field_to_param_and_init)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .unzip();

                let args = fields
                    .named
                    .iter()
                    .map(|field| field.ident.as_ref().unwrap())
                    .collect::<Vec<_>>();

                quote! {
                    impl #struct_identifier {
                        pub fn new(#(#args: #sig_types),*) -> Self {
                            Self {
                                #(#inits),*
                            }
                        }
                    }
                }
                .into()
            }
            Fields::Unnamed(_) => unimplemented!("New() macro not implemented for unnamed structs"),
            Fields::Unit => unimplemented!("New() macro not implemented for unit structs."),
        },
        Data::Enum(data_enum) => {
            let ctors = data_enum.variants.iter().map(variant_constructor);

            quote! {
                impl #struct_identifier {
                    #(#ctors)*
                }
            }
            .into()
        }
        _ => {
            panic!("Not implemented for non-struct data.")
        }
    }
}
