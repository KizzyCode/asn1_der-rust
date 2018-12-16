#![recursion_limit = "128"]

extern crate proc_macro;
extern crate syn;
#[macro_use] extern crate quote;

use ::{ proc_macro::TokenStream, syn::{ Data, Ident, Fields, DeriveInput } };


#[proc_macro_derive(Asn1Der)]
pub fn asn1_der_derive(input: TokenStream) -> TokenStream {
	// Parse the input tokens into a syntax tree
	let input: DeriveInput = syn::parse(input).unwrap();
	
	// Get struct from input
	let s = if let Data::Struct(s) = input.data { s }
		else { panic!("Asn1Der supports named structs only") };
	
	// Process fields
	let fields: Vec<Ident> = match s.fields {
		Fields::Named(fields) => fields.named.into_iter().map(|f| f.ident.unwrap()).collect(),
		_ => panic!("Asn1Der supports named structs only")
	};
	
	// Generate implementations
	gen_impl(&input.ident, fields)
}


fn gen_impl<'a>(s: &Ident, fields: Vec<Ident>) -> TokenStream {
	let (f0, f1, f2) =
		(fields.iter(), fields.iter(), fields.iter());
	
	// Implement `FromDerObject`
	let from = quote! {
		impl ::asn1_der::FromDerObject for #s {
			fn from_der_object(der_object: ::asn1_der::DerObject)
				-> ::std::result::Result<Self, ::asn1_der::Asn1DerError>
			{
				// Declare helper function
				fn parse_next<T: ::asn1_der::FromDerObject>
					(iter: &mut ::std::iter::Iterator<Item = ::asn1_der::DerObject>)
					-> ::std::result::Result<T, ::asn1_der::Asn1DerError>
				{
					let der_object = iter.next()
						.ok_or(::asn1_der::Asn1DerError::LengthMismatch)?;
					T::from_der_object(der_object)
				}
				
				// Create iterator from DER object
				let mut fields =
					::std::vec::Vec::<::asn1_der::DerObject>::from_der_object(der_object)?
					.into_iter();
				let s = Self{ #( #f0: parse_next(&mut fields)?, )* };
				
				// Validate that there are no unused objects left that don't match a field
				if fields.len() > 0 { Err(::asn1_der::Asn1DerError::LengthMismatch) }
					else { Ok(s) }
			}
		}
	};
	
	// Implement `IntoDerObject`
	let into = quote! {
		impl ::asn1_der::IntoDerObject for #s {
			fn into_der_object(self) -> ::asn1_der::DerObject {
				// Create objects from fields
				let mut objects = ::std::vec::Vec::new();
				#( objects.push(self.#f1.into_der_object()); )*
			
				// Create sequence from objects and convert it
				objects.into_der_object()
			}
			
			fn serialized_len(&self) -> usize {
				// Compute the lengths of the sequences objects
				let mut len = 0usize;
				#( len += self.#f2.serialized_len(); )*
				
				// Compute the serialized length
				::asn1_der::DerObject::compute_serialized_len(len)
			}
		}
	};
	
	// Generate the token stream from the implementations
	TokenStream::from(quote!( #into #from ))
}

