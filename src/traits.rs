use super::{ Result, DerObject };

/// A trait to parse `DerObject`s into native types
pub trait FromDerObject where Self: Sized {
	/// Converts a `DerElement` into `Self`
	///
	/// Returns either the successfully parsed object or on error:
	///  - `Asn1DerError::InvalidEncoding` if the encoded type does not conform to the DER-encoding
	///    rules
	///  - `Asn1DerError::Unsupported` if the encoded object is unsupported by this implementation
	///    (e.g. an integer that is too large)
	///  - `Asn1DerError::InvalidTag` if the tag annotates an incompatible type
	fn from_der_object(der_object: DerObject) -> Result<Self>;
}


/// A trait to convert native types into `DerObject`s
pub trait IntoDerObject where Self: Sized {
	/// Converts `Self` into a `DerObject`
	///
	/// Returns the created DER-object
	fn into_der_object(self) -> DerObject;
}


/// A trait to parse DER-encoded data into a typed representation
pub trait FromDerEncoded where Self: Sized {
	/// Decodes some DER-encoded data and converts them into `Self`
	///
	/// Parameters:
	///  - `data`: The DER-encoded data to parse and to convert into `Self`
	///
	/// Returns either the successfully parsed object or on error:
	///  - `Asn1DerError::NotEnoughBytes` if the overall length is zero, the length-field is too
	///    short or the payload is shorter than the annotated length
	///  - `Asn1DerError::InvalidEncoding` if the length-field is invalid or if the encoded type
	///    does not conform to the DER-encoding rules
	///  - `Asn1DerError::Unsupported` if the length is greater than
	///    [`std::usize::MAX`](https://doc.rust-lang.org/std/usize/constant.MAX.html) or if the
	///    encoded object is unsupported by this implementation (e.g. an integer that is too large)
	///  - `Asn1DerError::InvalidTag` if the tag annotates an incompatible type
	fn from_der_encoded(data: Vec<u8>) -> Result<Self>;
	
	/// Decodes some DER-encoded data and converts them into `Self`
	///
	/// _Warning: During the parsing we'll create a __copy__ of the payload. However, the copying
	/// happens only if the object is valid and will be parsed to a `DerObject` and the copy
	/// includes __only__ the payload (and not any other remaining data)._
	///
	/// Parameters:
	///  - `data`: The DER-encoded data to parse and to convert into `Self`
	///
	/// Returns either the successfully parsed object or on error:
	///  - `Asn1DerError::NotEnoughBytes` if the overall length is zero, the length-field is too
	///    short or the payload is shorter than the annotated length
	///  - `Asn1DerError::InvalidEncoding` if the length-field is invalid or if the encoded type
	///    does not conform to the DER-encoding rules
	///  - `Asn1DerError::Unsupported` if the length is greater than
	///    [`std::usize::MAX`](https://doc.rust-lang.org/std/usize/constant.MAX.html) or if the
	///    encoded object is unsupported by this implementation (e.g. an integer that is too large)
	///  - `Asn1DerError::InvalidTag` if the tag annotates an incompatible type
	fn with_der_encoded(data: &[u8]) -> Result<Self>;
}


/// A trait to convert native types into their DER-encoded representation
pub trait IntoDerEncoded {
	/// Converts `Self` into their DER-encoded representation
	///
	/// Returns the DER-encoded data
	fn into_der_encoded(self) -> Vec<u8>;
}