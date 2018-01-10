mod der_length;
/// Contains ASN.1-type-specific object implementations
pub mod typed;

/// ASN.1-DER-errors
#[derive(PartialEq, Eq, Debug)]
pub enum Error {
	/// The encoding of something does not conform to the ASN.1-DER-standard
	InvalidEncoding,
	/// The real-length does not match the expected length
	LengthMismatch,
	/// The tag does not match the object-type
	InvalidTag,
	/// The element might be valid but is not supported by this implementation
	Unsupported
}
impl From<std::string::FromUtf8Error> for Error {
	fn from(_: std::string::FromUtf8Error) -> Self {
		Error::InvalidEncoding
	}
}
pub type ASN1Result<T> = Result<T, Error>;


/// A generic ASN.1-object; can store any tag and payload
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Generic {
	pub tag: u8,
	pub payload: Vec<u8>
}
impl Generic {
	/// Checks if the object is a valid ASN.1-DER-object
	///
	/// Returns [`Error::LengthMismatch`](enum.Error.html) if the overall length is zero,
	/// 	the length-field is too short or the payload-length does not match the annotated length,
	/// [`Error::InvalidEncoding`](enum.Error.html) if the length is invalid or
	/// [`Error::Unsupported`](enum.Error.html) if the length is greater than [`std::usize::MAX`](https://doc.rust-lang.org/std/usize/constant.MAX.html).
	pub fn validate(data: &[u8]) -> Result<(), Error> {
		// Validate minimum-length
		if data.len() < 1 { return Err(Error::LengthMismatch) }
		
		// Get payload-size and validate overall size
		let (payload_length, der_length_size) = der_length::decode(&data[1 ..])?; // Try to decode the length
		if 1 + der_length_size + payload_length > data.len() { return Err(Error::LengthMismatch) }
		
		Ok(())
	}
	
	/// Create a `Generic`-object from DER-encoded data
	///
	/// Returns [`Error::LengthMismatch`](enum.Error.html) if the overall length is zero,
	/// 	the length-field is too short or the payload-length does not match the annotated length,
	/// [`Error::InvalidEncoding`](enum.Error.html) if the length is invalid or
	/// [`Error::Unsupported`](enum.Error.html) if the length is greater than [`std::usize::MAX`](https://doc.rust-lang.org/std/usize/constant.MAX.html).
	pub fn from_der_encoded(mut data: Vec<u8>) -> Result<Self, Error> {
		Generic::validate(&data)?;
		
		// Get `tag` and lengths
		let tag = data[0];
		let (payload_length, der_length_size) = der_length::decode(&data[1 ..])?; // Try to decode the length
		
		// Modify `data` to contain only the payload
		for i in 0 .. payload_length { data[i] = data[1 + der_length_size + i] } //memmove
		data.truncate(payload_length);

		Ok(Generic { tag, payload: data })
	}
	
	/// Create a `Generic`-object with DER-encoded data
	///
	/// Returns [`Error::LengthMismatch`](enum.Error.html) if the overall length is zero,
	/// 	the length-field is too short or the payload-length does not match the annotated length,
	/// [`Error::InvalidEncoding`](enum.Error.html) if the length is invalid or
	/// [`Error::Unsupported`](enum.Error.html) if the length is greater than [`std::usize::MAX`](https://doc.rust-lang.org/std/usize/constant.MAX.html).
	pub fn with_der_encoded(data: &[u8]) -> Result<Self, Error> {
		Generic::validate(&data)?;
		
		// Get `tag` and lengths and extract payload
		let tag = data[0];
		let (payload_length, der_length_size) = der_length::decode(&data[1 ..])?; // Try to decode the length
		let payload = data[1 + der_length_size .. 1 + der_length_size + payload_length].to_vec();
		
		Ok(Generic { tag, payload })
	}

	/// Computes the length of this object in DER-encoded representation without encoding it
	pub fn get_der_encoded_length(&self) -> usize {
		1 + der_length::get_encoded_length(self.payload.len()) + self.payload.len()
	}

	/// Transforms the object and returns a vector containing the DER-encoded object
	pub fn into_der_encoded(mut self) -> Vec<u8> {
		// Compute/store lengths
		let (der_length_size, payload_length) = (der_length::get_encoded_length(self.payload.len()), self.payload.len());

		// Create and resize buffer and move payload to the back
		self.payload.resize(1 + der_length_size + payload_length, 0);
		for i in (0 .. payload_length).rev() { self.payload[1 + der_length_size + i] = self.payload[i] } //memmove

		// Set tag and encode length
		self.payload[0] = self.tag;
		der_length::encode(payload_length, &mut self.payload[1 .. 1 + der_length_size]);
		
		self.payload
	}
}