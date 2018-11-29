use ::{ Asn1DerError, types::{ FromDerObject, IntoDerObject }, der::{ DerObject, DerTag} };


impl FromDerObject for String {
	fn from_der_object(der_object: DerObject) -> Result<Self, Asn1DerError> {
		if der_object.tag != DerTag::Utf8String { return Err(Asn1DerError::InvalidTag) }
		
		// Parse data to string
		let string = String::from_utf8(der_object.value.data)
			.map_err(|_| Asn1DerError::InvalidEncoding)?;
		
		Ok(string)
	}
}
impl IntoDerObject for String {
	fn into_der_object(self) -> DerObject {
		DerObject::new(DerTag::Utf8String, self.as_bytes().to_vec().into())
	}
	
	fn serialized_len(&self) -> usize {
		DerObject::compute_serialized_len(self.len())
	}
}