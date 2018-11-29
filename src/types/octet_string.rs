use ::{ Asn1DerError, types::{ FromDerObject, IntoDerObject }, der::{ DerObject, DerTag} };


impl FromDerObject for Vec<u8> {
	fn from_der_object(der_object: DerObject) -> Result<Self, Asn1DerError> {
		if der_object.tag != DerTag::OctetString { return Err(Asn1DerError::InvalidTag) }
		Ok(der_object.value.data )
	}
}
impl IntoDerObject for Vec<u8> {
	fn into_der_object(self) -> DerObject {
		DerObject::new(DerTag::OctetString, self.into())
	}
	
	fn serialized_len(&self) -> usize {
		DerObject::compute_serialized_len(self.len())
	}
}