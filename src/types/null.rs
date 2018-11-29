use ::{ Asn1DerError, types::{ FromDerObject, IntoDerObject }, der::{ DerObject, DerTag} };


impl FromDerObject for () {
	fn from_der_object(der_object: DerObject) -> Result<Self, Asn1DerError> {
		if der_object.tag != DerTag::Null { return Err(Asn1DerError::InvalidTag) }
		if !der_object.value.data.is_empty() { Err(Asn1DerError::InvalidEncoding) }
			else { Ok(()) }
	}
}
impl IntoDerObject for () {
	fn into_der_object(self) -> DerObject {
		DerObject::new(DerTag::Null, Vec::new().into())
	}
	
	fn serialized_len(&self) -> usize {
		DerObject::compute_serialized_len(0)
	}
}