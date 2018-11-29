extern crate asn1_der;
use ::asn1_der::{ Asn1DerError, IntoDerObject, FromDerObject };

const RANDOM: &[u8] = include_bytes!("rand.dat");


#[test]
fn test_ok() {
	fn test((bytes, data): &(&[u8], &[u8])) {
		// Test deserialization
		let deserialized = Vec::<u8>::deserialize(bytes.iter()).unwrap();
		assert_eq!(*data, deserialized.as_slice());
		
		// Test length prediction
		assert_eq!(deserialized.serialized_len(), bytes.len());
		
		// Test serialization
		let mut target = vec![0u8; bytes.len()];
		deserialized.serialize(target.iter_mut()).unwrap();
		assert_eq!(*bytes, target.as_slice());
	}
	
	[
		(b"\x04\x00".as_ref(), b"".as_ref()),
		(RANDOM, &RANDOM[5..])
	].iter().for_each(test);
}


#[test]
fn test_err() {
	fn test((bytes, error): &(&[u8], Asn1DerError)) {
		assert_eq!(u128::deserialize(bytes.iter()).unwrap_err(), *error);
	}
	
	[
		// Invalid tag
		(b"\x03\x01\x00".as_ref(), Asn1DerError::InvalidTag),
		// Length mismatch
		(b"\x04\x01".as_ref(), Asn1DerError::LengthMismatch)
	].iter().for_each(test);
}