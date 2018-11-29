extern crate asn1_der;
use ::asn1_der::{ Asn1DerError, DerValue };

const RANDOM: &[u8] = include_bytes!("rand.dat");


#[test]
fn test_ok() {
	// Test deserialization
	let deserialized = DerValue::deserialize(RANDOM.iter(), RANDOM.len()).unwrap();
	
	// Test length prediction
	assert_eq!(deserialized.serialized_len(), RANDOM.len());
	
	// Test serialization
	let mut target = vec![0u8; RANDOM.len()];
	deserialized.serialize(target.iter_mut()).unwrap();
	assert_eq!(RANDOM, target.as_slice());
}


#[test]
fn test_err() {
	// Test invalid length
	assert_eq!(
		DerValue::deserialize(RANDOM.iter(), RANDOM.len() + 1).unwrap_err(),
		Asn1DerError::LengthMismatch
	);
}