extern crate asn1_der;
use ::asn1_der::{ Asn1DerError, DerObject, DerTag, DerValue };

const RANDOM: &[u8] = include_bytes!("rand.dat");


#[test]
fn test_ok() {
	// Test (de-)serialization
	fn test((bytes, object): &(&[u8], DerObject)) {
		// Test deserialization
		let deserialized = DerObject::deserialize(bytes.iter()).unwrap();
		assert_eq!(object, &deserialized);
		
		// Test length prediction
		assert_eq!(deserialized.serialized_len(), bytes.len());
		
		// Test serialization
		let mut target = vec![0u8; bytes.len()];
		deserialized.serialize(target.iter_mut()).unwrap();
		assert_eq!(*bytes, target.as_slice());
		
	}
	
	// Test vectors
	[
		(
			b"\x05\x00".as_ref(),
			DerObject{ tag: DerTag::from(0x05), value: DerValue::from(Vec::new()) }
		),
		(
			b"\x04\x02\x37\xe4".as_ref(),
			DerObject {
				tag: DerTag::from(0x04),
				value: DerValue::from(b"\x37\xe4".to_vec())
			}
		),
		(
			RANDOM,
			DerObject{ tag: DerTag::from(0x04), value: DerValue::from(RANDOM[5..].to_vec()) }
		)
	].iter().for_each(test);
}


#[test]
fn test_err() {
	// Test (de-)serialization
	fn test((bytes, error): &(&[u8], Asn1DerError)) {
		assert_eq!(DerObject::deserialize(bytes.iter()).unwrap_err(), *error);
	}
	
	// Test invalid length-encodings and payload lengths
	[
		// Invalid complex length
		(b"\x00\x80".as_ref(), Asn1DerError::InvalidEncoding),
		// Invalid use of a complex length
		(b"\xaf\x81\x7f".as_ref(), Asn1DerError::InvalidEncoding),
		// Incomplete length
		(b"\xbe\x81".as_ref(), Asn1DerError::LengthMismatch),
		// Incomplete length
		(b"\xd7\x84\x01\x00\x00".as_ref(), Asn1DerError::LengthMismatch),
		// Incomplete value
		(b"\x0c\x09\x54\x65\x73\x74\x6F\x6C\x6F\x70".as_ref(), Asn1DerError::LengthMismatch),
		// Complex length > 2^64 - 1
		(b"\x77\x89\x01\x00\x00\x00\x00\x00\x00\x00\x00".as_ref(), Asn1DerError::Unsupported),
		// Excessive length announcement
		#[cfg(target_pointer_width = "64")]
		(b"\x9d\xf7\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x43\x9d\x01\x00\x00\x00\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d".as_ref(), Asn1DerError::LengthMismatch),
		#[cfg(target_pointer_width = "32")]
		(b"\x9d\xf7\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x43\x9d\x01\x00\x00\x00\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d".as_ref(), Asn1DerError::Unsupported)
	].iter().for_each(test);
}