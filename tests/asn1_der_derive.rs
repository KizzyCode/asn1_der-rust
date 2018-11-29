#![cfg(feature = "derive")]

#[macro_use] extern crate asn1_der;
use ::asn1_der::{ IntoDerObject, FromDerObject, DerObject };


#[test]
fn test() {
	// Define inner struct
	#[derive(Debug, Clone, Eq, PartialEq, Asn1Der)]
	struct Inner {
		integer: u128,
		boolean: bool,
		octet_string: Vec<u8>,
		utf8_string: String,
		null: (),
		sequence: Vec<Inner>,
		der_object: DerObject
	}
	impl Inner {
		pub fn new(num: u128) -> Self {
			Inner {
				integer: num, boolean: num % 2 == 0,
				octet_string: b"Testolope (octet_string)".to_vec(),
				utf8_string: format!("Inner {}", num),
				null: (), sequence: vec![],
				der_object: DerObject::from_raw(0x14, b"Testolope (der_object)".to_vec())
			}
		}
	}
	
	// Define outer struct
	#[derive(Debug, Clone, Eq, PartialEq, Asn1Der)]
	struct Outer {
		utf8_string: String,
		inner: Inner
	}
	
	// Create inner and outer
	let inner =  {
		let mut inner_0 = Inner::new(0);
		inner_0.sequence.push(Inner::new(1));
		inner_0.sequence.push(Inner::new(2));
		inner_0
	};
	let outer = Outer{ utf8_string: "Testolope".to_string(), inner };
	
	// Encode and compare
	let encoded = {
		let mut encoded = vec![0u8; outer.serialized_len()];
		outer.clone().serialize(encoded.iter_mut()).unwrap();
		encoded
	};
	let expected = b"\x30\x81\xe2\x0c\x09\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x30\x81\xd4\x02\x01\x00\x01\x01\xff\x04\x18\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x20\x28\x6f\x63\x74\x65\x74\x5f\x73\x74\x72\x69\x6e\x67\x29\x0c\x07\x49\x6e\x6e\x65\x72\x20\x30\x05\x00\x30\x81\x8e\x30\x45\x02\x01\x01\x01\x01\x00\x04\x18\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x20\x28\x6f\x63\x74\x65\x74\x5f\x73\x74\x72\x69\x6e\x67\x29\x0c\x07\x49\x6e\x6e\x65\x72\x20\x31\x05\x00\x30\x00\x14\x16\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x20\x28\x64\x65\x72\x5f\x6f\x62\x6a\x65\x63\x74\x29\x30\x45\x02\x01\x02\x01\x01\xff\x04\x18\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x20\x28\x6f\x63\x74\x65\x74\x5f\x73\x74\x72\x69\x6e\x67\x29\x0c\x07\x49\x6e\x6e\x65\x72\x20\x32\x05\x00\x30\x00\x14\x16\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x20\x28\x64\x65\x72\x5f\x6f\x62\x6a\x65\x63\x74\x29\x14\x16\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x20\x28\x64\x65\x72\x5f\x6f\x62\x6a\x65\x63\x74\x29".as_ref();
	assert_eq!(encoded, expected);
	
	// Decode
	let decoded = Outer::deserialize(encoded.iter()).unwrap();
	assert_eq!(decoded, outer);
}