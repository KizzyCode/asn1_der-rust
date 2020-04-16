#![cfg_attr(test, deny(warnings))]

pub mod helpers;

use crate::helpers::{ ResultExt, test_ok };
use asn1_der::{ DerObject, Sink, der };


#[test]
fn length() {
	for (i, test) in test_ok::load().length.into_iter().enumerate() {
		if test.value <= usize::max_value() as u64 {
			// Decode length
			let len = der::length::decode(&mut test.bytes.iter()).assert(i);
			assert_eq!(len, test.value as usize, "@test_vector:{}", i);
			
			// Encode length
			let (mut buf, mut buf_len) = ([0; 9], 0);
			let mut sink = buf.iter_mut().counting_sink(&mut buf_len);
			der::length::encode(len, &mut sink).assert(i);
			assert_eq!(&buf[..buf_len], test.bytes.as_slice(), "@test_vector:{}", i);
		}
	}
}


#[test]
fn object() {
	for (i, test) in test_ok::load().object.into_iter().enumerate() {
		// Test-copy the object
		#[cfg(not(any(feature = "no_std", feature = "no_panic")))]
		{
			let mut bytes = Vec::new();
			der::read(&mut test.bytes.iter(), &mut bytes).assert(i);
			assert_eq!(bytes, test.bytes, "@test_vector:{}", i);
		}
		
		// Decode the object
		let object = DerObject::decode(test.bytes.as_slice()).assert(i);
		assert_eq!(object.tag(), test.tag, "@test_vector:{}", i);
		assert_eq!(object.value(), test.value.as_slice(), "@test_vector:{}", i);
		
		// Encode the object
		let mut bytes = vec![0; test.bytes.len()];
		object.encode(&mut bytes.iter_mut()).assert(i);
		assert_eq!(bytes, test.bytes, "@test_vector:{}", i)
	}
}