#![cfg_attr(test, deny(warnings))]
#![cfg(feature = "native_types")]

pub mod helpers;

use crate::helpers::{ ResultExt, test_ok, rust::convert::TryFrom };
use asn1_der::{
	DerObject, SliceSink,
	typed::{
		DerTypeView, DerEncodable, DerDecodable,
		Boolean, Integer, Null, OctetString, Sequence, Utf8String
	}
};
#[cfg(not(any(feature = "no_std", feature = "no_panic")))]
	use asn1_der::typed::SequenceVec;


#[test]
fn boolean() {
	for (i, test) in test_ok::load().typed.bool.into_iter().enumerate() {
		// Decode the object
		let boolean = Boolean::decode(&test.bytes).assert(i);
		assert_eq!(boolean.get(), test.bool, "@test_vector:{}", i);
		
		let native = bool::decode(&test.bytes).assert(i);
		assert_eq!(native, test.bool, "@test_vector:{}", i);
		
		// Encode the object
		let mut bytes = vec![0; test.bytes.len()];
		boolean.encode(&mut bytes.iter_mut()).assert(i);
		assert_eq!(bytes, test.bytes, "@test_vector:{}", i);
		
		let mut bytes = vec![0; test.bytes.len()];
		test.bool.encode(&mut bytes.iter_mut()).assert(i);
		assert_eq!(bytes, test.bytes, "@test_vector:{}", i);
		
		let (mut bytes, mut pos) = ([0; 1024], 0);
		let sink = SliceSink::new(&mut bytes, &mut pos);
		Boolean::new(test.bool, sink).assert(i);
		assert_eq!(&bytes[..pos], test.bytes.as_slice(), "@test_vector:{}", i);
	}
}


#[test]
fn integer() {
	for (i, test) in test_ok::load().typed.integer.into_iter().enumerate() {
		// Decode the object
		let object = Integer::decode(test.bytes.as_slice()).assert(i);
		assert_eq!(object.object().value(), test.value.as_slice(), "@test_vector:{}", i);
		
		// Encode the object
		let mut bytes = vec![0; test.bytes.len()];
		object.encode(&mut bytes.iter_mut()).assert(i);
		assert_eq!(bytes, test.bytes, "@test_vector:{}", i);
		
		// Test native types
		macro_rules! native {
			($num:ty, $field:ident, $is_signed:expr) => {
				if let Some(value) = test.$field.and_then(|n| <$num>::try_from(n).ok()) {
					// Decode native
					let native = <$num>::decode(test.bytes.as_slice()).assert(i);
					assert_eq!(native, value, "@test_vector:{}", i);
					
					// Encode native
					let mut bytes = vec![0; test.bytes.len()];
					value.encode(&mut bytes.iter_mut()).assert(i);
					assert_eq!(bytes, test.bytes, "@test_vector:{}", i);
					
					let (mut bytes, mut pos) = ([0; 1024], 0);
					let sink = SliceSink::new(&mut bytes, &mut pos);
					Integer::new(&value.to_be_bytes(), $is_signed(value), sink).assert(i);
					assert_eq!(&bytes[..pos], test.bytes.as_slice(), "@test_vector:{}", i);
				}
			};
			(unsigned: $( $num:ty ),+) => ($( native!($num, uint, |_| false); )+);
			(signed: $( $num:ty ),+) => ($( native!($num, int, |n: $num| n.is_negative()); )+);
		}
		native!(unsigned: u8, u16, u32, u64, u128, usize);
		native!(signed: i8, i16, i32, i64, i128, isize);
	}
}


#[test]
fn null() {
	for (i, test) in test_ok::load().typed.null.into_iter().enumerate() {
		const TRUE: &'static [u8] = b"\x01\x01\xff";
		type OptBool = Option<bool>;
		
		// Decode the object
		let object = Null::decode(test.bytes.as_slice()).assert(i);
		
		let native = OptBool::decode(test.bytes.as_slice()).assert(i);
		assert!(native.is_none(), "@test_vector:{}", i);
		
		let native = OptBool::decode(TRUE).assert(i);
		assert_eq!(native, Some(true), "@test_vector:{}", i);
		
		// Encode the object
		let mut bytes = vec![0; test.bytes.len()];
		object.encode(&mut bytes.iter_mut()).assert(i);
		assert_eq!(bytes, test.bytes, "@test_vector:{}", i);
		
		let (mut bytes, mut pos) = ([0; 1024], 0);
		let sink = SliceSink::new(&mut bytes, &mut pos);
		Null::new(sink).assert(i);
		assert_eq!(&bytes[..pos], test.bytes.as_slice(), "@test_vector:{}", i);
		
		let mut bytes = [0; 2];
		OptBool::None.encode(&mut bytes.iter_mut()).assert(i);
		assert_eq!(bytes.as_ref(), test.bytes.as_slice(), "@test_vector:{}", i);
	}
}


#[test]
fn octet_string() {
	for (i, test) in test_ok::load().typed.octet_string.into_iter().enumerate() {
		// Decode the object
		let object = OctetString::decode(test.bytes.as_slice()).assert(i);
		assert_eq!(object.get(), test.value.as_slice(), "@test_vector:{}", i);
		
		#[cfg(not(any(feature = "no_std", feature = "no_panic")))] {
			let native = Vec::<u8>::decode(test.bytes.as_slice()).assert(i);
			assert_eq!(native, test.value, "@test_vector:{}", i);
		}
		
		// Encode the object
		let mut bytes = vec![0; test.bytes.len()];
		object.encode(&mut bytes.iter_mut()).assert(i);
		assert_eq!(bytes, test.bytes, "@test_vector:{}", i);
		
		#[cfg(not(any(feature = "no_std", feature = "no_panic")))] {
			let mut bytes = vec![0; test.bytes.len()];
			test.value.encode(&mut bytes.iter_mut()).assert(i);
			assert_eq!(bytes, test.bytes, "@test_vector:{}", i);
		}
		
		let (mut bytes, mut pos) = ([0; 1024], 0);
		let sink = SliceSink::new(&mut bytes, &mut pos);
		OctetString::new(&test.value, sink).assert(i);
		assert_eq!(&bytes[..pos], test.bytes.as_slice(), "@test_vector:{}", i);
	}
}


#[test]
fn sequence() {
	for (i, test) in test_ok::load().typed.sequence.into_iter().enumerate().skip(2).take(1) {
		// Decode the object
		let object = Sequence::decode(test.bytes.as_slice()).assert(i);
		assert_eq!(object.object().value(), test.value.as_slice(), "@test_vector:{}", i);
		
		for (j, obj) in test.sequence.iter().enumerate() {
			let object = object.get(j).assert2(i, j);
			assert_eq!(object.tag(), obj.tag, "@test_vector:{}", i);
			assert_eq!(object.value(), obj.value.as_slice(), "@test_vector:{}:{}", i, j);
		}
		
		#[cfg(not(any(feature = "no_std", feature = "no_panic")))] {
			let native = SequenceVec::<Vec<u8>>::decode(test.bytes.as_slice()).assert(i);
			for (j, obj) in test.sequence.iter().enumerate() {
				assert_eq!(native[j], obj.value.as_slice(), "@test_vector:{}:{}", i, j);
			}
		}
		
		// Encode the object
		let mut bytes = vec![0; test.bytes.len()];
		object.encode(&mut bytes.iter_mut()).assert(i);
		assert_eq!(bytes, test.bytes, "@test_vector:{}", i);
		
		#[cfg(not(any(feature = "no_std", feature = "no_panic")))] {
			let values: Vec<_> = test.sequence.iter()
				.map(|o| DerObject::decode(o.bytes.as_slice()).assert(i))
				.collect();
			let mut bytes = vec![0; test.bytes.len()];
			SequenceVec(values).encode(&mut bytes.iter_mut()).assert(i);
			assert_eq!(bytes, test.bytes, "@test_vector:{}", i);
		}
		
		{
			let values: Vec<_> = test.sequence.iter()
				.map(|o| DerObject::decode(o.bytes.as_slice()).assert(i))
				.collect();
			
			let (mut bytes, mut pos) = ([0; 4096], 0);
			let sink = SliceSink::new(&mut bytes, &mut pos);
			Sequence::new(&values, sink).assert(i);
			assert_eq!(&bytes[..pos], test.bytes.as_slice(), "@test_vector:{}", i);
		}
	}
}


#[test]
fn utf8_string() {
	for (i, test) in test_ok::load().typed.utf8_string.into_iter().enumerate() {
		// Decode the object
		let object = Utf8String::decode(test.bytes.as_slice()).assert(i);
		assert_eq!(object.get(), test.utf8str.as_str(), "@test_vector:{}", i);
		
		#[cfg(not(any(feature = "no_std", feature = "no_panic")))] {
			let native = String::decode(test.bytes.as_slice()).assert(i);
			assert_eq!(native, test.utf8str, "@test_vector:{}", i);
		}
		
		// Encode the object
		let mut bytes = vec![0; test.bytes.len()];
		object.encode(&mut bytes.iter_mut()).assert(i);
		assert_eq!(bytes, test.bytes, "@test_vector:{}", i);
		
		#[cfg(not(any(feature = "no_std", feature = "no_panic")))] {
			let mut bytes = vec![0; test.bytes.len()];
			test.utf8str.encode(&mut bytes.iter_mut()).assert(i);
			assert_eq!(bytes, test.bytes, "@test_vector:{}", i);
		}
		
		let (mut bytes, mut pos) = ([0; 1024], 0);
		let sink = SliceSink::new(&mut bytes, &mut pos);
		Utf8String::new(&test.utf8str, sink).assert(i);
		assert_eq!(&bytes[..pos], test.bytes.as_slice(), "@test_vector:{}", i);
	}
}