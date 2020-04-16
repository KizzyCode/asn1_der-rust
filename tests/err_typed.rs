#![cfg_attr(test, deny(warnings))]
#![cfg(feature = "native_types")]

pub mod helpers;

use crate::helpers::{ ResultExt, test_err };
use asn1_der::typed::{ DerDecodable, Boolean, Integer, Null, OctetString, Sequence, Utf8String };


#[test]
fn boolean() {
	for (i, test) in test_err::load().typed.bool.into_iter().enumerate() {
		Boolean::decode(&test.bytes).assert_err(&test.err, i);
		bool::decode(&test.bytes).assert_err(&test.err, i);
	}
}


#[test]
fn integer() {
	for (i, test) in test_err::load().typed.integer.into_iter().enumerate() {
		Integer::decode(&test.bytes).assert_err(&test.err, i);
		macro_rules! native {
			($num:ty) => (<$num>::decode(&test.bytes).assert_err(&test.err, i));
			($( $num:ty ),+) => ($( native!($num); )+);
		}
		native!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);
	}
}


#[test]
fn null() {
	for (i, test) in test_err::load().typed.null.into_iter().enumerate() {
		type OptBool = Option<bool>;
		Null::decode(&test.bytes).assert_err(&test.err, i);
		OptBool::decode(&test.bytes).assert_err(&test.err, i);
	}
}


#[test]
fn octet_string() {
	for (i, test) in test_err::load().typed.octet_string.into_iter().enumerate() {
		OctetString::decode(&test.bytes).assert_err(&test.err, i);
		#[cfg(not(any(feature = "no_std", feature = "no_panic")))]
			Vec::<u8>::decode(&test.bytes).assert_err(&test.err, i);
	}
}


#[test]
fn sequence() {
	for (i, test) in test_err::load().typed.sequence.into_iter().enumerate() {
		Sequence::decode(&test.bytes).assert_err(&test.err, i);
	}
}


#[test]
fn utf8_string() {
	for (i, test) in test_err::load().typed.utf8_string.into_iter().enumerate() {
		Utf8String::decode(&test.bytes).assert_err(&test.err, i);
		#[cfg(not(any(feature = "no_std", feature = "no_panic")))]
			String::decode(&test.bytes).assert_err(&test.err, i);
	}
}