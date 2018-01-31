use std;

#[derive(Debug)]
/// The error-type
pub enum ErrorType {
	/// The encoding of something does not conform to the ASN.1-DER-standard
	InvalidEncoding,
	/// The real-length does not match the expected length
	LengthMismatch,
	/// The tag does not match the object-type
	InvalidTag,
	/// The element might be valid but is not supported by this implementation
	Unsupported,
	
	/// Another error
	Other(String)
}
impl PartialEq for ErrorType {
	fn eq(&self, other: &Self) -> bool {
		let self_string = format!("{:?}", self);
		let other_string = format!("{:?}", other);
		self_string == other_string
	}
}
impl Eq for ErrorType {}



#[derive(Debug)]
/// An error-describing structure containing the error and it's file/line
pub struct Error {
	/// The error-type
	pub error_type: ErrorType,
	/// Description
	pub description: String,
	/// The file in which the error occurred
	pub file: &'static str,
	/// The line on which the error occurred
	pub line: u32
}
impl Error {
	pub fn as_string(&self) -> String {
		if !self.description.is_empty() { self.description.clone() }
			else { format!("{:?}", self) }
	}
}
impl std::fmt::Display for Error {
	fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "{:?}", self)
	}
}
impl std::error::Error for Error {
	fn description(&self) -> &str {
		&self.description
	}
}



#[macro_export]
/// Create an error from an `ErrorType`
macro_rules! new_err {
	($error_type:expr, $description:expr) => (Err($crate::error::Error {
		error_type: $error_type,
		description: $description,
		file: file!(),
		line: line!()
	}));
	($error_type:expr) => (new_err!($error_type, "".to_owned()));
}

#[macro_export]
/// Create an error from an `ErrorType`
macro_rules! throw_err {
	($error_type:expr, $description:expr) => (return new_err!($error_type, $description));
	($error_type:expr) => (throw_err!($error_type, "".to_owned()));
}

#[macro_export]
/// Tries an expression and propagates an eventual error
macro_rules! try_err {
	($code:expr, $description:expr) => (match $code {
		Ok(result) => result,
		Err(error) => throw_err!($crate::error::ErrorType::from(error), $description)
	});
	($code:expr) => (try_err!($code, "".to_owned()))
}