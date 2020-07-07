#![deny(missing_docs)]
// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This Rust crate can be used to interact with the Google Authenticator mobile app for 2-factor-authentication.
//! This Rust crates can generate secrets, generate codes, validate codes and present a QR-Code for scanning the secret.
//! It implements TOTP according to RFC6238
//!
//! # Examples
//!
//! ```rust
//! use google_authenticator::GoogleAuthenticator;
//!
//! let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
//!
//! let auth = GoogleAuthenticator::new();
//! let code = auth.get_code(secret,0).unwrap();
//! if auth.verify_code(secret, code.as_str(), 1, 0) {
//!     println!("match!");
//! }
//! ```

mod authenticator;

pub use authenticator::*;

lazy_static::lazy_static! {
    /// A globally accessible, thread safe instance of a `GoogleAuthenticator`. Note that if the
    /// code panics while this variable is in scope, the `std::sync::Mutex` can be poisoned,
    /// preventing further access to this variable.
    pub static ref GA_AUTH: GoogleAuthenticator = GoogleAuthenticator::new();
}

/// A macro that can be used for convenient access to the function
/// `GoogleAuthenticator::create_secret`, by providing a default of `32` to the `length` parameter.
#[macro_export]
macro_rules! create_secret {
    ($length: expr) => {
        GA_AUTH.create_secret($length)
    };
    () => {
        GA_AUTH.create_secret(32)
    };
}

/// A macro that can be used for convenient access to the function
/// `GoogleAuthenticator::create_secret`, by providing a default of the current time to the
/// `times_slice` parameter.
#[macro_export]
macro_rules! get_code {
    ($secret: expr, $time_slice: expr) => {
        GA_AUTH.get_code($secret, time_slice)
    };
    ($secret: expr) => {
        GA_AUTH.get_code($secret, 0)
    };
}

/// A macro that can be used for convenient access to the function
/// `GoogleAuthenticator::verify_code`, by providing a default of 0 to the `discrepancy` parameter,
/// and the current time to the `times_slice` parameter.
#[macro_export]
macro_rules! verify_code {
    ($secret: expr, $code: expr, $discrepancy: expr, $time_slice: expr) => {
        GA_AUTH.verify_code($secret, $code, $discrepancy, $time_slice)
    };
    ($secret: expr, $code: expr) => {
        GA_AUTH.verify_code($secret, $code, 0, 0)
    };
}

/// A macro that can be used for convenient access to the function
/// `GoogleAuthenticator::qr_code_url`, by providing a default of 200 to the `width` parameter, 200
/// to the `height` parameter, and `ErrorCorrectionLevel::Medium` to the `level` parameter.
#[macro_export]
macro_rules! qr_code_url {
    ($secret: expr, $name: expr, $title: expr, $width: expr, $height: expr, $level: expr) => {
        GA_AUTH.qr_code_url($secret, $name, $title, $width, $height, $level)
    };
    ($secret: expr, $name: expr, $title: expr) => {
        GA_AUTH.qr_code_url(
            $secret,
            $name,
            $title,
            200,
            200,
            crate::ErrorCorrectionLevel::Medium,
        )
    };
}

/// A macro that can be used for convenient access to the function
/// `GoogleAuthenticator::qr_code`, by providing a default of 200 to the `width` parameter, 200
/// to the `height` parameter, and `ErrorCorrectionLevel::Medium` to the `level` parameter.
#[macro_export]
macro_rules! qr_code {
    ($secret: expr, $name: expr, $title: expr, $width: expr, $height: expr, $level: expr) => {
        GA_AUTH.qr_code($secret, $name, $title, $width, $height, $level)
    };
    ($secret: expr, $name: expr, $title: expr) => {
        GA_AUTH.qr_code(
            $secret,
            $name,
            $title,
            200,
            200,
            crate::ErrorCorrectionLevel::Medium,
        )
    };
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "with-qrcode")]
    use crate::ErrorCorrectionLevel::*;
    use crate::GoogleAuthenticator;

    #[test]
    fn create_secret() {
        let auth = GoogleAuthenticator::new();
        let secret = auth.create_secret(32);
        //auth.get_code(secret.as_str(),0);
        //        println!("{:?}",secret);
        assert_eq!(secret.len(), 32);
    }
    #[test]
    fn test_code() {
        let auth = GoogleAuthenticator::new();
        let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
        assert_eq!(6, auth.get_code(&secret, 0).unwrap().len());
    }

    #[test]
    #[cfg(feature = "with-qrcode")]
    fn test_verify_code() {
        let auth = GoogleAuthenticator::new();
        let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
        println!(
            "{:?}",
            auth.qr_code(secret, "qr_code", "name", 0, 0, Medium)
        );
        assert!(auth.verify_code(secret, "224124", 3, 1523610659 / 30));
    }

    #[test]
    #[cfg(feature = "with-qrcode")]
    fn test_qr_code_url() {
        let auth = GoogleAuthenticator::new();
        let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
        let url = auth.qr_code_url(secret, "secret code", "hi there", 0, 0, Medium);
        println!("{}", url);
        let resp = ureq::get(&url).call();
        assert!(resp.ok());
        panic!();
    }

    #[test]
    #[cfg(feature = "with-qrcode")]
    fn test_qr_code() {
        let auth = GoogleAuthenticator::new();
        let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
        auth.qr_code(secret, "secret_code", "hi", 0, 0, Medium).unwrap();
    }
}

#[cfg(test)]
mod macro_tests {
    use crate::GA_AUTH;

    #[test]
    fn create_secret() {
        let secret = create_secret!();
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn test_code() {
        let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
        assert_eq!(6, get_code!(&secret).unwrap().len());
    }

    #[test]
    fn test_verify_code() {
        let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
        let code = get_code!(&secret).unwrap();
        assert!(verify_code!(secret, &code));
    }

    #[test]
    #[cfg(feature = "with-qrcode")]
    fn test_qr_code() {
        let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
        assert!(qr_code!(secret, "qr_code", "name").is_ok());
    }

    #[test]
    #[cfg(feature = "with-qrcode")]
    fn test_qr_code_url() {
        let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
        qr_code_url!(secret, "qr_code", "name");
    }
}
