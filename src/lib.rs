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
//! ```
//!
//! use google_authenticator::GoogleAuthenticator;
//!
//! let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
//!
//! let auth = GoogleAuthenticator::new();
//! let code = auth.get_code(secret,0).unwrap();
//! if auth.verify_code(secret, code.as_str(), 1, 0).unwrap() {
//!     println!("match!");
//! }
//!
//! ```
//!
//!
extern crate rand;
extern crate base32;
extern crate hmacsha1;


pub mod google_authenticator;

pub use google_authenticator::{GoogleAuthenticator,GAError};

#[cfg(test)]
mod tests {
    use google_authenticator::GoogleAuthenticator;

    #[test]
    fn create_secret() {
        let auth = GoogleAuthenticator::new();
        let secret = auth.create_secret(32);
        //auth.get_code(secret.as_str(),0);
//        println!("{:?}",secret);
        assert_eq!(secret.len(),32);
    }
    #[test]
    fn test_code(){
        let auth = GoogleAuthenticator::new();
        let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
        //otpauth://totp/test?secret=I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3 1523610659 559389
        assert_eq!(auth.get_code(secret,  1523610659 / 30).unwrap(), "224124");
    }

    #[test]
    fn test_verify_code(){
        let auth = GoogleAuthenticator::new();
        let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
        assert!(auth.verify_code(secret, "224124", 3, 1523610659 / 30).unwrap());
    }
}
