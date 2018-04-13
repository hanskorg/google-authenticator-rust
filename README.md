# yarclient
## Introduction
This Rust crate can be used to interact with the Google Authenticator mobile app for 2-factor-authentication.
This Rust crates can generate secrets, generate codes, validate codes and present a QR-Code for scanning the secret.
It implements TOTP according to RFC6238

[![Build Status](https://travis-ci.org/hanskorg/google-authenticator-rust.svg?branch=master)](https://travis-ci.org/hanskorg/google-authenticator-rust)
![Build Status](https://img.shields.io/crates/v/google-authenticator.svg)
## Usage
Add this to your `Cargo.toml`:

```toml
[dependencies]
google-authenticator = "0.1.0"
```
## Examples
```rust
 use google_authenticator::GoogleAuthenticator;
 let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";

 let auth = GoogleAuthenticator::new();
 let code = auth.get_code(secret,0).unwrap();

 if auth.verify_code(secret, code, 1, 0) {
      println!("match!");
 }
```

## FAQ
> You can post new issue for help.