# GoogleAuthenticator

[![Build Status](https://travis-ci.org/hanskorg/google-authenticator-rust.svg?branch=master)](https://travis-ci.org/hanskorg/google-authenticator-rust)
![Build Status](https://img.shields.io/crates/v/google-authenticator.svg)

## Introduction

This Rust crate can be used to interact with the Google Authenticator mobile app for 2-factor-authentication.This Rust crates can generate secrets, generate codes, validate codes and present a QR-Code for scanning the secret.It implements TOTP according to RFC6238
More about Google GoogleAuthenticator see:[Wiki](https://en.wikipedia.org/wiki/Google_Authenticator)


## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
google-authenticator = "0.1.5"
```

## Examples

```rust
use google_authenticator::GoogleAuthenticator;

fn main() {
    let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
    let auth = GoogleAuthenticator::new();
    // let secret = auth.create_secret(32);
    let code = auth.get_code(&secret, 0).unwrap();

    assert!(auth.verify_code(&secret, &code, 1, 0).unwrap());
}
```

```rust
#[macro_use]
extern crate google_authenticator;
use google_authenticator::GA_AUTH;

fn main() {
    let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
    if let Ok(code) = get_code!(&secret) {
        println!("{}", verify_code!(&secret, &code, 1, 0));
    }
}
```

## Get the secret QR code

### Get Google Charts Url to make QR Code

```rust
use google_authenticator::GoogleAuthenticator;

fn main() {
    let auth = GoogleAuthenticator::new();
    let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
    println!(
        "{}",
        auth.qr_code_url(secret, "qr_code", "name", 200, 200, 'H')
    );
}
```

```rust
#[macro_use]
extern crate google_authenticator;
use google_authenticator::GA_AUTH;

fn main() {
    let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
    println!("{}", qr_code_url!(&secret, "qr_code", "name"));
}
```

### Get QR code image in svg format

Change `Cargo.toml` to

```toml
[dependencies.google-authenticator]
version = "0.1.5"
default-features = false
features = ["with-qrcode"]
```

```rust
use google_authenticator::GoogleAuthenticator;

fn main() {
    let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
    let auth = GoogleAuthenticator::new();

    println!(
        "{}",
        auth.qr_code(secret, "qr_code", "name", 200, 200, 'H')
            .unwrap()
    );
}
```

```rust
#[macro_use]
extern crate google_authenticator;
use google_authenticator::GA_AUTH;

fn main() {
    let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
    if let Ok(url) = qr_code!(&secret, "qr_code", "name") {
        println!("{}", url);
    }
}
```

## FAQ
> You can post a new issue for help.
