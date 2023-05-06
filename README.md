# GoogleAuthenticator

[![CI](https://github.com/hanskorg/google-authenticator-rust/actions/workflows/ci.yml/badge.svg?event=push)](https://github.com/hanskorg/google-authenticator-rust/actions/workflows/ci.yml)
![Build Status](https://img.shields.io/crates/v/google-authenticator.svg)

## Introduction

This Rust crate can be used to interact with the Google Authenticator mobile app for 2-factor-authentication.This Rust crates can generate secrets, generate codes, validate codes and present a QR-Code for scanning the secret.It implements TOTP according to RFC6238
More about Google GoogleAuthenticator see:[Wiki](https://en.wikipedia.org/wiki/Google_Authenticator)


## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
google-authenticator = "0.4"


[dependencies.google-authenticator ]
version= "0.4"
features = ["with-qrcode"]

```
#### C/C++ lib
You can find the header file from [src/authenticator.h](src/authenticator.h), and then build the lib for your target.

How to make header file and build lib, you can refer to the following case.

Tools you may need: [rust-lipo](https://github.com/TimNN/cargo-lipo) [cbingen](https://github.com/eqrion/cbindgen)

```shell
## gen c/c++ header file
cbindgen ./ -l c --output src/authenticator.h

```

```shell 
## clone registry
git clone https://github.com/hanskorg/google-authenticator-rust.git && cd google-authenticator-rust

## change Cargo.toml
crate-type = ["staticlib","cdylib"] 
required-features = ["with-qrcode","clib"]

## build for MacOS and IOS
cargo lipo --features with-qrcode --targets aarch64-apple-darwin  x86_64-apple-darwin aarch64-apple-ios

## build for linux musl
cargo build --all-features  --lib --release --target x86_64-unknown-linux-musl

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
use google_authenticator::{GoogleAuthenticator, ErrorCorrectionLevel};

fn main() {
    let auth = GoogleAuthenticator::new();
    let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
    println!(
        "{}",
        auth.qr_code_url(secret, "qr_code", "name", 200, 200, ErrorCorrectionLevel::High)
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
version = "0.4"
features = ["with-qrcode"]
```

```rust
use google_authenticator::{GoogleAuthenticator, ErrorCorrectionLevel};

fn main() {
    let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
    let auth = GoogleAuthenticator::new();

    println!(
        "{}",
        auth.qr_code(secret, "qr_code", "name", 200, 200, ErrorCorrectionLevel::High)
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

## Contributors
Thanks to:
[JHZheng](https://github.com/zjhmale)  [Conbas](https://github.com/jtr109)

## FAQ
> You can post a new issue for help.
