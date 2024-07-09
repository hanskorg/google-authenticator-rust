// MIT License
//
// Copyright (c) 2018 hanskorg
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use hmacsha1::hmac_sha1;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{error, fmt, result};

#[cfg(any(feature = "with-qrcode",doc))]
use qrcode::render::svg;
#[cfg(any(feature = "with-qrcode",doc))]
use qrcode::{EcLevel, QrCode};

#[cfg(any(feature = "with-qrcode",doc))]
use qrcode::types::QrError;
/// cbindgen:ignore
const SECRET_MAX_LEN: usize = 128;
/// cbindgen:ignore
const SECRET_MIN_LEN: usize = 16;

/// Controls the amount of fault tolerance that the QR code should accept. Require the feature
/// flag `with-qrcode`.
// This is a new enum to use in our public interface instead of rqcode::EcLevel.
#[derive(Copy, Clone)]
#[repr(C)]
pub enum ErrorCorrectionLevel {
    /// 7% of data bytes can be restored.
    Low,
    /// 15% of data bytes can be restored.
    Medium,
    /// 25% of data bytes can be restored.
    Quartile,
    /// 30% of data bytes can be restored.
    High,
}

use self::ErrorCorrectionLevel::*;

impl fmt::Display for ErrorCorrectionLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let result = match self {
            Low => 'L',
            Medium => 'M',
            Quartile => 'Q',
            High => 'H',
        };
        write!(f, "{}", result)
    }
}

#[cfg(any(feature = "with-qrcode", doc))]
impl From<ErrorCorrectionLevel> for qrcode::EcLevel {
    fn from(level: ErrorCorrectionLevel) -> Self {
        match level {
            ErrorCorrectionLevel::High => EcLevel::H,
            ErrorCorrectionLevel::Medium => EcLevel::M,
            ErrorCorrectionLevel::Quartile => EcLevel::Q,
            ErrorCorrectionLevel::Low => EcLevel::L,
        }
    }
}

/// cbindgen:ignore
/// A list of all usable characters in base32.
const ALPHABET: [char; 33] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7', '=',
];

/// The main interface of this library. It exports several function that are necessary to interface
/// with google authenticator.
pub struct GoogleAuthenticator {
    code_len: usize,
}

impl Default for GoogleAuthenticator {
    fn default() -> Self {
        Self { code_len: 6 }
    }
}

impl GoogleAuthenticator {
    /// Create a new `GoogleAuthenticator` using the default implementation. This means that the
    /// codes generated have a length of 6 and the secret will be chosen from allowed base32
    /// characters.
    ///
    /// ### Example
    /// ```
    /// use google_authenticator::GoogleAuthenticator;
    ///
    /// let auth = GoogleAuthenticator::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Use this method to configure the length of the generated code.
    ///
    /// ### Example
    /// ```rust
    /// use google_authenticator::GoogleAuthenticator;
    ///
    /// let auth = GoogleAuthenticator::new()
    ///     .with_code_length(8);
    /// ```
    pub fn with_code_length(mut self, code_length: usize) -> Self {
        self.code_len = code_length;
        self
    }

    /// Create new secret.
    ///
    /// Example:
    /// ```rust
    /// use google_authenticator::GoogleAuthenticator;
    ///
    /// let google_authenticator = GoogleAuthenticator::new();
    /// google_authenticator.create_secret(32);
    /// ```
    pub fn create_secret(&self, length: u8) -> String {
        let mut secret = Vec::<char>::new();
        let mut index: usize;
        for _ in 0..length {
            index = (rand::random::<u8>() & 0x1F) as usize;
            secret.push(ALPHABET[index]);
        }
        secret.into_iter().collect()
    }

    /// Calculate the code, with given secret and point in time. The `secret` parameter is the
    /// secret configured for this user. The `times_slice` parameter is the unix timestamp divided
    /// by 30 at which the code should expire.
    ///
    /// ### Example
    /// ```rust
    /// use google_authenticator::GoogleAuthenticator;
    ///
    /// let authenticator = GoogleAuthenticator::new();
    /// authenticator.get_code("I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3", 1523610659 / 30).unwrap();
    /// ```
    pub fn get_code(&self, secret: &str, times_slice: u64) -> Result<String> {
        if secret.len() < SECRET_MIN_LEN || secret.len() > SECRET_MAX_LEN {
            return Err(GAError::Error(
                "bad secret length. must be less than 128 and more than 16, recommend 32",
            ));
        }

        let message = if times_slice == 0 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / 30
        } else {
            times_slice
        };
        let key = Self::base32_decode(secret)?;
        let msg_bytes = message.to_be_bytes();
        let hash = hmac_sha1(&key, &msg_bytes);
        let offset = hash[hash.len() - 1] & 0x0F;
        let mut truncated_hash: [u8; 4] = Default::default();
        truncated_hash.copy_from_slice(&hash[offset as usize..(offset + 4) as usize]);
        let mut code = i32::from_be_bytes(truncated_hash);
        code &= 0x7FFFFFFF;
        code %= 1_000_000;
        let mut code_str = code.to_string();
        for i in 0..(self.code_len - code_str.len()) {
            code_str.insert(i, '0');
        }
        Ok(code_str)
    }

    /// This function verifies that a provided code is correct. The parameter `secret` is used to
    /// verify the user. `code` is the code that will be verified. The parameter `discrepancy`
    /// indicates number of windows ago that a code may be generated, which results to `discrepancy` * 30
    /// seconds. If 0 is provided, the token cannot be expired. `time_slice` is used to modify what
    /// the current time is, as a unix timestamp. If 0 is provided here, the current time will be used.
    ///
    /// ### Example
    /// ```rust
    /// use google_authenticator::GoogleAuthenticator;
    ///
    /// let authenticator = GoogleAuthenticator::new();
    /// authenticator.verify_code("I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3", "224124", 0, 1523610659 / 30);
    /// ```
    pub fn verify_code(&self, secret: &str, code: &str, discrepancy: u64, time_slice: u64) -> bool {
        if code.len() != self.code_len {
            return false;
        }
        let curr_time_slice = if time_slice == 0 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / 30
        } else {
            time_slice
        };
        let start_time = curr_time_slice.saturating_sub(discrepancy);
        let end_time = curr_time_slice.saturating_add(discrepancy + 1);
        for _time_slice in start_time..end_time {
            if let Ok(c) = self.get_code(secret, _time_slice) {
                if code == c {
                    return true;
                }
            }
        }
        false
    }

    /// Get QR-Code URL for image, from google charts. For the height and width, if a value of 0 is
    /// provided, the default of `200px` is used. Level is the amount of fault tolerance that the
    /// QR code should accept, see
    /// [this page](https://en.wikipedia.org/wiki/QR_code#Error_correction) for more information.
    ///
    /// ### Example
    /// ```rust
    /// use google_authenticator::{GoogleAuthenticator, ErrorCorrectionLevel};
    ///
    /// let authenticator = GoogleAuthenticator::new();
    /// authenticator.qr_code_url(
    ///     "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3",
    ///     "your company name",
    ///     "hello",
    ///     0,
    ///     0,
    ///     ErrorCorrectionLevel::Medium,
    /// );
    /// ```
    pub fn qr_code_url(
        &self,
        secret: &str,
        name: &str,
        title: &str,
        width: u32,
        height: u32,
        level: ErrorCorrectionLevel,
    ) -> String {
        let width = if width == 0 { 200 } else { width };
        let height = if height == 0 { 200 } else { height };

        // Scheme will be a url to the totp we will use. Since it is a query parameter of the final
        // url, it must be percent encoded. In turn, this means that `name` and `title` must be
        // percent encoded twice for the final url to work if they contain characters that are not
        // allowed in urls.
        let scheme = Self::create_scheme(name, secret, title);
        let scheme = utf8_percent_encode(&scheme, NON_ALPHANUMERIC);
        format!(
            "https://chart.googleapis.com/chart?chs={}x{}&chld={}|0&cht=qr&chl={}",
            width, height, level, scheme
        )
    }

    /// Creates an in-memory SVG file that can be used to perform 2fa with Google Authenticator. The
    /// `height` and `width` parameters are the minimun dimensions of the generated svg. When 0 is
    /// supplied here, these values default to `200px`.
    ///
    /// ### Example
    /// ```rust
    /// use google_authenticator::{GoogleAuthenticator, ErrorCorrectionLevel};
    ///
    /// let authenticator = GoogleAuthenticator::new();
    /// authenticator.qr_code(
    ///     "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3",
    ///     "your company name",
    ///     "hello",
    ///     0,
    ///     0,
    ///     ErrorCorrectionLevel::Medium,
    /// );
    /// ```
    #[cfg(any(feature = "with-qrcode", doc))]
    pub fn qr_code(
        &self,
        secret: &str,
        name: &str,
        title: &str,
        width: u32,
        height: u32,
        level: ErrorCorrectionLevel,
    ) -> Result<String> {
        let width = if width == 0 { 200 } else { width };
        let height = if height == 0 { 200 } else { height };
        let scheme = Self::create_scheme(name, secret, title);
        let code = QrCode::with_error_correction_level(scheme.as_bytes(), level.into())?;
        Ok(code
            .render()
            .min_dimensions(width, height)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build())
    }

    /// Creates a totp url.
    fn create_scheme(name: &str, secret: &str, title: &str) -> String {
        let name = utf8_percent_encode(name, NON_ALPHANUMERIC);
        let title = utf8_percent_encode(title, NON_ALPHANUMERIC);
        format!("otpauth://totp/{}?secret={}&issuer={}", name, secret, title)
    }

    fn base32_decode(secret: &str) -> Result<Vec<u8>> {
        match base32::decode(base32::Alphabet::RFC4648 { padding: true }, secret) {
            Some(_decode_str) => Ok(_decode_str),
            _ => Err(GAError::Error("secret must be base32 decodeable.")),
        }
    }
}

/// Represents any of the reasons why using 2fa with Google Authenenticator can fail.
#[derive(Debug)]
pub enum GAError {
    /// An error in the logic of the QR code. Contains a static string with the error message.
    Error(&'static str),
    /// An error related to the QR code. This variant is only available with the feature flag
    /// `with-qrcode`.
    #[cfg(any(feature = "with-qrcode",doc))]
    QrError(QrError),
}

impl error::Error for GAError {
    fn description(&self) -> &str {
        match *self {
            GAError::Error(description) => description,
            #[cfg(any(feature = "with-qrcode",doc))]
            GAError::QrError(ref _err) => "",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            #[cfg(any(feature = "with-qrcode", doc))]
            GAError::QrError(ref _err) => None,
            GAError::Error(_) => None,
        }
    }
}

#[cfg(any(feature = "with-qrcode", doc))]
impl From<QrError> for GAError {
    fn from(err: QrError) -> GAError {
        GAError::QrError(err)
    }
}

impl fmt::Display for GAError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GAError::Error(desc) => f.write_str(desc),
            #[cfg(any(feature = "with-qrcode",doc))]
            GAError::QrError(ref err) => fmt::Display::fmt(err, f),
        }
    }
}

/// A type alias that can be used for fallible functions with `google_authenticator`.
pub type Result<T> = result::Result<T, GAError>;
