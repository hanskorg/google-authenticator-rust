//MIT License
//
//Copyright (c) 2018 hanskorg
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.
//
//

use rand;
use base32;
use hmacsha1::hmac_sha1;
use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};
use urlencoding;

#[cfg(any(feature = "with-qrcode"))]
use qrcode::{QrCode, Version, EcLevel};
#[cfg(any(feature = "with-qrcode"))]
use qrcode::render::svg;

const SECRET_MAX_LEN:usize = 128;
const SECRET_MIN_LEN:usize = 16;

pub struct GoogleAuthenticator{
    code_len:usize,
    _base32_alphabet:Vec<char>
}

impl GoogleAuthenticator{

    pub fn new() -> GoogleAuthenticator{
        GoogleAuthenticator{
            code_len: 6,
            _base32_alphabet: vec![
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
                'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
                '=',
            ]
        }
    }
    /// Create new secret.
    /// characters, randomly chosen from the allowed base32 characters.
    ///
    /// Example:
    ///```
    /// use google_authenticator::GoogleAuthenticator;
    ///
    /// let google_authenticator = GoogleAuthenticator::new();
    /// google_authenticator.create_secret(32);
    ///
    ///```
    ///
    pub fn create_secret(&self, length:u8) -> String{
        let mut secret = Vec::<char>::new();
        let mut index:usize = 0;
        for _ in 0 .. length {
            index = (rand::random::<u8>() & 0x1F) as usize;
            secret.push(self._base32_alphabet[ index ]);
        }
        secret.into_iter().collect()
    }

    /// Calculate the code, with given secret and point in time.
    ///
    /// Example:
    ///```
    ///     use google_authenticator::GoogleAuthenticator;
    ///
    ///     let google_authenticator = GoogleAuthenticator::new();
    ///     google_authenticator.get_code("I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3", 1523610659 / 30).unwrap();
    ///
    /// ```
    /// *secret* : user secret, it will verify each user.
    /// *times_slice* : unix_timestamp / 30 ,if give 0, it will system unix_timestamp
    ///
    pub fn get_code(&self, secret:&str, times_slice:u32) -> Result<String>{

        if secret.len() < SECRET_MIN_LEN || secret.len() > SECRET_MAX_LEN {
            return Err(GAError::Error("bad secret length. must be less than 128 and more than 16, recommand 32"));
        }

        let mut message: u32 = times_slice;
        if times_slice == 0 {
            message = (f64::from_bits(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) / 30.0).floor() as u32;
        }
        let key  = self._base32_decode(secret)?;
        let msg_bytes = unsafe { mem::transmute::<u32,[u8;4]>(message.to_be()) };
        let mut message_body:Vec<u8> = vec![0;4];
        for msg_byte in msg_bytes.iter() {
            message_body.push(*msg_byte);
        }
        let hash = hmac_sha1(&key, message_body.as_slice());

        let offset = hash[hash.len() - 1] & 0x0F;
        let mut truncated_hash:[u8;4] = Default::default();
        truncated_hash.copy_from_slice(&hash[offset  as usize .. (offset + 4)  as usize]);
        let mut code:u32 = unsafe { mem::transmute::<[u8;4], u32>(truncated_hash) };
        if cfg!(target_endian = "big") {
        } else {
            code = u32::from_be(code);
        }
        code =  code % 1_000_000u32;
        let mut code_str = code.to_string();
        for i in 0 .. (self.code_len - code_str.len()) {
            code_str.insert(i,'0');
        }
        Ok(code_str)
    }
    /// Check if the code is correct.
    /// `secret` use for verify user
    /// `code` the code to verify
    /// `discrepancy` This will accept codes starting from *discrepancy\*30sec* ago to *discrepancy\*30sec* from now.
    /// `time_slice` if give 0, it will system unix_timestamp
    ///
    ///```
    ///     use google_authenticator::GoogleAuthenticator;
    ///
    ///     let google_authenticator = GoogleAuthenticator::new();
    ///     google_authenticator.verify_code("I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3", "224124", 3, 1523610659 / 30).unwrap();
    ///
    /// ```
    ///
    pub fn verify_code(&self, secret:&str, code: &str, discrepancy:u32, time_slice:u32) -> Result<bool>{
        let mut curr_time_slice: u32 = time_slice;
        if time_slice == 0 {
            curr_time_slice = (f64::from_bits(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) / 30.0).floor() as u32;
        }
        if code.len() != self.code_len {
            return Ok(false);
        }
        for _time_slice in curr_time_slice.wrapping_sub(discrepancy) .. curr_time_slice.wrapping_add(discrepancy + 1)  {
            if code.eq(self.get_code(secret, _time_slice)?.as_str()) {
                return Ok(true);
            }

        }
        Ok(false)
    }
    /// Get QR-Code URL for image, from google charts.
    /// width: width of the qrcode. default value 200 px
    /// height: height of the qrcode. default value 200 px
    /// level: the qrcode level ,it will be L,M,Q,H. Default value is M
    ///
    pub fn qr_code_url(&self, secret:&str, name:&str, title:&str, width:u16, height:u16, level:char) -> String {
        let _width = if width == 0 {200} else {width};
        let _height = if  height == 0 {200} else {height};
        let levels = vec!['L', 'M', 'Q', 'H'];
        let _level = if levels.contains(&level) {level} else {'M'};
        let scheme =  urlencoding::encode(
            format!("otpauth://totp/{}?secret={}&issuer={}"
                    ,name
                    ,secret
                    ,urlencoding::encode(title)).as_str());
        format!("https://chart.googleapis.com/chart?chs={}x{}&chld={}|0&cht=qr&chl={}", _width, _height, level, scheme)
    }
    /// Get QR-Code  for svg
    /// Get QR-Code URL for image, from google charts.
    /// width: width of the qrcode. default value 200 px
    /// height: height of the qrcode. default value 200 px
    /// level: the qrcode level ,it will be L,M,Q,H. Default value is M
    #[cfg(any(feature = "with-qrcode"))]
    pub fn qr_code(&self, secret:&str, name:&str, title:&str, width:u16, height:u16, level:char) -> Result<String>{
        let _width = if width == 0 {200} else {width};
        let _height = if  height == 0 {200} else {height};
        let levels = vec!['L', 'M', 'Q', 'H'];
        let _level = match level {
            'L' => EcLevel::L,
            'H' => EcLevel::H,
            _ => EcLevel::M
        };
        let scheme =  urlencoding::encode(
            format!("otpauth://totp/{}?secret={}&issuer={}"
                    ,name
                    ,secret
                    ,urlencoding::encode(title)).as_str());
        let code = QrCode::with_error_correction_level(scheme.as_bytes(), _level)?;
        Ok(code.render()
            .min_dimensions(_width as u32, _height  as u32)
            .dark_color(svg::Color("#800000"))
            .light_color(svg::Color("#ffff80"))
            .build())
    }

    fn _base32_decode(&self, secret:&str) -> Result<Vec<u8>>{
        //use base32 extern
        match  base32::decode(base32::Alphabet::RFC4648 { padding: true }, secret) {
            Some(_decode_str) => Ok(_decode_str),
            _                 => Err(GAError::Error("secret must can decode by base32."))
        }
    }

}


use std::error;
use std::result;
use std::fmt;
#[cfg(any(feature = "with-qrcode"))]
use qrcode::types::QrError;
#[derive(Debug)]
pub enum GAError {
    Error(&'static str),
    #[cfg(any(feature = "with-qrcode"))]
    QrError(QrError)
}

impl error::Error for GAError{
    fn description(&self) -> &str {
        match *self {
            GAError::Error(description) =>description,
            #[cfg(any(feature = "with-qrcode"))]
            GAError::QrError(ref err) => ""
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            #[cfg(any(feature = "with-qrcode"))]
            GAError::QrError(ref err) =>  None,
            GAError::Error(_) => None,
        }
    }
}
#[cfg(any(feature = "with-qrcode"))]
impl From<QrError> for GAError{
    fn from(err:QrError) -> GAError {
        GAError::QrError(err)
    }
}

impl fmt::Display for GAError{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GAError::Error(desc) => f.write_str(desc),
            #[cfg(any(feature = "with-qrcode"))]
            GAError::QrError(ref err) =>  fmt::Display::fmt(err, f),
        }
    }
}

type Result<T> = result::Result<T,GAError>;
