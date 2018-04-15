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
        let rand_bytes = rand::random::<[u8;32]>();
        let mut secret = Vec::<char>::new();
        let mut index: usize;
        for i in 0 .. length {
            index = (rand_bytes[i as usize] & 0x1F) as usize;
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

        if secret.len() < 16 || secret.len() > 128 {
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

#[derive(Debug)]
pub enum GAError {
    Error(&'static str),
}

impl error::Error for GAError{
    fn description(&self) -> &str {
        match *self {
            GAError::Error(description) =>description,
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            GAError::Error(_) => None,
        }
    }
}


impl fmt::Display for GAError{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GAError::Error(desc) => f.write_str(desc),
        }
    }
}

type Result<T> = result::Result<T,GAError>;
