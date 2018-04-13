
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

    pub fn get_code(&self, secret:&str, times_slice:u32) -> String{
        let mut message: u32 = times_slice;
        if times_slice == 0 {
            message = (f64::from_bits(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) / 30.0).floor() as u32;
        }
        let key  = self._base32_decode(secret);
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
        code_str
    }

    pub fn verify_code(&self, secret:&str, code: &str, discrepancy:i32, time_slice:u32) -> bool{
        let mut curr_time_slice: u32 = time_slice;
        if time_slice == 0 {
            curr_time_slice = (f64::from_bits(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) / 30.0).floor() as u32;
        }
        if code.len() != self.code_len {
            return false;
        }
        for offset in (discrepancy * -1) .. discrepancy   {
            if code.eq(self.get_code(secret, curr_time_slice ).as_str()) {
                return true;
            }
        }
        false
    }

    fn _base32_decode(&self, secret:&str) -> Vec<u8>{
        return base32::decode(base32::Alphabet::RFC4648 { padding: true }, secret).unwrap()
    }




}