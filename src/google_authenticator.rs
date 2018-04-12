
use rand;
pub struct GoogleAuthenticator{
    pub code_len:u8,
    _base32_lookup_table:Vec<char>
}

impl GoogleAuthenticator{

    pub fn new(length:u8) -> GoogleAuthenticator{
        GoogleAuthenticator{
            code_len:length,
            _base32_lookup_table: vec![
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
            index = (rand_bytes[i as usize] & 31) as usize;
            secret.push(self._base32_lookup_table[ index ]);
        }
        secret.into_iter().collect()
    }

    pub fn get_code(&self, secret:&str, times_slice:u32) -> u32{
        123432
    }

    pub fn verify_code(&self, code: u32) -> bool{
        false
    }




}