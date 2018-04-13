extern crate rand;
extern crate base32;
extern crate hmacsha1;

pub mod google_authenticator;
pub use google_authenticator::GoogleAuthenticator;

#[cfg(test)]
mod tests {
    use google_authenticator::GoogleAuthenticator;
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
        println!("{}",1523610659 / 30);
        assert_eq!(auth.get_code(secret,  1523610659 / 30), "224124");
    }

    #[test]
    fn test_verify_code(){
        let auth = GoogleAuthenticator::new();
        let secret = "I3VFM3JKMNDJCDH5BMBEEQAW6KJ6NOE3";
        assert!(auth.verify_code(secret, "224124", 1, 523610659 / 30));
    }
}
