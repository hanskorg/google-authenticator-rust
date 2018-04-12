extern crate rand;

pub mod google_authenticator;
pub use google_authenticator::GoogleAuthenticator;

#[cfg(test)]
mod tests {
    use google_authenticator::GoogleAuthenticator;
    #[test]
    fn create_secret() {
        let secret = GoogleAuthenticator::new(6u8).create_secret(32);
        println!("{:?}",secret);
        assert_eq!(secret.len(),32);
    }
}
