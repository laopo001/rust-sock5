fn main() {
    use aes_gcm::aead::{Aead, NewAead};
    use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`

    let key = Key::from_slice(b"12312313123123123123131231231231");
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let data = b"plaintext message";
    dbg!(&data.len());
    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
    dbg!(&ciphertext);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!"); // NOTE: handle this error to avoid panics!
    dbg!(&String::from_utf8(plaintext.clone()).unwrap());

    // assert_eq!(&plaintext, b"plaintext message");
}
