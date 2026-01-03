use crate::init_buf_size;
use aes::cipher::KeyInit;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use aes::{Aes128Dec, Aes128Enc};
use base64::prelude::*;
///aes加密，并返回base64加密后的
#[allow(unused)]
pub fn my_aes_encrypt(plaintext: &str, key: &str) -> String {
    // 注意key的类型
    // let key1 = GenericArray::from([0u8; 16]);
    // let plaintext = *b"hello world! this is my plaintext.";
    let pt_len = plaintext.len();

    let enc_cipher = Aes128Enc::new_from_slice(key.as_bytes()).unwrap();
    // in-place
    // 注意这里的长度是 ((pt_len + 15)/16) * 16
    // 不然会panic
    let buf_len = init_buf_size(pt_len);
    let mut ct_buf = vec![0u8; buf_len];
    let res = enc_cipher
        .encrypt_padded_b2b_mut::<Pkcs7>(plaintext.as_bytes(), &mut ct_buf)
        .unwrap();
    BASE64_STANDARD.encode(res)
}
#[allow(unused)]
pub fn my_aes_decrypt(ciphertext: &str, key: &str) -> String {
    let dec_cipher = Aes128Dec::new_from_slice(key.as_bytes());
    if dec_cipher.is_err() {
        return "".to_owned();
    }
    let dec_cipher = dec_cipher.unwrap();
    let b64_res = BASE64_STANDARD.decode(ciphertext);
    if b64_res.is_err() {
        return "".to_owned();
    }
    let ciphertext = b64_res.unwrap();
    let mut dec_buf = vec![0u8; ciphertext.len()];
    let res = dec_cipher
        .decrypt_padded_b2b_mut::<Pkcs7>(&ciphertext, &mut dec_buf)
        .unwrap();
    String::from_utf8(res.to_vec()).unwrap_or("".to_owned())
}
