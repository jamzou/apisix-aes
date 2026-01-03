use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, block_padding::Pkcs7};
use base64::prelude::*;
use md5::{Digest, Md5};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
mod myaes;

type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_my_aes() {
        // let k1 = "1234567812345678";
        // let key_test = GenericArray::from_slice(k1.as_bytes());
        // let key_test:GenericArray<u8, U16> = GenericArray::from_slice(k1.as_bytes()).clone();
        let plaintext = "ehomeehomeehome1";
        let key = "1234567812345678";
        let ciphertext = myaes::my_aes_encrypt(plaintext, key);
        println!("ciphertext: {}", ciphertext);
        let decrypted_text = myaes::my_aes_decrypt(&ciphertext, key);
        println!("decrypted_text: {}", decrypted_text);
        assert_eq!(plaintext, decrypted_text);

        let source_cstring = CString::new(plaintext.to_owned()).unwrap();
        let cstr_source = source_cstring.as_ptr();
        let key_cstring = CString::new(key.to_owned()).unwrap();
        let cstr_key = key_cstring.as_ptr();

        let encrypted_res = ehome_aes_encrypt_for_eim(cstr_source, cstr_key);
        let char_u8 = mut_ptr_to_u8(encrypted_res);
        let s = String::from_utf8(char_u8).unwrap();
        println!("ciphertext 222: {}", s);
        assert_eq!(ciphertext, s);
    }

    #[test]
    fn ehome_aes_encrypt_decrypt() {
        let source = "helloworld";
        let key = "1234567812345678";
        let source_cstring = CString::new(source.to_owned()).unwrap();
        let cstr_source = source_cstring.as_ptr();
        let key_cstring = CString::new(key.to_owned()).unwrap();
        let cstr_key = key_cstring.as_ptr();

        let encrypted_res = ehome_aes_encrypt(cstr_source, cstr_key);
        let decrypted_res = ehome_aes_decrypt(encrypted_res, cstr_key);
        let decrypted_num_vec = mut_ptr_to_u8(decrypted_res);
        assert_eq!(source.as_bytes(), decrypted_num_vec.as_slice());
        free_buffer(encrypted_res);
        free_buffer(decrypted_res);
    }

    #[test]
    fn aes128_ecb_encrypt_decrypt() {
        // 创建包含 "hello" 的 C 字符串
        let source = "hello world";
        let plaintext_cstr = CString::new(source.to_owned()).unwrap();
        let key_cstr = CString::new("461595e4bdb090ce41e7818287954d86").unwrap();

        let plaintext: *const c_char = plaintext_cstr.as_ptr();
        let key_hex: *const c_char = key_cstr.as_ptr();
        println!("Starting encryption test...");
        let pt = aes128_ecb_encrypt(plaintext, key_hex);
        // 将返回的指针转换为 CStr，然后输出16进制
        assert_eq!(pt.is_null(), false);

        unsafe {
            let c_str = CStr::from_ptr(pt);
            let bytes = c_str.to_bytes();
            // 输出16进制字符
            print!("Encrypted result in hex: {}", const_hex::encode(bytes));
            //解密
            let ciphertext = std::ffi::CString::new(bytes).unwrap();
            let ct_ptr = ciphertext.as_ptr();
            let decrypted_source = aes128_ecb_decrypt(ct_ptr, key_hex);
            let decrypted_num_vec = mut_ptr_to_u8(decrypted_source);
            assert_eq!(decrypted_num_vec.as_slice(), source.as_bytes());
            // 释放内存
            free_buffer(pt);
            free_buffer(decrypted_source);
        }
    }

    #[test]
    fn eim_aes_encrypt_decrypt() {
        let source = "helloworld";
        let key = "1234567812345678";
        let source_cstring = CString::new(source.to_owned()).unwrap();
        let cstr_source = source_cstring.as_ptr();
        let key_cstring = CString::new(key.to_owned()).unwrap();
        let cstr_key = key_cstring.as_ptr();

        let encrypted_res = ehome_aes_encrypt_for_eim(cstr_source, cstr_key);
        let decrypted_res = ehome_aes_decrypt_for_eim(encrypted_res, cstr_key);
        let decrypted_num_vec = mut_ptr_to_u8(decrypted_res);
        assert_eq!(source.as_bytes(), decrypted_num_vec.as_slice());
        free_buffer(encrypted_res);
        free_buffer(decrypted_res);
    }

    fn mut_ptr_to_u8(c_str: *mut i8) -> Vec<u8> {
        let mut num_vec = vec![];
        let mut i = 0;
        unsafe {
            loop {
                let n = *c_str.add(i) as u8;
                if n == b'\0' {
                    break;
                } else {
                    num_vec.push(n);
                }
                i += 1;
            }
        }
        num_vec
    }
}

// 辅助：将 *const c_char 转为 &[u8]
unsafe fn c_str_to_bytes(s: *const c_char) -> Vec<u8> {
    if s.is_null() {
        return Vec::new();
    }
    unsafe { CStr::from_ptr(s).to_bytes().to_vec() }
}

// 辅助：将 &[u8] 转为 CString（带 null 结尾）
fn bytes_to_cstring(data: &[u8]) -> *mut c_char {
    match CString::new(data) {
        Ok(c_string) => c_string.into_raw(), // 直接转换为 *mut c_char
        Err(_) => std::ptr::null_mut(),      // 处理包含 null 字节的情况
    }
}

/// 核心加密函数
/// pt 为明文，key 为密钥
/// 返回值：加密后的密文，失败返回空
fn aes128_encrypt_core(pt: &[u8], key: &[u8]) -> Vec<u8> {
    if key.len() != 16 {
        return Vec::new();
    }
    let init_size = init_buf_size(pt.len());
    let mut buf = vec![0u8; init_size];
    let ct = Aes128EcbEnc::new(key.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(&pt, &mut buf)
        .unwrap_or(b"");
    ct.to_owned()
}

#[unsafe(no_mangle)]
pub extern "C" fn aes128_ecb_encrypt(
    plaintext: *const c_char,
    key_hex: *const c_char,
) -> *mut c_char {
    let key_hex_str: Vec<u8> = unsafe { c_str_to_bytes(key_hex) };
    let pt: Vec<u8> = unsafe { c_str_to_bytes(plaintext) };
    let key = const_hex::decode(&key_hex_str).unwrap_or_default();
    let ct = aes128_encrypt_core(&pt, &key);
    println!("encrypted string hex: {}", const_hex::encode(&ct));
    bytes_to_cstring(&ct)
}

#[unsafe(no_mangle)]
pub extern "C" fn aes128_ecb_decrypt(
    ciphertext: *const c_char,
    key_hex: *const c_char,
) -> *mut c_char {
    let ct: Vec<u8> = unsafe { c_str_to_bytes(ciphertext) };
    let key_hex_str: Vec<u8> = unsafe { c_str_to_bytes(key_hex) };
    let key = const_hex::decode(&key_hex_str).unwrap_or_default();
    let pt = aes128_decrypt_core(&ct, &key);
    bytes_to_cstring(&pt)
}

/// ehome_aes_encrypt
/// 先将字符串key转为md5，然后用md5的16字节作为key进行aes128-ecb加密
/// 加密成功返回base64字符串，加密失败返回空字符串
#[unsafe(no_mangle)]
pub extern "C" fn ehome_aes_encrypt(plaintext: *const c_char, key: *const c_char) -> *mut c_char {
    let pt: Vec<u8> = unsafe { c_str_to_bytes(plaintext) };
    let key_str = unsafe { c_str_to_bytes(key) };
    let mut hasher = Md5::new();
    hasher.update(&key_str);
    let key_md5 = hasher.finalize();
    let ct = aes128_encrypt_core(&pt, &key_md5[..]);
    let b64 = BASE64_STANDARD.encode(ct);
    bytes_to_cstring(b64.as_bytes())
}

/// ehome_aes_decrypt
/// 用key进行md5, ciphertext进行base64解码，再用aes128-ecb解密
#[unsafe(no_mangle)]
pub extern "C" fn ehome_aes_decrypt(ciphertext: *const c_char, key: *const c_char) -> *mut c_char {
    let ct: Vec<u8> = unsafe { c_str_to_bytes(ciphertext) };
    let key_str = unsafe { c_str_to_bytes(key) };
    let mut hasher = Md5::new();
    hasher.update(&key_str);
    let key_md5 = hasher.finalize();
    let ct_b64 = BASE64_STANDARD.decode(&ct).unwrap_or_default();
    let plain_text = aes128_decrypt_core(&ct_b64, &key_md5[..]);
    bytes_to_cstring(&plain_text)
}

/// ehome_aes_encrypt
/// 用16字节的key进行aes128-ecb加密
/// 加密成功返回base64字符串，加密失败返回空字符串
#[unsafe(no_mangle)]
pub extern "C" fn ehome_aes_encrypt_for_eim(
    plaintext: *const c_char,
    key: *const c_char,
) -> *mut c_char {
    let pt: Vec<u8> = unsafe { c_str_to_bytes(plaintext) };
    let key_str: Vec<u8> = unsafe { c_str_to_bytes(key) };
    let ct = aes128_encrypt_core(&pt, &key_str);
    let b64 = BASE64_STANDARD.encode(ct);
    bytes_to_cstring(b64.as_bytes())
}

/// ehome_aes_decrypt
/// 用16字节的key, ciphertext经过base64解码，进行aes128-ecb解密
/// 解密成功返回字符串，解密失败返回空字符串
#[unsafe(no_mangle)]
pub extern "C" fn ehome_aes_decrypt_for_eim(
    ciphertext: *const c_char,
    key: *const c_char,
) -> *mut c_char {
    let ct: Vec<u8> = unsafe { c_str_to_bytes(ciphertext) };
    let key_str = unsafe { c_str_to_bytes(key) };

    let ct_b64 = BASE64_STANDARD.decode(&ct).unwrap_or_default();
    let plain_text = aes128_decrypt_core(&ct_b64, &key_str);
    bytes_to_cstring(&plain_text)
}

fn init_buf_size(p_len: usize) -> usize {
    let init_size = if p_len % 16 == 0 {
        p_len + 16
    } else {
        p_len + 16 - (p_len % 16)
    };
    init_size
}

fn aes128_decrypt_core(ct: &[u8], key: &[u8]) -> Vec<u8> {
    if key.len() != 16 {
        return Vec::new();
    }
    let mut buf = vec![0u8; ct.len()];
    let pt = Aes128EcbDec::new(key.into())
        .decrypt_padded_b2b_mut::<Pkcs7>(ct, &mut buf)
        .unwrap_or(b"");
    pt.to_owned()
}

// 注意：Lua 需要负责释放返回的内存（或我们设计成不释放，由 Rust 管理）
// 更安全的做法是让 Lua 传入 buffer，但为简单起见，这里返回新分配内存
#[unsafe(no_mangle)]
pub extern "C" fn free_buffer(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr));
        }
    }
}
