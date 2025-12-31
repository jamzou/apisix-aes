use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, block_padding::Pkcs7};
use std::ffi::CStr;
use std::os::raw::c_char;

type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        // 创建包含 "hello" 的 C 字符串
        let plaintext_cstr = std::ffi::CString::new("hello").unwrap();
        let key_cstr = std::ffi::CString::new("461595e4bdb090ce41e7818287954d86").unwrap();

        let plaintext: *const c_char = plaintext_cstr.as_ptr();
        let key_hex: *const c_char = key_cstr.as_ptr();
        println!("Starting encryption test...");
        let pt = aes128_ecb_encrypt(plaintext, key_hex);
        // 将返回的指针转换为 CStr，然后输出16进制
        if !pt.is_null() {
            unsafe {
                let c_str = CStr::from_ptr(pt);
                let bytes = c_str.to_bytes();

                // 输出16进制字符
                print!("Encrypted result in hex: ");
                for byte in bytes {
                    print!("{:02x}", byte);
                }
                println!();

                // 释放内存
                free_buffer(pt);
            }
        } else {
            println!("Encryption failed, returned null pointer");
        }
    }
}

// 辅助：将 *const c_char 转为 &[u8]
unsafe fn c_str_to_bytes(s: *const c_char) -> Vec<u8> {
    if s.is_null() {
        return Vec::new();
    }
    unsafe {
        let cstr = CStr::from_ptr(s);
        cstr.to_bytes().to_vec()
    }
}

// 辅助：将 &[u8] 转为 CString（带 null 结尾）
fn bytes_to_cstring(data: &[u8]) -> *mut c_char {
    let mut vec = data.to_vec();
    vec.push(0); // null terminator
    let boxed = vec.into_boxed_slice();
    Box::into_raw(boxed) as *mut c_char
}

#[unsafe(no_mangle)]
pub extern "C" fn aes128_ecb_encrypt(
    plaintext: *const c_char,
    key_hex: *const c_char,
) -> *mut c_char {
    let key_hex_str: Vec<u8> = unsafe { c_str_to_bytes(key_hex) };
    let pt: Vec<u8> = unsafe { c_str_to_bytes(plaintext) };

    // 解析 hex key
    println!("key_hex_str len is {}", key_hex_str.len());
    let key = hex::decode(&key_hex_str).unwrap_or_default();
    if key.len() != 16 {
        return bytes_to_cstring(b"");
    }
    //buf需要是16的倍数
    let init_size = init_buf_size(pt.len());
    let mut buf = vec![0u8; init_size];
    // 加密
    let err_ct: Vec<u8> = vec![];
    let ct = Aes128EcbEnc::new(key.as_slice().into())
        .encrypt_padded_b2b_mut::<Pkcs7>(&pt, &mut buf)
        .unwrap_or(&err_ct);
    println!("encrypted string hex: {}", hex::encode(ct));
    bytes_to_cstring(&ct)
}

fn init_buf_size(p_len: usize) -> usize {
    let init_size = if p_len % 16 == 0 {
        p_len + 16
    } else {
        p_len + 16 - (p_len % 16)
    };
    init_size
}

#[unsafe(no_mangle)]
pub extern "C" fn aes128_ecb_decrypt(
    ciphertext: *const c_char,
    key_hex: *const c_char,
) -> *mut c_char {
    let ct: Vec<u8> = unsafe { c_str_to_bytes(ciphertext) };
    let key_hex_str: Vec<u8> = unsafe { c_str_to_bytes(key_hex) };

    let key = hex::decode(&key_hex_str).unwrap_or_default();
    if key.len() != 16 {
        return bytes_to_cstring(b"ERR_KEY_LEN");
    }
    let mut buf = vec![0u8; ct.len()];
    let pt_err: Vec<u8> = vec![];
    let pt = Aes128EcbDec::new(key.as_slice().into())
        .decrypt_padded_b2b_mut::<Pkcs7>(ct.as_slice(), &mut buf)
        .unwrap_or(&pt_err);
    bytes_to_cstring(pt)
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
