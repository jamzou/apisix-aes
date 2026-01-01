# aes-128加解密动态库
## 背景
apisix的lua插件中，使用openresty的库根本不支持aes-ecb加密。其中两个库resty.aes,resty.openssl.cipher都是有bug

1. resty.aes有bug，它的aes-ecb根本是不标准的，不知道它里面的实现是如何的
2. resty.openssl.cipher则是会莫名其妙的报错，有可能是不支持ecb加解密。

apisix容器里面的openssl执行aes-ecb加解密倒是正确的，AI会给你最终的方案是用命令行调用openssl来获取结果，但是这样太麻烦了，性能不高

## 解决方案
openresty的库尝试无果后，决定自己用rust写一个动态库，生成.so文件，然后在lua脚本中使用ffi调用动态库来实现aes-ecb加解密

## 运行和打包
测试：
```bash
cargo test
#带输出test
cargo test -- --nocapture
```
打包：
```bash
cargo build --release
```

常见问题：
1. 打包出来的动态库，在linux上运行会报错：
```text
2026/01/01 08:32:38 [error] 106#106: *84832 lua entry thread aborted: runtime error: /usr/local/apisix/apisix/plugins/aes_with_rust.lua:13: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by /usr/local/apisix/libapisix_aes.so)
stack traceback:
coroutine 0:
        [C]: in function 'dofile'
        /usr/local/apisix/apisix/plugins/auth-by-cluster.lua:71: in function 'phase_func'
        /usr/local/apisix/apisix/plugin.lua:1192: in function 'run_plugin'
        /usr/local/apisix/apisix/init.lua:788: in function 'http_access_phase
```
解答：这是因为运行时环境的glibc版本低于2.33，需要将动态库打包成静态库，或者将运行环境升级到2.以上


#### 第一步：查看目标平台glibc版本
```bash
docker run --rm -it apache/apisix:3.14.0-debian bash
# 在容器内执行
/lib/x86_64-linux-gnu/libc.so.6
# 或
getconf GNU_LIBC_VERSION
# 或
ldd --version
```
#### 第二步：使用cargo-zigbuild来编译目标glibc版本
```bash
#安装zig
sudo apt install zig
#或者先去官网下载，国内下载较慢，自己想办法找梯子，再配置环境变量
wget https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz
tar -xf zig-x86_64-linux-0.15.2.tar.xz
vi ~/.bashrc
#末尾加上这一行
export PATH=$PATH:/home/jamzou/zig/zig-x86_64-linux-0.15.2
source ~/.bashrc
#测试zig安装是否成功
zig version
#安装cargo-zigbuild
cargo install cargo-zigbuild
# 编译兼容 glibc 2.31（Debian 11 (Bullseye)）
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.31
```
这个 .so 就可以在apisix:3.14.0-debian容器运行了



#### 补充：

| 发行版               | glibc 版本 |
| -------------------- | ---------- |
| Debian 11 (Bullseye) | 2.31       |
| Debian 12 (Bookworm) | 2.36       |
| Ubuntu 22.04         | 2.35       |
| CentOS 7             | 2.17       |

## 测试.so文件是否可用
**1. 编写c程序，test_apisix_aes.c**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>  // 动态加载库所需头文件

// 定义与 Rust 函数匹配的函数指针类型
typedef char* (*Aes128EcbEncryptFunc)(const char*, const char*);
typedef char* (*Aes128EcbDecryptFunc)(const char*, const char*);
typedef void (*FreeBufferFunc)(char*);

int main() {
    // 1. 加载动态库
    void* lib_handle = dlopen("./libapisix_aes.so", RTLD_LAZY);
    if (!lib_handle) {
        fprintf(stderr, "无法加载动态库: %s\n", dlerror());
        return 1;
    }

    // 2. 获取函数指针（绑定 Rust 暴露的函数）
    Aes128EcbEncryptFunc aes128_ecb_encrypt = (Aes128EcbEncryptFunc)dlsym(lib_handle, "aes128_ecb_encrypt");
    Aes128EcbDecryptFunc aes128_ecb_decrypt = (Aes128EcbDecryptFunc)dlsym(lib_handle, "aes128_ecb_decrypt");
    FreeBufferFunc free_buffer = (FreeBufferFunc)dlsym(lib_handle, "free_buffer");

    // 检查函数是否加载成功
    char* err;
    if ((err = dlerror()) != NULL) {
        fprintf(stderr, "获取函数失败: %s\n", err);
        dlclose(lib_handle);
        return 1;
    }

    // 3. 测试数据（与 Rust 测试用例一致的明文和 16 字节 16 进制密钥）
    const char* plaintext = "hello";          // 待加密明文
    const char* key_hex = "461595e4bdb090ce41e7818287954d86";  // 16字节（32位16进制）密钥

    // 4. 执行加密
    printf("=== 开始 AES-128-ECB 加密测试 ===\n");
    char* ciphertext = aes128_ecb_encrypt(plaintext, key_hex);
    if (ciphertext == NULL || strlen(ciphertext) == 0) {
        fprintf(stderr, "加密失败，返回空值\n");
        free_buffer(ciphertext);
        dlclose(lib_handle);
        return 1;
    }
    printf("明文: %s\n", plaintext);
    printf("加密结果(二进制转16进制): ");
    // 修复：提前声明循环变量 i，兼容 C89 标准
    int i;  // 把变量声明移到循环外
    for (i = 0; i < strlen(ciphertext); i++) {
        printf("%02x", (unsigned char)ciphertext[i]);
    }
    printf("\n");

    // 5. 执行解密
    printf("\n=== 开始 AES-128-ECB 解密测试 ===\n");
    char* decrypted_text = aes128_ecb_decrypt(ciphertext, key_hex);
    if (decrypted_text == NULL || strlen(decrypted_text) == 0) {
        fprintf(stderr, "解密失败，返回空值\n");
        free_buffer(ciphertext);
        free_buffer(decrypted_text);
        dlclose(lib_handle);
        return 1;
    }
    printf("解密结果: %s\n", decrypted_text);

    // 6. 验证解密结果是否与原明文一致
    if (strcmp(decrypted_text, plaintext) == 0) {
        printf("\n✅ 测试成功：解密结果与原明文一致！\n");
    } else {
        printf("\n❌ 测试失败：解密结果与原明文不一致！\n");
    }

    // 7. 释放 Rust 分配的内存（必须调用，避免内存泄漏）
    free_buffer(ciphertext);
    free_buffer(decrypted_text);

    // 8. 关闭动态库
    dlclose(lib_handle);

    return 0;
}
```

**2. 编译和测试**

```bash
# 将test_aes.c和libapisix_aes.so放到同一个文件夹中
gcc test_apisix_aes.c -o test_apisix_aes -ldl -Wall
# 运行
./test_apisix_aes
# 输出如下
# [root@192 apisix]# ./test_apisix_aes
# === 开始 AES-128-ECB 加密测试 ===
# key_hex_str len is 32
# encrypted string hex: 0394f83fbde4a1738410e6337b7fac39
# 明文: hello
# 加密结果(二进制转16进制): 0394f83fbde4a1738410e6337b7fac39
# 
# === 开始 AES-128-ECB 解密测试 ===
# 解密结果: hello
# 
# ✅ 测试成功：解密结果与原明文一致！
```

- `-ldl`：链接动态加载库（必须，否则无法调用 `dlopen/dlsym`）
- `-Wall`：显示警告信息，方便排查问题