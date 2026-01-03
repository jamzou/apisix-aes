## mac下面如何打包
1. 先构建一个通用的linux-rust环境
使用Dockerfile构建环境
2. 进去容器里执行打包
```bash
podman run --rm -it -v /Users/zouyuejian/Documents/:/app localhost/rust-build-env:1.91-zig0.15.2
```