# 适配多架构的 Rust 1.91 基础镜像（ARM64/x86_64）
FROM rust:1.91-slim-bullseye

# ========== 1. 清理代理环境变量 + 配置阿里源（稳定无拦截） ==========
ENV http_proxy="" \
    https_proxy="" \
    HTTP_PROXY="" \
    HTTPS_PROXY="" \
    no_proxy="localhost,127.0.0.1,mirrors.aliyun.com"

# 替换为阿里源，保证基础依赖安装速度
RUN echo "deb http://mirrors.aliyun.com/debian/ bullseye main contrib non-free" > /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/debian/ bullseye-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/debian-security/ bullseye-security main contrib non-free" >> /etc/apt/sources.list

# ========== 2. Rust 环境变量 + 路径配置 ==========
ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    # 把 zig 路径加入系统 PATH
    PATH=/usr/local/cargo/bin:/usr/local/zig:$PATH \
    # Rust 国内源加速（rsproxy）
    RUSTUP_DIST_SERVER=https://rsproxy.cn \
    RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

# ========== 3. 安装基础依赖（仅必需项，无网络风险） ==========
RUN apt-get update -o Acquire::http::Timeout=120 -o Acquire::Retries=3 && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    zip unzip curl git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ========== 4. 拷贝本地 zig 安装包到镜像内并解压 ==========
# 第一步：拷贝本地的 zig-aarch64-linux-0.15.2.tar.xz 到镜像临时目录
COPY ./zig-aarch64-linux-0.15.2.tar.xz /tmp/zig.tar.xz

# 第二步：解压并安装 zig（指定路径，加入系统 PATH）
RUN mkdir -p /usr/local/zig && \
    tar -xJf /tmp/zig.tar.xz -C /usr/local/zig --strip-components=1 && \
    # 删除临时安装包，减小镜像体积
    rm -f /tmp/zig.tar.xz && \
    # 验证 zig 安装（关键：确认版本和架构匹配）
    zig version && \
    zig env | grep target

# ========== 5. 安装 cargo-zigbuild（依赖 Rust 国内源，速度快） ==========
RUN rm -rf /usr/local/cargo/config && \
    echo '[source.crates-io]' > /usr/local/cargo/config.toml && \
    echo 'replace-with = "rsproxy-sparse"' >> /usr/local/cargo/config.toml && \
    echo '[source.rsproxy-sparse]' >> /usr/local/cargo/config.toml && \
    echo 'registry = "sparse+https://rsproxy.cn/index/"' >> /usr/local/cargo/config.toml


RUN cargo install cargo-zigbuild
# ========== 6. 工作目录 + 权限配置（避免挂载后权限问题） ==========
RUN mkdir -p /app && chmod 777 /app
WORKDIR /app

# ========== 7. 最终验证所有工具 ==========
RUN echo "===== 工具版本验证 =====" && \
    rustc --version && \
    cargo --version && \
    zig version && \
    cargo-zigbuild --version && \
    echo "===== 架构验证 =====" && \
    uname -m && \
    rustc -vV | grep host && \
    zig env | grep target

# 启动容器后默认进入交互终端
CMD ["/bin/bash"]
