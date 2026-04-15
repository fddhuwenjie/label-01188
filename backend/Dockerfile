# 多阶段构建 - 支持 ARM64 和 AMD64 架构
# 构建阶段
FROM --platform=$BUILDPLATFORM alpine:3.19 AS builder

# 安装编译工具
RUN apk add --no-cache \
    g++ \
    make \
    musl-dev

# 设置工作目录
WORKDIR /app

# 复制源代码
COPY main.cpp *.h ./

# 编译程序 - 静态链接以确保跨平台兼容性
RUN g++ -O3 -std=c++17 -static -o cipher_cracker main.cpp

# 运行阶段 - 使用最小化镜像
FROM --platform=$TARGETPLATFORM alpine:3.19

# 添加必要的运行时库
RUN apk add --no-cache libstdc++

# 创建非root用户
RUN adduser -D -u 1000 appuser

# 设置工作目录
WORKDIR /app

# 从构建阶段复制编译好的程序
COPY --from=builder /app/cipher_cracker .

# 设置文件权限
RUN chmod +x cipher_cracker && chown appuser:appuser cipher_cracker

# 切换到非root用户
USER appuser

# 运行程序
CMD ["./cipher_cracker"]
