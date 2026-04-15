#!/bin/bash

# ============================================
# Docker 启动脚本
# 前提：已安装 Docker 和 Docker Compose
# ============================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查 Docker 是否可用
if ! command -v docker >/dev/null 2>&1; then
    print_error "未检测到 Docker，请先安装: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    print_error "Docker 未运行，请先启动 Docker Desktop 或 Docker 服务"
    exit 1
fi

# 检测 compose 命令
if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
else
    print_error "未检测到 Docker Compose，请参考: https://docs.docker.com/compose/install/"
    exit 1
fi

echo ""
echo "============================================"
echo "  古典密码破解程序"
echo "============================================"
echo ""

# 清理旧容器
$COMPOSE down 2>/dev/null || true

# 构建并运行
print_info "构建镜像..."
$COMPOSE build --no-cache

print_info "启动容器..."
$COMPOSE up -d

# 等待容器执行完成
print_info "等待程序执行..."
while [ "$(docker inspect -f '{{.State.Running}}' cipher-cracker 2>/dev/null)" = "true" ]; do
    sleep 1
done

# 显示结果
echo ""
echo "============================================"
print_success "运行结果"
echo "============================================"
echo ""
docker logs cipher-cracker

# 清理
$COMPOSE down 2>/dev/null || true
echo ""
print_success "完成"
