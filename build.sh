#!/bin/bash

echo "开始编译 ProxyApiExplorer 多平台版本..."
echo

# 设置程序名称
PROGRAM_NAME="ProxyApiExplorer"

# 创建输出目录
mkdir -p builds

# 编译函数
build_target() {
    local os=$1
    local arch=$2
    local arm_version=$3
    local output_name=$4
    
    echo "编译 $output_name..."
    
    if [ "$arch" = "arm" ] && [ -n "$arm_version" ]; then
        GOOS=$os GOARCH=$arch GOARM=$arm_version go build -o builds/${PROGRAM_NAME}-${output_name} ${PROGRAM_NAME}.go
    else
        GOOS=$os GOARCH=$arch go build -o builds/${PROGRAM_NAME}-${output_name} ${PROGRAM_NAME}.go
    fi
    
    if [ $? -eq 0 ]; then
        echo "✓ $output_name 编译成功"
        # 为Linux/macOS可执行文件添加执行权限
        if [ "$os" != "windows" ]; then
            chmod +x builds/${PROGRAM_NAME}-${output_name}
        fi
    else
        echo "✗ $output_name 编译失败"
    fi
    echo
}

# 编译各个平台
build_target "windows" "386" "" "windows-x86.exe"
build_target "windows" "amd64" "" "windows-amd64.exe"
build_target "linux" "386" "" "linux-x86"
build_target "linux" "amd64" "" "linux-amd64"
build_target "linux" "arm" "7" "linux-armv7"
build_target "linux" "arm64" "" "linux-armv8"

echo "编译完成！查看 builds 目录获取所有平台的可执行文件。"
echo
echo "生成的文件："
ls -la builds/
echo

# 显示文件大小
echo "文件大小统计："
du -h builds/*
echo