@echo off
chcp 65001 >nul
echo 开始编译 ProxyApiExplorer 多平台版本...
echo.

:: 设置程序名称
set PROGRAM_NAME=ProxyApiExplorer

:: 创建输出目录
if not exist "builds" mkdir builds

:: 编译 Windows x86 (32位)
echo 编译 Windows x86 (32位)...
set GOOS=windows
set GOARCH=386
go build -o builds/%PROGRAM_NAME%-windows-x86.exe %PROGRAM_NAME%.go
if %errorlevel% equ 0 (
    echo ✓ Windows x86 编译成功
) else (
    echo ✗ Windows x86 编译失败
)

:: 编译 Windows amd64 (64位)
echo 编译 Windows amd64 (64位)...
set GOOS=windows
set GOARCH=amd64
go build -o builds/%PROGRAM_NAME%-windows-amd64.exe %PROGRAM_NAME%.go
if %errorlevel% equ 0 (
    echo ✓ Windows amd64 编译成功
) else (
    echo ✗ Windows amd64 编译失败
)

:: 编译 Linux x86 (32位)
echo 编译 Linux x86 (32位)...
set GOOS=linux
set GOARCH=386
go build -o builds/%PROGRAM_NAME%-linux-x86 %PROGRAM_NAME%.go
if %errorlevel% equ 0 (
    echo ✓ Linux x86 编译成功
) else (
    echo ✗ Linux x86 编译失败
)

:: 编译 Linux amd64 (64位)
echo 编译 Linux amd64 (64位)...
set GOOS=linux
set GOARCH=amd64
go build -o builds/%PROGRAM_NAME%-linux-amd64 %PROGRAM_NAME%.go
if %errorlevel% equ 0 (
    echo ✓ Linux amd64 编译成功
) else (
    echo ✗ Linux amd64 编译失败
)

:: 编译 Linux ARM v7 (32位)
echo 编译 Linux ARM v7 (32位)...
set GOOS=linux
set GOARCH=arm
set GOARM=7
go build -o builds/%PROGRAM_NAME%-linux-armv7 %PROGRAM_NAME%.go
if %errorlevel% equ 0 (
    echo ✓ Linux ARM v7 编译成功
) else (
    echo ✗ Linux ARM v7 编译失败
)

:: 编译 Linux ARM64 v8 (64位)
echo 编译 Linux ARM64 v8 (64位)...
set GOOS=linux
set GOARCH=arm64
go build -o builds/%PROGRAM_NAME%-linux-armv8 %PROGRAM_NAME%.go
if %errorlevel% equ 0 (
    echo ✓ Linux ARM64 v8 编译成功
) else (
    echo ✗ Linux ARM64 v8 编译失败
)

:: 重置环境变量
set GOOS=
set GOARCH=
set GOARM=

echo.
echo 编译完成！查看 builds 目录获取所有平台的可执行文件。
echo.
echo 生成的文件：
dir builds /b
echo.
pause