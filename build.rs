@echo off
REM Build script for AeroNyx Rust Crypto library on Windows

echo Building AeroNyx Crypto for Windows...
echo.

REM Check for Rust installation
where cargo >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: Rust/Cargo not found in PATH
    echo Please install Rust from https://rustup.rs/
    exit /b 1
)

REM Set environment variables
set RUST_BACKTRACE=1
set CARGO_INCREMENTAL=0

REM Clean previous builds
echo Cleaning previous builds...
cargo clean

REM Build for Windows x86_64
echo.
echo Building for x86_64-pc-windows-msvc...
cargo build --release --target x86_64-pc-windows-msvc
if %ERRORLEVEL% NEQ 0 (
    echo Build failed for x86_64-pc-windows-msvc
    exit /b 1
)

REM Build for Windows ARM64 (if toolchain is installed)
echo.
echo Checking for ARM64 toolchain...
rustup target list --installed | findstr "aarch64-pc-windows-msvc" >nul
if %ERRORLEVEL% EQU 0 (
    echo Building for aarch64-pc-windows-msvc...
    cargo build --release --target aarch64-pc-windows-msvc
    if %ERRORLEVEL% NEQ 0 (
        echo Build failed for aarch64-pc-windows-msvc
        exit /b 1
    )
) else (
    echo ARM64 toolchain not installed, skipping ARM64 build
    echo To install: rustup target add aarch64-pc-windows-msvc
)

REM Create output directory
echo.
echo Creating output directory...
if not exist "output\windows" mkdir "output\windows"

REM Copy built libraries
echo Copying libraries...
copy "target\x86_64-pc-windows-msvc\release\aeronyx_crypto.dll" "output\windows\aeronyx_crypto_x64.dll" >nul
copy "target\x86_64-pc-windows-msvc\release\aeronyx_crypto.dll.lib" "output\windows\aeronyx_crypto_x64.lib" >nul

if exist "target\aarch64-pc-windows-msvc\release\aeronyx_crypto.dll" (
    copy "target\aarch64-pc-windows-msvc\release\aeronyx_crypto.dll" "output\windows\aeronyx_crypto_arm64.dll" >nul
    copy "target\aarch64-pc-windows-msvc\release\aeronyx_crypto.dll.lib" "output\windows\aeronyx_crypto_arm64.lib" >nul
)

REM Generate C header file
echo.
echo Generating C header file...
cbindgen --config cbindgen.toml --crate aeronyx-crypto --output output/windows/aeronyx_crypto.h

echo.
echo Build complete!
echo Output files are in: output\windows\
echo.
echo Files generated:
dir /b output\windows\
