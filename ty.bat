@echo off
REM ty — Windows build / test / clean helper
REM Note: flooding and sniffing require WSL2 or a Linux VM — raw sockets
REM are not available on Windows without a kernel driver.

setlocal EnableDelayedExpansion

set BINARY=ty.exe
set PROJECT_DIR=%~dp0

if "%1"=="" goto :usage
if "%1"=="help" goto :usage
if "%1"=="build" goto :build
if "%1"=="build-debug" goto :build_debug
if "%1"=="test" goto :test
if "%1"=="clean" goto :clean
if "%1"=="check-deps" goto :check_deps
if "%1"=="lint" goto :lint

echo Unknown command: %1
goto :usage

:usage
echo.
echo ty — IPv6 Toolkit Windows helper
echo.
echo Usage: ty.bat ^<command^>
echo.
echo Commands:
echo   build        Build Rust frontend in release mode
echo   build-debug  Build Rust frontend in debug mode
echo   test         Run Rust unit tests
echo   lint         Run clippy + rustfmt check
echo   clean        Remove build artefacts
echo   check-deps   Check required tools
echo   help         Show this help
echo.
echo Note: Raw socket operations (flooding, sniffing) require Linux.
echo       Use WSL2 or a Linux VM for network attack tools.
echo.
goto :eof

:build
echo Building ty (release)...
cargo build --release
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)
echo Build complete: target\release\%BINARY%
goto :eof

:build_debug
echo Building ty (debug)...
cargo build
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)
echo Debug build: target\debug\%BINARY%
goto :eof

:test
echo Running unit tests...
cargo test --lib -- --test-threads=4
if errorlevel 1 (
    echo Tests failed.
    exit /b 1
)
echo All tests passed.
goto :eof

:lint
echo Running clippy...
cargo clippy --all-targets -- -D warnings
if errorlevel 1 (
    echo Clippy failed.
    exit /b 1
)
echo Running rustfmt check...
cargo fmt --check
if errorlevel 1 (
    echo Format check failed. Run: cargo fmt
    exit /b 1
)
echo Lint passed.
goto :eof

:clean
echo Cleaning...
cargo clean
echo Clean.
goto :eof

:check_deps
echo Checking dependencies...
where cargo >nul 2>&1
if errorlevel 1 (
    echo [MISSING] cargo -- install Rust from https://rustup.rs
) else (
    for /f "tokens=*" %%v in ('cargo --version') do echo [OK]    %%v
)
where cl >nul 2>&1
if errorlevel 1 (
    where gcc >nul 2>&1
    if errorlevel 1 (
        echo [INFO]   No C compiler found -- C tools require Linux / WSL2
    ) else (
        echo [OK]    gcc found
    )
) else (
    echo [OK]    MSVC cl found
)
echo.
echo For network tools: use WSL2 ^(wsl --install^) or a Linux VM.
goto :eof
