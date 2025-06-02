//! Build script for AeroNyx crypto library
//! Configures platform-specific build settings

use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    
    // Platform-specific configuration
    match target_os.as_str() {
        "windows" => {
            configure_windows(&target);
        }
        "macos" => {
            configure_macos(&target);
        }
        "ios" => {
            configure_ios(&target);
        }
        "android" => {
            configure_android(&target);
        }
        "linux" => {
            configure_linux(&target);
        }
        _ => {
            println!("cargo:warning=Unsupported target OS: {}", target_os);
        }
    }
    
    // Generate version information
    generate_version_info();
}

fn configure_windows(target: &str) {
    println!("cargo:rerun-if-changed=build.rs");
    
    // Link Windows system libraries
    println!("cargo:rustc-link-lib=advapi32");
    println!("cargo:rustc-link-lib=crypt32");
    println!("cargo:rustc-link-lib=kernel32");
    println!("cargo:rustc-link-lib=user32");
    
    // Enable Windows-specific features
    println!("cargo:rustc-cfg=feature=\"windows_secure_storage\"");
    
    // Set Windows SDK paths if needed
    if target.contains("msvc") {
        // MSVC-specific settings
        println!("cargo:rustc-link-arg=/NXCOMPAT");
        println!("cargo:rustc-link-arg=/DYNAMICBASE");
        println!("cargo:rustc-link-arg=/LARGEADDRESSAWARE");
    }
    
    // Embed Windows resources
    #[cfg(windows)]
    {
        use winres::WindowsResource;
        WindowsResource::new()
            .set_icon("resources/aeronyx.ico")
            .set("ProductName", "AeroNyx Crypto")
            .set("FileDescription", "Cryptographic library for AeroNyx DePIN network")
            .set("LegalCopyright", "Copyright © 2025 AeroNyx Team")
            .compile()
            .unwrap();
    }
}

fn configure_macos(target: &str) {
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
    
    if target.contains("ios") {
        println!("cargo:rustc-link-lib=framework=UIKit");
    } else {
        println!("cargo:rustc-link-lib=framework=AppKit");
    }
    
    // Enable macOS-specific features
    println!("cargo:rustc-cfg=feature=\"macos_keychain\"");
}

fn configure_ios(_target: &str) {
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=UIKit");
    
    // Enable iOS-specific features
    println!("cargo:rustc-cfg=feature=\"ios_keychain\"");
}

fn configure_android(_target: &str) {
    // Android-specific configuration
    println!("cargo:rustc-link-lib=log");
    println!("cargo:rustc-link-lib=android");
    
    // Enable Android-specific features
    println!("cargo:rustc-cfg=feature=\"android_keystore\"");
}

fn configure_linux(_target: &str) {
    // Linux-specific configuration
    println!("cargo:rustc-link-lib=crypto");
    
    // Check for libsecret availability
    if pkg_config::probe_library("libsecret-1").is_ok() {
        println!("cargo:rustc-cfg=feature=\"linux_secret_service\"");
    }
}

fn generate_version_info() {
    // Get version from Cargo.toml
    let version = env!("CARGO_PKG_VERSION");
    
    // Get git commit hash if available
    let git_hash = std::process::Command::new("git")
        .args(&["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    // Get build timestamp
    let timestamp = chrono::Utc::now().to_rfc3339();
    
    // Export as environment variables for use in the code
    println!("cargo:rustc-env=AERONYX_VERSION={}", version);
    println!("cargo:rustc-env=AERONYX_GIT_HASH={}", git_hash);
    println!("cargo:rustc-env=AERONYX_BUILD_TIME={}", timestamp);
}
