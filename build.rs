fn main() {
    println!("cargo:rustc-link-search=native=/opt/homebrew/opt/openssl@3/lib");
    println!("cargo:rustc-link-lib=static=ssl");
    println!("cargo:rustc-link-lib=static=crypto");
    
    // 시스템에 따라 다른 라이브러리 경로 설정
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }
} 