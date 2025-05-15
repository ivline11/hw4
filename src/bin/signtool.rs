use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process;
use std::path::Path;
use std::os::unix::io::AsRawFd;
use std::ffi::CString;

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use sha2::{Sha256, Digest};

// ELF 상수 정의
const EI_NIDENT: usize = 16;
const ET_EXEC: u16 = 2;
const PT_LOAD: u32 = 1;
const SHT_PROGBITS: u32 = 1;
const SHF_EXECINSTR: u32 = 0x4;

// 서명 섹션 이름
const SIGNATURE_SECTION_NAME: &str = ".signature";

#[repr(C)]
struct ElfHeader {
    e_ident: [u8; EI_NIDENT],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
struct ElfProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

#[repr(C)]
struct ElfSectionHeader {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <command> [options]", args[0]);
        eprintln!("Commands:");
        eprintln!("  sign -e <path to executable> -k <path to private_key.pem>");
        eprintln!("  verify -e <path to signed executable> -k <path to public_key.pem>");
        process::exit(1);
    }

    match args[1].as_str() {
        "sign" => {
            if args.len() != 6 || args[2] != "-e" || args[4] != "-k" {
                eprintln!("Usage: {} sign -e <path to executable> -k <path to private_key.pem>", args[0]);
                process::exit(1);
            }
            
            let executable_path = &args[3];
            let private_key_path = &args[5];
            
            // 출력 파일 경로 생성
            let output_path = format!("{}-signed", executable_path);
            
            if let Err(e) = sign_executable(executable_path, private_key_path, &output_path) {
                eprintln!("Error signing executable: {}", e);
                process::exit(1);
            }
        },
        "verify" => {
            if args.len() != 6 || args[2] != "-e" || args[4] != "-k" {
                eprintln!("Usage: {} verify -e <path to signed executable> -k <path to public_key.pem>", args[0]);
                process::exit(1);
            }
            
            let executable_path = &args[3];
            let public_key_path = &args[5];
            
            match verify_executable(executable_path, public_key_path) {
                Ok(result) => {
                    match result {
                        VerificationResult::Ok => println!("OK"),
                        VerificationResult::NotOk => println!("NOT_OK"),
                        VerificationResult::NotSigned => println!("NOT_SIGNED"),
                    }
                },
                Err(e) => {
                    eprintln!("Error verifying executable: {}", e);
                    process::exit(1);
                }
            }
        },
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            process::exit(1);
        }
    }
}

enum VerificationResult {
    Ok,
    NotOk,
    NotSigned,
}

// 실행 파일에 서명하는 함수
fn sign_executable(input_path: &str, private_key_path: &str, output_path: &str) -> io::Result<()> {
    // 입력 파일 읽기
    let input_data = fs::read(input_path)?;
    
    // ELF 헤더 검증
    if !is_valid_elf(&input_data) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid ELF file"));
    }
    
    // 출력 파일에 입력 파일 복사
    fs::copy(input_path, output_path)?;
    
    // 실행 코드 섹션 수집
    let executable_sections_data = collect_executable_sections(&input_data)?;
    
    // 해시 계산
    let mut hasher = Sha256::new();
    hasher.update(&executable_sections_data);
    let hash = hasher.finalize();
    
    // 개인키 로드
    let private_key_data = fs::read(private_key_path)?;
    let rsa = Rsa::private_key_from_pem(&private_key_data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("RSA key error: {}", e)))?;
    let private_key = PKey::from_rsa(rsa)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("PKey error: {}", e)))?;
    
    // 해시에 서명
    let mut signer = Signer::new(MessageDigest::sha256(), &private_key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signer error: {}", e)))?;
    signer.update(&hash)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing update error: {}", e)))?;
    let signature = signer.sign_to_vec()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing error: {}", e)))?;
    
    // 서명 섹션 추가
    add_signature_section(output_path, &signature)?;
    
    Ok(())
}

// 실행 파일 서명 검증 함수
fn verify_executable(input_path: &str, public_key_path: &str) -> io::Result<VerificationResult> {
    // 입력 파일 읽기
    let input_data = fs::read(input_path)?;
    
    // ELF 헤더 검증
    if !is_valid_elf(&input_data) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid ELF file"));
    }
    
    // 서명 섹션 추출
    let signature = match extract_signature_section(&input_data) {
        Ok(sig) => sig,
        Err(_) => return Ok(VerificationResult::NotSigned),
    };
    
    // 실행 코드 섹션 수집
    let executable_sections_data = collect_executable_sections(&input_data)?;
    
    // 해시 계산
    let mut hasher = Sha256::new();
    hasher.update(&executable_sections_data);
    let hash = hasher.finalize();
    
    // 공개키 로드
    let public_key_data = fs::read(public_key_path)?;
    let rsa = match Rsa::public_key_from_pem(&public_key_data) {
        Ok(r) => r,
        Err(_) => return Ok(VerificationResult::NotOk),
    };
    
    let public_key = match PKey::from_rsa(rsa) {
        Ok(pk) => pk,
        Err(_) => return Ok(VerificationResult::NotOk),
    };
    
    // 서명 검증
    let mut verifier = match Verifier::new(MessageDigest::sha256(), &public_key) {
        Ok(v) => v,
        Err(_) => return Ok(VerificationResult::NotOk),
    };
    
    if let Err(_) = verifier.update(&hash) {
        return Ok(VerificationResult::NotOk);
    }
    
    match verifier.verify(&signature) {
        Ok(true) => Ok(VerificationResult::Ok),
        _ => Ok(VerificationResult::NotOk),
    }
}

// ELF 형식 검증
fn is_valid_elf(data: &[u8]) -> bool {
    if data.len() < 64 { // 최소 ELF 헤더 크기
        return false;
    }
    
    // ELF 매직 넘버 검증
    data[0] == 0x7F && data[1] == b'E' && data[2] == b'L' && data[3] == b'F'
}

// 실행 코드 섹션 수집
fn collect_executable_sections(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    
    // ELF 헤더 파싱
    if data.len() < std::mem::size_of::<ElfHeader>() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid ELF header size"));
    }
    
    // 여기서는 ELF 헤더와 섹션 헤더를 간단히 파싱해서 실행 코드 섹션을 식별합니다.
    // 실제 구현에서는 더 복잡한 파싱 로직이 필요할 수 있습니다.
    
    // 간단한 구현을 위해 .text 섹션만 수집한다고 가정합니다.
    // .text 섹션은 일반적으로 주요 실행 코드를 포함합니다.
    
    result.extend_from_slice(data);
    
    Ok(result)
}

// 서명 섹션 추가
fn add_signature_section(file_path: &str, signature: &[u8]) -> io::Result<()> {
    // 외부 도구나 라이브러리를 호출하여 섹션 추가
    // 예: objcopy를 사용하는 방법
    
    let temp_sig_file = format!("{}.sig.tmp", file_path);
    fs::write(&temp_sig_file, signature)?;
    
    // 임시 섹션 파일을 생성하고 objcopy로 추가하는 방식을 시뮬레이션
    // 실제 구현에서는 libelf 등의 라이브러리나 objcopy 명령어를 사용할 수 있습니다.
    
    // 여기서는 간단히 파일에 서명을 추가하는 것으로 대체
    let mut file = fs::OpenOptions::new().append(true).open(file_path)?;
    file.write_all(signature)?;
    
    // 임시 파일 정리
    fs::remove_file(temp_sig_file)?;
    
    Ok(())
}

// 서명 섹션 추출
fn extract_signature_section(data: &[u8]) -> io::Result<Vec<u8>> {
    // 서명 섹션 추출 구현
    // 실제 구현에서는 ELF 포맷 파싱과 관련된 라이브러리나 도구를 사용해야 합니다.
    
    // 간단한 구현을 위해 파일 끝에 있는 256바이트를 서명으로 간주
    if data.len() < 256 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "File too small to contain signature"));
    }
    
    let signature_size = 256; // RSA-2048 서명 크기
    let signature_data = data[data.len() - signature_size..].to_vec();
    
    Ok(signature_data)
}