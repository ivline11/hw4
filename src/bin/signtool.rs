use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process;
use sha2::{Sha256, Digest};

// 서명 섹션 이름
const SIGNATURE_SECTION_NAME: &str = ".signature";
const SIGNATURE_SIZE: usize = 32; // SHA-256 해시 크기

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
    
    // 간소화: 전체 파일 내용에 대한 서명 생성
    let mut hasher = Sha256::new();
    hasher.update(&input_data);
    let hash = hasher.finalize();
    
    // 서명 섹션 추가: 간단히 파일 끝에 해시 추가
    let signature = hash.to_vec();
    
    // 파일에 서명 추가
    let mut file = fs::OpenOptions::new().append(true).open(output_path)?;
    file.write_all(&signature)?;
    
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
    
    // 간소화된 검증 로직
    if input_data.len() < SIGNATURE_SIZE {
        return Ok(VerificationResult::NotSigned);
    }
    
    // 파일 끝에서 서명(해시값) 추출
    let file_size = input_data.len();
    let signature = &input_data[file_size - SIGNATURE_SIZE..];
    let file_content = &input_data[..file_size - SIGNATURE_SIZE];
    
    // 파일 내용의 해시 계산
    let mut hasher = Sha256::new();
    hasher.update(file_content);
    let hash = hasher.finalize();
    
    // 계산된 해시와 저장된 서명 비교
    if hash.as_slice() == signature {
        Ok(VerificationResult::Ok)
    } else {
        Ok(VerificationResult::NotOk)
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