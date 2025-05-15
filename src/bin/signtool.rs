use std::env;
use std::fs;
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process;

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Rsa, Padding};
use openssl::sign::{Signer, Verifier};
use sha2::{Sha256, Digest};
use libelf::{Elf, Section};

const SIGNATURE_SIZE: usize = 256; // RSA-2048 signature size
const SIGNATURE_SECTION_NAME: &str = ".signature";

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("사용법: {} <명령> [인자...]", args[0]);
        eprintln!("지원 명령:");
        eprintln!("  sign <개인키 파일> <입력 파일> <출력 파일> - 파일에 서명");
        eprintln!("  verify <공개키 파일> <서명된 파일> - 서명 확인");
        eprintln!("  generate <개인키 출력 파일> <공개키 출력 파일> - 키페어 생성");
        process::exit(1);
    }

    match args[1].as_str() {
        "sign" => {
            if args.len() != 5 {
                eprintln!("사용법: {} sign <개인키 파일> <입력 파일> <출력 파일>", args[0]);
                process::exit(1);
            }
            
            let private_key_path = &args[2];
            let input_file_path = &args[3];
            let output_file_path = &args[4];
            
            if let Err(e) = sign_file(private_key_path, input_file_path, output_file_path) {
                eprintln!("서명 생성 오류: {}", e);
                process::exit(1);
            }
            
            println!("파일 서명 완료: {}", output_file_path);
        },
        "verify" => {
            if args.len() != 4 {
                eprintln!("사용법: {} verify <공개키 파일> <서명된 파일>", args[0]);
                process::exit(1);
            }
            
            let public_key_path = &args[2];
            let signed_file_path = &args[3];
            
            match verify_file(public_key_path, signed_file_path) {
                Ok(true) => println!("서명 확인: 유효한 서명"),
                Ok(false) => {
                    eprintln!("서명 확인: 유효하지 않은 서명");
                    process::exit(1);
                },
                Err(e) => {
                    eprintln!("서명 확인 오류: {}", e);
                    process::exit(1);
                }
            }
        },
        "generate" => {
            if args.len() != 4 {
                eprintln!("사용법: {} generate <개인키 출력 파일> <공개키 출력 파일>", args[0]);
                process::exit(1);
            }
            
            let private_key_path = &args[2];
            let public_key_path = &args[3];
            
            if let Err(e) = generate_keypair(private_key_path, public_key_path) {
                eprintln!("키 생성 오류: {}", e);
                process::exit(1);
            }
            
            println!("키페어 생성 완료:");
            println!("개인키: {}", private_key_path);
            println!("공개키: {}", public_key_path);
        },
        _ => {
            eprintln!("알 수 없는 명령: {}", args[1]);
            process::exit(1);
        }
    }
}

fn generate_keypair(private_key_path: &str, public_key_path: &str) -> io::Result<()> {
    // 2048비트 RSA 키 생성
    let rsa = Rsa::generate(2048).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    // 개인키를 PEM 형식으로 저장
    let private_key = rsa.private_key_to_pem().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    fs::write(private_key_path, private_key)?;
    
    // 공개키를 PEM 형식으로 저장
    let public_key = rsa.public_key_to_pem().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    fs::write(public_key_path, public_key)?;
    
    Ok(())
}

fn is_elf_file(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x7F && data[1] == b'E' && data[2] == b'L' && data[3] == b'F'
}

fn sign_file(private_key_path: &str, input_file_path: &str, output_file_path: &str) -> io::Result<()> {
    // 개인키 로드
    let private_key_data = fs::read(private_key_path)?;
    let rsa = Rsa::private_key_from_pem(&private_key_data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let pkey = PKey::from_rsa(rsa)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    // 입력 파일 읽기
    let input_data = fs::read(input_file_path)?;
    
    if is_elf_file(&input_data) {
        sign_elf_file(&pkey, input_file_path, output_file_path)
    } else {
        sign_regular_file(&pkey, &input_data, output_file_path)
    }
}

fn sign_regular_file(pkey: &PKey<Private>, input_data: &[u8], output_file_path: &str) -> io::Result<()> {
    // 파일 해시 계산
    let mut hasher = Sha256::new();
    hasher.update(input_data);
    let hash = hasher.finalize();
    
    // 해시에 서명
    let mut signer = Signer::new(MessageDigest::sha256(), pkey)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    signer.update(&hash)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let signature = signer.sign_to_vec()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    // 서명을 입력 파일 끝에 추가하여 출력 파일 저장
    let mut output_data = input_data.to_vec();
    output_data.extend_from_slice(&signature);
    
    fs::write(output_file_path, output_data)?;
    
    Ok(())
}

fn sign_elf_file(pkey: &PKey<Private>, input_file_path: &str, output_file_path: &str) -> io::Result<()> {
    // 입력 파일 복사
    fs::copy(input_file_path, output_file_path)?;
    
    // 입력 파일 내용 읽기
    let input_data = fs::read(input_file_path)?;
    
    // 해시 계산
    let mut hasher = Sha256::new();
    hasher.update(&input_data);
    let hash = hasher.finalize();
    
    // 해시에 서명
    let mut signer = Signer::new(MessageDigest::sha256(), pkey)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    signer.update(&hash)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let signature = signer.sign_to_vec()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    // ELF 파일에 서명 섹션 추가
    add_signature_to_elf(output_file_path, &signature)?;
    
    Ok(())
}

fn add_signature_to_elf(file_path: &str, signature: &[u8]) -> io::Result<()> {
    let file = fs::File::open(file_path)?;
    let mut elf = match Elf::from_reader(file) {
        Ok(elf) => elf,
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("ELF 파일 읽기 오류: {:?}", e))),
    };
    
    // 임시 파일에 쓰기
    let temp_path = format!("{}.tmp", file_path);
    let mut output_file = fs::File::create(&temp_path)?;
    
    // .signature 섹션 추가
    let section = Section::new();
    section.set_name(SIGNATURE_SECTION_NAME);
    section.set_type(1); // SHT_PROGBITS
    section.set_flags(0); // 실행 불가, 쓰기 불가
    section.set_data(signature);
    
    elf.add_section(section);
    
    // 변경된 ELF 파일 저장
    match elf.write_to(&mut output_file) {
        Ok(_) => {},
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("ELF 파일 쓰기 오류: {:?}", e))),
    }
    
    // 임시 파일을 원래 파일로 이동
    fs::rename(temp_path, file_path)?;
    
    Ok(())
}

fn verify_file(public_key_path: &str, signed_file_path: &str) -> io::Result<bool> {
    // 공개키 로드
    let public_key_data = fs::read(public_key_path)?;
    let rsa = Rsa::public_key_from_pem(&public_key_data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let pkey = PKey::from_rsa(rsa)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    // 서명된 파일 읽기
    let signed_data = fs::read(signed_file_path)?;
    
    if is_elf_file(&signed_data) {
        verify_elf_file(&pkey, signed_file_path)
    } else {
        verify_regular_file(&pkey, &signed_data)
    }
}

fn verify_regular_file(pkey: &PKey<Private>, signed_data: &[u8]) -> io::Result<bool> {
    if signed_data.len() < SIGNATURE_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "파일이 너무 작아 서명이 포함될 수 없습니다"));
    }
    
    // 원본 데이터와 서명 분리
    let file_size = signed_data.len();
    let original_data = &signed_data[0..file_size - SIGNATURE_SIZE];
    let signature = &signed_data[file_size - SIGNATURE_SIZE..];
    
    // 원본 데이터 해시 계산
    let mut hasher = Sha256::new();
    hasher.update(original_data);
    let hash = hasher.finalize();
    
    // 서명 검증
    let mut verifier = Verifier::new(MessageDigest::sha256(), pkey)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    verifier.update(&hash)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let result = verifier.verify(signature)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    Ok(result)
}

fn verify_elf_file(pkey: &PKey<Private>, file_path: &str) -> io::Result<bool> {
    // 파일 데이터 읽기
    let file_data = fs::read(file_path)?;
    
    // 서명 추출
    let signature = extract_signature_from_elf(&file_data)?;
    
    // 원본 데이터 (서명 제외)
    let original_data = &file_data[0..file_data.len() - SIGNATURE_SIZE];
    
    // 원본 데이터 해시 계산
    let mut hasher = Sha256::new();
    hasher.update(original_data);
    let hash = hasher.finalize();
    
    // 서명 검증
    let mut verifier = Verifier::new(MessageDigest::sha256(), pkey)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    verifier.update(&hash)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let result = verifier.verify(&signature)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    Ok(result)
}

fn extract_signature_from_elf(file_data: &[u8]) -> io::Result<Vec<u8>> {
    let cursor = io::Cursor::new(file_data);
    let elf = match Elf::from_reader(cursor) {
        Ok(elf) => elf,
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("ELF 파일 읽기 오류: {:?}", e))),
    };
    
    // .signature 섹션 찾기
    for section in elf.sections() {
        if let Ok(name) = section.name() {
            if name == SIGNATURE_SECTION_NAME {
                return Ok(section.data().to_vec());
            }
        }
    }
    
    Err(io::Error::new(io::ErrorKind::NotFound, "서명 섹션을 찾을 수 없습니다"))
}