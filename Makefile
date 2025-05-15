.PHONY: all build run test clean

all: build

build:
	cargo build --release

debug:
	cargo build

run:
	cargo run --bin signtool

sign:
	cargo run --bin signtool sign $(PRIVATE_KEY) $(INPUT_FILE) $(OUTPUT_FILE)

verify:
	cargo run --bin signtool verify $(PUBLIC_KEY) $(SIGNED_FILE)

generate:
	cargo run --bin signtool generate private_key.pem public_key.pem

test:
	cargo test

clean:
	cargo clean
	rm -f *.pem *.tmp

help:
	@echo "사용 가능한 명령어:"
	@echo "  make build          - 릴리즈 모드로 빌드"
	@echo "  make debug          - 디버그 모드로 빌드"
	@echo "  make run            - 기본 실행"
	@echo "  make generate       - 키페어 생성"
	@echo "  make sign           - 파일 서명 (PRIVATE_KEY, INPUT_FILE, OUTPUT_FILE 변수 필요)"
	@echo "  make verify         - 서명 확인 (PUBLIC_KEY, SIGNED_FILE 변수 필요)"
	@echo "  make test           - 테스트 실행"
	@echo "  make clean          - 빌드 결과물 제거" 