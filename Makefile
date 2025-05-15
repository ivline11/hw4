.PHONY: all build clean run

all: signtool

signtool:
	rustc src/bin/signtool.rs -o signtool --crate-type=bin \
		-L dependency=./target/release/deps \
		--extern sha2=./target/release/deps/libsha2*.rlib \
		--extern openssl=./target/release/deps/libopenssl*.rlib \
		--extern hex_literal=./target/release/deps/libhex_literal*.rlib

deps:
	cargo build --release

clean:
	rm -f signtool
	cargo clean

run: signtool
	./signtool

help:
	@echo "사용 가능한 명령어:"
	@echo "  make          - signtool 바이너리 빌드"
	@echo "  make deps     - 의존성 라이브러리 빌드"
	@echo "  make clean    - 빌드 결과물 제거"
	@echo "  make run      - 프로그램 실행"