.PHONY: all clean

all: signtool

# cargo를 이용하여 빌드 - 더 안정적인 의존성 관리
signtool:
	cargo build --release
	cp target/release/signtool .

clean:
	rm -f signtool
	cargo clean
	rm -f *.tmp