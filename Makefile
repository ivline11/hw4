.PHONY: all clean

all: signtool

signtool: src/bin/signtool.rs
	rustc src/bin/signtool.rs -o signtool \
		--extern openssl=./target/release/deps/libopenssl*.rlib \
		--extern sha2=./target/release/deps/libsha2*.rlib \
		-L dependency=./target/release/deps

deps:
	cargo build --release

clean:
	rm -f signtool
	rm -f *.tmp