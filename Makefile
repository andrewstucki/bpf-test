DIRECTORY := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
CONTAINER := docker run --rm -v ${DIRECTORY}:/src andrewstucki/libbpf-rust-builder:0.0.7

build:
	@echo "Compiling release binary"
	@$(CONTAINER) /bin/sh -c "cargo build --release && cp target/release/probe . && strip probe"

clean:
	@echo "Cleaning"
	@rm -rf probe-sys/src/.output target probe

toolchain-llvm:
	cd toolchain/llvm && \
	docker build . -t andrewstucki/llvm10rc3-musl-toolchain
	docker push andrewstucki/llvm10rc3-musl-toolchain

toolchain-libbpf:
	cd toolchain/libbpf && \
	docker build . -t andrewstucki/libbpf-builder:0.0.7
	docker push andrewstucki/libbpf-builder:0.0.7

toolchain-rust:
	cd toolchain/rust && \
	docker build . -t andrewstucki/libbpf-rust-builder:0.0.7
	docker push andrewstucki/libbpf-rust-builder:0.0.7
