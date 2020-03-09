DIRECTORY := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
MAKE := docker run --rm -v ${DIRECTORY}/src:/src andrewstucki/libbpf-builder:0.0.7 make

build:
	@$(MAKE)

clean:
	@$(MAKE) clean

toolchain-llvm:
	cd toolchain/llvm && \
	docker build . -t andrewstucki/llvm10rc3-musl-toolchain
	docker push andrewstucki/llvm10rc3-musl-toolchain

toolchain-libbpf:
	cd toolchain/libbpf && \
	docker build . -t andrewstucki/libbpf-builder:0.0.7
	docker push andrewstucki/libbpf-builder:0.0.7
