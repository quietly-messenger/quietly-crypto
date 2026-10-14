# quietly-crypto — build the Go crypto core as a C shared library.
#
# `go build -buildmode=c-shared` compiles the `ffi` package into a shared
# object (.so on Linux, .dylib on macOS, .dll on Windows) plus a matching C
# header, so the library can be loaded from any FFI consumer (Dart/Flutter,
# C, C++, Rust, ...).

GO      ?= go
OUT     := dist
PKG     := ./ffi
LIBNAME := quietly_crypto

# Release optimizations:
#   -trimpath      strip local filesystem paths (reproducible builds)
#   -buildvcs=false omit VCS stamping (reproducible builds)
#   -ldflags -s -w strip the symbol table and DWARF debug info
#   CGO_CFLAGS -O3 optimize the small cgo C shim aggressively
GOFLAGS   := -trimpath -buildvcs=false
LDFLAGS   := -s -w
CGO_CFLAGS  ?= -O3 -g0
CGO_LDFLAGS ?= -s

export CGO_CFLAGS CGO_LDFLAGS

UNAME_S := $(shell uname -s 2>/dev/null)
ifeq ($(OS),Windows_NT)
  HOST_OS := windows
else ifeq ($(UNAME_S),Darwin)
  HOST_OS := darwin
else
  HOST_OS := linux
endif

.PHONY: all build build-linux build-darwin build-windows build-windows-arm64 test vet fmt clean help

## all: build the shared library for every supported platform
all: build-linux build-windows

## build: build the shared library for the host OS
build: build-$(HOST_OS)

## build-linux: build dist/libquietly_crypto.so (linux/amd64)
build-linux:
	@mkdir -p $(OUT)
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
	$(GO) build -buildmode=c-shared $(GOFLAGS) -ldflags "$(LDFLAGS)" \
		-o $(OUT)/lib$(LIBNAME).so $(PKG)

## build-darwin: build dist/libquietly_crypto.dylib (darwin/arm64)
# Cross-compiling cgo to macOS needs osxcross; normally run this on a Mac.
build-darwin:
	@mkdir -p $(OUT)
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC=o64-clang \
	$(GO) build -buildmode=c-shared $(GOFLAGS) -ldflags "$(LDFLAGS)" \
		-o $(OUT)/lib$(LIBNAME).dylib $(PKG)

## build-windows: build dist/quietly_crypto.dll (windows/amd64)
build-windows:
	@mkdir -p $(OUT)
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
	$(GO) build -buildmode=c-shared $(GOFLAGS) -ldflags "$(LDFLAGS)" \
		-o $(OUT)/$(LIBNAME).dll $(PKG)

## build-windows-arm64: build dist/quietly_crypto.dll (windows/arm64)
build-windows-arm64:
	@mkdir -p $(OUT)
	CGO_ENABLED=1 GOOS=windows GOARCH=arm64 CC=aarch64-w64-mingw32-gcc \
	$(GO) build -buildmode=c-shared $(GOFLAGS) -ldflags "$(LDFLAGS)" \
		-o $(OUT)/$(LIBNAME).dll $(PKG)

## test: run the test suite
test:
	$(GO) test -race ./...

## vet: run go vet
vet:
	$(GO) vet ./...

## fmt: format all Go source files
fmt:
	gofmt -w cryptocore ffi

## clean: remove build artifacts
clean:
	rm -rf $(OUT)

## help: list available targets
help:
	@printf "Available targets:\n"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //' | column -t -s ':'
