# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output

CLANG ?= clang
CLANG_FORMAT ?= clang-format
LLVM_STRIP ?= llvm-strip
GO ?= go
DOCKER ?= docker

LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)

BPFTOOL_SRC := $(abspath ./bpftool/src)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BTFFILE = /sys/kernel/btf/vmlinux
VMLINUX := ./vmlinux/$(ARCH)/vmlinux.h

IMAGE_TAG ?= latest

# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I../../libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

.PHONY: all
all: daemon

.PHONY: clean
clean:
	rm -rf $(OUTPUT) \
		daemon.bpf.o \
		daemon

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)    \
		INCLUDEDIR= LIBDIR= UAPIDIR=                 \
		install

$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

daemon.bpf.o: daemon.h daemon.bpf.c $(LIBBPF_OBJ) | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c daemon.bpf.c -o $@
	$(LLVM_STRIP) -g $@

daemon: daemon.bpf.o main.go
	$(GO) build -o $@ main.go

.PHONY: $(VMLINUX)
$(VMLINUX): $(BPFTOOL)
	$(BPFTOOL) btf dump file $(BTFFILE) format c > $(VMLINUX)

.PHONY: format
format:
	$(CLANG_FORMAT) -i \
	daemon.bpf.c \
	daemon.h

.PHONY: image
image:
	$(DOCKER) image build --no-cache -t docker.io/soilsecurity/bpf-daemonset-template:$(IMAGE_TAG) .

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.bpf.o, etc) targets
.SECONDARY:
