#
#  SPDX-License-Identifier: AGPL-3.0-only
#  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
#

# The development version of clang is distributed as the 'clang' binary,
# while stable/released versions have a version number attached.
# Pin the default clang to a stable version.
CLANG ?= clang
STRIP ?= llvm-strip
CFLAGS := -O2 -Wall -Werror $(CFLAGS)
TARGET ?= bpfel,bpfeb
OUTPUT ?= dae
RULE_SYNC_OUTPUT ?= build/dae-rule-sync
MAX_MATCH_SET_LEN ?= 1024
CFLAGS := -DMAX_MATCH_SET_LEN=$(MAX_MATCH_SET_LEN) $(CFLAGS)
DEFAULT_GOEXPERIMENT := heapminimum512kib,randomizedheapbase64
GOEXPERIMENT_MERGED := $(shell printf '%s\n' "$(DEFAULT_GOEXPERIMENT),$(GOEXPERIMENT)" | tr ',' '\n' | sed '/^$$/d' | awk '!seen[$$0]++' | paste -sd, -)
export GOEXPERIMENT := $(GOEXPERIMENT_MERGED)
NOSTRIP ?= n
STRIP_PATH := $(shell command -v $(STRIP) 2>/dev/null)
BUILD_TAGS_FILE := .build_tags
ifeq ($(strip $(NOSTRIP)),y)
	STRIP_FLAG := -no-strip
else ifeq ($(wildcard $(STRIP_PATH)),)
	STRIP_FLAG := -no-strip
else
	STRIP_FLAG := -strip=$(STRIP_PATH)
endif

GOARCH ?= $(shell go env GOARCH)

include hack/go-cache.mk

.PHONY: print-go-env
print-go-env:
	@echo "export GOCACHE=$(GOCACHE)"; \
	echo "export GOMODCACHE=$$(go env GOMODCACHE)"; \
	echo "export GOTMPDIR=$$(go env GOTMPDIR)"; \
	echo "export GOPATH=$$(go env GOPATH)"

# Offline source archives (release tarballs) ship ./go-mod/cache. Uncomment
# when building from that archive; CI seed/PR builds must not use this — they
# share ~/go/pkg/mod via setup-go's cache instead.
#export GOMODCACHE=$(PWD)/go-mod

# Get version from .git.
date=$(shell git log -1 --format="%cd" --date=short | sed s/-//g)
count=$(shell git rev-list --count HEAD)
commit=$(shell git rev-parse --short HEAD)
ifeq ($(wildcard .git/.),)
	VERSION ?= unstable-0.nogit
else
	VERSION ?= unstable-$(date).r$(count).$(commit)
endif

BUILD_ARGS := -trimpath -ldflags "-s -w -X github.com/daeuniverse/dae/cmd.Version=$(VERSION) -X github.com/daeuniverse/dae/common/consts.MaxMatchSetLen_=$(MAX_MATCH_SET_LEN)" $(BUILD_ARGS)

.PHONY: clean-ebpf ebpf ebpf-config ebpf-sync ebpf-sync-check ebpf-test ebpf-test-tagged ebpf-test-debug ebpf-test-debug-tagged ebpf-audit dae dae-rule-sync submodule submodules test test-race print-go-env

## Begin Dae Build
dae: export GOOS=linux
ifndef CGO_ENABLED
dae: export CGO_ENABLED=0
endif
dae: ebpf
	@echo $(CFLAGS)
	go build -tags=$(shell cat $(BUILD_TAGS_FILE)) -o $(OUTPUT) $(BUILD_ARGS) .
## End Dae Build

## Begin Rule Sync Build
dae-rule-sync:
	@mkdir -p $(dir $(RULE_SYNC_OUTPUT))
	go build -trimpath -o $(RULE_SYNC_OUTPUT) ./tools/dae-rule-sync
## End Rule Sync Build

## Begin Git Submodules
.gitmodules.d.mk: .gitmodules
	@set -e && \
	submodules=$$(grep '\[submodule "' .gitmodules | cut -d'"' -f2 | tr '\n' ' ' | tr ' \n' '\n') && \
	echo "submodule_paths=$${submodules}" > $@

-include .gitmodules.d.mk

$(submodule_paths): .gitmodules.d.mk
	git submodule update --init --recursive -- $@ && \
	touch $@

submodule submodules: $(submodule_paths)
	@if [ -z "$(submodule_paths)" ]; then \
		rm -f .gitmodules.d.mk; \
		echo "Failed to generate submodules list. Please try again."; \
		exit 1; \
	fi
## End Git Submodules

## Begin Ebpf
EBPF_CONFIG_FILE := .ebpf.config
EBPF_CONTROL_STAMP := .ebpf.control.stamp
EBPF_TEST_STAMP := .ebpf.test.stamp
EBPF_CONTROL_SOURCES := control/control.go control/kern/tproxy.c control/kern/ebpf_sync_defs.h \
	trace/trace.go trace/kern/trace.c \
	$(wildcard control/kern/headers/*.h) $(wildcard trace/kern/headers/*.h)
EBPF_TEST_SOURCES := control/bpf_bug_verification_test.go \
	control/kern/tests/bpf_test.go control/kern/tests/bpf_test.c control/kern/tests/bpf_test.h \
	$(wildcard control/kern/headers/*.h)
ifeq ($(FORCE_EBPF),y)
	EBPF_FORCE_DEPS := clean-ebpf
endif

clean-ebpf:
	@rm -f control/bpf_bpf*.go && \
			rm -f control/bpf_bpf*.o
	@rm -f control/bpftest_bpf*.go && \
			rm -f control/bpftest_bpf*.o
	@rm -f trace/bpf_*_bpf*.go && \
			rm -f trace/bpf_*_bpf*.o
	@rm -f control/kern/tests/bpftest_bpf*.go && \
			rm -f control/kern/tests/bpftest_bpf*.o
	@rm -f $(EBPF_CONTROL_STAMP) $(EBPF_TEST_STAMP) $(EBPF_CONFIG_FILE)
fmt:
	go fmt ./...

ebpf-sync:
	@unset GOOS && \
	unset GOARCH && \
	unset GOARM && \
	unset GOAMD64 && \
	go generate ./common/consts/ebpf.go

ebpf-sync-check: ebpf-sync
	git diff --exit-code -- common/consts/ebpf_generated.go control/kern/ebpf_sync_defs.h

ebpf-config:
	@printf '%s\n' "$(CLANG)" "$(CFLAGS)" "$(TARGET)" "$(STRIP_FLAG)" "$(MAX_MATCH_SET_LEN)" > $(EBPF_CONFIG_FILE).tmp
	@if [ ! -f $(EBPF_CONFIG_FILE) ] || ! cmp -s $(EBPF_CONFIG_FILE) $(EBPF_CONFIG_FILE).tmp; then \
		mv $(EBPF_CONFIG_FILE).tmp $(EBPF_CONFIG_FILE); \
	else \
		rm -f $(EBPF_CONFIG_FILE).tmp; \
	fi

$(EBPF_CONFIG_FILE):
	@$(MAKE) --no-print-directory ebpf-config

$(EBPF_CONTROL_STAMP): $(EBPF_CONTROL_SOURCES) $(EBPF_CONFIG_FILE)
	@unset GOOS && \
	unset GOARCH && \
	unset GOARM && \
	echo $(STRIP_FLAG) && \
	go generate ./control/control.go && \
	if go generate ./trace/trace.go; then \
		echo trace > $(BUILD_TAGS_FILE); \
	else \
		echo > $(BUILD_TAGS_FILE); \
	fi
	@touch $@

$(EBPF_TEST_STAMP): $(EBPF_TEST_SOURCES) $(EBPF_CONFIG_FILE)
	@unset GOOS && \
	unset GOARCH && \
	unset GOARM && \
	echo $(STRIP_FLAG) && \
	go generate ./control/bpf_bug_verification_test.go && \
	go generate ./control/kern/tests/bpf_test.go
	@touch $@

# $BPF_CLANG is used in go:generate invocations.
ebpf: export BPF_CLANG := $(CLANG)
ebpf: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf: export BPF_CFLAGS := $(CFLAGS)
ebpf: export BPF_TARGET := $(TARGET)
ebpf: export BPF_TRACE_TARGET := $(GOARCH)
ebpf: $(EBPF_FORCE_DEPS) ebpf-sync submodule ebpf-config
	@if [ ! -f control/bpf_bpfel.go ] || [ ! -f control/bpf_bpfeb.go ]; then rm -f $(EBPF_CONTROL_STAMP); fi
	@$(MAKE) --no-print-directory $(EBPF_CONTROL_STAMP)

EBPF_LINT_SOURCES := control/kern/tproxy.c control/kern/tests/bpf_test.c trace/kern/trace.c
EBPF_LINT_IGNORE := COMMIT_COMMENT_SYMBOL,NOT_UNIFIED_DIFF,COMMIT_LOG_LONG_LINE,LONG_LINE_COMMENT,VOLATILE,ASSIGN_IN_IF,PREFER_DEFINED_ATTRIBUTE_MACRO,CAMELCASE,LEADING_SPACE,OPEN_ENDED_LINE,SPACING,BLOCK_COMMENT_STYLE

ebpf-lint:
	./scripts/checkpatch.pl --no-tree --strict --no-summary --show-types --color=always $(EBPF_LINT_SOURCES) --ignore $(EBPF_LINT_IGNORE)

ifeq ($(TESTCACHE),clean)
	EBPF_TESTCACHE_DEPS := clean-testcache
endif
.PHONY: clean-testcache
clean-testcache:
	go clean -testcache

ebpf-test: export BPF_CLANG := $(CLANG)
ebpf-test: export BPF_STRIP_FLAG := $(STRIP_FLAG)
ebpf-test: export BPF_CFLAGS := $(CFLAGS)
ebpf-test: export BPF_TARGET := $(TARGET)
ebpf-test: export BPF_TRACE_TARGET := $(GOARCH)
ebpf-test: $(EBPF_FORCE_DEPS) $(EBPF_TESTCACHE_DEPS) ebpf-sync submodule ebpf-config
	@if [ ! -f control/kern/tests/bpftest_bpfel.go ] && [ ! -f control/bpftest_bpfel.go ]; then rm -f $(EBPF_TEST_STAMP); fi
	@$(MAKE) --no-print-directory $(EBPF_TEST_STAMP)
	go test -v -tags dae_bpf_tests ./control/kern/tests/...

ebpf-test-tagged: ebpf-test

ebpf-test-debug:
	$(MAKE) FORCE_EBPF=y TESTCACHE=clean CFLAGS="$(CFLAGS) -D__BPF_TEST_ENABLE_DEBUG" ebpf-test

ebpf-test-debug-tagged: ebpf-test-debug

ebpf-audit:
	./scripts/ebpf-audit.sh

test:
	go test -tags dae_stub_ebpf ./...

test-race:
	go test -race -tags dae_stub_ebpf -timeout 30m ./control/... ./component/... ./cmd/...

## End Ebpf
