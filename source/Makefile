API ?= 35
OUTDIR ?= build/bin
EMBEDDIR ?= build/embed
TARGET_HEADER ?= src/target.h

NDK_ROOT ?=
NDK_PREBUILT ?= $(if $(filter Darwin,$(shell uname -s)),darwin-x86_64,linux-x86_64)
NDK_TOOLCHAIN ?= $(NDK_ROOT)/toolchains/llvm/prebuilt/$(NDK_PREBUILT)
TARGET_CC ?= $(NDK_TOOLCHAIN)/bin/aarch64-linux-android$(API)-clang

EMBED_SU := $(EMBEDDIR)/su_daemon_aarch64_pie
PRELOAD := $(OUTDIR)/preload.so
CORE_SRCS := \
  src/main.c \
  src/util.c \
  src/slide.c \
  src/fops.c \
  src/pipe.c
PRELOAD_SRCS := $(CORE_SRCS) src/preload.c src/su_blob.S

COMMON_CFLAGS := -O2 -g0 -Wall -Wextra -Isrc
PIE_CFLAGS := -fPIE -pie $(COMMON_CFLAGS)
SO_CFLAGS := -fPIC $(COMMON_CFLAGS)
WARN_CFLAGS := -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function
TARGET_CFLAGS := -DTARGET_CONFIG_H=\"target.h\"

.DEFAULT_GOAL := preload
.PHONY: all preload clean info

all: preload

preload: $(TARGET_HEADER) $(PRELOAD)

$(TARGET_HEADER):
	@echo "missing $@; run build.py or generate_target.py first" >&2
	@false

$(OUTDIR) $(EMBEDDIR):
	mkdir -p $@

$(EMBED_SU): src/su_daemon.c | $(EMBEDDIR)
	$(TARGET_CC) $(PIE_CFLAGS) $(TARGET_CFLAGS) $< -o $@

$(PRELOAD): $(PRELOAD_SRCS) $(EMBED_SU) $(TARGET_HEADER) \
    src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) $(SO_CFLAGS) $(WARN_CFLAGS) $(TARGET_CFLAGS) \
	  $(PRELOAD_SRCS) -shared -o $@ -pthread
	sha256sum $@

info:
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "TARGET_HEADER=$(TARGET_HEADER)"
	@echo "PRELOAD=$(PRELOAD)"

clean:
	rm -rf build
