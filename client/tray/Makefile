# Makefile — fwknop Windows 便携版构建（MinGW-w64 GCC）
#
# 用途：从源码构建便携包三个产物：
#   fwknop-tray.exe  托盘 GUI（本目录，仅依赖 Win32 API + shlwapi）
#   fwknop.exe       fwknop 客户端（v4 敲门器：TOTP 端口跳变 + device_id）
#   libfko.a         libfko 静态库（tray 不需要，fwknop.exe 链接它）
#
# 便携包 = 含 fwknop-tray.exe + fwknop.exe 的目录，解压即用。
#
# 使用：
#   make            # 构建全部
#   make tray       # 仅构建托盘程序
#   make portable   # 构建并打包到 dist/fwknop-portable/
#   make clean
#
# 依赖：MinGW-w64（gcc / windres / ar），Windows SDK 头库随编译器附带。

CC       := gcc
RC       := windres
AR       := ar
STRIP    := strip

# 目录（相对本 Makefile 所在的 client/tray/）
TRAYDIR  := .
CLIENT   := ..
LIB      := ../../lib
COMMON   := ../../common
WIN32    := ../../win32

CFLAGS   := -O2 -Wall -DWIN32 -DHAVE_CONFIG_H -D_CRT_SECURE_NO_WARNINGS \
            -D_WINSOCK_DEPRECATED_NO_WARNINGS -fno-strict-aliasing
INCLUDES := -I$(WIN32) -I$(LIB) -I$(CLIENT) -I$(COMMON)
LDFLAGS  :=

# ---------------- libfko.a ----------------
LIB_SRC := \
	$(LIB)/base64.c          $(LIB)/cipher_funcs.c   $(LIB)/digest.c \
	$(LIB)/fko_client_timeout.c $(LIB)/fko_decode.c  $(LIB)/fko_digest.c \
	$(LIB)/fko_encode.c      $(LIB)/fko_encryption.c $(LIB)/fko_error.c \
	$(LIB)/fko_funcs.c       $(LIB)/fko_hmac.c       $(LIB)/fko_message.c \
	$(LIB)/fko_nat_access.c  $(LIB)/fko_rand_value.c $(LIB)/fko_server_auth.c \
	$(LIB)/fko_timestamp.c   $(LIB)/fko_user.c       $(LIB)/hmac.c \
	$(LIB)/md5.c             $(LIB)/rijndael.c       $(LIB)/sha1.c \
	$(LIB)/sha2.c            $(LIB)/sha3.c \
	$(LIB)/fko_totp.c        $(LIB)/fko_device_id.c  $(LIB)/fko_fingerprint.c \
	$(COMMON)/fko_util.c     $(COMMON)/strlcat.c     $(COMMON)/strlcpy.c \
	$(WIN32)/getlogin.c

# gpgme_funcs.c 在无 libgpgme 时编译为空实现；如编译报错可从列表移除
LIB_SRC  += $(LIB)/gpgme_funcs.c

LIB_OBJ  := $(patsubst $(LIB)/%.c,build/lib/%.o,$(filter $(LIB)/%.c,$(LIB_SRC)))
LIB_OBJ  += $(patsubst $(COMMON)/%.c,build/common/%.o,$(filter $(COMMON)/%.c,$(LIB_SRC)))
LIB_OBJ  += $(patsubst $(WIN32)/%.c,build/win32/%.o,$(filter $(WIN32)/%.c,$(LIB_SRC)))

# ---------------- fwknop.exe ----------------
CLIENT_SRC := \
	$(CLIENT)/config_init.c   $(CLIENT)/fwknop.c       $(CLIENT)/getpasswd.c \
	$(CLIENT)/http_resolve_host.c $(CLIENT)/log_msg.c  $(CLIENT)/spa_comm.c \
	$(CLIENT)/utils.c         $(CLIENT)/wizard.c       $(CLIENT)/cli_subcmds.c \
	$(COMMON)/fko_util.c      $(COMMON)/strlcat.c      $(COMMON)/strlcpy.c

# getopt.c/getopt1.c 是上游 K&R 老式实现（extern char *getenv(); 无参声明），
# 在 C17 默认下会与带参调用冲突，故单独用 gnu89 编译。
GETOPT_OBJ := build/win32/getopt.o build/win32/getopt1.o

# ---------------- fwknop-tray.exe ----------------
# UNICODE/_UNICODE 在 fwknop-tray.c 内已定义，故此处不再重复传，避免告警。
TRAY_CFLAGS := -O2 -Wall -D_WIN32_WINNT=0x0600 -D_WIN32_IE=0x0600

.PHONY: all tray client lib portable clean

all: tray client

# ---------- 托盘程序 ----------
build/tray_res.o: tray.rc tray.manifest | build
	$(RC) -i tray.rc -J rc -O coff -o build/tray_res.o

build/fwknop-tray.exe: fwknop-tray.c build/tray_res.o | build
	$(CC) $(TRAY_CFLAGS) -municode -mwindows \
		fwknop-tray.c build/tray_res.o \
		-o build/fwknop-tray.exe \
		-lshlwapi -lshell32 -luser32 -lgdi32
	$(STRIP) build/fwknop-tray.exe

tray: build/fwknop-tray.exe

# ---------- libfko.a ----------
build/lib/%.o: $(LIB)/%.c | build/dir
	@mkdir -p build/lib
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

build/common/%.o: $(COMMON)/%.c | build/dir
	@mkdir -p build/common
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

build/win32/%.o: $(WIN32)/%.c | build/dir
	@mkdir -p build/win32
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# getopt 老式代码单独用 gnu89 编译
build/win32/getopt.o: $(WIN32)/getopt.c | build/dir
	@mkdir -p build/win32
	$(CC) -std=gnu89 -Wno-old-style-definition -Wno-strict-prototypes \
		$(CFLAGS) $(INCLUDES) -c $< -o $@

build/win32/getopt1.o: $(WIN32)/getopt1.c | build/dir
	@mkdir -p build/win32
	$(CC) -std=gnu89 -Wno-old-style-definition -Wno-strict-prototypes \
		$(CFLAGS) $(INCLUDES) -c $< -o $@

build/dir:
	@mkdir -p build

build:
	@mkdir -p build

build/libfko.a: $(LIB_OBJ)
	$(AR) rcs $@ $^

lib: build/libfko.a

# ---------- fwknop.exe ----------
build/fwknop.exe: $(CLIENT_SRC) $(GETOPT_OBJ) build/libfko.a | build
	@mkdir -p build
	$(CC) $(CFLAGS) $(INCLUDES) $(CLIENT_SRC) $(GETOPT_OBJ) build/libfko.a \
		-o build/fwknop.exe -lws2_32
	$(STRIP) build/fwknop.exe

client: build/fwknop.exe

# ---------- 便携包 ----------
portable: all
	@rm -rf dist
	@mkdir -p dist/fwknop-portable
	cp build/fwknop-tray.exe dist/fwknop-portable/
	cp build/fwknop.exe      dist/fwknop-portable/
	cp README-tray.txt       dist/fwknop-portable/ 2>/dev/null || true
	@echo "便携包已生成: dist/fwknop-portable/"

clean:
	rm -rf build dist
