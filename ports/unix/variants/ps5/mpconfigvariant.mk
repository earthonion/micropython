# PS5 (prospero) variant of the unix port.
#
# Included after mpconfigport.mk, so plain '=' here overrides port defaults.

# sysroot has no libffi (and host pkg-config would return x86-linux libs).
MICROPY_PY_FFI = 0

# berkeley-db 1.xx is pre-ANSI C and trips -Werror under clang; not needed.
MICROPY_PY_BTREE = 0

# Hosted port: block-device VFS (fatfs/littlefs) is pointless here and pulls
# in extra submodules; host FS access works via the os module regardless.
MICROPY_VFS_FAT = 0
MICROPY_VFS_LFS1 = 0
MICROPY_VFS_LFS2 = 0

# Freeze only in-tree modules (no micropython-lib submodule needed).
FROZEN_MANIFEST ?= $(VARIANT_DIR)/manifest.py

# `import ps5` console helper module (modps5.c)
USER_C_MODULES = $(VARIANT_DIR)/ps5mod

PROG = micropython_ps5.elf
