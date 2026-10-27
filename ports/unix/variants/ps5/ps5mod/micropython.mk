# `import ps5` user C module for the PS5 (prospero) unix variant.
SRC_USERMOD_C += $(USERMOD_DIR)/modps5.c
CFLAGS_USERMOD += -I$(USERMOD_DIR)
LIBS_USERMOD += -lSceNotification
