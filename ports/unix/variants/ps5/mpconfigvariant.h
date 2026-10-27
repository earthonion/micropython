// PS5 (prospero) variant of the unix port.

// Set base feature level.
#define MICROPY_CONFIG_ROM_LEVEL (MICROPY_CONFIG_ROM_LEVEL_EXTRA_FEATURES)

// Enable extra Unix features.
#include "../mpconfigvariant_common.h"

#define MICROPY_PY_SYS_PLATFORM  "ps5"
#define MICROPY_HW_BOARD_NAME    "PS5"
#define MICROPY_HW_MCU_NAME      "prospero"
