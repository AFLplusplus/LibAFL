#include "common.h"

EXT_FUNC_IMPL(__sanitizer_set_death_callback, void, (void (*callback)(void)), false) {
  (void)callback;
}
