#include "common.h"

EXT_FUNC_IMPL(__sanitizer_set_death_callback, void, (void), false) {
  return;
}