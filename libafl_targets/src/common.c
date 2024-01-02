#include "common.h"

#ifdef DEFAULT_SANITIZERS_OPTIONS
// TODO MSan and LSan. however they don't support abort_on_error

const char *__asan_default_options() {
  return "abort_on_error=1:detect_leaks=0:"
         "malloc_context_size=0:symbolize=0:"
         "allocator_may_return_null=1:"
         "detect_odr_violation=0:handle_segv=0:"
         "handle_sigbus=0:handle_abort=0:"
         "handle_sigfpe=0:handle_sigill=0";
}

const char *__ubsan_default_options() {
  return "abort_on_error=1:"
         "allocator_release_to_os_interval_ms=500:"
         "handle_abort=0:handle_segv=0:"
         "handle_sigbus=0:handle_sigfpe=0:"
         "handle_sigill=0:print_stacktrace=0:"
         "symbolize=0:symbolize_inline_frames=0";
}
#endif  // DEFAULT_SANITIZERS_OPTIONS
