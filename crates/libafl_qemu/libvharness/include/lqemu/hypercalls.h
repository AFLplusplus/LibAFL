#ifndef LQEMU_HYPERCALLS_H
#define LQEMU_HYPERCALLS_H

#include "defs.h"
#include "platform.h"

#ifdef __cplusplus
extern "C" {
#endif

lqword LQEMU_CALLING_CONVENTION _lqemu_custom_insn_call0(lqword cmd);
lqword LQEMU_CALLING_CONVENTION _lqemu_custom_insn_call1(lqword cmd,
                                                         lqword arg1);
lqword LQEMU_CALLING_CONVENTION _lqemu_custom_insn_call2(lqword cmd,
                                                         lqword arg1,
                                                         lqword arg2);

lqword LQEMU_CALLING_CONVENTION _lqemu_backdoor_call0(lqword cmd);
lqword LQEMU_CALLING_CONVENTION _lqemu_backdoor_call1(lqword cmd, lqword arg1);
lqword LQEMU_CALLING_CONVENTION _lqemu_backdoor_call2(lqword cmd, lqword arg1,
                                                      lqword arg2);

#ifdef __cplusplus
}
#endif

#endif
