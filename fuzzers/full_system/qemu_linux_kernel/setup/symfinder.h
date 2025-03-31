#ifndef LIBAFL_SYMFINDER_H
#define LIBAFL_SYMFINDER_H

#include <linux/kernel.h>

/* symfinder_symfinder_widen_range
 *
 * Append a symbol range to the current addresses. If an address is null, it
 * will always take the value of the requested symbol.
 *
 *  - [in]  symbol: symbol to look for in kernel space
 *  - [out] min_addr_start: the minimal address start
 *  - [out] max_addr_end: the maximal address end
 */
int lqemu_symfinder_widen_range(const char *symbol, uintptr_t *min_addr_start,
                                uintptr_t *max_addr_end);

/* lqemu_symfinder_find_range
 *
 * Find the kernel address of the input symbol
 *
 *  - [in]  symbol: symbol to look for in kernel space
 *  - [out] addr_start: start addr for the input symbol
 *  - [out] addr_end: end addr for the input symbol
 */
int lqemu_symfinder_find_range(const char *symbol, uintptr_t *addr_start,
                               uintptr_t *addr_end);

#endif