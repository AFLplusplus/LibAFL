//! Stub out syscalls. Linux only.

use std::ptr;

use libc::{c_int, c_void, off_t, size_t};
use meminterval::Interval;

use crate::{Context, Mapping, Pointer};

const PAGE_SIZE: usize = 4096;

extern "C" {
    //void* __libafl_raw_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    fn __libafl_raw_mmap(
        addr: *mut c_void,
        length: size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> *mut c_void;

    //int __libafl_raw_munmap(void *addr, size_t length);
    fn __libafl_raw_munmap(addr: *mut c_void, length: size_t) -> c_int;

    //void *__libafl_raw_mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */);
    fn __libafl_raw_mremap(
        old_address: *mut c_void,
        old_size: size_t,
        new_size: size_t,
        flags: c_int,
        new_address: *mut c_void,
    ) -> *mut c_void;

    //int __libafl_raw_mprotect(void *addr, size_t len, int prot);
    fn __libafl_raw_mprotect(addr: *mut c_void, len: size_t, prot: c_int) -> c_int;

    //int __libafl_raw_madvise(void *addr, size_t length, int advice) {
    fn __libafl_raw_madvise(addr: *mut c_void, length: size_t, advice: c_int) -> c_int;
}

/// # Safety
/// Call to functions using syscalls
#[no_mangle]
#[allow(clippy::too_many_lines)]
#[cfg(not(windows))]
pub unsafe extern "C" fn mmap(
    addr: Pointer,
    length: size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: off_t,
) -> Pointer {
    let ctx = Context::get();

    if !ctx.enabled {
        return __libafl_raw_mmap(addr, length, prot, flags, fd, offset) as Pointer;
    }

    // validity checks
    if length == 0 || length % PAGE_SIZE != 0 || (addr as usize) % PAGE_SIZE != 0 {
        #[cfg(target_os = "linux")]
        {
            *libc::__errno_location() = libc::EINVAL;
        }
        return libc::MAP_FAILED as Pointer;
    }

    ctx.disable();

    if addr == 0 as Pointer {
        let mut candidate = None;
        for entry in ctx.mappings.query((0 as Pointer)..(usize::MAX as Pointer)) {
            if entry.value.mapped || entry.value.prot != prot {
                continue;
            }
            if length <= entry.interval.end as usize - entry.interval.start as usize {
                candidate = Some((*entry.interval, entry.value.clone()));
                break;
            }
        }

        let ret = if let Some(cand) = candidate {
            let size = cand.0.end as usize - cand.0.start as usize;
            if length < size {
                ctx.mappings.delete(cand.0);

                let end = cand.0.start.add(length);
                ctx.mappings.insert(
                    cand.0.start..end,
                    Mapping {
                        prot,
                        flags,
                        mapped: true,
                    },
                );

                ctx.mappings.insert(end..cand.0.end, cand.1);
            } else {
                let val = ctx.mappings.query_mut(cand.0).next().unwrap().value;
                val.mapped = true;
                val.flags = flags;
            }

            ptr::write_bytes(cand.0.start, 0, length);

            cand.0.start
        } else {
            let ret = __libafl_raw_mmap(addr, length, prot, flags, fd, offset) as Pointer;

            if ret != libc::MAP_FAILED as Pointer {
                let end = ret.add(length);
                ctx.mappings.insert(
                    ret..end,
                    Mapping {
                        prot,
                        flags,
                        mapped: true,
                    },
                );
            }

            ret
        };

        ctx.enable();

        return ret;
    }

    let end = addr.add(length);

    let mut prev: Option<(_, _)> = None;
    let mut fail = false;
    let mut already_mapped = false;
    let mut reminder = None;

    let mut intervals = vec![]; // TODO put scratch in ctx

    for entry in ctx.mappings.query(addr..end) {
        if let Some(p) = prev {
            if entry.interval.start != p.0 {
                fail = true;
            }
        } else if entry.interval.start > addr {
            fail = true;
        } else if entry.interval.start < addr {
            reminder = Some((entry.interval.start, entry.value.clone()));
        }
        if entry.value.prot != prot {
            fail = true;
        }
        if entry.value.mapped {
            fail = true;
            already_mapped = true;
        }

        intervals.push(*entry.interval);

        prev = Some((entry.interval.end, entry.value));
    }

    let mut reminder_next = None;
    #[allow(clippy::comparison_chain)]
    if let Some(p) = prev.take() {
        if p.0 < end {
            fail = true;
        } else if p.0 > end {
            reminder_next = Some((p.0, p.1.clone()));
        }
    } else {
        fail = true; // new allocation
    }

    for interval in intervals {
        ctx.mappings.delete(interval);
    }

    if let Some(r) = reminder {
        ctx.mappings.insert(r.0..addr, r.1);
    }
    if let Some(r) = reminder_next {
        ctx.mappings.insert(end..r.0, r.1);
    }

    let ret = if fail || fd != -1 {
        if !already_mapped {
            __libafl_raw_munmap(addr, length);
        }

        let ret = __libafl_raw_mmap(addr, length, prot, flags, fd, offset) as Pointer;

        if ret != libc::MAP_FAILED as Pointer {
            ctx.mappings.insert(
                addr..end,
                Mapping {
                    prot,
                    flags,
                    mapped: true,
                },
            );
        }

        ret
    } else {
        ctx.mappings.insert(
            addr..end,
            Mapping {
                prot,
                flags,
                mapped: true,
            },
        );

        ptr::write_bytes(addr, 0, length);

        addr
    };

    // TODO keep track file backed regions

    ctx.enable();

    ret
}

/// # Safety
/// Call to functions using syscalls
#[no_mangle]
pub unsafe extern "C" fn munmap(addr: *mut c_void, length: size_t) -> c_int {
    let ctx = Context::get();

    if !ctx.enabled {
        return __libafl_raw_munmap(addr, length);
    }

    // validity checks
    if length == 0 || (addr as usize) % PAGE_SIZE != 0 {
        #[cfg(target_os = "linux")]
        {
            *libc::__errno_location() = libc::EINVAL;
        }
        return -1;
    }
    let aligned_length = if length % PAGE_SIZE != 0 {
        length + (PAGE_SIZE - length % PAGE_SIZE)
    } else {
        length
    };
    let end = addr.add(aligned_length);

    ctx.disable();

    let mut new_entries: Vec<(Interval<_>, Mapping)> = vec![]; // TODO put scratch in ctx
    let mut intervals = vec![]; // TODO put scratch in ctx

    // TODO unmap file backed regions

    for entry in ctx.mappings.query(addr..end) {
        let rng = Interval::new(
            if entry.interval.start <= addr {
                addr
            } else {
                entry.interval.start
            },
            if entry.interval.end >= end {
                end
            } else {
                entry.interval.end
            },
        );

        let consolidated = if let Some(last) = new_entries.last_mut() {
            // consolidate
            if last.0.end == rng.start && last.1.prot == entry.value.prot {
                last.0.end = rng.end;
                true
            } else {
                false
            }
        } else {
            false
        };

        if entry.interval.start < addr {
            new_entries.push((
                Interval::new(entry.interval.start, addr),
                entry.value.clone(),
            ));
        }

        if !consolidated {
            let mut val = entry.value.clone();
            val.mapped = false;
            new_entries.push((rng, val));
        }

        if entry.interval.end > end {
            new_entries.push((Interval::new(end, entry.interval.end), entry.value.clone()));
        }

        intervals.push(*entry.interval);
    }

    for interval in intervals {
        ctx.mappings.delete(interval);
    }

    for (rng, val) in new_entries {
        ctx.mappings.insert(rng, val);
    }

    ctx.enable();

    0
}

/// # Safety
/// Calling to functions using syscalls
#[no_mangle]
pub unsafe extern "C" fn mprotect(addr: *mut c_void, length: size_t, prot: c_int) -> c_int {
    let ctx = Context::get();

    if !ctx.enabled {
        // in theory it can change perms to a tracked region, in practice we assume not
        return __libafl_raw_mprotect(addr, length, prot);
    }

    let aligned_length = if length % PAGE_SIZE != 0 {
        length + (PAGE_SIZE - length % PAGE_SIZE)
    } else {
        length
    };
    let end = addr.add(aligned_length);

    ctx.disable();

    let mut query_iter = ctx.mappings.query(addr..end);

    if let Some(mut entry) = query_iter.next() {
        // cache the repeated mprotects on the same region
        if entry.interval.start == addr && entry.interval.end == end && entry.value.prot == prot {
            ctx.enable();
            return 0;
        }

        let ret = __libafl_raw_mprotect(addr, length, prot);
        // return on error
        if ret != 0 {
            ctx.enable();
            return ret;
        }

        let mut new_entries: Vec<(Interval<_>, Mapping)> = vec![]; // TODO put scratch in ctx
        let mut intervals = vec![]; // TODO put scratch in ctx

        loop {
            let rng = Interval::new(
                if entry.interval.start <= addr {
                    addr
                } else {
                    entry.interval.start
                },
                if entry.interval.end >= end {
                    end
                } else {
                    entry.interval.end
                },
            );

            let consolidated = if let Some(last) = new_entries.last_mut() {
                // consolidate
                if last.0.end == rng.start && last.1.prot == entry.value.prot {
                    last.0.end = rng.end;
                    true
                } else {
                    false
                }
            } else {
                false
            };

            if entry.interval.start < addr {
                new_entries.push((
                    Interval::new(entry.interval.start, addr),
                    entry.value.clone(),
                ));
            }

            if !consolidated {
                let mut val = entry.value.clone();
                val.prot = prot;
                debug_assert!(val.mapped);
                new_entries.push((rng, val));
            }

            if entry.interval.end > end {
                new_entries.push((Interval::new(end, entry.interval.end), entry.value.clone()));
            }

            intervals.push(*entry.interval);

            if let Some(next) = query_iter.next() {
                entry = next;
            } else {
                break;
            }
        }

        for interval in intervals {
            ctx.mappings.delete(interval);
        }

        for (rng, val) in new_entries {
            ctx.mappings.insert(rng, val);
        }

        ctx.enable();

        0
    } else {
        let ret = __libafl_raw_mprotect(addr, length, prot);
        // return on error
        if ret != 0 {
            ctx.enable();
            return ret;
        }

        ctx.mappings.insert(
            addr..end,
            Mapping {
                prot,
                flags: 0, // TODO what to do with flags?
                mapped: true,
            },
        );

        ctx.enable();
        ret
    }
}

/// # Safety
/// Call to functions using syscalls
#[no_mangle]
#[cfg(not(windows))]
pub unsafe extern "C" fn madvise(addr: *mut c_void, length: size_t, advice: c_int) -> c_int {
    let ctx = Context::get();
    if ctx.enabled && advice == libc::MADV_DONTNEED {
        0
    } else {
        __libafl_raw_madvise(addr, length, advice)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use rusty_fork::rusty_fork_test;

    use super::*;
    // cargo test -- --nocapture --test-threads=1

    rusty_fork_test! {
        #[test]
        fn test_map_unmap_1() {
            unsafe {
                Context::get().enable();

                let p = mmap(0x7ffff9f9e000usize as Pointer, 4096, 0x7, 0x22, 0, 0);
                assert!(p as isize != -1);

                println!("Pre {p:?}", );
                Context::get().print_mappings();

                let r = munmap(p, 1);
                assert!(r == 0);

                println!("Post");
                Context::get().print_mappings();
            }
        }
    }

    rusty_fork_test! {
        #[test]
        fn test_map_unmap_2() {
            unsafe {
                Context::get().enable();

                let p = mmap(0x7ffff9f9e000usize as Pointer, PAGE_SIZE*4, 0x7, 0x22, 0, 0);
                assert!(p as isize != -1);

                println!("Pre {p:?}",);
                Context::get().print_mappings();

                let r = munmap(p.add(PAGE_SIZE), PAGE_SIZE*2);
                assert!(r == 0);

                println!("Post");
                Context::get().print_mappings();
            }
        }
    }

    rusty_fork_test! {
        #[test]
        fn test_map_unmap_3() {
            unsafe {
                Context::get().enable();

                let p = mmap(0x7ffff9f9e000usize as Pointer, PAGE_SIZE*4, 0x7, 0x22, 0, 0);
                assert!(p as isize != -1);

                println!("Pre {p:?}");
                Context::get().print_mappings();

                let r = munmap(p.add(PAGE_SIZE), PAGE_SIZE*2);
                assert!(r == 0);

                println!("Post");
                Context::get().print_mappings();

                let p = mmap(p.add(PAGE_SIZE), PAGE_SIZE, 0x1, 0x22, 0, 0);
                assert!(p as isize != -1);

                println!("Remap {p:?}");
                Context::get().print_mappings();
            }
        }
    }

    rusty_fork_test! {
        #[test]
        fn test_map_unmap_zero_1() {
            unsafe {
                Context::get().enable();

                let p = mmap(0 as Pointer, PAGE_SIZE*4, 0x7, 0x22, 0, 0);
                assert!(p as isize != -1);

                println!("Pre {p:?}");
                Context::get().print_mappings();

                let r = munmap(p.add(PAGE_SIZE), PAGE_SIZE*2);
                assert!(r == 0);

                println!("Post");
                Context::get().print_mappings();

                let p = mmap(0 as Pointer, PAGE_SIZE, 0x7, 0x22, 0, 0);
                assert!(p as isize != -1);

                println!("Remap {p:?}");
                Context::get().print_mappings();
            }
        }
    }
}
