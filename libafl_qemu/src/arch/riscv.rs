use core::ffi::c_long;
use std::sync::OnceLock;

use capstone::arch::BuildsCapstone;
use enum_map::{enum_map, EnumMap};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;
#[cfg(feature = "riscv64")]
pub use syscall_numbers::riscv64::*;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
/// RISCV 32bit syscalls are not currently supported by the `syscall_numbers` crate, so we just paste this here for now.
/// These are all the syscalls which can be found in 32 and 64 bit.
/// NOTE: We are missing some syscalls which are only available in 32 bit mode.
/// <https://github.com/qemu/qemu/blob/3665dd6bb9043bef181c91e2dce9e1efff47ed51/linux-user/riscv/syscall32_nr.h>
pub use syscall_numbers::riscv64::{
    SYS_accept, SYS_accept4, SYS_acct, SYS_add_key, SYS_arch_specific_syscall, SYS_bind, SYS_bpf,
    SYS_brk, SYS_capget, SYS_capset, SYS_chdir, SYS_chroot, SYS_clone, SYS_clone3, SYS_close,
    SYS_close_range, SYS_connect, SYS_copy_file_range, SYS_delete_module, SYS_dup, SYS_dup3,
    SYS_epoll_create1, SYS_epoll_ctl, SYS_epoll_pwait, SYS_epoll_pwait2, SYS_eventfd2, SYS_execve,
    SYS_execveat, SYS_exit, SYS_exit_group, SYS_faccessat, SYS_faccessat2, SYS_fallocate,
    SYS_fanotify_init, SYS_fanotify_mark, SYS_fchdir, SYS_fchmod, SYS_fchmodat, SYS_fchown,
    SYS_fchownat, SYS_fdatasync, SYS_fgetxattr, SYS_finit_module, SYS_flistxattr, SYS_flock,
    SYS_fremovexattr, SYS_fsconfig, SYS_fsetxattr, SYS_fsmount, SYS_fsopen, SYS_fspick, SYS_fsync,
    SYS_get_mempolicy, SYS_get_robust_list, SYS_getcpu, SYS_getcwd, SYS_getdents64, SYS_getegid,
    SYS_geteuid, SYS_getgid, SYS_getgroups, SYS_getitimer, SYS_getpeername, SYS_getpgid,
    SYS_getpid, SYS_getppid, SYS_getpriority, SYS_getrandom, SYS_getresgid, SYS_getresuid,
    SYS_getrlimit, SYS_getrusage, SYS_getsid, SYS_getsockname, SYS_getsockopt, SYS_gettid,
    SYS_getuid, SYS_getxattr, SYS_init_module, SYS_inotify_add_watch, SYS_inotify_init1,
    SYS_inotify_rm_watch, SYS_io_cancel, SYS_io_destroy, SYS_io_setup, SYS_io_submit,
    SYS_io_uring_enter, SYS_io_uring_register, SYS_io_uring_setup, SYS_ioctl, SYS_ioprio_get,
    SYS_ioprio_set, SYS_kcmp, SYS_kexec_file_load, SYS_kexec_load, SYS_keyctl, SYS_kill,
    SYS_landlock_add_rule, SYS_landlock_create_ruleset, SYS_landlock_restrict_self, SYS_lgetxattr,
    SYS_linkat, SYS_listen, SYS_listxattr, SYS_llistxattr, SYS_lookup_dcookie, SYS_lremovexattr,
    SYS_lsetxattr, SYS_madvise, SYS_mbind, SYS_membarrier, SYS_memfd_create, SYS_migrate_pages,
    SYS_mincore, SYS_mkdirat, SYS_mknodat, SYS_mlock, SYS_mlock2, SYS_mlockall, SYS_mount,
    SYS_mount_setattr, SYS_move_mount, SYS_move_pages, SYS_mprotect, SYS_mq_getsetattr,
    SYS_mq_notify, SYS_mq_open, SYS_mq_unlink, SYS_mremap, SYS_msgctl, SYS_msgget, SYS_msgrcv,
    SYS_msgsnd, SYS_msync, SYS_munlock, SYS_munlockall, SYS_munmap, SYS_name_to_handle_at,
    SYS_nfsservctl, SYS_open_by_handle_at, SYS_open_tree, SYS_openat, SYS_openat2,
    SYS_perf_event_open, SYS_personality, SYS_pidfd_getfd, SYS_pidfd_open, SYS_pidfd_send_signal,
    SYS_pipe2, SYS_pivot_root, SYS_pkey_alloc, SYS_pkey_free, SYS_pkey_mprotect, SYS_prctl,
    SYS_pread64, SYS_preadv, SYS_preadv2, SYS_prlimit64, SYS_process_madvise, SYS_process_vm_readv,
    SYS_process_vm_writev, SYS_ptrace, SYS_pwrite64, SYS_pwritev, SYS_pwritev2, SYS_quotactl,
    SYS_read, SYS_readahead, SYS_readlinkat, SYS_readv, SYS_reboot, SYS_recvfrom, SYS_recvmsg,
    SYS_remap_file_pages, SYS_removexattr, SYS_renameat2, SYS_request_key, SYS_restart_syscall,
    SYS_rseq, SYS_rt_sigaction, SYS_rt_sigpending, SYS_rt_sigprocmask, SYS_rt_sigqueueinfo,
    SYS_rt_sigreturn, SYS_rt_sigsuspend, SYS_rt_tgsigqueueinfo, SYS_sched_get_priority_max,
    SYS_sched_get_priority_min, SYS_sched_getaffinity, SYS_sched_getattr, SYS_sched_getparam,
    SYS_sched_getscheduler, SYS_sched_setaffinity, SYS_sched_setattr, SYS_sched_setparam,
    SYS_sched_setscheduler, SYS_sched_yield, SYS_seccomp, SYS_semctl, SYS_semget, SYS_semop,
    SYS_sendmmsg, SYS_sendmsg, SYS_sendto, SYS_set_mempolicy, SYS_set_robust_list,
    SYS_set_tid_address, SYS_setdomainname, SYS_setfsgid, SYS_setfsuid, SYS_setgid, SYS_setgroups,
    SYS_sethostname, SYS_setitimer, SYS_setns, SYS_setpgid, SYS_setpriority, SYS_setregid,
    SYS_setresgid, SYS_setresuid, SYS_setreuid, SYS_setrlimit, SYS_setsid, SYS_setsockopt,
    SYS_setuid, SYS_setxattr, SYS_shmat, SYS_shmctl, SYS_shmdt, SYS_shmget, SYS_shutdown,
    SYS_sigaltstack, SYS_signalfd4, SYS_socket, SYS_socketpair, SYS_splice, SYS_statx, SYS_swapoff,
    SYS_swapon, SYS_symlinkat, SYS_sync, SYS_sync_file_range, SYS_syncfs, SYS_sysinfo, SYS_syslog,
    SYS_tee, SYS_tgkill, SYS_timer_create, SYS_timer_delete, SYS_timer_getoverrun,
    SYS_timerfd_create, SYS_times, SYS_tkill, SYS_umask, SYS_umount2, SYS_uname, SYS_unlinkat,
    SYS_unshare, SYS_userfaultfd, SYS_vhangup, SYS_vmsplice, SYS_waitid, SYS_write, SYS_writev,
};
#[allow(non_upper_case_globals)]
pub const SYS_syscalls: c_long = 447;
#[allow(non_upper_case_globals)]
pub const SYS_riscv_flush_icache: c_long = SYS_arch_specific_syscall + 15;
#[allow(non_upper_case_globals)]
pub const SYS_riscv_hwprobe: c_long = SYS_arch_specific_syscall + 14;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_clock_adjtime64: c_long = 405;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_clock_getres_time64: c_long = 406;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_clock_gettime64: c_long = 403;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_clock_nanosleep_time64: c_long = 407;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_clock_settime64: c_long = 404;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_fadvise64_64: c_long = 223;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_fcntl64: c_long = 25;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_fstat64: c_long = 80;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_fstatat64: c_long = 79;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_fstatfs64: c_long = 44;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_ftruncate64: c_long = 46;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_futex_time64: c_long = 422;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_io_pgetevents_time64: c_long = 416;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_llseek: c_long = 62;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_mmap2: c_long = 222;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_mq_timedreceive_time64: c_long = 419;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_mq_timedsend_time64: c_long = 418;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_ppoll_time64: c_long = 414;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_pselect6_time64: c_long = 413;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_recvmmsg_time64: c_long = 417;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_rt_sigtimedwait_time64: c_long = 421;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_sched_rr_get_interval_time64: c_long = 423;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_semtimedop_time64: c_long = 420;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_sendfile64: c_long = 71;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_statfs64: c_long = 43;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_timer_gettime64: c_long = 408;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_timer_settime64: c_long = 409;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_timerfd_gettime64: c_long = 410;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_timerfd_settime64: c_long = 411;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_truncate64: c_long = 45;
#[cfg(feature = "riscv32")]
#[allow(non_upper_case_globals)]
pub const SYS_utimensat_time64: c_long = 412;

use crate::{sync_exit::ExitArgs, CallingConvention, QemuRWError, QemuRWErrorKind};

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Regs {
    Zero = 0, // x0: Hardwired zero
    Ra = 1,   // x1: Return address
    Sp = 2,   // x2: Stack pointer
    Gp = 3,   // x3: Global pointer
    Tp = 4,   // x4: Thread pointer
    T0 = 5,   // x5: Temporary register
    T1 = 6,   // x6: Temporary register
    T2 = 7,   // x7: Temporary register
    FP = 8,   // x8: Saved register / frame pointer
    S1 = 9,   // x9: Saved register
    A0 = 10,  // x10: Function argument / return value
    A1 = 11,  // x11: Function argument / return value
    A2 = 12,  // x12: Function argument
    A3 = 13,  // x13: Function argument
    A4 = 14,  // x14: Function argument
    A5 = 15,  // x15: Function argument
    A6 = 16,  // x16: Function argument
    A7 = 17,  // x17: Function argument
    S2 = 18,  // x18: Saved register
    S3 = 19,  // x19: Saved register
    S4 = 20,  // x20: Saved register
    S5 = 21,  // x21: Saved register
    S6 = 22,  // x22: Saved register
    S7 = 23,  // x23: Saved register
    S8 = 24,  // x24: Saved register
    S9 = 25,  // x25: Saved register
    S10 = 26, // x26: Saved register
    S11 = 27, // x27: Saved register
    T3 = 28,  // x28: Temporary register
    T4 = 29,  // x29: Temporary register
    T5 = 30,  // x30: Temporary register
    T6 = 31,  // x31: Temporary register
    Pc = 32,  // Program Counter (code pointer not actual register)
}

static EXIT_ARCH_REGS: OnceLock<EnumMap<ExitArgs, Regs>> = OnceLock::new();

pub fn get_exit_arch_regs() -> &'static EnumMap<ExitArgs, Regs> {
    EXIT_ARCH_REGS.get_or_init(|| {
        enum_map! {
            ExitArgs::Ret  => Regs::A0,
            ExitArgs::Cmd  => Regs::A0,
            ExitArgs::Arg1 => Regs::A1,
            ExitArgs::Arg2 => Regs::A2,
            ExitArgs::Arg3 => Regs::A3,
            ExitArgs::Arg4 => Regs::A4,
            ExitArgs::Arg5 => Regs::A5,
            ExitArgs::Arg6 => Regs::A6,
        }
    })
}

#[cfg(not(feature = "riscv64"))]
pub type GuestReg = u32;
#[cfg(feature = "riscv64")]
pub type GuestReg = u64;

/// Return a RISCV ArchCapstoneBuilder
pub fn capstone() -> capstone::arch::riscv::ArchCapstoneBuilder {
    #[cfg(not(feature = "riscv64"))]
    return capstone::Capstone::new()
        .riscv()
        .mode(capstone::arch::riscv::ArchMode::RiscV32);
    #[cfg(feature = "riscv64")]
    return capstone::Capstone::new()
        .riscv()
        .mode(capstone::arch::riscv::ArchMode::RiscV64);
}

impl crate::ArchExtras for crate::CPU {
    fn read_return_address<T>(&self) -> Result<T, QemuRWError>
    where
        T: From<GuestReg>,
    {
        self.read_reg(Regs::Ra)
    }

    fn write_return_address<T>(&self, val: T) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        self.write_reg(Regs::Ra, val)
    }

    fn read_function_argument<T>(&self, conv: CallingConvention, idx: u8) -> Result<T, QemuRWError>
    where
        T: From<GuestReg>,
    {
        QemuRWError::check_conv(QemuRWErrorKind::Read, CallingConvention::Cdecl, conv)?;

        // Note that 64 bit values may be passed in two registers (and are even-odd eg. A0, A2 and A3 where A1 is empty), then this mapping is off.
        // Note: This does not consider the floating point registers.
        // See https://riscv.org/wp-content/uploads/2015/01/riscv-calling.pdf
        let reg_id = match idx {
            0 => Regs::A0, // argument / return value
            1 => Regs::A1, // argument / return value
            2 => Regs::A2, // argument value
            3 => Regs::A3, // argument value
            4 => Regs::A4, // argument value
            5 => Regs::A5, // argument value
            6 => Regs::A6, // argument value
            7 => Regs::A7, // argument value
            r => {
                return Err(QemuRWError::new_argument_error(
                    QemuRWErrorKind::Read,
                    i32::from(r),
                ))
            }
        };

        self.read_reg(reg_id)
    }

    fn write_function_argument<T>(
        &self,
        conv: CallingConvention,
        idx: i32,
        val: T,
    ) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        QemuRWError::check_conv(QemuRWErrorKind::Write, CallingConvention::Cdecl, conv)?;

        let val: GuestReg = val.into();
        match idx {
            0 => self.write_reg(Regs::A0, val), // argument / return value
            1 => self.write_reg(Regs::A1, val), // argument / return value
            r => Err(QemuRWError::new_argument_error(QemuRWErrorKind::Write, r)),
        }
    }
}
