use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum_macros::EnumIter;

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Amd64Regs {
    Rax = 0,
    Rbx = 1,
    Rcx = 2,
    Rdx = 3,
    Rsi = 4,
    Rdi = 5,
    Rbp = 6,
    Rsp = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
    Rip = 16,
    Rflags = 17,
}

/// alias registers
#[allow(non_upper_case_globals)]
impl Amd64Regs {
    pub const Sp: Amd64Regs = Amd64Regs::Rsp;
    pub const Pc: Amd64Regs = Amd64Regs::Rip;
}

#[cfg(feature = "python")]
impl IntoPy<PyObject> for Amd64Regs {
    fn into_py(self, py: Python) -> PyObject {
        let n: i32 = self.into();
        n.into_py(py)
    }
}

#[allow(non_upper_case_globals)]
pub const TARGET_NR_read: i32 = 0;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_write: i32 = 1;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_open: i32 = 2;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_close: i32 = 3;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_stat: i32 = 4;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fstat: i32 = 5;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_lstat: i32 = 6;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_poll: i32 = 7;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_lseek: i32 = 8;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mmap: i32 = 9;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mprotect: i32 = 10;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_munmap: i32 = 11;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_brk: i32 = 12;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_rt_sigaction: i32 = 13;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_rt_sigprocmask: i32 = 14;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_rt_sigreturn: i32 = 15;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_ioctl: i32 = 16;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pread64: i32 = 17;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pwrite64: i32 = 18;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_readv: i32 = 19;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_writev: i32 = 20;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_access: i32 = 21;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pipe: i32 = 22;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_select: i32 = 23;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sched_yield: i32 = 24;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mremap: i32 = 25;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_msync: i32 = 26;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mincore: i32 = 27;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_madvise: i32 = 28;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_shmget: i32 = 29;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_shmat: i32 = 30;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_shmctl: i32 = 31;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_dup: i32 = 32;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_dup2: i32 = 33;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pause: i32 = 34;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_nanosleep: i32 = 35;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getitimer: i32 = 36;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_alarm: i32 = 37;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setitimer: i32 = 38;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getpid: i32 = 39;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sendfile: i32 = 40;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_socket: i32 = 41;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_connect: i32 = 42;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_accept: i32 = 43;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sendto: i32 = 44;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_recvfrom: i32 = 45;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sendmsg: i32 = 46;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_recvmsg: i32 = 47;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_shutdown: i32 = 48;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_bind: i32 = 49;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_listen: i32 = 50;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getsockname: i32 = 51;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getpeername: i32 = 52;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_socketpair: i32 = 53;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setsockopt: i32 = 54;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getsockopt: i32 = 55;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_clone: i32 = 56;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fork: i32 = 57;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_vfork: i32 = 58;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_execve: i32 = 59;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_exit: i32 = 60;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_wait4: i32 = 61;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_kill: i32 = 62;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_uname: i32 = 63;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_semget: i32 = 64;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_semop: i32 = 65;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_semctl: i32 = 66;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_shmdt: i32 = 67;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_msgget: i32 = 68;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_msgsnd: i32 = 69;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_msgrcv: i32 = 70;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_msgctl: i32 = 71;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fcntl: i32 = 72;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_flock: i32 = 73;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fsync: i32 = 74;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fdatasync: i32 = 75;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_truncate: i32 = 76;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_ftruncate: i32 = 77;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getdents: i32 = 78;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getcwd: i32 = 79;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_chdir: i32 = 80;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fchdir: i32 = 81;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_rename: i32 = 82;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mkdir: i32 = 83;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_rmdir: i32 = 84;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_creat: i32 = 85;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_link: i32 = 86;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_unlink: i32 = 87;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_symlink: i32 = 88;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_readlink: i32 = 89;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_chmod: i32 = 90;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fchmod: i32 = 91;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_chown: i32 = 92;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fchown: i32 = 93;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_lchown: i32 = 94;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_umask: i32 = 95;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_gettimeofday: i32 = 96;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getrlimit: i32 = 97;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getrusage: i32 = 98;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sysinfo: i32 = 99;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_times: i32 = 100;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_ptrace: i32 = 101;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getuid: i32 = 102;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_syslog: i32 = 103;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getgid: i32 = 104;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setuid: i32 = 105;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setgid: i32 = 106;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_geteuid: i32 = 107;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getegid: i32 = 108;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setpgid: i32 = 109;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getppid: i32 = 110;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getpgrp: i32 = 111;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setsid: i32 = 112;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setreuid: i32 = 113;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setregid: i32 = 114;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getgroups: i32 = 115;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setgroups: i32 = 116;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setresuid: i32 = 117;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getresuid: i32 = 118;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setresgid: i32 = 119;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getresgid: i32 = 120;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getpgid: i32 = 121;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setfsuid: i32 = 122;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setfsgid: i32 = 123;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getsid: i32 = 124;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_capget: i32 = 125;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_capset: i32 = 126;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_rt_sigpending: i32 = 127;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_rt_sigtimedwait: i32 = 128;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_rt_sigqueueinfo: i32 = 129;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_rt_sigsuspend: i32 = 130;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sigaltstack: i32 = 131;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_utime: i32 = 132;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mknod: i32 = 133;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_uselib: i32 = 134;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_personality: i32 = 135;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_ustat: i32 = 136;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_statfs: i32 = 137;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fstatfs: i32 = 138;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sysfs: i32 = 139;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getpriority: i32 = 140;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setpriority: i32 = 141;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sched_setparam: i32 = 142;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sched_getparam: i32 = 143;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sched_setscheduler: i32 = 144;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sched_getscheduler: i32 = 145;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sched_get_priority_max: i32 = 146;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sched_get_priority_min: i32 = 147;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sched_rr_get_interval: i32 = 148;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mlock: i32 = 149;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_munlock: i32 = 150;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mlockall: i32 = 151;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_munlockall: i32 = 152;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_vhangup: i32 = 153;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_modify_ldt: i32 = 154;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pivot_root: i32 = 155;
#[allow(non_upper_case_globals)]
pub const TARGET_NR__sysctl: i32 = 156;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_prctl: i32 = 157;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_arch_prctl: i32 = 158;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_adjtimex: i32 = 159;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setrlimit: i32 = 160;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_chroot: i32 = 161;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sync: i32 = 162;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_acct: i32 = 163;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_settimeofday: i32 = 164;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mount: i32 = 165;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_umount2: i32 = 166;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_swapon: i32 = 167;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_swapoff: i32 = 168;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_reboot: i32 = 169;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sethostname: i32 = 170;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setdomainname: i32 = 171;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_iopl: i32 = 172;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_ioperm: i32 = 173;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_create_module: i32 = 174;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_init_module: i32 = 175;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_delete_module: i32 = 176;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_get_kernel_syms: i32 = 177;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_query_module: i32 = 178;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_quotactl: i32 = 179;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_nfsservctl: i32 = 180;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getpmsg: i32 = 181;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_putpmsg: i32 = 182;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_afs_syscall: i32 = 183;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_tuxcall: i32 = 184;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_security: i32 = 185;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_gettid: i32 = 186;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_readahead: i32 = 187;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setxattr: i32 = 188;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_lsetxattr: i32 = 189;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fsetxattr: i32 = 190;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getxattr: i32 = 191;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_lgetxattr: i32 = 192;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fgetxattr: i32 = 193;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_listxattr: i32 = 194;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_llistxattr: i32 = 195;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_flistxattr: i32 = 196;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_removexattr: i32 = 197;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_lremovexattr: i32 = 198;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fremovexattr: i32 = 199;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_tkill: i32 = 200;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_time: i32 = 201;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_futex: i32 = 202;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sched_setaffinity: i32 = 203;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sched_getaffinity: i32 = 204;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_set_thread_area: i32 = 205;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_io_setup: i32 = 206;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_io_destroy: i32 = 207;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_io_getevents: i32 = 208;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_io_submit: i32 = 209;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_io_cancel: i32 = 210;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_get_thread_area: i32 = 211;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_lookup_dcookie: i32 = 212;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_epoll_create: i32 = 213;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_epoll_ctl_old: i32 = 214;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_epoll_wait_old: i32 = 215;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_remap_file_pages: i32 = 216;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getdents64: i32 = 217;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_set_tid_address: i32 = 218;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_restart_syscall: i32 = 219;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_semtimedop: i32 = 220;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fadvise64: i32 = 221;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_timer_create: i32 = 222;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_timer_settime: i32 = 223;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_timer_gettime: i32 = 224;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_timer_getoverrun: i32 = 225;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_timer_delete: i32 = 226;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_clock_settime: i32 = 227;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_clock_gettime: i32 = 228;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_clock_getres: i32 = 229;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_clock_nanosleep: i32 = 230;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_exit_group: i32 = 231;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_epoll_wait: i32 = 232;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_epoll_ctl: i32 = 233;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_tgkill: i32 = 234;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_utimes: i32 = 235;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_vserver: i32 = 236;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mbind: i32 = 237;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_set_mempolicy: i32 = 238;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_get_mempolicy: i32 = 239;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mq_open: i32 = 240;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mq_unlink: i32 = 241;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mq_timedsend: i32 = 242;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mq_timedreceive: i32 = 243;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mq_notify: i32 = 244;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mq_getsetattr: i32 = 245;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_kexec_load: i32 = 246;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_waitid: i32 = 247;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_add_key: i32 = 248;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_request_key: i32 = 249;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_keyctl: i32 = 250;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_ioprio_set: i32 = 251;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_ioprio_get: i32 = 252;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_inotify_init: i32 = 253;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_inotify_add_watch: i32 = 254;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_inotify_rm_watch: i32 = 255;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_migrate_pages: i32 = 256;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_openat: i32 = 257;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mkdirat: i32 = 258;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mknodat: i32 = 259;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fchownat: i32 = 260;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_futimesat: i32 = 261;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_newfstatat: i32 = 262;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_unlinkat: i32 = 263;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_renameat: i32 = 264;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_linkat: i32 = 265;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_symlinkat: i32 = 266;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_readlinkat: i32 = 267;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fchmodat: i32 = 268;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_faccessat: i32 = 269;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pselect6: i32 = 270;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_ppoll: i32 = 271;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_unshare: i32 = 272;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_set_robust_list: i32 = 273;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_get_robust_list: i32 = 274;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_splice: i32 = 275;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_tee: i32 = 276;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sync_file_range: i32 = 277;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_vmsplice: i32 = 278;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_move_pages: i32 = 279;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_utimensat: i32 = 280;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_epoll_pwait: i32 = 281;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_signalfd: i32 = 282;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_timerfd_create: i32 = 283;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_eventfd: i32 = 284;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fallocate: i32 = 285;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_timerfd_settime: i32 = 286;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_timerfd_gettime: i32 = 287;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_accept4: i32 = 288;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_signalfd4: i32 = 289;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_eventfd2: i32 = 290;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_epoll_create1: i32 = 291;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_dup3: i32 = 292;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pipe2: i32 = 293;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_inotify_init1: i32 = 294;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_preadv: i32 = 295;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pwritev: i32 = 296;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_rt_tgsigqueueinfo: i32 = 297;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_perf_event_open: i32 = 298;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_recvmmsg: i32 = 299;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fanotify_init: i32 = 300;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fanotify_mark: i32 = 301;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_prlimit64: i32 = 302;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_name_to_handle_at: i32 = 303;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_open_by_handle_at: i32 = 304;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_clock_adjtime: i32 = 305;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_syncfs: i32 = 306;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sendmmsg: i32 = 307;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_setns: i32 = 308;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getcpu: i32 = 309;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_process_vm_readv: i32 = 310;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_process_vm_writev: i32 = 311;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_kcmp: i32 = 312;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_finit_module: i32 = 313;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sched_setattr: i32 = 314;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_sched_getattr: i32 = 315;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_renameat2: i32 = 316;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_seccomp: i32 = 317;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_getrandom: i32 = 318;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_memfd_create: i32 = 319;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_kexec_file_load: i32 = 320;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_bpf: i32 = 321;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_execveat: i32 = 322;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_userfaultfd: i32 = 323;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_membarrier: i32 = 324;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_mlock2: i32 = 325;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_copy_file_range: i32 = 326;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_preadv2: i32 = 327;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pwritev2: i32 = 328;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pkey_mprotect: i32 = 329;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pkey_alloc: i32 = 330;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pkey_free: i32 = 331;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_statx: i32 = 332;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_io_pgetevents: i32 = 333;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_rseq: i32 = 334;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pidfd_send_signal: i32 = 424;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_io_uring_setup: i32 = 425;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_io_uring_enter: i32 = 426;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_io_uring_register: i32 = 427;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_open_tree: i32 = 428;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_move_mount: i32 = 429;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fsopen: i32 = 430;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fsconfig: i32 = 431;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fsmount: i32 = 432;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_fspick: i32 = 433;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pidfd_open: i32 = 434;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_clone3: i32 = 435;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_close_range: i32 = 436;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_openat2: i32 = 437;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_pidfd_getfd: i32 = 438;
#[allow(non_upper_case_globals)]
pub const TARGET_NR_faccessat2: i32 = 439;
