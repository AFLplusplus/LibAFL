//! AFL++ style TSL caching

use std::{
    fmt::Debug,
    fs::File,
    io::{Read, Write},
    marker::PhantomData,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        raw::c_int,
    },
    process,
};

use libafl_bolts::{any_as_bytes, any_as_bytes_mut, tuples::MatchFirstType};
use libafl_qemu::{
    BlockExecHook, BlockGenHook, BlockPostGenHook, CPU, EmulatorModules, GuestAddr, Qemu,
    modules::{
        EmulatorModule, EmulatorModuleTuple,
        utils::filters::{HasAddressFilter, NopAddressFilter},
    },
    sys::{GuestUsize, GuestVirtAddr, TranslationBlock},
};
use libafl_targets::{FORKSRV_FD, ForkserverHook};
use nix::{
    libc,
    sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction},
    unistd::{Pid, close, dup2, pipe},
};

/// Forkserver tsl file descriptor.
/// Save as aflpp's tsl fd.
pub const TSL_FD: i32 = (FORKSRV_FD as i32) - 1;

#[derive(Clone, Debug, Default)]
struct TslTb {
    pc: GuestVirtAddr,
    cs_base: u64,
    flags: u32,
    cflags: u32,
}

#[derive(Clone, Debug, Default)]
struct TslChain {
    last_tb: TslTb,
    tb_exit: i32,
}

#[derive(Clone, Debug, Default)]
struct TslRequest {
    tb: TslTb,
    chain: Option<TslChain>,
}

/// Forkserver hook responsible for sending (in child) and receiving (in parent) tsl requests.
#[derive(Debug)]
pub struct TSLForkserverHook {
    tsl_read_file: Option<File>,
}

/// Emulator module hooking qemu generated blocks, and transfering the requests to the forkserver hook.
/// Must be created through [`TSLForkserverHook`].
#[derive(Debug)]
pub struct TSLModule<I, S> {
    addr_filter: NopAddressFilter,
    tsl_write_file: Option<File>,
    phantom: PhantomData<(I, S)>,
}

extern "C" fn close_tsl_fd() {}

impl<I, S> TSLModule<I, S> {
    /// Create a new [`TSLModule`] from a [`TSLForkserverHook`].
    pub fn new() -> Self {
        Self {
            addr_filter: NopAddressFilter,
            phantom: PhantomData,
            tsl_write_file: None,
        }
    }
}

impl TSLForkserverHook {
    pub fn new() -> Self {
        TSLForkserverHook {
            tsl_read_file: None,
        }
    }

    /// Collect tsl requests, and perform them on reception.
    pub fn wait_tsl(&mut self, qemu: Qemu, cpu: CPU) {
        let mut tsl_request = TslRequest::default();

        loop {
            unsafe {
                match self
                    .tsl_read_file
                    .as_mut()
                    .unwrap_unchecked()
                    .read(any_as_bytes_mut(&mut tsl_request))
                {
                    Ok(nbytes) => {
                        // Read is correct, handle the request.
                        if nbytes == 0 {
                            // child process is dead, we can end the loop
                            break;
                        }

                        assert_eq!(nbytes, size_of_val(&tsl_request))
                    }
                    Err(read_err) => match read_err.kind() {
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::Interrupted => {
                            break;
                        }
                        _ => {
                            panic!("Unexpected error while reading tsl request: {read_err:?}")
                        }
                    },
                }
            }

            let mut valid_pc = true;

            // check if the tb exist
            let mut tb = unsafe {
                qemu.tb_lookup(
                    cpu,
                    tsl_request.tb.pc,
                    tsl_request.tb.cs_base,
                    tsl_request.tb.flags,
                    tsl_request.tb.cflags,
                )
            };

            if tb.is_null() {
                if qemu.is_valid_addr(tsl_request.tb.pc) {
                    // if it does not exist and the address is valid, generate the cached tb

                    tb = unsafe {
                        qemu.tb_gen_code(
                            cpu,
                            tsl_request.tb.pc,
                            tsl_request.tb.cs_base,
                            tsl_request.tb.flags,
                            tsl_request.tb.cflags as i32,
                        )
                    };
                } else {
                    valid_pc = false;
                }
            }

            debug_assert!(!tb.is_null());

            if valid_pc {
                // if pc was valid, try to chain blocks when possible
                if let Some(chain) = &tsl_request.chain {
                    let last_tb = unsafe {
                        qemu.tb_lookup(
                            cpu,
                            chain.last_tb.pc,
                            chain.last_tb.cs_base,
                            chain.last_tb.flags,
                            chain.last_tb.cflags,
                        )
                    };

                    unsafe {
                        if !last_tb.is_null()
                            && ((*last_tb).jmp_reset_offset[chain.tb_exit as usize]
                                != libafl_qemu_sys::TB_JMP_OFFSET_INVALID as u16)
                        {
                            qemu.tb_add_jump(last_tb, chain.tb_exit, tb);
                        }
                    }
                }
            }
        }
    }
}

extern "C" fn parent_sigchld_handler(_: c_int) {}

impl ForkserverHook for TSLForkserverHook {
    fn pre_fork(&mut self) {
        // setup the tsl communication channel
        let (read_fd, write_fd) = pipe().unwrap();

        // dup write fd to a known value.
        let _tsl_fd = dup2(write_fd.as_raw_fd(), TSL_FD as RawFd).unwrap();

        // set read fd in forkserver hook.
        self.tsl_read_file = Some(File::from(read_fd));
    }

    fn post_parent_fork(&mut self, _pid: Pid) {
        // drop write fd in child
        close(TSL_FD).unwrap();
    }

    fn post_child_fork(&mut self) {
        // drop read fd in child
        self.tsl_read_file.take();
    }

    fn pre_parent_wait(&mut self) {
        // at this point, QEMU should be correctly initialized,
        // and the current CPU should be the one running the target.
        let qemu = Qemu::get().unwrap();
        let cpu = qemu.current_cpu().unwrap();

        self.wait_tsl(qemu, cpu);
    }
}

fn tsl_block_post_gen_hook<ET, I, S>(
    _qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    _block_length: GuestUsize,
    tb: *const TranslationBlock,
    last_tb: *const TranslationBlock,
    tb_exit: i32,
) where
    ET: MatchFirstType + Unpin,
    I: Unpin + 'static,
    S: Unpin + 'static,
{
    let module =
        MatchFirstType::match_first_type_mut::<TSLModule<I, S>>(emulator_modules.modules_mut())
            .unwrap();

    // Collect TB and last TB important data
    let tsl_request = unsafe {
        let tb = TslTb {
            pc,
            cs_base: (*tb).cs_base,
            flags: (*tb).flags,
            cflags: (*tb).cflags,
        };

        let chain = if !last_tb.is_null() {
            Some(TslChain {
                last_tb: TslTb {
                    pc: (*last_tb).pc,
                    cs_base: (*last_tb).cs_base,
                    flags: (*last_tb).flags,
                    // WARNING: this differs from original tsl implementation
                    // it is using tb cflags, and not last_tb cflags. I think this is a bug,
                    // so I use the other one there.
                    cflags: (*last_tb).cflags,
                },
                tb_exit,
            })
        } else {
            None
        };

        TslRequest { tb, chain }
    };

    // request tsl to the forkserver
    unsafe {
        module
            .tsl_write_file
            .as_mut()
            .unwrap_unchecked()
            .write_all(any_as_bytes(&tsl_request))
            .unwrap();
    }
}

impl<I, S> EmulatorModule<I, S> for TSLModule<I, S>
where
    I: Debug + Unpin + 'static,
    S: Debug + Unpin + 'static,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        unsafe {
            self.tsl_write_file = Some(File::from_raw_fd(TSL_FD));
            libc::atexit(close_tsl_fd);
        }

        emulator_modules.blocks(
            BlockGenHook::Empty,
            BlockPostGenHook::Function(tsl_block_post_gen_hook),
            BlockExecHook::Empty,
        );
    }
}

impl<I, S> HasAddressFilter for TSLModule<I, S> {
    type AddressFilter = NopAddressFilter;

    fn address_filter(&self) -> &Self::AddressFilter {
        &self.addr_filter
    }

    fn address_filter_mut(&mut self) -> &mut Self::AddressFilter {
        &mut self.addr_filter
    }
}
