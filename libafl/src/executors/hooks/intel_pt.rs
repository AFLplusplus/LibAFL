// TODO: docs
#![allow(missing_docs)]

use std::{
    borrow::ToOwned,
    convert::Into,
    ffi::CString,
    fs,
    ops::Range,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        raw::c_void,
    },
    path::Path,
    process, ptr, slice,
    string::String,
    sync::LazyLock,
    vec::Vec,
};

use arbitrary_int::u4;
use bitbybit::bitfield;
use caps::{CapSet, Capability};
use libafl_bolts::ownedref::OwnedRefMut;
use libipt::{
    block::BlockDecoder, AddrConfig, AddrFilter, AddrFilterBuilder, AddrRange, Asid, BlockFlags,
    ConfigBuilder, Cpu, Image, SectionCache,
};
use num_enum::TryFromPrimitive;
use perf_event_open_sys::{
    bindings::{perf_event_attr, perf_event_mmap_page, PERF_FLAG_FD_CLOEXEC},
    ioctls::{DISABLE, ENABLE, SET_FILTER},
    perf_event_open,
};
use proc_maps::get_process_maps;
use raw_cpuid::CpuId;
use serde::Serialize;

use crate::{
    executors::{command::SerdeAnyi32, hooks::ExecutorHook, HasObservers},
    inputs::UsesInput,
    state::HasCorpus,
    std::string::ToString,
    Error, HasNamedMetadata,
};

const PAGE_SIZE: usize = 4096;
// TODO parametrize buffer sizes?
const PERF_BUFFER_SIZE: usize = (1 + (1 << 7)) * PAGE_SIZE;
const PERF_AUX_BUFFER_SIZE: usize = 2 * 1024 * 1024;
const PT_EVENT_PATH: &str = "/sys/bus/event_source/devices/intel_pt";

static PERF_EVENT_TYPE: LazyLock<Result<u32, String>> = LazyLock::new(|| {
    let path = format!("{PT_EVENT_PATH}/type");
    let s = fs::read_to_string(&path)
        .map_err(|_| format!("Failed to read Intel PT perf event type from {path}"))?;
    s.trim()
        .parse::<u32>()
        .map_err(|_| format!("Failed to parse Intel PT perf event type in {path}"))
});

// TODO: when polishing the API move this to a caps module mimicking /sys/bus/event_source/devices/intel_pt/caps ?
static NUM_OF_ADDR_FILTERS: LazyLock<Result<u32, String>> = LazyLock::new(|| {
    let path = format!("{PT_EVENT_PATH}/nr_addr_filters");
    let s = fs::read_to_string(&path)
        .map_err(|_| format!("Failed to read Intel PT number of address filters from {path}"))?;
    s.trim()
        .parse::<u32>()
        .map_err(|_| format!("Failed to parse Intel PT number of address filters in {path}"))
});

static CURRENT_CPU: LazyLock<Option<Cpu>> = LazyLock::new(|| {
    let cpuid = CpuId::new();
    cpuid
        .get_feature_info()
        .map(|fi| Cpu::intel(fi.family_id().into(), fi.model_id(), fi.stepping_id()))
});

#[derive(TryFromPrimitive, Debug)]
#[repr(i32)]
enum KvmPTMode {
    System = 0,
    HostGuest = 1,
}

/// Perf event config for `IntelPT`
///
/// (This is almost mapped to `IA32_RTIT_CTL MSR` by perf)
#[bitfield(u64, default = 0)]
struct PtConfig {
    /// Disable call return address compression. AKA DisRETC in Intel SDM
    #[bit(11, rw)]
    noretcomp: bool,
    #[bits(24..=27, rw)]
    psb_period: u4,
}

// TODO generic decoder: D,
#[derive(Debug)]
pub struct IntelPT {
    fd: OwnedFd,
    perf_buffer: *mut c_void,
    perf_aux_buffer: *mut c_void,
    aux_head: *mut u64,
    aux_tail: *mut u64,
    previous_decode_head: u64,
    ip_filters: Vec<Range<usize>>,
}

#[derive(Debug)]
pub struct IntelPTBuilder {
    pid: Option<libc::pid_t>,
    exclude_kernel: bool,
}

#[derive(Debug)]
pub struct IntelPTHook {
    pt: Option<IntelPT>,
    image: Option<Image<'static>>,
    image_cache: Option<SectionCache<'static>>,
    map: *mut u8,
    len: usize,
}

#[derive(Debug)]
pub struct IntelPTChildHook {
    pt: Option<IntelPT>,
    image: Option<Image<'static>>,
    image_cache: Option<SectionCache<'static>>,
    ip_filters: Vec<Range<usize>>,
    map: *mut u8,
    len: usize,
}

impl IntelPTChildHook {
    pub fn new(map: *mut u8, len: usize, ip_filters: &[Range<usize>]) -> Self {
        Self {
            pt: None,
            image: None,
            image_cache: None,
            ip_filters: ip_filters.to_vec(),
            map,
            len,
        }
    }
}

// TODO remove some S traits
impl<S> ExecutorHook<S> for IntelPTChildHook
where
    S: UsesInput + Serialize + HasNamedMetadata + HasCorpus,
    S::Corpus: core::fmt::Debug,
{
    fn init<E: HasObservers>(&mut self, _state: &mut S) {
        assert!(self.image.is_none(), "Intel PT image was already set up");
        assert!(
            self.image_cache.is_none(),
            "Intel PT cache was already set up"
        );
        let mut image_cache = SectionCache::new(Some("image_cache")).unwrap();
        let mut image = Image::new(Some("image")).unwrap();
        let pid: SerdeAnyi32 = *_state
            .named_metadata_map()
            .get("child")
            .expect("Child pid not in state metadata");

        let maps = get_process_maps(pid.inner).unwrap();
        for map in maps {
            if map.is_exec() && map.filename().is_some() {
                if let Ok(isid) = image_cache.add_file(
                    map.filename().unwrap().to_str().unwrap(),
                    map.offset as u64,
                    map.size() as u64,
                    map.start() as u64,
                ) {
                    image
                        .add_cached(&mut image_cache, isid, Asid::default())
                        .unwrap();
                    println!(
                        "{}\toffset: {:x}\tsize: {:x}\t start: {:x}",
                        map.filename().unwrap().to_str().unwrap(),
                        map.offset as u64,
                        map.size() as u64,
                        map.start() as u64,
                    );
                }
            }
        }

        self.image_cache = Some(image_cache);
        self.image = Some(image);
    }

    #[allow(clippy::cast_possible_wrap)]
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) {
        assert!(self.pt.is_none(), "Intel PT was already set up");

        let pid: SerdeAnyi32 = *_state
            .named_metadata_map()
            .get("child")
            .expect("Child pid not in state metadata");

        let pt_builder = IntelPT::builder().pid(Some(pid.inner));
        self.pt = Some(pt_builder.build().unwrap());
        self.pt
            .as_mut()
            .unwrap()
            .set_ip_filters(&self.ip_filters)
            .unwrap();
        self.pt.as_mut().unwrap().enable_tracing().unwrap();
    }

    #[allow(clippy::cast_possible_wrap)]
    fn post_exec(&mut self, _state: &mut S, _input: &S::Input) {
        let pt = self.pt.as_mut().unwrap();
        pt.disable_tracing().unwrap();

        let decode_res = pt.decode_with_image(self.image.as_mut().unwrap(), None);

        match decode_res {
            Ok(ids) => {
                for ip in ids {
                    unsafe {
                        let map_loc = self.map.add(ip as usize % self.len);
                        *map_loc = (*map_loc).saturating_add(1);
                    }
                }
            }
            Err(e) => log::warn!("Intel PT trace decoding failed: {e}"),
        }

        // println!("{:?}", _state.corpus());

        self.pt = None;
    }
}

impl IntelPTHook {
    pub fn new(map: *mut u8, len: usize) -> Self {
        Self {
            pt: None,
            image: None,
            image_cache: None,
            map,
            len,
        }
    }
}
impl<S> ExecutorHook<S> for IntelPTHook
where
    S: UsesInput + Serialize,
{
    #[allow(clippy::cast_possible_wrap)]
    fn init<E: HasObservers>(&mut self, _state: &mut S) {
        assert!(self.pt.is_none(), "Intel PT was already set up");
        assert!(self.image.is_none(), "Intel PT image was already set up");
        assert!(
            self.image_cache.is_none(),
            "Intel PT cache was already set up"
        );

        let mut image_cache = SectionCache::new(Some("image_cache")).unwrap();
        let mut image = Image::new(Some("image")).unwrap();

        let pid = process::id();
        let maps = get_process_maps(pid as i32).unwrap();
        for map in maps {
            if map.is_exec() && map.filename().is_some() {
                if let Ok(isid) = image_cache.add_file(
                    map.filename().unwrap().to_str().unwrap(),
                    map.offset as u64,
                    map.size() as u64,
                    map.start() as u64,
                ) {
                    image
                        .add_cached(&mut image_cache, isid, Asid::default())
                        .unwrap();
                }
            }
        }

        self.image_cache = Some(image_cache);
        self.image = Some(image);
        let pt_builder = IntelPT::builder();
        self.pt = Some(pt_builder.build().unwrap());
    }

    #[allow(clippy::cast_possible_wrap)]
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) {
        self.pt.as_mut().unwrap().enable_tracing().unwrap();
    }

    #[allow(clippy::cast_possible_wrap)]
    fn post_exec(&mut self, _state: &mut S, _input: &S::Input) {
        let pt = self.pt.as_mut().unwrap();
        pt.disable_tracing().unwrap();

        // let read_mem = |buf: &mut [u8], addr: u64| {
        //     let src = addr as *const u8;
        //     let dst = buf.as_mut_ptr();
        //     let size = buf.len();
        //     unsafe {
        //         ptr::copy_nonoverlapping(src, dst, size);
        //     }
        // };

        let decode_res = pt.decode_with_image(self.image.as_mut().unwrap(), None);

        if let Ok(ids) = decode_res {
            for ip in ids {
                unsafe {
                    let map_loc = self.map.add(ip as usize % self.len);
                    *map_loc = (*map_loc).saturating_add(1);
                };
            }
        }
    }
}

impl Default for IntelPTBuilder {
    fn default() -> Self {
        Self {
            pid: None,
            exclude_kernel: true,
        }
    }
}

impl IntelPTBuilder {
    pub fn build(&self) -> Result<IntelPT, Error> {
        let mut perf_event_attr = new_perf_event_attr_intel_pt()?;
        perf_event_attr.set_exclude_kernel(self.exclude_kernel.into());

        // SAFETY: perf_event_attr is properly initialized
        let fd = match unsafe {
            perf_event_open(
                ptr::from_mut(&mut perf_event_attr),
                self.pid.unwrap_or(0),
                -1,
                -1,
                PERF_FLAG_FD_CLOEXEC.into(),
            )
        } {
            -1 => return Err(Error::last_os_error("Failed to open Intel PT perf event")),
            fd => {
                // SAFETY: On success, perf_event_open() returns a new file descriptor.
                // On error, -1 is returned, and it is checked above
                unsafe { OwnedFd::from_raw_fd(fd) }
            }
        };

        let perf_buffer = setup_perf_buffer(&fd)?;

        // the first perf_buff page is a metadata page
        let buff_metadata = perf_buffer.cast::<perf_event_mmap_page>();
        let aux_offset = unsafe { ptr::addr_of_mut!((*buff_metadata).aux_offset) };
        let aux_size = unsafe { ptr::addr_of_mut!((*buff_metadata).aux_size) };
        let data_offset = unsafe { ptr::addr_of_mut!((*buff_metadata).data_offset) };
        let data_size = unsafe { ptr::addr_of_mut!((*buff_metadata).data_size) };

        unsafe {
            aux_offset.write_volatile(next_page_aligned_addr(
                data_offset.read_volatile() + data_size.read_volatile(),
            ));
            aux_size.write_volatile(PERF_AUX_BUFFER_SIZE as u64);
        }

        let perf_aux_buffer = unsafe {
            setup_perf_aux_buffer(&fd, aux_size.read_volatile(), aux_offset.read_volatile())?
        };

        let aux_head = unsafe { ptr::addr_of_mut!((*buff_metadata).aux_head) };
        let aux_tail = unsafe { ptr::addr_of_mut!((*buff_metadata).aux_tail) };

        let ip_filters = Vec::with_capacity(*NUM_OF_ADDR_FILTERS.as_ref().unwrap_or(&0) as usize);

        Ok(IntelPT {
            fd,
            perf_buffer,
            perf_aux_buffer,
            aux_head,
            aux_tail,
            previous_decode_head: 0,
            ip_filters,
        })
    }

    #[must_use]
    pub fn pid(mut self, pid: Option<libc::pid_t>) -> Self {
        self.pid = pid;
        self
    }

    #[must_use]
    pub fn exclude_kernel(mut self, exclude_kernel: bool) -> Self {
        self.exclude_kernel = exclude_kernel;
        self
    }
}

impl IntelPT {
    #[must_use]
    pub fn builder() -> IntelPTBuilder {
        IntelPTBuilder::default()
    }

    pub fn set_ip_filters(&mut self, filters: &[Range<usize>]) -> Result<(), Error> {
        let mut str_filter = Vec::with_capacity(filters.len());
        for filter in filters {
            let size = filter.end - filter.start;
            str_filter.push(format!("filter {:#016x}/{:#016x}", filter.start, size));
        }

        // SAFETY: CString::from_vec_unchecked is safe because no null bytes are added to str_filter
        let c_str_filter =
            unsafe { CString::from_vec_unchecked(str_filter.join(" ").into_bytes()) };
        match unsafe { SET_FILTER(self.fd.as_raw_fd(), c_str_filter.into_raw()) } {
            -1 => Err(Error::last_os_error("Failed to set IP filters")),
            0 => {
                self.ip_filters = filters.to_vec();
                Ok(())
            }
            ret => Err(Error::unsupported(format!(
                "Failed to set IP filter, ioctl returned unexpected value {ret}"
            ))),
        }
    }

    fn ip_filters_to_addr_filter(&self) -> AddrFilter {
        let mut builder = AddrFilterBuilder::new();
        let mut iter = self
            .ip_filters
            .iter()
            .map(|f| AddrRange::new(f.start as u64, f.end as u64, AddrConfig::FILTER));
        if let Some(f) = iter.next() {
            builder.addr0(f);
            if let Some(f) = iter.next() {
                builder.addr1(f);
                if let Some(f) = iter.next() {
                    builder.addr2(f);
                    if let Some(f) = iter.next() {
                        builder.addr3(f);
                    }
                }
            }
        }
        builder.finish()
    }

    pub fn enable_tracing(&mut self) -> Result<(), Error> {
        match unsafe { ENABLE(self.fd.as_raw_fd(), 0) } {
            -1 => Err(Error::last_os_error("Failed to enable tracing")),
            0 => Ok(()),
            ret => Err(Error::unsupported(format!(
                "Failed to enable tracing, ioctl returned unexpected value {ret}"
            ))),
        }
    }

    pub fn disable_tracing(&mut self) -> Result<(), Error> {
        match unsafe { DISABLE(self.fd.as_raw_fd(), 0) } {
            -1 => Err(Error::last_os_error("Failed to disable tracing")),
            0 => Ok(()),
            ret => Err(Error::unsupported(format!(
                "Failed to disable tracing, ioctl returned unexpected value {ret}"
            ))),
        }
    }

    pub fn decode_with_image(
        &mut self,
        image: &mut Image,
        copy_buffer: Option<&mut Vec<u8>>,
    ) -> Result<Vec<u64>, Error> {
        self.decode(
            None::<fn(_: &mut [u8], _: u64, _: Asid) -> i32>,
            Some(image),
            copy_buffer,
        )
    }

    #[allow(clippy::cast_possible_wrap)]
    pub fn decode_with_callback<F: Fn(&mut [u8], u64)>(
        &mut self,
        read_memory: F,
        copy_buffer: Option<&mut Vec<u8>>,
    ) -> Result<Vec<u64>, Error> {
        self.decode(
            Some(|buff: &mut [u8], addr: u64, _: Asid| {
                debug_assert!(i32::try_from(buff.len()).is_ok());
                read_memory(buff, addr);
                buff.len() as i32
            }),
            None,
            copy_buffer,
        )
    }

    fn decode<F: Fn(&mut [u8], u64, Asid) -> i32>(
        &mut self,
        read_memory: Option<F>,
        image: Option<&mut Image>,
        copy_buffer: Option<&mut Vec<u8>>,
    ) -> Result<Vec<u64>, Error> {
        let mut ips = Vec::new();

        let head = unsafe { self.aux_head.read_volatile() };
        let tail = unsafe { self.aux_tail.read_volatile() };
        if head < tail {
            return Err(Error::unknown(
                "Intel PT: aux buffer head is behind aux tail.",
            ));
        };
        if self.previous_decode_head < tail {
            return Err(Error::unknown(
                "Intel PT: aux previous head is behind aux tail.",
            ));
        };
        let len = (head - tail) as usize;
        if len >= PERF_AUX_BUFFER_SIZE {
            log::warn!(
                "This fuzzer run resulted in a full PT buffer. Try increasing the aux buffer size or refining the IP filters."
            );
        }
        let skip = self.previous_decode_head - tail;

        let head_wrap = wrap_aux_pointer(head);
        let tail_wrap = wrap_aux_pointer(tail);

        smp_rmb(); // TODO double check impl

        let mut data = if head_wrap >= tail_wrap {
            unsafe {
                let ptr = self.perf_aux_buffer.add(tail_wrap as usize) as *mut u8;
                OwnedRefMut::Ref(slice::from_raw_parts_mut(ptr, len))
            }
        } else {
            // Head pointer wrapped, the trace is split
            unsafe {
                let first_ptr = self.perf_aux_buffer.add(tail_wrap as usize) as *mut u8;
                let first_len = PERF_AUX_BUFFER_SIZE - tail_wrap as usize;
                let second_ptr = self.perf_aux_buffer as *mut u8;
                let second_len = head_wrap as usize;
                OwnedRefMut::Owned(
                    [
                        slice::from_raw_parts(first_ptr, first_len),
                        slice::from_raw_parts(second_ptr, second_len),
                    ]
                    .concat()
                    .into_boxed_slice(),
                )
            }
        };

        if let Some(b) = copy_buffer {
            b.extend_from_slice(data.as_ref());
        }

        let mut config =
            ConfigBuilder::new(data.as_mut()).map_err(|e| Error::unknown(e.to_string()))?;
        config.filter(self.ip_filters_to_addr_filter());
        if let Some(cpu) = &*CURRENT_CPU {
            config.cpu(*cpu);
        }
        let flags = BlockFlags::END_ON_CALL.union(BlockFlags::END_ON_JUMP);
        config.flags(flags);
        let mut decoder =
            BlockDecoder::new(&config.finish()).map_err(|e| Error::unknown(e.to_string()))?;
        if let Some(i) = image {
            decoder
                .set_image(Some(i))
                .map_err(|e| Error::unknown(format!("Failed to set image {e}")))?;
        }
        if let Some(rm) = read_memory {
            decoder
                .image()
                .map_err(|e| Error::unknown(e.to_string()))?
                .set_callback(Some(rm))
                .map_err(|e| Error::unknown(format!("Failed to set get memory callback {e}")))?;
        }
        // TODO rewrite decently
        let mut previous_block_ip = 0;
        let mut status;
        loop {
            status = match decoder.sync_forward() {
                Ok(s) => s,
                Err(_) => {
                    // println!("pterror in sync {e:?}");
                    break;
                }
            };

            loop {
                if loop {
                    if !status.event_pending() {
                        break Ok(());
                    }
                    match decoder.event() {
                        Ok((_, s)) => {
                            // TODO maybe we care about some events?
                            status = s;
                        }
                        Err(e) => {
                            println!("pterror in event {e:?}");
                            break Err(e);
                        }
                    };
                }
                .is_err()
                {
                    break;
                }

                let block = decoder.next();
                match block {
                    Err(_) => {
                        // libipt-rs library ignores the fact that
                        // Even in case of errors, we may have succeeded in decoding some instructions.
                        // https://github.com/intel/libipt/blob/4a06fdffae39dadef91ae18247add91029ff43c0/ptxed/src/ptxed.c#L1954
                        // Using my fork that fixes this atm
                        // println!("pterror in packet next {e:?}");
                        // println!("err block ip: 0x{:x?}", b.ip());
                        //if skip < decoder.offset().expect("Failed to get decoder offset") {
                        //    ips.push(b.ip());
                        //}
                        // status = Status::from_bits(e.code() as u32).unwrap();
                        break;
                    }
                    Ok((b, s)) => {
                        status = s;

                        // TODO optimize this check and its equivalent up here?
                        if !b.speculative()
                            && skip
                                < decoder
                                    .offset()
                                    .map_err(|e| Error::unknown(e.to_string()))?
                        {
                            let id = hash_me(previous_block_ip) ^ hash_me(b.ip());
                            ips.push(id);
                            previous_block_ip = b.ip();
                        }

                        if status.eos() {
                            break;
                        }
                    }
                }
            }
        }

        // Advance the trace pointer up to the latest sync point, otherwise the next execution might
        // not contain the PSB.
        decoder
            .sync_backward()
            .map_err(|e| Error::unknown(e.to_string()))?;
        let offset = decoder
            .sync_offset()
            .map_err(|e| Error::unknown(e.to_string()))?;
        unsafe { self.aux_tail.write_volatile(tail + offset) };
        self.previous_decode_head = head;
        Ok(ips)
    }

    /// Check if Intel PT is available on the current system.
    ///
    /// This function can be helpful when `IntelPT::try_new` or `set_ip_filter` fail for an unclear
    /// reason.
    ///
    /// Returns `Ok(())` if Intel PT is available and has the features used by `LibAFL`, otherwise
    /// returns an `Err` containing the reasons.
    ///
    /// If you use this with QEMU check out [`Self::availability_in_qemu()`] instead.
    pub fn availability() -> Result<(), Error> {
        let mut reasons = Vec::new();
        if cfg!(not(target_os = "linux")) {
            reasons.push("Only linux hosts are supported at the moment.".to_owned());
        }
        if cfg!(not(target_arch = "x86_64")) {
            reasons.push("Only x86_64 is supported.".to_owned());
        }

        let cpuid = CpuId::new();
        if let Some(vendor) = cpuid.get_vendor_info() {
            if vendor.as_str() != "GenuineIntel" && vendor.as_str() != "GenuineIotel" {
                reasons.push("Only Intel CPUs are supported.".to_owned());
            }
        } else {
            reasons.push("Failed to read CPU vendor".to_owned());
        }

        if let Some(ef) = cpuid.get_extended_feature_info() {
            if !ef.has_processor_trace() {
                reasons.push("Intel PT is not supported by the CPU.".to_owned());
            }
        } else {
            reasons.push("Failed to read CPU Extended Features".to_owned());
        }

        if let Err(e) = &*PERF_EVENT_TYPE {
            reasons.push(e.clone());
        }

        if let Err(e) = &*NUM_OF_ADDR_FILTERS {
            reasons.push(e.to_string());
        }

        // official way of knowing if perf_event_open() support is enabled
        // https://man7.org/linux/man-pages/man2/perf_event_open.2.html
        let perf_event_support_path = "/proc/sys/kernel/perf_event_paranoid";
        if !Path::new(perf_event_support_path).exists() {
            reasons.push(format!(
                "perf_event_open() support is not enabled: {perf_event_support_path} not found"
            ));
        }

        // TODO check also the value of perf_event_paranoid, check which values are required by pt
        // https://www.kernel.org/doc/Documentation/sysctl/kernel.txt
        // also, looks like it is distribution dependent
        // https://askubuntu.com/questions/1400874/what-does-perf-paranoia-level-four-do
        // CAP_SYS_ADMIN might make this check useless

        if let Ok(current_capabilities) = caps::read(None, CapSet::Permitted) {
            let required_caps = [
                Capability::CAP_IPC_LOCK,
                Capability::CAP_SYS_PTRACE,
                Capability::CAP_SYS_ADMIN, // TODO: CAP_PERFMON doesn't look to be enough!?
                Capability::CAP_SYSLOG,
            ];

            for rc in required_caps {
                if !current_capabilities.contains(&rc) {
                    reasons.push(format!("Required capability {rc} missing."));
                }
            }
        } else {
            reasons.push("Failed to read linux capabilities".to_owned());
        }

        if reasons.is_empty() {
            Ok(())
        } else {
            Err(Error::unsupported(reasons.join("\n")))
        }
    }

    /// Check if Intel PT is available on the current system and can be used in combination with
    /// QEMU.
    ///
    /// If you don't use this with QEMU check out [`IntelPT::availability()`] instead.
    pub fn availability_in_qemu() -> Result<(), Error> {
        let mut reasons = match Self::availability() {
            Err(Error::Unsupported(s, _)) => vec![s],
            Err(e) => panic!("IntelPT::availability() returned an unknown error {e}"),
            Ok(()) => Vec::new(),
        };

        let kvm_pt_mode_path = "/sys/module/kvm_intel/parameters/pt_mode";
        if let Ok(s) = fs::read_to_string(kvm_pt_mode_path) {
            match s.trim().parse::<i32>().map(TryInto::try_into) {
                Ok(Ok(KvmPTMode::System)) => (),
                Ok(Ok(KvmPTMode::HostGuest)) => reasons.push(format!(
                    "KVM Intel PT mode must be set to {:?} `{}` to be used with libafl_qemu",
                    KvmPTMode::System,
                    KvmPTMode::System as i32
                )),
                _ => reasons.push(format!(
                    "Failed to parse KVM Intel PT mode in {kvm_pt_mode_path}"
                )),
            }
        };

        if reasons.is_empty() {
            Ok(())
        } else {
            Err(Error::unsupported(reasons.join("\n")))
        }
    }
}

impl Drop for IntelPT {
    fn drop(&mut self) {
        unsafe {
            let ret = libc::munmap(self.perf_aux_buffer, PERF_AUX_BUFFER_SIZE);
            debug_assert_eq!(ret, 0, "Intel PT: Failed to unmap perf aux buffer");
            let ret = libc::munmap(self.perf_buffer, PERF_BUFFER_SIZE);
            debug_assert_eq!(ret, 0, "Intel PT: Failed to unmap perf buffer");
        }
    }
}

#[inline]
const fn next_page_aligned_addr(address: u64) -> u64 {
    (address + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1)
}

fn setup_perf_buffer(fd: &OwnedFd) -> Result<*mut c_void, Error> {
    match unsafe {
        libc::mmap(
            ptr::null_mut(),
            PERF_BUFFER_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    } {
        libc::MAP_FAILED => Err(Error::last_os_error("IntelPT: Failed to mmap perf buffer")),
        mmap_addr => Ok(mmap_addr),
    }
}

fn setup_perf_aux_buffer(fd: &OwnedFd, size: u64, offset: u64) -> Result<*mut c_void, Error> {
    match unsafe {
        libc::mmap(
            ptr::null_mut(),
            size as usize,
            // PROT_WRITE sets PT to stop when the buffer is full
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            i64::try_from(offset)?,
        )
    } {
        libc::MAP_FAILED => Err(Error::last_os_error(
            "IntelPT: Failed to mmap perf aux buffer",
        )),
        mmap_addr => Ok(mmap_addr),
    }
}

fn new_perf_event_attr_intel_pt() -> Result<perf_event_attr, Error> {
    let type_ = match &*PERF_EVENT_TYPE {
        Ok(t) => Ok(*t),
        Err(e) => Err(Error::unsupported(e.clone())),
    }?;
    let config = PtConfig::builder()
        .with_noretcomp(true)
        .with_psb_period(u4::new(0))
        .build()
        .raw_value;

    let mut attr = perf_event_attr {
        size: size_of::<perf_event_attr>() as u32,
        type_,
        config,
        ..Default::default()
    };

    // Do not enable tracing as soon as the perf_event_open syscall is issued
    attr.set_disabled(1);

    Ok(attr)
}

#[inline]
const fn wrap_aux_pointer(ptr: u64) -> u64 {
    ptr & (PERF_AUX_BUFFER_SIZE as u64 - 1)
}

#[inline]
pub fn smp_rmb() {
    // SAFETY: just a memory barrier
    unsafe {
        core::arch::asm!("lfence", options(nostack, preserves_flags));
    }
}

// copy pasted from libafl_qemu/src/modules/edges.rs
// adapted from https://xorshift.di.unimi.it/splitmix64.c
#[inline]
#[must_use]
pub const fn hash_me(mut x: u64) -> u64 {
    x = (x ^ (x.overflowing_shr(30).0))
        .overflowing_mul(0xbf58476d1ce4e5b9)
        .0;
    x = (x ^ (x.overflowing_shr(27).0))
        .overflowing_mul(0x94d049bb133111eb)
        .0;
    x ^ (x.overflowing_shr(31).0)
}

#[cfg(test)]
mod test {
    use std::{arch::asm, fs::OpenOptions, io::Write, process};

    use arbitrary_int::Number;
    use nix::{
        sys::{
            signal::{kill, raise, Signal},
            wait::{waitpid, WaitPidFlag},
        },
        unistd::{fork, ForkResult},
    };
    use proc_maps::get_process_maps;
    use static_assertions::{assert_eq_size, const_assert, const_assert_eq};

    use super::*;

    // PERF_BUFFER_SIZE should be 1+2^n pages
    const_assert!(((PERF_BUFFER_SIZE - PAGE_SIZE) / PAGE_SIZE).is_power_of_two());
    // PERF_AUX_BUFFER_SIZE must be page aligned
    // TODO:replace with is_multiple_of once stable
    const_assert_eq!(PERF_AUX_BUFFER_SIZE % PAGE_SIZE, 0);
    // PERF_AUX_BUFFER_SIZE must be a power of two
    const_assert!(PERF_AUX_BUFFER_SIZE.is_power_of_two());
    // Only 64-bit systems are supported, ensure we can use usize and u64 interchangeably
    assert_eq_size!(usize, u64);

    #[test]
    fn intel_pt_pt_config_noretcomp_format() {
        let ptconfig_noretcomp = PtConfig::DEFAULT.with_noretcomp(true).raw_value;
        let path = format!("{PT_EVENT_PATH}/format/noretcomp");
        let s = fs::read_to_string(&path).expect("Failed to read Intel PT config noretcomp format");
        assert!(
            s.starts_with("config:"),
            "Unexpected Intel PT config noretcomp format"
        );
        let bit = s["config:".len()..]
            .trim()
            .parse::<u32>()
            .expect("Failed to parse Intel PT config noretcomp format");
        assert_eq!(
            ptconfig_noretcomp,
            0b1 << bit,
            "Unexpected Intel PT config noretcomp format"
        );
    }

    #[test]
    fn intel_pt_pt_config_psb_period_format() {
        let ptconfig_psb_period = PtConfig::DEFAULT.with_psb_period(u4::MAX).raw_value;
        let path = format!("{PT_EVENT_PATH}/format/psb_period");
        let s =
            fs::read_to_string(&path).expect("Failed to read Intel PT config psb_period format");
        assert!(
            s.starts_with("config:"),
            "Unexpected Intel PT config psb_period format"
        );
        let from = s["config:".len().."config:".len() + 2]
            .parse::<u32>()
            .expect("Failed to parse Intel PT config psb_period format");
        let to = s["config:".len() + 3..]
            .trim()
            .parse::<u32>()
            .expect("Failed to parse Intel PT config psb_period format");
        let mut format = 0;
        for bit in from..=to {
            format |= 0b1 << bit;
        }
        assert_eq!(
            ptconfig_psb_period, format,
            "Unexpected Intel PT config psb_period format"
        );
    }

    /// To run this test ensure that the executable has the required capabilities.
    /// This can be achieved with the following command:
    /// ```bash
    /// #!/usr/bin/env bash
    ///
    /// # Trigger test compilation
    /// cargo test intel_pt -p libafl --features=intel_pt --no-default-features
    ///
    /// # Find the test binaries
    /// for test_bin in target/debug/deps/libafl*; do
    ///   # Check if the file is a binary
    ///   if file "$test_bin" | grep -q "ELF"; then
    ///     # Set the desired capabilities on the binary
    ///     sudo setcap cap_ipc_lock,cap_sys_ptrace,cap_sys_admin,cap_syslog=ep "$test_bin"
    ///   fi
    /// done
    ///
    /// # Run tests with caps
    /// cargo test intel_pt -p libafl --features=intel_pt --no-default-features -- --show-output
    /// ```
    ///
    /// Or by running with `sudo`:
    /// ```toml
    /// # libafl_qemu/.cargo/config.toml
    /// [target.x86_64-unknown-linux-gnu]
    /// runner = 'sudo -E'
    /// ```
    #[test]
    fn intel_pt_trace_fork() {
        if let Err(reason) = IntelPT::availability() {
            // Mark as `skipped` once this will be possible https://github.com/rust-lang/rust/issues/68007
            println!("Intel PT is not available, skipping test. Reasons:");
            println!("{reason}");
            return;
        }

        let pid = match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => child,
            Ok(ForkResult::Child) => {
                raise(Signal::SIGSTOP).expect("Failed to stop the process");
                // This will generate a sequence of tnt packets containing 255 taken branches
                unsafe {
                    let mut count = 0;
                    asm!(
                        "2:",
                        "add {0:r}, 1",
                        "cmp {0:r}, 255",
                        "jle 2b",
                        inout(reg) count,
                        options(nostack)
                    );
                    let _ = count;
                }
                process::exit(0);
            }
            Err(e) => panic!("Fork failed {e}"),
        };

        let pt_builder = IntelPT::builder().pid(Some(pid.as_raw()));
        let mut pt = pt_builder.build().expect("Failed to create IntelPT");
        pt.enable_tracing().expect("Failed to enable tracing");

        waitpid(pid, Some(WaitPidFlag::WUNTRACED)).expect("Failed to wait for the child process");
        let maps = get_process_maps(pid.into()).unwrap();
        kill(pid, Signal::SIGCONT).expect("Failed to continue the process");

        waitpid(pid, None).expect("Failed to wait for the child process");
        pt.disable_tracing().expect("Failed to disable tracing");

        let mut image = Image::new(Some("test_trace_pid")).unwrap();
        for map in maps {
            if map.is_exec() && map.filename().is_some() {
                match image.add_file(
                    map.filename().unwrap().to_str().unwrap(),
                    map.offset as u64,
                    map.size() as u64,
                    None,
                    map.start() as u64,
                ) {
                    Err(e) => println!(
                        "Error adding mapping for {:?}: {:?}, skipping",
                        map.filename().unwrap(),
                        e
                    ),
                    Ok(()) => println!(
                        "mapping for {:?} added successfully {:#x} - {:#x}",
                        map.filename().unwrap(),
                        map.start(),
                        map.start() + map.size()
                    ),
                }
            }
        }

        let mut trace = Vec::new();
        let mut ips = pt.decode_with_image(&mut image, Some(&mut trace)).unwrap();
        let _ = dump_trace_to_file(&trace)
            .inspect_err(|e| println!("Failed to dump trace to file: {e}"));
        ips.sort_unstable();
        ips.dedup();
        println!("Intel PT traces unique block ips: {ips:#x?}");
    }
    //static mut FILENUM: u32 = 0;
    fn dump_trace_to_file(buff: &[u8]) -> Result<(), Error> {
        let trace_path = "./traces/test_trace_pid_ipt_raw_trace.tmp"; //format!({FILENUM})
                                                                      //unsafe { FILENUM += 1 };
        fs::create_dir_all(Path::new(&trace_path).parent().unwrap())?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(trace_path)
            .expect("Failed to open trace output file");

        file.write_all(buff)
            .map_err(|e| Error::os_error(e, "Failed to write traces"))?;

        Ok(())
    }
}
