//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.

use libafl::{
    bolts::{
        shmem::UnixShMem,
        tuples::{tuple_list, Named},
    },
    corpus::{
        Corpus, InMemoryCorpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
        QueueCorpusScheduler,
    },
    events::{setup_restarting_mgr, EventManager},
    executors::{inprocess::InProcessExecutor, Executor, ExitKind, HasObservers},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, HasCorpusScheduler, StdFuzzer},
    inputs::{HasTargetBytes, Input},
    mutators::{scheduled::HavocBytesMutator, token_mutations::Tokens},
    observers::{HitcountsMapObserver, ObserversTuple, StdMapObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, State},
    stats::SimpleStats,
    utils::{current_nanos, StdRand},
    Error,
};

use frida_gum::{
    stalker::{NoneEventSink, Stalker, Transformer},
    InstructionWriter,
};
use frida_gum::{Gum, MemoryRange, Module, NativePointer, PageProtection, Register};
#[cfg(target_arch = "aarch64")]
use frida_gum::IndexMode;

use libloading;

use std::{cell::RefCell, env, ffi::c_void, path::PathBuf, ptr};

/// An helper that feeds FridaInProcessExecutor with user-supplied instrumentation
pub trait FridaHelper<'a> {
    fn transformer(&self) -> &Transformer<'a>;
}

const MAP_SIZE: usize = 64 * 1024;

/// An helper that feeds FridaInProcessExecutor with edge-coverage instrumentation
struct FridaEdgeCoverageHelper<'a> {
    map: [u8; MAP_SIZE],
    previous_pc: RefCell<u64>,
    base_address: u64,
    size: usize,
    current_log_impl: u64,
    /// Transformer that has to be passed to FridaInProcessExecutor
    transformer: Option<Transformer<'a>>,
}

impl<'a> FridaHelper<'a> for FridaEdgeCoverageHelper<'a> {
    fn transformer(&self) -> &Transformer<'a> {
        self.transformer.as_ref().unwrap()
    }
}

/// Helper function to get the size of a module's CODE section from frida
pub fn get_module_size(module_name: &str) -> usize {
    let mut code_size = 0;
    let code_size_ref = &mut code_size;
    Module::enumerate_ranges(
        module_name,
        PageProtection::ReadExecute,
        move |details, _user_data| {
            *code_size_ref = details.memory_range().size() as usize;
            0
        },
        ptr::null_mut(),
    );

    code_size
}

/// A minimal maybe_log implementation. We insert this into the transformed instruction stream
/// every time we need a copy that is within a direct branch of the start of the transformed basic
/// block.
#[cfg(target_arch = "x86_64")]
const MAYBE_LOG_CODE: [u8; 69] = [
    0x9c,  // pushfq
    0x50,  // push rax
    0x51,  // push rcx
    0x52,  // push rdx
    0x56,  // push rsi

    0x89, 0xf8,                                // mov eax, edi
    0xc1, 0xe0, 0x08,                          // shl eax, 8
    0xc1, 0xef, 0x04,                          // shr edi, 4
    0x31, 0xc7,                                // xor edi, eax
    0x0f, 0xb7, 0xc7,                          // movzx eax, di
    0x48, 0x8d, 0x0d, 0x34, 0x00, 0x00, 0x00,  // lea rcx, sym._afl_area_ptr_ptr
    0x48, 0x8b, 0x09,                          // mov rcx, qword [rcx]
    0x48, 0x8d, 0x15, 0x22, 0x00, 0x00, 0x00,  // lea rdx, sym._afl_prev_loc_ptr
    0x48, 0x8b, 0x32,                          // mov rsi, qword [rdx]
    0x48, 0x8b, 0x36,                          // mov rsi, qword [rsi]
    0x48, 0x31, 0xc6,                          // xor rsi, rax
    0x48, 0x81, 0xe6, 0xff, 0x1f, 0x00, 0x00,  // and rsi, 0x1fff (8 * 1024 - 1) TODO: make this variable
    0xfe, 0x04, 0x31,                          // inc byte [rcx + rsi]

    0x48, 0xd1, 0xe8,  // shr rax, 1
    0x48, 0x8b, 0x0a,  // mov rcx, qword [rdx]
    0x48, 0x89, 0x01,  // mov qword [rcx], rax

    0x5e,  // pop rsi
    0x5a,  // pop rdx
    0x59,  // pop rcx
    0x58,  // pop rax
    0x9d,  // popfq

    0xc3,  // ret
           // Read-only data goes here:
           // uint64_t* afl_prev_loc_ptr
           // uint8_t** afl_area_ptr_ptr
           // unsigned int afl_instr_rms
];

#[cfg(target_arch = "aarch64")]
const MAYBE_LOG_CODE: [u8; 104] = [
    0xE1, 0x0B, 0xBF, 0xA9, // stp x1, x2, [sp, -0x10]!
    0xE3, 0x13, 0xBF, 0xA9, // stp x3, x4, [sp, -0x10]!

    0xE1, 0x03, 0x00, 0xAA, // mov x1, x0
    0x00, 0xDC, 0x78, 0xD3, // lsl x0, x0, #8
    0x21, 0xFC, 0x44, 0xD3, // lsr x1, x1, #4
    0x00, 0x00, 0x01, 0xCA, // eor x0, x0, x1
    0x00, 0x3C, 0x00, 0x53, // uxth w0, w0
    0xa1, 0x02, 0x00, 0x58, // ldr x1, =area_ptr
    0x42, 0x02, 0x00, 0x58, // ldr x2, =pc_ptr
    0x43, 0x00, 0x40, 0xF9, // ldr x3, [x2]
    0x63, 0x00, 0x00, 0xCA, // eor x3, x3, x0
    0x63, 0x40, 0x40, 0x92, // and x3, x3, #0x1ffff
    0x21, 0x00, 0x03, 0x8B, // add x1, x1, x3
    0x24, 0x00, 0x40, 0x39, // ldrb w4, [x1, #0
    0x84, 0x04, 0x00, 0x91, // add x4, x4, #1
    0x24, 0x00, 0x00, 0x39, // strb w4, [x1, #0]
    0x00, 0xFC, 0x41, 0xD3, // lsr x0, x0, #1
    0x40, 0x00, 0x00, 0xF9, // str x0, [x2]

    0xE3, 0x13, 0xc1, 0xA8, // ldp x3, x4, [sp], #0x10
    0xE1, 0x0B, 0xc1, 0xA8, // ldp x1, x2, [sp], #0x10

    0xC0, 0x03, 0x5F, 0xD6, // ret
    0x1f, 0x20, 0x03, 0xD5, // nop
    0x1f, 0x20, 0x03, 0xD5, // nop
    0x1f, 0x20, 0x03, 0xD5, // nop
    0x1f, 0x20, 0x03, 0xD5, // nop
    0x1f, 0x20, 0x03, 0xD5, // nop
];

/// The implementation of the FridaEdgeCoverageHelper
impl<'a> FridaEdgeCoverageHelper<'a> {
    /// Constructor function to create a new FridaEdgeCoverageHelper, given a module_name.
    pub fn new(gum: &'a Gum, module_name: &str) -> Self {
        let mut helper = Self {
            map: [0u8; MAP_SIZE],
            previous_pc: RefCell::new(0x0),
            base_address: Module::find_base_address(module_name).0 as u64,
            size: get_module_size(module_name),
            current_log_impl: 0,
            transformer: None,
        };

        let transformer = Transformer::from_callback(gum, |basic_block, _output| {
            let mut first = true;
            for instruction in basic_block {
                if first {
                    let address = unsafe { (*instruction.get_instruction()).address };
                    if address >= helper.base_address
                        && address <= helper.base_address + helper.size as u64
                    {
                        let writer = _output.writer();
                        if helper.current_log_impl == 0
                            || !writer.can_branch_directly_to(helper.current_log_impl)
                            || !writer.can_branch_directly_between(
                                writer.pc() + 128,
                                helper.current_log_impl,
                            )
                        {
                            let after_log_impl = writer.code_offset() + 1;

                            #[cfg(target_arch = "x86_64")]
                            writer.put_jmp_near_label(after_log_impl);
                            #[cfg(target_arch = "aarch64")]
                            writer.put_b_label(after_log_impl);

                            helper.current_log_impl = writer.pc();
                            writer.put_bytes(&MAYBE_LOG_CODE);
                            let prev_loc_pointer = helper.previous_pc.as_ptr() as *mut _ as usize;
                            let map_pointer = helper.map.as_ptr() as usize;

                            writer.put_bytes(&prev_loc_pointer.to_ne_bytes());
                            writer.put_bytes(&map_pointer.to_ne_bytes());

                            writer.put_label(after_log_impl);
                        }
                        #[cfg(target_arch = "x86_64")]
                        {
                            writer.put_lea_reg_reg_offset(Register::RSP, Register::RSP, -(frida_gum_sys::GUM_RED_ZONE_SIZE as i32));
                            writer.put_push_reg(Register::RDI);
                            writer.put_mov_reg_address(Register::RDI, address);
                            writer.put_call_address(helper.current_log_impl);
                            writer.put_pop_reg(Register::RDI);
                            writer.put_lea_reg_reg_offset(Register::RSP, Register::RSP, frida_gum_sys::GUM_RED_ZONE_SIZE as i32);
                        }
                        #[cfg(target_arch = "aarch64")]
                        {
                            writer.put_stp_reg_reg_reg_offset(Register::LR, Register::X0, Register::SP, -(16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i32) as i64, IndexMode::PreAdjust);
                            writer.put_ldr_reg_u64(Register::X0, address);
                            writer.put_bl_imm(helper.current_log_impl);
                            writer.put_ldp_reg_reg_reg_offset(Register::LR, Register::X0, Register::SP, 16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i64, IndexMode::PostAdjust);

                        }
                    }
                    first = false;
                }
                instruction.keep()
            }
        });

        helper.transformer = Some(transformer);
        helper
    }
}

struct FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    base: InProcessExecutor<'a, H, I, OT>,
    /// Frida's dynamic rewriting engine
    stalker: Stalker<'a>,
    /// User provided callback for instrumentation
    helper: &'a FH,
    followed: bool,
}

impl<'a, FH, H, I, OT> Executor<I> for FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    /// Called right before exexution starts
    #[inline]
    fn pre_exec<EM, S>(&mut self, state: &mut S, event_mgr: &mut EM, input: &I) -> Result<(), Error>
    where
        EM: EventManager<I, S>,
    {
        if !self.followed {
            self.followed = true;
            self.stalker
                .follow_me::<NoneEventSink>(self.helper.transformer(), None);
        } else {
            self.stalker.activate(NativePointer(
                self.base.harness_mut() as *mut _ as *mut c_void
            ))
        }
        self.base.pre_exec(state, event_mgr, input)
    }

    /// Instruct the target about the input and run
    #[inline]
    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error> {
        self.base.run_target(input)
    }

    /// Called right after execution finished.
    #[inline]
    fn post_exec<EM, S>(&mut self, state: &S, event_mgr: &mut EM, input: &I) -> Result<(), Error>
    where
        EM: EventManager<I, S>,
    {
        self.stalker.deactivate();
        self.base.post_exec(state, event_mgr, input)
    }
}

impl<'a, FH, H, I, OT> HasObservers<OT> for FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn observers(&self) -> &OT {
        self.base.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        self.base.observers_mut()
    }
}

impl<'a, FH, H, I, OT> Named for FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    fn name(&self) -> &str {
        self.base.name()
    }
}

impl<'a, FH, H, I, OT> FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    pub fn new(gum: &'a Gum, base: InProcessExecutor<'a, H, I, OT>, helper: &'a FH) -> Self {
        let mut stalker = Stalker::new(gum);

        // Let's exclude the main module and libc.so at least:
        stalker.exclude(&MemoryRange::new(
            Module::find_base_address(&env::args().next().unwrap()),
            get_module_size(&env::args().next().unwrap()),
        ));
        stalker.exclude(&MemoryRange::new(
            Module::find_base_address("libc.so"),
            get_module_size("libc.so"),
        ));

        Self {
            base: base,
            stalker: stalker,
            helper: helper,
            followed: false,
        }
    }
}

/// The main fn, usually parsing parameters, and starting the fuzzer
pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );
    unsafe {
        fuzz(
            &env::args().nth(1).expect("no module specified"),
            &env::args().nth(2).expect("no symbol specified"),
            vec![PathBuf::from("./corpus")],
            PathBuf::from("./crashes"),
            1337,
        )
        .expect("An error occurred while fuzzing");
    }
}

/// Not supported on windows right now
#[cfg(windows)]
fn fuzz(
    _module_name: &str,
    _symbol_name: &str,
    _corpus_dirs: Vec<PathBuf>,
    _objective_dir: PathBuf,
    _broker_port: u16,
) -> Result<(), ()> {
    todo!("Example not supported on Windows");
}

/// The actual fuzzer
#[cfg(unix)]
unsafe fn fuzz(
    module_name: &str,
    symbol_name: &str,
    corpus_dirs: Vec<PathBuf>,
    objective_dir: PathBuf,
    broker_port: u16,
) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    let (state, mut restarting_mgr) =
        match setup_restarting_mgr::<_, _, UnixShMem, _>(stats, broker_port) {
            Ok(res) => res,
            Err(err) => match err {
                Error::ShuttingDown => {
                    return Ok(());
                }
                _ => {
                    panic!("Failed to setup the restarter: {}", err);
                }
            },
        };

    let gum = Gum::obtain();
    let lib = libloading::Library::new(module_name).unwrap();
    let target_func: libloading::Symbol<unsafe extern "C" fn(data: *const u8, size: usize) -> i32> =
        lib.get(symbol_name.as_bytes()).unwrap();
    let mut frida_helper = FridaEdgeCoverageHelper::new(&gum, module_name);

    // Create an observation channel using the coverage map
    let edges_observer = HitcountsMapObserver::new(StdMapObserver::new_from_ptr(
        "edges",
        frida_helper.map.as_mut_ptr(),
        MAP_SIZE,
    ));

    let mut frida_harness = move |buf: &[u8]| {
        (target_func)(buf.as_ptr(), buf.len());
        ExitKind::Ok
    };

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        State::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryCorpus::new(),
            // Feedbacks to rate the interestingness of an input
            tuple_list!(MaxMapFeedback::new_with_observer_track(
                &edges_observer,
                true,
                false
            )),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // Feedbacks to recognize an input as solution
            tuple_list!(CrashFeedback::new()),
        )
    });

    println!("We're a client, let's fuzz :)");

    // Create a PNG dictionary if not existing
    if state.metadata().get::<Tokens>().is_none() {
        state.add_metadata(Tokens::new(vec![
            vec![137, 80, 78, 71, 13, 10, 26, 10], // PNG header
            "IHDR".as_bytes().to_vec(),
            "IDAT".as_bytes().to_vec(),
            "PLTE".as_bytes().to_vec(),
            "IEND".as_bytes().to_vec(),
        ]));
    }

    // Setup a basic mutator with a mutational stage
    let mutator = HavocBytesMutator::default();
    let stage = StdMutationalStage::new(mutator);

    // A fuzzer with just one stage and a minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());
    let fuzzer = StdFuzzer::new(scheduler, tuple_list!(stage));

    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = FridaInProcessExecutor::new(
        &gum,
        InProcessExecutor::new(
            "in-process(edges)",
            &mut frida_harness,
            tuple_list!(edges_observer),
            &mut state,
            &mut restarting_mgr,
        )?,
        &frida_helper,
    );
    // Let's exclude the main module and libc.so at least:
    executor.stalker.exclude(&MemoryRange::new(
        Module::find_base_address(&env::args().next().unwrap()),
        get_module_size(&env::args().next().unwrap()),
    ));
    executor.stalker.exclude(&MemoryRange::new(
        Module::find_base_address("libc.so"),
        get_module_size("libc.so"),
    ));

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(
                &mut executor,
                &mut restarting_mgr,
                fuzzer.scheduler(),
                &corpus_dirs,
            )
            .expect(&format!(
                "Failed to load initial corpus at {:?}",
                &corpus_dirs
            ));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    fuzzer.fuzz_loop(&mut state, &mut executor, &mut restarting_mgr)?;

    // Never reached
    Ok(())
}
