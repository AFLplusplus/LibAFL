#[cfg(windows)]
use std::ptr::write_volatile;
use std::{
    cell::RefCell,
    fs::{File, Permissions},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    rc::Rc,
    str::FromStr,
    sync::Arc,
};

#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice},
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{StdMapObserver, TimeObserver},
    prelude::{
        powersched::PowerSchedule, ConstFeedback, HitcountsMapObserver, PowerQueueScheduler,
    },
    schedulers::{
        IndexesLenTimeMinimizerScheduler, LenTimeMinimizerScheduler, QueueScheduler,
        StdWeightedScheduler,
    },
    stages::{mutational::StdMutationalStage, CalibrationStage, StdPowerMutationalStage},
    state::{HasSolutions, StdState},
};
use libafl_v8::{
    deno_core,
    deno_core::{FsModuleLoader, JsRuntime, RuntimeOptions},
    deno_runtime,
    deno_runtime::{
        inspector_server::InspectorServer,
        ops::io::StdioPipe,
        worker::{MainWorker, WorkerOptions},
    },
    runtime,
    runtime::Runtime,
    v8,
    v8::{ContextScope, Global},
    JSMapObserver, Mutex, V8Executor,
};

use crate::{
    deno_runtime::{ops::io::Stdio, BootstrapOptions},
    v8::Context,
};

#[allow(clippy::similar_names)]
pub fn main() -> anyhow::Result<()> {
    // setup JS
    let module_loader = Rc::new(FsModuleLoader);
    let inspector_server = Arc::new(InspectorServer::new(
        SocketAddr::from_str("127.0.0.1:1337")?,
        "baby_fuzzer".to_string(),
    ));
    let create_web_worker_cb = Arc::new(|_| {
        unimplemented!("Web workers are not supported by baby fuzzer");
    });
    let web_worker_event_cb = Arc::new(|_| {
        unimplemented!("Web workers are not supported by baby fuzzer");
    });
    let options = WorkerOptions {
        bootstrap: BootstrapOptions {
            args: vec![],
            cpu_count: 1,
            debug_flag: false,
            enable_testing_features: false,
            location: None,
            no_color: false,
            is_tty: false,
            runtime_version: "".to_string(),
            ts_version: "".to_string(),
            unstable: false,
            user_agent: "libafl".to_string(),
        },
        extensions: vec![],
        unsafely_ignore_certificate_errors: None,
        root_cert_store: None,
        maybe_inspector_server: Some(inspector_server.clone()),
        should_break_on_first_statement: true,
        get_error_class_fn: None,
        origin_storage_dir: None,
        blob_store: Default::default(),
        broadcast_channel: Default::default(),
        shared_array_buffer_store: None,
        compiled_wasm_module_store: None,
        module_loader,
        npm_resolver: None,
        create_web_worker_cb,
        web_worker_preload_module_cb: web_worker_event_cb.clone(),
        web_worker_pre_execute_module_cb: web_worker_event_cb,
        format_js_error_fn: None,
        seed: None,
        source_map_getter: None,
        stdio: Stdio {
            stdin: Default::default(),
            stdout: StdioPipe::File(File::create("stdout.log")?),
            stderr: StdioPipe::File(File::create("stderr.log")?),
        },
    };

    let js_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("js/target.js");
    let main_module = deno_core::resolve_path(&js_path.to_string_lossy())?;
    let permissions = deno_runtime::permissions::Permissions::allow_all();

    let worker = Arc::new(Mutex::new(MainWorker::bootstrap_from_options(
        main_module.clone(),
        permissions,
        options,
    )));

    let rt = Runtime::new()?;

    let map_observer =
        HitcountsMapObserver::new(JSMapObserver::new("jsmap", &rt, worker.clone()).unwrap());
    let time_observer = TimeObserver::new("time");

    // Feedback to rate the interestingness of an input
    let mut map_feedback = MaxMapFeedback::new_tracking(&map_observer, true, false);

    let calibration = CalibrationStage::new(&map_feedback);

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let power = StdPowerMutationalStage::new(mutator, &map_observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut map_feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are displayed to the user
    #[cfg(not(feature = "tui"))]
    let mon = SimpleMonitor::new(|s| println!("{}", s));
    #[cfg(feature = "tui")]
    let mon = TuiMonitor::new(String::from("Baby Fuzzer"), false);

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(StdWeightedScheduler::with_schedule(
        PowerSchedule::EXPLORE,
    ));
    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, map_feedback, objective);

    // Create the executor for an in-process function with just one observer
    let mut executor = V8Executor::new(
        &rt,
        worker,
        main_module,
        tuple_list!(map_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mut stages = tuple_list!(calibration, power);

    while state.solutions().count() == 0 {
        fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, 1000)?;
    }

    Ok(())
}
