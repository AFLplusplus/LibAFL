// ===== overview for prommon =====
// Need to run a prometheus server (can use precompiled binary or docker), which scrapes / stores data from the client. 
// It is configurable via a yaml file.

// Need the application to be instrumented with the Rust client library. Lets you define metrics, 
// then you expose them via an HTTP endpoint for the server to scrape.
// ^^ this file! ^^
// ====================
// == how to use it ===
// in your fuzzer, include:
// use libafl::monitors::PrometheusMonitor;
// as well as:
// let mon = PrometheusMonitor::new(|s| println!("{}", s));
// and then like with any other monitor, pass it into the event manager like so:
// let mut mgr = SimpleEventManager::new(mon);


// imports
    // will need to use an HTTP library (tide?-- want something extremely lightweight)
    // will need the prometheus rust client lib : https://github.com/prometheus/client_rust

// check for introspection feature config
    // if so, do appropriate imports
    // alternatively: node exporter via prometheus?


// on each 'update', will need to keep track of prev metric value to take delta
    // with delta, add it to the counter / guage. Note that delta MUST be signed to account for decreases (only applicable to guages)
    // alternatively: does prometheus allow just a straight numeric update? rather than increment / decrement. Would save some cycles.
    // should have easy access to ClientStats vector.

// counters: runtime (sec), executions (int), objectives (size)
// guages: clients (int), corpus (size), execution rate (exec/sec)
    // NOTE: set() only available with guages (not counters).
        // - may have to just make everything a guage

// set up HTTP listener on /metrics, port 9090 (or just default)
    // example using tide: https://github.com/prometheus/client_rust/blob/master/examples/tide.rs

#[cfg(feature = "introspection")]
use alloc::string::ToString;
// use alloc::{fmt::Debug, string::String, vec::Vec, boxed::Box}; // Box added for tide
use alloc::{fmt::Debug, string::String, vec::Vec};
// use core::{fmt::Write, time::Duration};
// alloc::boxed::Box
use core::{fmt, time::Duration};
    
use crate::{
    bolts::{current_time, format_duration_hms},
    monitors::{ClientStats, Monitor},
};

// stuff for prometheus
// using the official rust client library for Prometheus: https://github.com/prometheus/client_rust
use prometheus_client::encoding::text::encode;
// use prometheus_client::encoding::Encode;
// use prometheus_client::encoding::text::Encode;
use prometheus_client::metrics::gauge::Gauge;
// use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;

use std::sync::Arc;
use std::thread; // to start the HTTP server in a separate thread
use futures::executor::block_on;
// use std::string::ToString;

// Using tide for the HTTP server library. fast, async, simple
// use tide::{Middleware, Next, Request, Result};
use tide::Request;
// end of stuff for prometheus

// static registry: Registry = Registry::default(); // creates more type issues

/// Tracking monitor during fuzzing.
#[derive(Clone)]
pub struct PrometheusMonitor<F>
where
    F: FnMut(String),
{
    print_fn: F,
    start_time: Duration,
    client_stats: Vec<ClientStats>,
    // registry: Registry<Family<Labels,Gauge>>
}

impl<F> Debug for PrometheusMonitor<F>
where
    F: FnMut(String),
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrometheusMonitor")
            .field("start_time", &self.start_time)
            .field("client_stats", &self.client_stats)
            .finish()
    }
}

impl<F> Monitor for PrometheusMonitor<F>
where
    F: FnMut(String),
{
    /// the client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        &mut self.client_stats
    }

    /// the client monitor
    fn client_stats(&self) -> &[ClientStats] {
        &self.client_stats
    }

    /// Time this fuzzing run stated
    fn start_time(&mut self) -> Duration {
        self.start_time
    }

    fn display(&mut self, event_msg: String, sender_id: u32) {
        update_registry(self.corpus_size(), self.objective_size(), self.total_execs(), self.execs_per_sec()); // TODO: implement this function and all stats
        let fmt = format!(
            "[Prometheus] [{} #{}] run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            event_msg,
            sender_id,
            format_duration_hms(&(current_time() - self.start_time)),
            self.client_stats().len(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec()
        );
        (self.print_fn)(fmt);

        // Only print perf monitor if the feature is enabled
        #[cfg(feature = "introspection")]
        {
            // Print the client performance monitor.
            let fmt = format!(
                "Client {:03}:\n{}",
                sender_id, self.client_stats[sender_id as usize].introspection_monitor
            );
            (self.print_fn)(fmt);
            // might need to use this version? from multi.
            // for (i, client) in self.client_stats.iter().skip(1).enumerate() {
            //     let fmt = format!("Client {:03}:\n{}", i + 1, client.introspection_monitor);
            //     (self.print_fn)(fmt);
            // }

            // Separate the spacing just a bit
            (self.print_fn)(String::new());
        }
    }
}

impl<F> PrometheusMonitor<F>
where
    F: FnMut(String), // shouldn't need this generic. can get rid of it
{
    /// Creates the monitor, using the `current_time` as `start_time`.
    pub fn new(print_fn: F) -> Self {
        // registry should be created here, and added into the Struct, so can access with self
            // problem is.. "Clone" not implemented issues blah blah blah figure this out. implement manually if needed
            // also potential issue of passing btwn threads?
        // need to run the metrics server in a diff thread to avoid blocking
        thread::spawn(move || {
            block_on(serve_metrics()).map_err(|err| println!("{:?}", err)).ok(); // TODO: less ugly way to get rid of the 'must use Result' thing
        });
        // the function that is passed when initializing a new monitor in a fuzzer is "print_fn". in this case don't need it.
        Self {
            print_fn,
            start_time: current_time(),
            client_stats: vec![],
        }
        
    }

    /// Creates the monitor with a given `start_time`.
    pub fn with_time(print_fn: F, start_time: Duration) -> Self {
        Self {
            print_fn,
            start_time,
            client_stats: vec![],
        }
    }
}

// ----------------------------------------------------------
// using https://github.com/prometheus/client_rust/blob/master/examples/tide.rs as a base server
// static registry: Registry<Gauge>= Registry::default();
// apparently using lazy static is quite slow https://stackoverflow.com/questions/64719104/what-is-better-in-rust-defining-a-static-variable-to-access-it-globally-or-pass
// #[async_std::main]
pub async fn serve_metrics() -> Result<(), std::io::Error> {
    tide::log::start();
    println!("we're in tide"); // debugging

    // will need to move all the prometheus_client stuff into PrometheusMonitor
        // TODO: THIS ^^^^^^
    // this tide stuff should just stand up the endpoint, pulling data from the registry
    // the prometheus_client code in PrometheusMonitor should add all data to the registry

    let mut registry = Registry::default();
    // let executions = Family::<Labels, Gauge>::default();
    let executions = Gauge::default();
    registry.register(
        "executions_total",
        "Number of executions the fuzzer has done",
        executions.clone(),
    );
    // ... do for all stats

    // let middleware = MetricsMiddleware {
    //     executions,
    // };
    // let updatemetrics = UpdateRegistry {
    //     executions,
    // };

    let mut app = tide::with_state(State {
        registry: Arc::new(registry),
    });

    // app.with(middleware);
    app.at("/").get(|_| async { Ok("Wassup") });
    app.at("/metrics")
        .get(|req: Request<State>| async move {
            let mut encoded = Vec::new();
            encode(&mut encoded, &req.state().registry).unwrap();
            let response = tide::Response::builder(200)
                .body(encoded)
                .content_type("application/openmetrics-text; version=1.0.0; charset=utf-8")
                .build();
            Ok(response)
        });
    app.listen("127.0.0.1:8080").await?;

    Ok(())
}

pub fn update_registry(_corpus_size: u64, _objective_size: u64, _total_execs: u64, _execs_per_sec: u64) {
    // TODO: set vals in registry to the passed values
    // executions.set(_total_execs); // NEED TO BE ABLE TO ACCESS IN THIS SCOPE WHY IS THIS DIFFICULT LOL
    println!("{}", _corpus_size) // just a test to see if it gets updated... and it does!
}

// #[derive(Clone, Hash, PartialEq, Eq, Encode)]
// struct Labels {
//     being_fuzzed: String,
// }

#[derive(Clone)]
struct State {
    #[allow(dead_code)]
    registry: Arc<Registry<Gauge>>,
}

// #[derive(Default)]
// struct UpdateRegistry {
//     executions: Family<Labels, Gauge>,
// }

// impl UpdateRegistry {
//     fn update_registry(&mut self, _corpus_size: u64, _objective_size: u64, _total_execs: u64, _execs_per_sec: u64) {
//         self.executions.set(_total_execs);
//     }
// }

// #[derive(Default)]
// struct MetricsMiddleware {
//     executions: Family<Labels, Gauge>,
// }

// #[tide::utils::async_trait]
// impl Middleware<State> for MetricsMiddleware {
//     // likely don't need middleware
//     async fn handle(&self, req: Request<State>, next: Next<'_, State>) -> Result {
//         let path = req.url().path().to_string();
//         let _count = self
//             .executions
//             .get_or_create(&Labels { path })
//             .inc();

//         let res = next.run(req).await;
//         Ok(res)
//     }
// }