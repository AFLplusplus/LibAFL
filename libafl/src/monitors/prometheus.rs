// ===== overview for prommon =====
// The client (i.e., the fuzzer) sets up an HTTP endpoint (/metrics). 
// The endpoint contains metrics such as execution rate.

// A prometheus server (can use precompiled binary or docker) then scrapes \
// the endpoint at regular intervals (configurable via yaml file).
// ====================
//
// == how to use it ===
// This monitor should plug into any fuzzer similar to other monitors.
// In your fuzzer, include:
// use libafl::monitors::PrometheusMonitor;
// as well as:
// let mon = PrometheusMonitor::new(|s| println!("{}", s));
// and then like with any other monitor, pass it into the event manager like so:
// let mut mgr = SimpleEventManager::new(mon);
// ====================

// #[cfg(feature = "introspection")]
// use alloc::string::ToString;
use alloc::{fmt::Debug, string::String, vec::Vec};
use core::{fmt, time::Duration};

use crate::{
    bolts::{current_time, format_duration_hms},
    monitors::{ClientStats, Monitor},
};

// -- imports for prometheus instrumentation --
// using the official rust client library for Prometheus: https://github.com/prometheus/client_rust
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
// use prometheus_client::registry::Unit;

use std::sync::Arc;
// using thread in order to start the HTTP server in a separate thread
use std::thread;
use futures::executor::block_on;

// using tide for the HTTP server library (fast, async, simple)
use tide::Request;
// -- end of imports for instrumentation --

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
    corpus_count: Gauge,
    objective_count: Gauge,
    executions: Gauge,
    exec_rate: Gauge,
    runtime: Gauge
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
        
        // Update the prometheus metrics
        let corpus_size = self.corpus_size();
        self.corpus_count.set(corpus_size);
        let objective_size = self.objective_size();
        self.objective_count.set(objective_size);
        let total_execs = self.total_execs();
        self.executions.set(total_execs);
        let execs_per_sec = self.execs_per_sec();
        self.exec_rate.set(execs_per_sec);
        let run_time = (current_time() - self.start_time).as_secs();
        self.runtime.set(run_time); // run time in seconds, which can be converted to a time format by Grafana or similar

        // display stats in a SimpleMonitor format
        // TODO: put this behind a configuration flag / feature
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
            ); // can access things w introspection_monitor"."
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
    pub fn new(print_fn: F) -> Self {
        // note that Gauge's clone does Arc stuff, so ~shouldn't~ need to worry about passing btwn threads
        let corpus_count = Gauge::default();
        let corpus_count_clone = corpus_count.clone();
        let objective_count = Gauge::default();
        let objective_count_clone = objective_count.clone();
        let executions = Gauge::default();
        let executions_clone = executions.clone();
        let exec_rate = Gauge::default();
        let exec_rate_clone = exec_rate.clone();
        let runtime = Gauge::default();
        let runtime_clone = runtime.clone();

        // Need to run the metrics server in a diff thread to avoid blocking
        thread::spawn(move || {
            block_on(serve_metrics(corpus_count_clone, objective_count_clone, executions_clone, exec_rate_clone, runtime_clone)).map_err(|err| println!("{:?}", err)).ok(); // TODO: less ugly way to get rid of the 'must use Result' thing
        });
        Self {
            print_fn,
            start_time: current_time(),
            client_stats: vec![],
            corpus_count: corpus_count,
            objective_count: objective_count,
            executions: executions,
            exec_rate: exec_rate,
            runtime: runtime,
        }

    }
    // TODO: add metrics creations
    /// Creates the monitor with a given `start_time`.
    pub fn with_time(print_fn: F, start_time: Duration) -> Self {
        Self {
            print_fn,
            start_time,
            client_stats: vec![],
            corpus_count: Gauge::default(),
            objective_count: Gauge::default(),
            executions: Gauge::default(),
            exec_rate: Gauge::default(),
            runtime: Gauge::default(),
        }
    }
}


// Using https://github.com/prometheus/client_rust/blob/master/examples/tide.rs as a base server

// set up an HTTP endpoint, /metrics, localhost:8080
pub async fn serve_metrics(corpus: Gauge, objectives: Gauge, executions: Gauge, exec_rate: Gauge, runtime: Gauge) -> Result<(), std::io::Error> {
    tide::log::start();

    let mut registry = Registry::default();
    registry.register(
        "corpus_count",
        "Number of test cases in the corpus",
        corpus,
    );
    registry.register(
        "objective_count",
        "Number of times the objective has been achieved (e.g., crashes)",
        objectives,
    );
    registry.register(
        "executions_total",
        "Number of executions the fuzzer has done",
        executions,
    );
    registry.register(
        "execution_rate",
        "Rate of executions per second",
        exec_rate,
    );
    registry.register(
        "runtime", 
        "How long the fuzzer has been running for (seconds)", 
        runtime,
    );

    let mut app = tide::with_state(State {
        registry: Arc::new(registry),
    });

    app.at("/").get(|_| async { Ok("Hi! Prometheus Client Metrics -> /metrics :)") });
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

#[derive(Clone)]
struct State {
    #[allow(dead_code)]
    registry: Arc<Registry<Gauge>>,
}
