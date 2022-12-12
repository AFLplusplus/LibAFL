// ===== overview for prommon =====
// The client (i.e., the fuzzer) sets up an HTTP endpoint (/metrics).
// The endpoint contains metrics such as execution rate.

// A prometheus server (can use a precompiled binary or docker) then scrapes \
// the endpoint at regular intervals (configurable via prometheus.yml file).
// ====================
//
// == how to use it ===
// This monitor should plug into any fuzzer similar to other monitors.
// In your fuzzer, include:
// use libafl::monitors::PrometheusMonitor;
// as well as:
// let listener = "127.0.0.1:8080".to_string(); // point prometheus to scrape here in your prometheus.yml
// let mon = PrometheusMonitor::new(listener, |s| println!("{}", s));
// and then like with any other monitor, pass it into the event manager like so:
// let mut mgr = SimpleEventManager::new(mon);
// When using docker, you may need to point prometheus.yml to the docker0 interface or host.docker.internal
// ====================

use alloc::{fmt::Debug, string::String, vec::Vec};
use core::{fmt, time::Duration};
use std::{
    boxed::Box,
    sync::{atomic::AtomicU64, Arc},
    thread,
};

// using thread in order to start the HTTP server in a separate thread
use futures::executor::block_on;
// using the official rust client library for Prometheus: https://github.com/prometheus/client_rust
use prometheus_client::{
    encoding::text::{encode, Encode, SendSyncEncodeMetric},
    metrics::{family::Family, gauge::Gauge},
    registry::Registry,
};
// using tide for the HTTP server library (fast, async, simple)
use tide::Request;

use crate::{
    bolts::{current_time, format_duration_hms},
    monitors::{ClientStats, Monitor, UserStats},
};

/// Tracking monitor during fuzzing.
#[derive(Clone)]
pub struct PrometheusMonitor<F>
where
    F: FnMut(String),
{
    print_fn: F,
    start_time: Duration,
    client_stats: Vec<ClientStats>,
    corpus_count: Family<Labels, Gauge>,
    objective_count: Family<Labels, Gauge>,
    executions: Family<Labels, Gauge>,
    exec_rate: Family<Labels, Gauge>,
    runtime: Family<Labels, Gauge>,
    clients_count: Family<Labels, Gauge>,
    custom_stat: Family<Labels, Gauge<f64, AtomicU64>>,
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
        // Label each metric with the sender / client_id
        let corpus_size = self.corpus_size();
        self.corpus_count
            .get_or_create(&Labels {
                client: sender_id,
                stat: String::new(),
            })
            .set(corpus_size);
        let objective_size = self.objective_size();
        self.objective_count
            .get_or_create(&Labels {
                client: sender_id,
                stat: String::new(),
            })
            .set(objective_size);
        let total_execs = self.total_execs();
        self.executions
            .get_or_create(&Labels {
                client: sender_id,
                stat: String::new(),
            })
            .set(total_execs);
        let execs_per_sec = self.execs_per_sec();
        self.exec_rate
            .get_or_create(&Labels {
                client: sender_id,
                stat: String::new(),
            })
            .set(execs_per_sec);
        let run_time = (current_time() - self.start_time).as_secs();
        self.runtime
            .get_or_create(&Labels {
                client: sender_id,
                stat: String::new(),
            })
            .set(run_time); // run time in seconds, which can be converted to a time format by Grafana or similar
        let total_clients = self.client_stats().len().try_into().unwrap(); // convert usize to u64 (unlikely that # of clients will be > 2^64 -1...)
        self.clients_count
            .get_or_create(&Labels {
                client: sender_id,
                stat: String::new(),
            })
            .set(total_clients);

        // display stats in a SimpleMonitor format
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

        let cur_client = self.client_stats_mut_for(sender_id);
        let cur_client_clone = cur_client.clone();

        for (key, val) in cur_client_clone.user_monitor {
            // Update metrics added to the user_stats hashmap by feedback event-fires
            // You can filter for each custom stat in promQL via labels of both the stat name and client id
            println!("{key}: {val}");
            #[allow(clippy::cast_precision_loss)]
            let value: f64 = match val {
                UserStats::Number(n) => n as f64,
                UserStats::Float(f) => f,
                UserStats::String(_s) => 0.0,
                UserStats::Ratio(a, b) => (a as f64 / b as f64) * 100.0,
            };
            self.custom_stat
                .get_or_create(&Labels {
                    client: sender_id,
                    stat: key.clone(),
                })
                .set(value);
        }
    }
}

impl<F> PrometheusMonitor<F>
where
    F: FnMut(String),
{
    pub fn new(listener: String, print_fn: F) -> Self {
        // Gauge's implementation of clone uses Arc
        let corpus_count = Family::<Labels, Gauge>::default();
        let corpus_count_clone = corpus_count.clone();
        let objective_count = Family::<Labels, Gauge>::default();
        let objective_count_clone = objective_count.clone();
        let executions = Family::<Labels, Gauge>::default();
        let executions_clone = executions.clone();
        let exec_rate = Family::<Labels, Gauge>::default();
        let exec_rate_clone = exec_rate.clone();
        let runtime = Family::<Labels, Gauge>::default();
        let runtime_clone = runtime.clone();
        let clients_count = Family::<Labels, Gauge>::default();
        let clients_count_clone = clients_count.clone();
        let custom_stat = Family::<Labels, Gauge<f64, AtomicU64>>::default();
        let custom_stat_clone = custom_stat.clone();

        // Need to run the metrics server in a different thread to avoid blocking
        thread::spawn(move || {
            block_on(serve_metrics(
                listener,
                corpus_count_clone,
                objective_count_clone,
                executions_clone,
                exec_rate_clone,
                runtime_clone,
                clients_count_clone,
                custom_stat_clone,
            ))
            .map_err(|err| println!("{err:?}"))
            .ok();
        });
        Self {
            print_fn,
            start_time: current_time(),
            client_stats: vec![],
            corpus_count,
            objective_count,
            executions,
            exec_rate,
            runtime,
            clients_count,
            custom_stat,
        }
    }
    /// Creates the monitor with a given `start_time`.
    pub fn with_time(listener: String, print_fn: F, start_time: Duration) -> Self {
        let corpus_count = Family::<Labels, Gauge>::default();
        let corpus_count_clone = corpus_count.clone();
        let objective_count = Family::<Labels, Gauge>::default();
        let objective_count_clone = objective_count.clone();
        let executions = Family::<Labels, Gauge>::default();
        let executions_clone = executions.clone();
        let exec_rate = Family::<Labels, Gauge>::default();
        let exec_rate_clone = exec_rate.clone();
        let runtime = Family::<Labels, Gauge>::default();
        let runtime_clone = runtime.clone();
        let clients_count = Family::<Labels, Gauge>::default();
        let clients_count_clone = clients_count.clone();
        let custom_stat = Family::<Labels, Gauge<f64, AtomicU64>>::default();
        let custom_stat_clone = custom_stat.clone();

        thread::spawn(move || {
            block_on(serve_metrics(
                listener,
                corpus_count_clone,
                objective_count_clone,
                executions_clone,
                exec_rate_clone,
                runtime_clone,
                clients_count_clone,
                custom_stat_clone,
            ))
            .map_err(|err| println!("{err:?}"))
            .ok();
        });
        Self {
            print_fn,
            start_time,
            client_stats: vec![],
            corpus_count,
            objective_count,
            executions,
            exec_rate,
            runtime,
            clients_count,
            custom_stat,
        }
    }
}

// set up an HTTP endpoint /metrics
#[allow(clippy::too_many_arguments)]
pub async fn serve_metrics(
    listener: String,
    corpus: Family<Labels, Gauge>,
    objectives: Family<Labels, Gauge>,
    executions: Family<Labels, Gauge>,
    exec_rate: Family<Labels, Gauge>,
    runtime: Family<Labels, Gauge>,
    clients_count: Family<Labels, Gauge>,
    custom_stat: Family<Labels, Gauge<f64, AtomicU64>>,
) -> Result<(), std::io::Error> {
    tide::log::start();

    let mut registry = <Registry>::default();

    registry.register(
        "corpus_count",
        "Number of test cases in the corpus",
        Box::new(corpus),
    );
    registry.register(
        "objective_count",
        "Number of times the objective has been achieved (e.g., crashes)",
        Box::new(objectives),
    );
    registry.register(
        "executions_total",
        "Number of executions the fuzzer has done",
        Box::new(executions),
    );
    registry.register(
        "execution_rate",
        "Rate of executions per second",
        Box::new(exec_rate),
    );
    registry.register(
        "runtime",
        "How long the fuzzer has been running for (seconds)",
        Box::new(runtime),
    );
    registry.register(
        "clients_count",
        "How many clients have been spawned for the fuzzing job",
        Box::new(clients_count),
    );
    registry.register(
        "custom_stat",
        "A metric to contain custom stats returned by feedbacks, filterable by label",
        Box::new(custom_stat),
    );

    let mut app = tide::with_state(State {
        registry: Arc::new(registry),
    });

    app.at("/")
        .get(|_| async { Ok("LibAFL Prometheus Monitor") });
    app.at("/metrics").get(|req: Request<State>| async move {
        let mut encoded = Vec::new();
        encode(&mut encoded, &req.state().registry).unwrap();
        let response = tide::Response::builder(200)
            .body(encoded)
            .content_type("application/openmetrics-text; version=1.0.0; charset=utf-8")
            .build();
        Ok(response)
    });
    app.listen(listener).await?;

    Ok(())
}

#[derive(Clone, Hash, PartialEq, Eq, Encode, Debug)]
pub struct Labels {
    client: u32, // sender_id: u32, to differentiate between clients when multiple are spawned.
    stat: String, // for custom_stat filtering.
}

#[derive(Clone)]
struct State {
    #[allow(dead_code)]
    registry: Arc<Registry<Box<dyn SendSyncEncodeMetric>>>,
}
