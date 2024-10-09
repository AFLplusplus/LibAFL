//! The [`PrometheusMonitor`] logs fuzzer progress to a prometheus endpoint.
//!
//! ## Overview
//!
//! The client (i.e., the fuzzer) sets up an HTTP endpoint (/metrics).
//! The endpoint contains metrics such as execution rate.
//!
//! A prometheus server (can use a precompiled binary or docker) then scrapes
//! the endpoint at regular intervals (configurable via prometheus.yml file).
//!
//! ## How to use it
//!
//! Create a [`PrometheusMonitor`] and plug it into any fuzzer similar to other monitors.
//! In your fuzzer:
//!
//! ```rust
//! // First, include:
//! use libafl::monitors::PrometheusMonitor;
//!
//! // Then, create the monitor:
//! let listener = "127.0.0.1:8080".to_string(); // point prometheus to scrape here in your prometheus.yml
//! let mon = PrometheusMonitor::new(listener, |s| log::info!("{s}"));
//!
//! // and finally, like with any other monitor, pass it into the event manager like so:
//! // let mgr = SimpleEventManager::new(mon);
//! ```
//!
//! When using docker, you may need to point `prometheus.yml` to the `docker0` interface or `host.docker.internal`

use alloc::{borrow::Cow, fmt::Debug, string::String, vec::Vec};
use core::{fmt, time::Duration};
use std::{
    sync::{atomic::AtomicU64, Arc},
    thread,
};

// using thread in order to start the HTTP server in a separate thread
use futures::executor::block_on;
use libafl_bolts::{current_time, format_duration_hms, ClientId};
// using the official rust client library for Prometheus: https://github.com/prometheus/client_rust
use prometheus_client::{
    encoding::{text::encode, EncodeLabelSet},
    metrics::{family::Family, gauge::Gauge},
    registry::Registry,
};
// using tide for the HTTP server library (fast, async, simple)
use tide::Request;

use crate::monitors::{ClientStats, Monitor, UserStatsValue};

/// Tracking monitor during fuzzing.
#[derive(Clone)]
pub struct PrometheusMonitor<F>
where
    F: FnMut(&str),
{
    print_fn: F,
    start_time: Duration,
    client_stats: Vec<ClientStats>,
    corpus_count: Family<Labels, Gauge>,
    objective_count: Family<Labels, Gauge>,
    executions: Family<Labels, Gauge>,
    exec_rate: Family<Labels, Gauge<f64, AtomicU64>>,
    runtime: Family<Labels, Gauge>,
    clients_count: Family<Labels, Gauge>,
    custom_stat: Family<Labels, Gauge<f64, AtomicU64>>,
}

impl<F> Debug for PrometheusMonitor<F>
where
    F: FnMut(&str),
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrometheusMonitor")
            .field("start_time", &self.start_time)
            .field("client_stats", &self.client_stats)
            .finish_non_exhaustive()
    }
}

impl<F> Monitor for PrometheusMonitor<F>
where
    F: FnMut(&str),
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
    fn start_time(&self) -> Duration {
        self.start_time
    }

    /// Set creation time
    fn set_start_time(&mut self, time: Duration) {
        self.start_time = time;
    }

    #[allow(clippy::cast_sign_loss)]
    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        // Update the prometheus metrics
        // Label each metric with the sender / client_id
        // The gauges must take signed i64's, with max value of 2^63-1 so it is
        // probably fair to error out at a count of nine quintillion across any
        // of these counts.
        // realistically many of these metrics should be counters but would
        // require a fair bit of logic to handle "amount to increment given
        // time since last observation"
        let corpus_size = self.corpus_size();
        self.corpus_count
            .get_or_create(&Labels {
                client: sender_id.0,
                stat: Cow::from(""),
            })
            .set(corpus_size.try_into().unwrap());
        let objective_size = self.objective_size();
        self.objective_count
            .get_or_create(&Labels {
                client: sender_id.0,
                stat: Cow::from(""),
            })
            .set(objective_size.try_into().unwrap());
        let total_execs = self.total_execs();
        self.executions
            .get_or_create(&Labels {
                client: sender_id.0,
                stat: Cow::from(""),
            })
            .set(total_execs.try_into().unwrap());
        let execs_per_sec = self.execs_per_sec();
        self.exec_rate
            .get_or_create(&Labels {
                client: sender_id.0,
                stat: Cow::from(""),
            })
            .set(execs_per_sec);
        let run_time = (current_time() - self.start_time).as_secs();
        self.runtime
            .get_or_create(&Labels {
                client: sender_id.0,
                stat: Cow::from(""),
            })
            .set(run_time.try_into().unwrap()); // run time in seconds, which can be converted to a time format by Grafana or similar
        let total_clients = self.client_stats_count().try_into().unwrap(); // convert usize to u64 (unlikely that # of clients will be > 2^64 -1...)
        self.clients_count
            .get_or_create(&Labels {
                client: sender_id.0,
                stat: Cow::from(""),
            })
            .set(total_clients);

        // display stats in a SimpleMonitor format
        let fmt = format!(
            "[Prometheus] [{} #{}] run time: {}, clients: {}, corpus: {}, objectives: {}, executions: {}, exec/sec: {}",
            event_msg,
            sender_id.0,
            format_duration_hms(&(current_time() - self.start_time)),
            self.client_stats_count(),
            self.corpus_size(),
            self.objective_size(),
            self.total_execs(),
            self.execs_per_sec_pretty()
        );
        (self.print_fn)(&fmt);

        self.client_stats_insert(sender_id);
        let cur_client = self.client_stats_mut_for(sender_id);
        let cur_client_clone = cur_client.clone();

        for (key, val) in cur_client_clone.user_monitor {
            // Update metrics added to the user_stats hashmap by feedback event-fires
            // You can filter for each custom stat in promQL via labels of both the stat name and client id
            log::info!("{key}: {val}");
            #[allow(clippy::cast_precision_loss)]
            let value: f64 = match val.value() {
                UserStatsValue::Number(n) => *n as f64,
                UserStatsValue::Float(f) => *f,
                UserStatsValue::String(_s) => 0.0,
                UserStatsValue::Ratio(a, b) => (*a as f64 / *b as f64) * 100.0,
                UserStatsValue::Percent(p) => *p * 100.0,
            };
            self.custom_stat
                .get_or_create(&Labels {
                    client: sender_id.0,
                    stat: key.clone(),
                })
                .set(value);
        }
    }
}

impl<F> PrometheusMonitor<F>
where
    F: FnMut(&str),
{
    /// Create a new [`PrometheusMonitor`].
    /// The `listener` is the address to send logs to.
    /// The `print_fn` is the printing function that can output the logs otherwise.
    pub fn new(listener: String, print_fn: F) -> Self {
        // Gauge's implementation of clone uses Arc
        let corpus_count = Family::<Labels, Gauge>::default();
        let corpus_count_clone = corpus_count.clone();
        let objective_count = Family::<Labels, Gauge>::default();
        let objective_count_clone = objective_count.clone();
        let executions = Family::<Labels, Gauge>::default();
        let executions_clone = executions.clone();
        let exec_rate = Family::<Labels, Gauge<f64, AtomicU64>>::default();
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
            .map_err(|err| log::error!("{err:?}"))
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
        let exec_rate = Family::<Labels, Gauge<f64, AtomicU64>>::default();
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
            .map_err(|err| log::error!("{err:?}"))
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

/// Set up an HTTP endpoint /metrics
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_metrics(
    listener: String,
    corpus: Family<Labels, Gauge>,
    objectives: Family<Labels, Gauge>,
    executions: Family<Labels, Gauge>,
    exec_rate: Family<Labels, Gauge<f64, AtomicU64>>,
    runtime: Family<Labels, Gauge>,
    clients_count: Family<Labels, Gauge>,
    custom_stat: Family<Labels, Gauge<f64, AtomicU64>>,
) -> Result<(), std::io::Error> {
    let mut registry = Registry::default();

    registry.register("corpus_count", "Number of test cases in the corpus", corpus);
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
    registry.register("execution_rate", "Rate of executions per second", exec_rate);
    registry.register(
        "runtime",
        "How long the fuzzer has been running for (seconds)",
        runtime,
    );
    registry.register(
        "clients_count",
        "How many clients have been spawned for the fuzzing job",
        clients_count,
    );
    registry.register(
        "custom_stat",
        "A metric to contain custom stats returned by feedbacks, filterable by label",
        custom_stat,
    );

    let mut app = tide::with_state(State {
        registry: Arc::new(registry),
    });

    app.at("/")
        .get(|_| async { Ok("LibAFL Prometheus Monitor") });
    app.at("/metrics").get(|req: Request<State>| async move {
        let mut encoded = String::new();
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

/// Struct used to define the labels in `prometheus`.
#[derive(Clone, Hash, PartialEq, Eq, EncodeLabelSet, Debug)]
pub struct Labels {
    /// The `sender_id` helps to differentiate between clients when multiple are spawned.
    client: u32,
    /// Used for `custom_stat` filtering.
    stat: Cow<'static, str>,
}

/// The state for this monitor.
#[derive(Clone)]
struct State {
    registry: Arc<Registry>,
}
