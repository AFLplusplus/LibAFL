# StatsD Monitor

In modern fuzzing situations, it is very common to have multiple fuzzing instances running. LibAFL supports monitoring mutiple fuzzing instances with `StatsdMonitor`, which can be easily enabled by adding `statsd_monitor` feature in `Cargo.toml`:

```toml
[dependencies]
libafl = { version = "*", features = ["statsd_monitor"]}
```

## Introduction to StatsD Architecture

A typical StatsD setup involves four participants: multiple StatsD clients, a StatsD aggregator, a Prometheus, and a visualizer.

Normally, each fuzzing instance is bound to a StatsD client (the `StatsdMonitor`). The StatsD client pushes fuzzing metrics (e.g. exec per second) towards the StatsD aggregator consistently. The Prometheus server is the center of StatsD metrics, which polls StatsD metrics from the StatsD aggregator at a speicific polling frequency. The visualizer queries the Prometheus server, and display the metrics for further analysis and monitoring.

## Set up a StatsD Monitor Infrastructure

The easiest way to install and set up the infrastructure is with Docker and Docker Compose. To begin with, create a directory with the following files:

* `docker-compose.yml`
    ```yml
    networks:
      statsd-net:
        driver: bridge
    
    volumes:
      grafana-data:

    services:
      prometheus:
        image: prom/prometheus
        container_name: prometheus
        volumes:
          - ./prometheus.yml:/prometheus.yml
        command:
          - '--config.file=/prometheus.yml'
        restart: unless-stopped
        ports:
          - "9090:9090"
        networks:
          - statsd-net

      statsd_exporter:
        image: prom/statsd-exporter
        container_name: statsd_exporter
        volumes:
          - ./statsd_mapping.yml:/statsd_mapping.yml
        command:
          - "--statsd.mapping-config=/statsd_mapping.yml"
        ports:
          - "9102:9102/tcp"
          - "8125:9125/udp"
        networks:
          - statsd-net

      grafana:
        image: grafana/grafana
        container_name: grafana
        volumes:
          - grafana-data:/var/lib/grafana
        restart: unless-stopped
        ports:
            - "3000:3000"
        networks:
          - statsd-net
    ```
* `prometheus.yml`

    ```yml
    global:
      scrape_interval:      15s
      evaluation_interval:  15s

    scrape_configs:
      - job_name: 'fuzzing_metrics'
        static_configs:
          - targets: ['statsd_exporter:9102']
    ```
* `statsd_mapping.yml`

    ```yml
    mappings:
    - match: "fuzzing.*"
      name: "fuzzing"
      labels:
          type: "$1"
    ```

And use

```shell
docker compose up -d
```

Then the basic infrastructure is set up, and you can go to `localhost:3000` to view StatsD metrics (the default username and password for Grafana docker login is admin/admin).

It is worth noting that all participants are not necessarily be in the same machine, as long as they could communicate with each other with network. Speicifically, the StatsD aggregator should be accessible from StatsD clients and Prometheus server, and the Prometheus server should be accessible from the visualizer.

In this infrastructure setup, we choose the [prometheus/statsd-exporter](https://github.com/prometheus/statsd_exporter) as a StatsD aggregator, which aggregates metrics from multiple StatsD clients, and converts the metrics into Prometheus format. And we choose the [Grafana](https://grafana.com) as the visualizer.

## Use `StatsdMonitor` in LibAFL

It is rather easy to use the `StatsdMonitor` in LibAFL. Let's say you were using a `MultiMonitor` previously:

```rust,ignore
let monitor = MultiMonitor::new(|s| println!("{s}"));
```

Then you could just create a `StatsdMonitor` and combine this two monitors with a `tuple_list!`:

```rust,ignore
let multi_monitor = MultiMonitor::new(|s| println!("{s}"));
let statsd_monitor = StatsdMonitor::new("localhost".to_string(), 8125, StatsdMonitorTagFlavor::default());
let monitor = tuple_list!(multi_monitor, statsd_monitor);
```

Then the monitor will automatically push StatsD metrics towards the StatsD aggregator at localhost:8125, which is speicified in the `docker-compose.yml` above.

### Tag Flavor

The vanilla StatsD metrics do not contain a tag

## References

* [AFL++'s docs about rpc_statsd](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/rpc_statsd.md)
* [Prometheus wikipedia](https://en.wikipedia.org/wiki/Prometheus_(software))
