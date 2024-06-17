//! Multi Machine Generator
//!
//! Generates a ready-to-run multi-machine configuration, as a balanced tree.
//! A simple algorithm will first create such a tree, and associate IPs to them.
//! It will finally output a set of commands to run to have each fuzzer communicating correctly with the other machines of the network.
//!
//! We suppose everyone is on the same network and the machines have the fuzzer ready to run on each machine.


use std::fs;
use std::net::SocketAddr;
use std::str::FromStr;
use petgraph::dot::Dot;
use crate::graph::MultiMachineTree;

pub mod graph;

fn main() {
    let machines = [
        SocketAddr::from_str("0.0.0.1:50000").unwrap(),
        SocketAddr::from_str("0.0.0.2:50000").unwrap(),
        SocketAddr::from_str("0.0.0.3:50000").unwrap(),
        SocketAddr::from_str("0.0.0.4:50000").unwrap(),
        SocketAddr::from_str("0.0.0.5:50000").unwrap(),
        SocketAddr::from_str("0.0.0.6:50000").unwrap(),
        SocketAddr::from_str("0.0.0.7:50000").unwrap(),
        SocketAddr::from_str("0.0.0.8:50000").unwrap(),
        SocketAddr::from_str("0.0.0.9:50000").unwrap(),
        SocketAddr::from_str("0.0.0.10:50000").unwrap(),
        SocketAddr::from_str("0.0.0.11:50000").unwrap(),
        SocketAddr::from_str("0.0.0.12:50000").unwrap(),
        SocketAddr::from_str("0.0.0.13:50000").unwrap(),
        SocketAddr::from_str("0.0.0.14:50000").unwrap(),
        SocketAddr::from_str("0.0.0.15:50000").unwrap(),
        SocketAddr::from_str("0.0.0.16:50000").unwrap(),
        SocketAddr::from_str("0.0.0.17:50000").unwrap(),
        SocketAddr::from_str("0.0.0.18:50000").unwrap(),
    ];

    let multi_machine_graph = MultiMachineTree::generate(&machines, 3);

    let dot = Dot::new(&multi_machine_graph.graph);

    fs::write("multi_machine.dot", format!("{:?}", dot)).unwrap();
}
