//! Multi Machine Generator
//!
//! Generates a ready-to-run multi-machine configuration, as a balanced tree.
//! A simple algorithm will first create such a tree, and associate IPs to them.
//! It will finally output a set of commands to run to have each fuzzer communicating correctly with the other machines of the network.
//!
//! We suppose everyone is on the same network and the machines have the fuzzer ready to run on each machine.

use std::{fs, fs::File, io, io::BufRead, path::PathBuf};

use clap::Parser;
use petgraph::dot::Dot;

use crate::graph::MultiMachineTree;

pub mod graph;

#[derive(Parser)]
struct Opt {
    #[arg(short, long)]
    machines_file: PathBuf,
    #[arg(long)]
    dot_output: Option<PathBuf>,
    #[arg(short, long)]
    json_output: Option<PathBuf>,
    #[arg(short, long, default_value_t = 50000)]
    default_port: u16,
    // #[arg(short, long)]
    // cmd_file: PathBuf,
}

fn main() {
    let opt = Opt::parse();

    let machine_file = File::open(opt.machines_file.as_path()).unwrap();
    let machines: Vec<String> = io::BufReader::new(machine_file)
        .lines()
        .map(|m| m.unwrap())
        .collect();

    let multi_machine_graph = MultiMachineTree::generate(&machines, 3);

    // final graph
    if let Some(dot_path) = opt.dot_output {
        let dot = Dot::new(&multi_machine_graph.graph);
        fs::write(dot_path, format!("{dot}")).unwrap();
    }

    if let Some(json_path) = opt.json_output {
        let cfg = multi_machine_graph.get_config(opt.default_port);
        let cfg_json = serde_json::to_string_pretty(&cfg).unwrap();
        fs::write(json_path, cfg_json).unwrap();
    }
}
