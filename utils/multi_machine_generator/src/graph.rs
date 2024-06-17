use std::net::SocketAddr;
use petgraph::Graph;

pub struct MultiMachineNode {
    addr: SocketAddr
}

pub struct MultiMachineTree {
    graph: Graph<>
}