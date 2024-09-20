use std::{
    fmt::{Display, Formatter},
    mem,
};

use petgraph::{graph::NodeIndex, Direction, Graph};
use serde::Serialize;

/// A node of the network
#[derive(Debug, Clone)]
pub struct MultiMachineNode {
    addr: String,
}

/// The final configuration of a node on the network
#[derive(Debug, Clone, Serialize)]
pub struct MultiMachineNodeConfig {
    addr: String,
    parent: Option<String>,
    port: u16,
}

/// The tree
pub struct MultiMachineTree {
    pub graph: Graph<MultiMachineNode, MultiMachineEdge>,
}

pub struct MultiMachineEdge;

impl Display for MultiMachineEdge {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "")
    }
}

impl Display for MultiMachineNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl MultiMachineNode {
    #[must_use]
    pub fn new(addr: String) -> Self {
        Self { addr }
    }
}

impl MultiMachineTree {
    /// Generate a multi-machine tree.
    ///
    ///
    /// - machines: machines to add.
    /// - `max_children_per_parent`: each parent will have at most this amount of children
    #[must_use]
    pub fn generate(machines: &[String], max_children_per_parent: u64) -> Self {
        let mut graph = Graph::<MultiMachineNode, MultiMachineEdge>::new();
        let mut machines = Vec::from(machines);
        machines.reverse();

        let root = if let Some(root) = machines.pop() {
            graph.add_node(MultiMachineNode::new(root))
        } else {
            return Self { graph };
        };

        let mut graph = Self { graph };

        let mut populate_idx = 0u64; // round-robin population to avoid congestion
        let mut nodes_to_populate_now: Vec<NodeIndex> = vec![root]; // current nodes we are working on

        let mut nodes_to_populate_later: Vec<NodeIndex> = Vec::new();

        // place all the machines in the graph
        while let Some(machine) = machines.pop() {
            if graph.nb_children(nodes_to_populate_now[populate_idx as usize])
                == max_children_per_parent
            {
                nodes_to_populate_now = mem::take(&mut nodes_to_populate_later);
                populate_idx = 0; // should be useless
            }

            let new_child = graph.add_child(
                nodes_to_populate_now[populate_idx as usize],
                MultiMachineNode::new(machine),
            );
            nodes_to_populate_later.push(new_child);

            populate_idx = (populate_idx + 1) % nodes_to_populate_now.len() as u64;
        }

        graph
    }

    fn add_child(&mut self, parent: NodeIndex, child: MultiMachineNode) -> NodeIndex {
        let child_idx = self.graph.add_node(child);
        self.graph.add_edge(child_idx, parent, MultiMachineEdge);
        child_idx
    }

    fn nb_children(&self, node: NodeIndex) -> u64 {
        self.graph
            .neighbors_directed(node, Direction::Incoming)
            .count() as u64
    }

    fn get_parent(&self, node: NodeIndex) -> Option<NodeIndex> {
        self.graph
            .neighbors_directed(node, Direction::Outgoing)
            .next()
    }

    #[must_use]
    pub fn get_config(&self, default_port: u16) -> Vec<MultiMachineNodeConfig> {
        let mut node_configs: Vec<MultiMachineNodeConfig> = Vec::new();
        for node_idx in self.graph.node_indices() {
            let node = &self.graph[node_idx];

            let parent = self
                .get_parent(node_idx)
                .map(|parent_idx| self.graph[parent_idx].addr.clone());

            node_configs.push(MultiMachineNodeConfig {
                addr: node.addr.clone(),
                parent,
                port: default_port,
            });
        }

        node_configs
    }
}
