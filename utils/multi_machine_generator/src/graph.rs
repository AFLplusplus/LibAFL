use std::net::SocketAddr;

use petgraph::{graph::NodeIndex, Direction, Graph};

/// A node of the network
#[derive(Debug, Clone, Default)]
pub struct MultiMachineNode {}

/// The tree
pub struct MultiMachineTree {
    pub graph: Graph<MultiMachineNode, ()>,
}

impl MultiMachineNode {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl MultiMachineTree {
    /// Generate a multi-machine tree.
    ///
    ///
    /// - machines: machines to add.
    /// - `max_children_per_parent`: each parent will have at most this amount of children
    #[must_use]
    pub fn generate(machines: &[SocketAddr], max_children_per_parent: u64) -> Self {
        let mut graph = Graph::<MultiMachineNode, ()>::new();
        let mut machines = Vec::from(machines);

        let root = if let Some(_root) = machines.pop() {
            graph.add_node(MultiMachineNode::new())
        } else {
            return Self { graph };
        };

        let mut graph = Self { graph };

        let mut populate_idx = 0u64; // round-robin population to avoid congestion
        let mut nodes_to_populate_now: Vec<NodeIndex> = vec![root]; // current nodes we are working on

        let mut nodes_to_populate_later: Vec<NodeIndex> = Vec::new();

        // place all the machines in the graph
        while let Some(_machine) = machines.pop() {
            if graph.nb_children(nodes_to_populate_now[populate_idx as usize])
                == max_children_per_parent
            {
                nodes_to_populate_now = core::mem::take(&mut nodes_to_populate_later);
                populate_idx = 0; // should be useless
            }

            let new_child = graph.add_child(
                nodes_to_populate_now[populate_idx as usize],
                MultiMachineNode::new(),
            );
            nodes_to_populate_later.push(new_child);

            populate_idx = (populate_idx + 1) % nodes_to_populate_now.len() as u64;
        }

        graph
    }

    fn add_child(&mut self, parent: NodeIndex, child: MultiMachineNode) -> NodeIndex {
        let child_idx = self.graph.add_node(child);
        self.graph.add_edge(child_idx, parent, ());
        child_idx
    }

    fn nb_children(&self, node: NodeIndex) -> u64 {
        self.graph
            .neighbors_directed(node, Direction::Incoming)
            .count() as u64
    }
}
