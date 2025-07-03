//! LLVM style control flow graph with information of AFL-style index of the each
//! edges, use together with ``AFLCoverage`` pass having --dump-afl-cfg flag enabled.

extern crate alloc;

use alloc::collections::BinaryHeap;
use core::marker::PhantomData;
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Compute the weight of a [`CfgEdge`]. Lower means shorter distance in the graph.
pub trait HasWeight<T> {
    /// Compute the weight of a [`CfgEdge`]. Lower means shorter distance in the graph.
    fn compute(metadata: Option<&T>) -> u32;
}

/// An edge in the CFG.
#[derive(Debug, Serialize, Deserialize)]
pub struct CfgEdge<T>
where
    T: HasWeight<T>,
{
    /// The index of the coverage map AFL inserts to, which is (``prev_loc`` >> 1) ^ ``cur_loc``.
    pub xored_loc: usize,
    /// The from node's index (i.e., ``prev_loc``) in the edge.
    pub top_node_loc: usize,
    /// The to node's index (i.e., ``cur_loc``) in the edge.
    pub bottom_node_loc: usize,
    /// Name of the function that contains such edge. For anonymous function, it is "__".
    pub calling_func: String,
    /// Indexes of successor block.
    pub successor_basic_blocks: Vec<usize>,
    /// ``prev_loc`` >> 1 ^ ``cur_loc`` of edges connecting [`CfgEdge.bottom_node_loc`]
    /// to successor blocks.
    pub successor_edges: Vec<usize>,
    /// Custom metadata.
    pub metadata: Option<T>,
}

impl<T> CfgEdge<T>
where
    T: HasWeight<T>,
{
    /// Add a successor for an edge.
    pub fn add_successor(&mut self, successor_loc: usize) {
        self.successor_basic_blocks.push(successor_loc);
        self.successor_edges
            .push((self.bottom_node_loc >> 1) ^ successor_loc);
    }

    /// Calculate the weight of an edge.
    pub fn get_weight(&self) -> u32 {
        T::compute(self.metadata.as_ref())
    }
}

/// An entry basic block of a function.
#[derive(Debug)]
pub struct EntryBasicBlockInfo {
    /// Name of the function that contains such basic block. For anonymous function, it is "__".
    pub calling_func: String,
    /// The node's index (i.e., ``cur_loc``).
    pub node_loc: usize,
    /// ``prev_loc`` >> 1 ^ ``cur_loc`` of edges connecting [`EntryBasicBlockInfo.node_loc`]
    /// to successor blocks.
    pub successor_edges: Vec<usize>,
}

impl EntryBasicBlockInfo {
    /// Add a successor for an edge.
    pub fn add_successor(&mut self, successor_loc: usize) {
        self.successor_edges
            .push((self.node_loc >> 1) ^ successor_loc);
    }
}

/// An LLVM style control flow graph.
/// Note: This does not track across functions.
#[derive(Debug)]
pub struct ControlFlowGraph<T>
where
    T: HasWeight<T>,
{
    /// List of edges in the control flow graph.
    ///
    /// If there is collision, then only the latest edge would be saved.
    edges: Vec<Option<CfgEdge<T>>>,
    /// Mapping each function's name to its corresponding entry basic block information.
    func_to_entry_bb: HashMap<String, EntryBasicBlockInfo>,
}

impl<T> ControlFlowGraph<T>
where
    T: HasWeight<T>,
{
    /// Inserts an edge into CFG.
    #[must_use]
    pub fn new() -> Self {
        let map_size = option_env!("LIBAFL_EDGES_MAP_DEFAULT_SIZE")
            .map_or(Ok(65536), str::parse)
            .expect("Could not parse LIBAFL_EDGES_MAP_DEFAULT_SIZE");
        Self {
            edges: (0..map_size).map(|_| None).collect(),
            func_to_entry_bb: HashMap::default(),
        }
    }

    /// Inserts an edge into CFG.
    fn insert_edge(&mut self, xored_loc: usize, edge: CfgEdge<T>) {
        self.edges[xored_loc] = Some(edge);
    }

    /// Inserts a function and its entry basic block information into CFG.
    fn create_func_entry(&mut self, func_name: &str, entry_info: EntryBasicBlockInfo) {
        self.func_to_entry_bb
            .insert(func_name.to_string(), entry_info);
    }
}

/// Helper for reading CFG dump files.
#[derive(Debug)]
struct CfgFileReader<T>
where
    T: HasWeight<T>,
{
    current_bb: usize,
    bb_to_func: HashMap<usize, String>,
    bb_to_successors: HashMap<usize, Vec<usize>>,
    func_to_entry_bb: HashMap<String, usize>,
    phantom: PhantomData<T>,
}

impl<T> CfgFileReader<T>
where
    T: HasWeight<T>,
{
    pub fn new() -> Self {
        Self {
            current_bb: 0,
            bb_to_func: HashMap::default(),
            bb_to_successors: HashMap::default(),
            func_to_entry_bb: HashMap::default(),
            phantom: PhantomData,
        }
    }

    /// Parse a line in CFG dump files.
    pub fn parse_line(&mut self, line: &str) -> bool {
        const FAILED_TO_PARSE: &str = "Cannot parsing CFG file at line";
        if line.len() < 2 {
            return false;
        }
        let (_, line_content) = line.split_at(2);

        match &line[0..2] {
            "->" => {
                // "->{basic block id}": Map current basic block to its destination basic block.
                let successor: usize = line_content.parse().expect(FAILED_TO_PARSE);
                match self.bb_to_successors.get_mut(&self.current_bb) {
                    None => {
                        self.bb_to_successors
                            .insert(self.current_bb, vec![successor]);
                    }
                    Some(successors) => {
                        successors.push(successor);
                    }
                }
            }
            "%%" => {
                // "%%{function name}+{index}": Make current basic block to be {index}.
                let mut splitter = line_content.split('+');
                let func_name = splitter.next().expect(FAILED_TO_PARSE).into();
                self.current_bb = splitter.next().expect(FAILED_TO_PARSE).parse().expect("");
                self.bb_to_func.insert(self.current_bb, func_name);
            }
            "$$" => {
                // "$${function name}+{index}": Function {function name}'s entry block is {index}.
                let mut splitter = line_content.split('+');
                let func_name = splitter.next().expect(FAILED_TO_PARSE).into();
                let entry_bb: usize = splitter
                    .next()
                    .expect(FAILED_TO_PARSE)
                    .parse()
                    .expect(FAILED_TO_PARSE);
                self.func_to_entry_bb.insert(func_name, entry_bb);
            }
            _ => {}
        }
        true
    }

    /// Convert current state to a [`ControlFlowGraph`].
    pub fn to_cfg(&self) -> ControlFlowGraph<T> {
        let mut cfg = ControlFlowGraph::new();
        let mut entry_bb_locs: Vec<usize> = vec![];
        for (func_name, entry_bb) in &self.func_to_entry_bb {
            entry_bb_locs.push(*entry_bb);
            let mut entry = EntryBasicBlockInfo {
                calling_func: func_name.to_string(),
                node_loc: *entry_bb,
                successor_edges: vec![],
            };
            if let Some(successors) = self.bb_to_successors.get(entry_bb) {
                for successor in successors {
                    entry.add_successor(*successor);
                }
            }
            cfg.create_func_entry(func_name, entry);
        }

        // Insert edges from zero to entry basic blocks.
        let mut bb_to_successors_with_zero = self.bb_to_successors.clone();
        if !entry_bb_locs.is_empty() {
            bb_to_successors_with_zero.insert(0, entry_bb_locs);
        }

        for (bb_loc, successor_locs) in &bb_to_successors_with_zero {
            let current_func = match bb_loc {
                0 => self.bb_to_func.get(&successor_locs[0]).unwrap(),
                _ => self.bb_to_func.get(bb_loc).unwrap(),
            };
            for successor_loc in successor_locs {
                let xored_loc = (*bb_loc >> 1) ^ (*successor_loc);
                let mut edge = CfgEdge {
                    xored_loc,
                    top_node_loc: *bb_loc,
                    bottom_node_loc: *successor_loc,
                    calling_func: current_func.clone(),
                    successor_basic_blocks: vec![],
                    successor_edges: vec![],
                    metadata: None,
                };
                if let Some(successors_of_successor) = self.bb_to_successors.get(successor_loc) {
                    for successor_of_successor in successors_of_successor {
                        edge.add_successor(*successor_of_successor);
                    }
                }
                cfg.insert_edge(xored_loc, edge);
            }
        }
        cfg
    }
}

impl<T> ControlFlowGraph<T>
where
    T: HasWeight<T>,
{
    /// Load a CFG from a dump file generated by ``AFLCoverage`` pass.
    #[must_use]
    pub fn from_file(file_name: &str) -> ControlFlowGraph<T> {
        ControlFlowGraph::from_content(
            std::fs::read_to_string(file_name)
                .expect("file not found!")
                .as_str(),
        )
    }

    /// Load a CFG from string generated by ``AFLCoverage`` pass.
    #[expect(unused_must_use)]
    #[must_use]
    pub fn from_content(content: &str) -> ControlFlowGraph<T> {
        let mut reader = CfgFileReader::new();
        content
            .lines()
            .map(|line| reader.parse_line(line))
            .collect::<Vec<bool>>();
        reader.to_cfg()
    }
    /// Get the edge at the index of the coverage map AFL inserts to.
    #[must_use]
    pub fn get_edge(&self, xored_loc: usize) -> Option<&CfgEdge<T>> {
        self.edges[xored_loc].as_ref()
    }

    /// Get the mutable edge at the index of the coverage map AFL inserts to.
    #[must_use]
    pub fn get_edge_mut(&mut self, xored_loc: usize) -> Option<&mut CfgEdge<T>> {
        self.edges[xored_loc].as_mut()
    }

    /// Get entry basic block information of a function.
    #[must_use]
    pub fn get_entry(&self, func_name: &str) -> Option<&EntryBasicBlockInfo> {
        self.func_to_entry_bb.get(func_name)
    }

    /// Get mutable entry basic block information of a function.
    #[must_use]
    pub fn get_entry_mut(&mut self, func_name: &str) -> Option<&mut EntryBasicBlockInfo> {
        self.func_to_entry_bb.get_mut(func_name)
    }

    /// Calculate shortest distance from start edge to all other edges
    /// in the function containing such ``start``.
    ///
    /// Unreachable edges from ``start`` would not be inserted in the returned hash map.
    #[must_use]
    pub fn calculate_distances_to_all_edges(&self, start: usize) -> HashMap<usize, u32> {
        let mut distances: HashMap<usize, u32> = HashMap::new();
        let mut visited = HashSet::new();
        let mut to_visit = BinaryHeap::new(); // BinaryHeap<(loc, distance)>
        let initial_weight = self
            .get_edge(start)
            .expect("unknown destination")
            .get_weight();
        distances.insert(start, initial_weight);
        to_visit.push((start, initial_weight));

        while let Some((edge, distance)) = to_visit.pop() {
            if !visited.insert(edge) {
                continue;
            }
            if let Some(edge_info) = self.get_edge(edge) {
                for successor in &edge_info.successor_edges {
                    let successor_info =
                        self.get_edge(*successor).expect("unknown successor added");
                    let new_distance = distance + successor_info.get_weight();
                    let is_shorter = distances
                        .get(successor)
                        .is_none_or(|&current| new_distance < current);

                    if is_shorter {
                        distances.insert(*successor, new_distance);
                        to_visit.push((*successor, new_distance));
                    }
                }
            }
        }
        distances
    }
}

impl<T> Default for ControlFlowGraph<T>
where
    T: HasWeight<T>,
{
    fn default() -> Self {
        ControlFlowGraph::from_file(".cfg")
    }
}

#[cfg(test)]
mod tests {
    use crate::cfg::{ControlFlowGraph, HasWeight};

    struct TestMetadata {}

    impl HasWeight<TestMetadata> for TestMetadata {
        fn compute(_metadata: Option<&TestMetadata>) -> u32 {
            1
        }
    }

    // ┌────────────┐
    // │main (41864)├───────► main (52706)
    // └────┬───────┘             ▲
    //      │                     │
    //      └───────────────► main (26911) ────────────► main (41925)
    const TEST_GRAPH_STR: &str = "$$main+41864\n$$_ZN7MyClass1VEi+50306\n%%_ZN7MyClass1VEi+50306\n->19123\n%%main+41864\n->52706\n->26911\n%%main+52706\n%%main+26911\n->52706\n->41925\n";

    #[test]
    #[cfg_attr(miri, ignore)] // Testcase takes long in miri.
    fn test_basic_cfg_from_str() {
        let cfg: ControlFlowGraph<TestMetadata> = ControlFlowGraph::from_content(TEST_GRAPH_STR);
        let entry = cfg.get_entry("main").unwrap();
        assert_eq!(entry.calling_func, "main");
        assert_eq!(entry.successor_edges.len(), 2);
        assert_eq!(entry.node_loc, 41864);
        assert_eq!(entry.successor_edges[0], (41864 >> 1) ^ 52706);
        assert_eq!(entry.successor_edges[1], (41864 >> 1) ^ 26911);

        let mut edge = cfg.get_edge((50306 >> 1) ^ 19123).unwrap();
        assert_eq!(edge.calling_func, "_ZN7MyClass1VEi");
        assert_eq!(edge.successor_edges.len(), 0);
        assert_eq!(edge.successor_basic_blocks.len(), 0);

        edge = cfg.get_edge((26911 >> 1) ^ 52706).unwrap();
        assert_eq!(edge.calling_func, "main");
        assert_eq!(edge.successor_edges.len(), 0);
        assert_eq!(edge.successor_basic_blocks.len(), 0);

        edge = cfg.get_edge((41864 >> 1) ^ 26911).unwrap();
        assert_eq!(edge.calling_func, "main");
        assert_eq!(edge.successor_edges.len(), 2);
        assert_eq!(*edge.successor_edges.first().unwrap(), (26911 >> 1) ^ 52706);

        assert!(cfg.get_edge(26911).is_none());
        assert!(cfg.get_edge(41864).is_some());
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Testcase takes too long in miri. :/
    fn test_shortest_path() {
        let cfg: ControlFlowGraph<TestMetadata> = ControlFlowGraph::from_content(TEST_GRAPH_STR);
        let distances = cfg.calculate_distances_to_all_edges((41864 >> 1) ^ 26911);
        assert_eq!(*distances.get(&((41864 >> 1) ^ 26911)).unwrap(), 1);
        assert_eq!(*distances.get(&((26911 >> 1) ^ 52706)).unwrap(), 2);
        assert_eq!(*distances.get(&((26911 >> 1) ^ 41925)).unwrap(), 2);
        assert!(!distances.contains_key(&((41864 >> 1) ^ 52706)));
    }
}
