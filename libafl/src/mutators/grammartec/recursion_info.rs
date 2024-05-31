// Nautilus
// Copyright (C) 2020  Daniel Teuchert, Cornelius Aschermann, Sergej Schumilo

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use alloc::vec::Vec;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand::Rng;
use rand::SeedableRng;
use std::collections::HashMap;
use std::fmt;

use context::Context;
use loaded_dice::LoadedDiceSampler;
use newtypes::{NTermID, NodeID};
use tree::Tree;

pub struct RecursionInfo {
    recursive_parents: HashMap<NodeID, NodeID>,
    sampler: LoadedDiceSampler<StdRng>,
    depth_by_offset: Vec<usize>,
    node_by_offset: Vec<NodeID>,
}

impl fmt::Debug for RecursionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecursionInfo")
            .field("recursive_parents", &self.recursive_parents)
            .field("depth_by_offset", &self.depth_by_offset)
            .field("node_by_offset", &self.node_by_offset)
            .finish()
    }
}

impl RecursionInfo {
    pub fn new(t: &Tree, n: NTermID, ctx: &Context) -> Option<Self> {
        let (recursive_parents, node_by_offset, depth_by_offset) =
            RecursionInfo::find_parents(&t, n, ctx)?;
        let sampler = RecursionInfo::build_sampler(&depth_by_offset);
        return Some(Self {
            recursive_parents,
            sampler,
            node_by_offset,
            depth_by_offset,
        });
    }

    // constructs a tree where each node points to the first ancestor with the same nonterminal (e.g. each node points the next node above it, were the pair forms a recursive occurance of a nonterminal).
    // This structure is an ''inverted tree''. We use it later to sample efficiently from the set
    // of all possible recursive pairs without occuring n^2 overhead. Additionally, we return a
    // ordered vec of all nodes with nonterminal n and the depth of this node in the freshly
    // constructed 'recursion tree' (weight). Each node is the end point of exactly `weigth` many
    // differnt recursions. Therefore we use the weight of the node to sample the endpoint of a path trough the
    // recursion tree. Then we just sample the length of this path uniformly as (1.. weight). This
    // yields a uniform sample from the whole set of recursions inside the tree. If you read this, Good luck you are on your own.
    fn find_parents(
        t: &Tree,
        nt: NTermID,
        ctx: &Context,
    ) -> Option<(HashMap<NodeID, NodeID>, Vec<NodeID>, Vec<usize>)> {
        let mut stack = vec![(None, 0)];
        let mut res = None;
        for (i, rule) in t.rules.iter().enumerate() {
            let node = NodeID::from(i);
            let (mut maybe_parent, depth) = stack.pop().expect("RAND_3404900492");
            if ctx.get_nt(rule) == nt {
                if let Some(parent) = maybe_parent {
                    let (mut parents, mut ids, mut weights) =
                        res.unwrap_or_else(|| (HashMap::new(), vec![], vec![]));
                    parents.insert(node, parent);
                    ids.push(node);
                    weights.push(depth);
                    res = Some((parents, ids, weights));
                }
                maybe_parent = Some(node)
            }
            for _ in 0..ctx.get_num_children(rule) {
                stack.push((maybe_parent, depth + 1));
            }
        }
        return res;
    }

    fn build_sampler(depths: &Vec<usize>) -> LoadedDiceSampler<StdRng> {
        let mut weights = depths.iter().map(|x| *x as f64).collect::<Vec<_>>();
        let norm: f64 = weights.iter().sum();
        assert!(norm > 0.0);
        for v in weights.iter_mut() {
            *v /= norm;
        }
        return LoadedDiceSampler::new(
            weights,
            StdRng::from_rng(thread_rng()).expect("RAND_1769941938"),
        );
    }

    pub fn get_random_recursion_pair(&mut self) -> (NodeID, NodeID) {
        let offset = self.sampler.sample();
        return self.get_recursion_pair_by_offset(offset);
    }

    pub fn get_recursion_pair_by_offset(&self, offset: usize) -> (NodeID, NodeID) {
        let node1 = self.node_by_offset[offset];
        let mut node2 = node1;
        for _ in 0..(self.depth_by_offset[offset]) {
            node2 = self.recursive_parents[&node1];
        }
        return (node2, node1);
    }

    pub fn get_number_of_recursions(&self) -> usize {
        return self.node_by_offset.len();
    }
}
