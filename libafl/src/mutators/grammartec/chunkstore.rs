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

use alloc::{string::String, vec::Vec};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::Write,
    sync::{atomic::AtomicBool, RwLock},
};

use libafl_bolts::rands::Rand;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};

use super::{
    context::Context,
    newtypes::{NTermID, NodeID, RuleID},
    rule::RuleIDOrCustom,
    tree::{Tree, TreeLike},
};

pub struct ChunkStoreWrapper {
    pub chunkstore: RwLock<ChunkStore>,
    pub is_locked: AtomicBool,
}
impl ChunkStoreWrapper {
    pub fn new(work_dir: String) -> Self {
        return ChunkStoreWrapper {
            chunkstore: RwLock::new(ChunkStore::new(work_dir)),
            is_locked: AtomicBool::new(false),
        };
    }
}

#[derive(Serialize, Deserialize)]
pub struct ChunkStore {
    nts_to_chunks: HashMap<NTermID, Vec<(usize, NodeID)>>,
    seen_outputs: HashSet<Vec<u8>>,
    trees: Vec<Tree>,
    work_dir: String,
    number_of_chunks: usize,
}

impl ChunkStore {
    pub fn new(work_dir: String) -> Self {
        return ChunkStore {
            nts_to_chunks: HashMap::new(),
            seen_outputs: HashSet::new(),
            trees: vec![],
            work_dir: work_dir,
            number_of_chunks: 0,
        };
    }

    pub fn add_tree(&mut self, tree: Tree, ctx: &Context) {
        let mut buffer = vec![];
        let id = self.trees.len();
        let mut contains_new_chunk = false;
        for i in 0..tree.size() {
            buffer.truncate(0);
            if tree.sizes[i] > 30 {
                continue;
            }
            let n = NodeID::from(i);
            tree.unparse(n, ctx, &mut buffer);
            if !self.seen_outputs.contains(&buffer) {
                self.seen_outputs.insert(buffer.clone());
                self.nts_to_chunks
                    .entry(tree.get_rule(n, ctx).nonterm())
                    .or_insert_with(|| vec![])
                    .push((id, n));
                let mut file = File::create(format!(
                    "{}/outputs/chunks/chunk_{:09}",
                    self.work_dir, self.number_of_chunks
                ))
                .expect("RAND_596689790");
                self.number_of_chunks += 1;
                file.write(&buffer).expect("RAND_606896756");
                contains_new_chunk = true;
            }
        }
        if contains_new_chunk {
            self.trees.push(tree);
        }
    }

    pub fn get_alternative_to<'a, R: Rand>(
        &'a self,
        rand: &R,
        r: RuleID,
        ctx: &Context,
    ) -> Option<(&Tree, NodeID)> {
        let chunks = self
            .nts_to_chunks
            .get(&ctx.get_nt(&RuleIDOrCustom::Rule(r)));
        let relevant = chunks.map(|vec| {
            vec.iter()
                .filter(move |&&(tid, nid)| self.trees[tid].get_rule_id(nid) != r)
        });
        //The unwrap_or is just a quick and dirty fix to catch Errors from the sampler
        let selected = relevant.and_then(|iter| rand.choose(iter));
        return selected.map(|&(tid, nid)| (&self.trees[tid], nid));
    }

    pub fn trees(&self) -> usize {
        return self.trees.len();
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use std::fs;

    use super::super::{chunkstore::ChunkStore, context::Context, tree::TreeLike};

    #[test]
    fn chunk_store() {
        let mut ctx = Context::new();
        let r1 = ctx.add_rule("A", b"a {B:a}");
        let r2 = ctx.add_rule("B", b"b {C:a}");
        let _ = ctx.add_rule("C", b"c");
        ctx.initialize(101);
        let random_size = ctx.get_random_len_for_ruleid(&r1);
        println!("random_size: {}", random_size);
        let tree = ctx.generate_tree_from_rule(r1, random_size);
        fs::create_dir_all("/tmp/outputs/chunks").expect("40234068");
        let mut cks = ChunkStore::new("/tmp/".to_string());
        cks.add_tree(tree, &ctx);
        // assert!(cks.seen_outputs.contains("a b c".as_bytes()));
        // assert!(cks.seen_outputs.contains("b c".as_bytes()));
        // assert!(cks.seen_outputs.contains("c".as_bytes()));
        assert_eq!(cks.nts_to_chunks[&ctx.nt_id("A")].len(), 1);
        let (tree_id, _) = cks.nts_to_chunks[&ctx.nt_id("A")][0];
        assert_eq!(cks.trees[tree_id].unparse_to_vec(&ctx), "a b c".as_bytes());

        let random_size = ctx.get_random_len_for_ruleid(&r2);
        let tree = ctx.generate_tree_from_rule(r2, random_size);
        cks.add_tree(tree, &ctx);
        // assert_eq!(cks.seen_outputs.len(), 3);
        // assert_eq!(cks.nts_to_chunks[&ctx.nt_id("B")].len(), 1);
        let (tree_id, node_id) = cks.nts_to_chunks[&ctx.nt_id("B")][0];
        assert_eq!(
            cks.trees[tree_id].unparse_node_to_vec(node_id, &ctx),
            "b c".as_bytes()
        );
    }
}
