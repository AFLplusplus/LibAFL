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
use std::{cmp, collections::HashSet, io, io::Write, marker::Sized};

use context::Context;
use newtypes::{NTermID, NodeID, RuleID};
use pyo3::{
    prelude::{PyObject, PyResult, Python},
    types::{PyBytes, PyString, PyTuple},
    FromPyObject,
};
use rand::{thread_rng, Rng};
use recursion_info::RecursionInfo;
use rule::{PlainRule, RegExpRule, Rule, RuleChild, RuleIDOrCustom, ScriptRule};
use serde::{Deserialize, Serialize};

enum UnparseStep<'dat> {
    Term(&'dat [u8]),
    Nonterm(NTermID),
    Script(usize, PyObject),
    PushBuffer(),
}

struct Unparser<'data, 'tree: 'data, 'ctx: 'data, W: Write, T: TreeLike> {
    tree: &'tree T,
    stack: Vec<UnparseStep<'data>>,
    buffers: Vec<io::Cursor<Vec<u8>>>,
    w: W,
    i: usize,
    ctx: &'ctx Context,
}

impl<'data, 'tree: 'data, 'ctx: 'data, W: Write, T: TreeLike> Unparser<'data, 'tree, 'ctx, W, T> {
    fn new(nid: NodeID, w: W, tree: &'tree T, ctx: &'ctx Context) -> Self {
        let i = nid.to_i();
        let nt = tree.get_rule(NodeID::from(i), ctx).nonterm();
        let op = UnparseStep::<'data>::Nonterm(nt);
        let stack = vec![op];
        return Self {
            stack,
            buffers: vec![],
            w,
            tree,
            i,
            ctx,
        };
    }

    fn unparse_step(&mut self) -> bool {
        match self.stack.pop() {
            Some(UnparseStep::Term(data)) => self.write(data),
            Some(UnparseStep::Nonterm(nt)) => self.nonterm(nt),
            Some(UnparseStep::Script(num, expr)) => self.unwrap_script(num, expr),
            Some(UnparseStep::PushBuffer()) => self.push_buffer(),
            None => return false,
        };
        return true;
    }

    fn write(&mut self, data: &[u8]) {
        if let Some(buff) = self.buffers.last_mut() {
            buff.write(data).unwrap();
        } else {
            self.w.write(data).unwrap();
        }
    }

    fn nonterm(&mut self, nt: NTermID) {
        self.next_rule(nt);
    }
    fn unwrap_script(&mut self, num: usize, expr: PyObject) {
        let gil = Python::acquire_gil();
        let py = gil.python();
        self.script(py, num, expr)
            .map_err(|e| e.print_and_set_sys_last_vars(py))
            .unwrap();
    }
    fn script(&mut self, py: Python, num: usize, expr: PyObject) -> PyResult<()> {
        use pyo3::AsPyRef;
        let bufs = self.buffers.split_off(self.buffers.len() - num);
        let bufs = bufs
            .into_iter()
            .map(|cur| cur.into_inner())
            .collect::<Vec<_>>();
        let byte_arrays = bufs.iter().map(|b| PyBytes::new(py, b));
        let res = expr.call1(py, PyTuple::new(py, byte_arrays))?;
        if py.is_instance::<PyString, _>(&res)? {
            let pystr = <&PyString>::extract(res.as_ref(py))?;
            self.write(pystr.to_string_lossy().as_bytes());
        } else if py.is_instance::<PyBytes, _>(&res)? {
            let pybytes = <&PyBytes>::extract(res.as_ref(py))?;
            self.write(pybytes.as_bytes());
        } else {
            return Err(pyo3::exceptions::ValueError::py_err(
                "script function should return string or bytes",
            ));
        }
        return Ok(());
    }

    fn push_buffer(&mut self) {
        self.buffers.push(io::Cursor::new(vec![]));
    }

    fn next_rule(&mut self, nt: NTermID) {
        let nid = NodeID::from(self.i);
        let rule: &'ctx Rule = self.tree.get_rule(nid, self.ctx);
        assert_eq!(nt, rule.nonterm());
        self.i += 1;
        match rule {
            Rule::Plain(r) => self.next_plain(r),
            Rule::Script(r) => self.next_script(r),
            Rule::RegExp(_) => self.next_regexp(self.tree.get_custom_rule_data(nid)),
        }
    }

    fn next_plain(&mut self, r: &'ctx PlainRule) {
        for rule_child in r.children.iter().rev() {
            let op = match rule_child {
                RuleChild::Term(data) => UnparseStep::<'data>::Term(&data),
                RuleChild::NTerm(id) => UnparseStep::<'data>::Nonterm(*id),
            };
            self.stack.push(op);
        }
    }

    fn next_script(&mut self, r: &ScriptRule) {
        {
            let gil = Python::acquire_gil();
            let py = gil.python();
            self.stack.push(UnparseStep::Script(
                r.nonterms.len(),
                r.script.clone_ref(py),
            ));
        }
        for nterm in r.nonterms.iter().rev() {
            self.stack.push(UnparseStep::Nonterm(*nterm));
            self.stack.push(UnparseStep::PushBuffer());
        }
    }

    fn next_regexp(&mut self, data: &'tree [u8]) {
        self.stack.push(UnparseStep::<'data>::Term(&data));
    }

    fn unparse(&mut self) -> NodeID {
        while self.unparse_step() {}
        return NodeID::from(self.i);
    }
}

pub trait TreeLike
where
    Self: Sized,
{
    fn get_rule_id(&self, n: NodeID) -> RuleID;
    fn size(&self) -> usize;
    fn to_tree(&self, _: &Context) -> Tree;
    fn get_rule<'c>(&self, n: NodeID, ctx: &'c Context) -> &'c Rule;
    fn get_rule_or_custom(&self, n: NodeID) -> &RuleIDOrCustom;
    fn get_custom_rule_data(&self, n: NodeID) -> &[u8];
    fn get_nonterm_id(&self, n: NodeID, ctx: &Context) -> NTermID {
        self.get_rule(n, ctx).nonterm()
    }

    fn unparse<W: Write>(&self, id: NodeID, ctx: &Context, mut w: &mut W) {
        Unparser::new(id, &mut w, self, ctx).unparse();
    }

    fn unparse_to<W: Write>(&self, ctx: &Context, w: &mut W) {
        self.unparse(NodeID::from(0), ctx, w);
    }

    fn unparse_to_vec(&self, ctx: &Context) -> Vec<u8> {
        self.unparse_node_to_vec(NodeID::from(0), ctx)
    }

    fn unparse_node_to_vec(&self, n: NodeID, ctx: &Context) -> Vec<u8> {
        let mut data = vec![];
        self.unparse(n, ctx, &mut data);
        return data;
    }

    fn unparse_print(&self, ctx: &Context) {
        self.unparse_to(ctx, &mut io::stdout());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tree {
    pub rules: Vec<RuleIDOrCustom>,
    pub sizes: Vec<usize>,
    pub paren: Vec<NodeID>,
}

impl TreeLike for Tree {
    fn get_rule_id(&self, n: NodeID) -> RuleID {
        self.rules[n.to_i()].id()
    }

    fn size(&self) -> usize {
        return self.rules.len();
    }

    fn to_tree(&self, _ctx: &Context) -> Tree {
        return self.clone();
    }

    fn get_rule<'c>(&self, n: NodeID, ctx: &'c Context) -> &'c Rule {
        return ctx.get_rule(self.get_rule_id(n));
    }
    fn get_custom_rule_data(&self, n: NodeID) -> &[u8] {
        self.rules[n.to_i()].data()
    }
    fn get_rule_or_custom(&self, n: NodeID) -> &RuleIDOrCustom {
        &self.rules[n.to_i()]
    }
}

impl Tree {
    pub fn from_rule_vec(rules: Vec<RuleIDOrCustom>, ctx: &Context) -> Self {
        let sizes = vec![0; rules.len()];
        let paren = vec![NodeID::from(0); rules.len()];
        let mut res = Tree {
            rules,
            sizes,
            paren,
        };
        if res.rules.len() > 0 {
            res.calc_subtree_sizes_and_parents(ctx);
        }
        return res;
    }

    pub fn get_rule_id(&self, n: NodeID) -> RuleID {
        return self.rules[n.to_i()].id();
    }

    fn get_rule_or_custom(&self, n: NodeID) -> &RuleIDOrCustom {
        &self.rules[n.to_i()]
    }

    pub fn subtree_size(&self, n: NodeID) -> usize {
        return self.sizes[n.to_i()];
    }

    pub fn mutate_replace_from_tree<'a>(
        &'a self,
        n: NodeID,
        other: &'a Tree,
        other_node: NodeID,
    ) -> TreeMutation<'a> {
        let old_size = self.subtree_size(n);
        let new_size = other.subtree_size(other_node);
        return TreeMutation {
            prefix: self.slice(0.into(), n),
            repl: other.slice(other_node, other_node + new_size),
            postfix: self.slice(n + old_size, self.rules.len().into()),
        };
    }

    fn calc_subtree_sizes_and_parents(&mut self, ctx: &Context) {
        self.calc_parents(ctx);
        self.calc_sizes();
    }

    fn calc_parents(&mut self, ctx: &Context) {
        if self.size() == 0 {
            return;
        }
        let mut stack: Vec<(NTermID, NodeID)> = Vec::new();
        stack.push((
            self.get_rule(NodeID::from(0), ctx).nonterm(),
            NodeID::from(0),
        ));
        for i in 0..self.size() {
            let node_id = NodeID::from(i);
            let nonterm = self.get_rule(node_id, ctx).nonterm();
            //sanity check
            let (nterm_id, node) = stack.pop().expect("Not a valid tree for unparsing!");
            if nterm_id != nonterm {
                panic!("Not a valid tree for unparsing!");
            } else {
                self.paren[i] = node;
            }
            let rule = self.get_rule(node_id, ctx);
            for nonterm in rule.nonterms().iter().rev() {
                stack.push((*nonterm, node_id));
            }
        }
    }

    fn calc_sizes(&mut self) {
        //Initiate with 1
        for size in self.sizes.iter_mut() {
            *size = 1;
        }
        for i in (1..self.size()).rev() {
            self.sizes[self.paren[i].to_i()] += self.sizes[i];
        }
    }

    fn slice(&self, from: NodeID, to: NodeID) -> &[RuleIDOrCustom] {
        return &self.rules[from.into()..to.into()];
    }

    pub fn get_parent(&self, n: NodeID) -> Option<NodeID> {
        if n != NodeID::from(0) {
            return Some(self.paren[n.to_i()]);
        }
        return None;
    }

    pub fn truncate(&mut self) {
        self.rules.truncate(0);
        self.sizes.truncate(0);
        self.paren.truncate(0);
    }

    pub fn generate_from_nt(&mut self, start: NTermID, len: usize, ctx: &Context) {
        let ruleid = ctx.get_random_rule_for_nt(start, len);
        self.generate_from_rule(ruleid, len - 1, ctx);
    }

    pub fn generate_from_rule(&mut self, ruleid: RuleID, max_len: usize, ctx: &Context) {
        match ctx.get_rule(ruleid) {
            Rule::Plain(..) | Rule::Script(..) => {
                self.truncate();
                self.rules.push(RuleIDOrCustom::Rule(ruleid));
                self.sizes.push(0);
                self.paren.push(NodeID::from(0));
                ctx.get_rule(ruleid).generate(self, &ctx, max_len);
                self.sizes[0] = self.rules.len();
            }
            Rule::RegExp(RegExpRule { hir, .. }) => {
                let rid = RuleIDOrCustom::Custom(
                    ruleid,
                    regex_mutator::generate(hir, thread_rng().gen::<u64>()),
                );
                self.truncate();
                self.rules.push(rid);
                self.sizes.push(0);
                self.paren.push(NodeID::from(0));
                self.sizes[0] = self.rules.len();
            }
        }
    }

    pub fn calc_recursions(&self, ctx: &Context) -> Option<Vec<RecursionInfo>> {
        let mut ret = Vec::new();
        let mut done_nterms = HashSet::new();
        for rule in &self.rules {
            let nterm = ctx.get_nt(&rule);
            if !done_nterms.contains(&nterm) {
                match RecursionInfo::new(self, nterm, ctx) {
                    Some(rec_info) => ret.push(rec_info),
                    None => {}
                }
                done_nterms.insert(nterm);
            }
        }
        if ret.is_empty() {
            return None;
        }
        return Some(ret);
    }

    fn find_recursions_iter(&self, ctx: &Context) -> Vec<(NodeID, NodeID)> {
        let mut found_recursions = Vec::new();
        //Only search for iterations for up to 10000 nodes
        for i in 1..cmp::min(self.size(), 10000) {
            let node_id = NodeID::from(self.size() - i);
            let current_nterm: NTermID = self.get_rule(node_id, ctx).nonterm();
            let mut current_node_id = self.paren[node_id.to_i()];
            let mut depth = 0;
            while current_node_id != NodeID::from(0) {
                if self.get_rule(current_node_id, ctx).nonterm() == current_nterm {
                    found_recursions.push((current_node_id, node_id));
                }
                current_node_id = self.paren[current_node_id.to_i()];
                if depth > 15 {
                    break;
                }
                depth += 1;
            }
        }
        return found_recursions;
    }
}

pub struct TreeMutation<'a> {
    pub prefix: &'a [RuleIDOrCustom],
    pub repl: &'a [RuleIDOrCustom],
    pub postfix: &'a [RuleIDOrCustom],
}

impl<'a> TreeMutation<'a> {
    pub fn get_at(&self, n: NodeID) -> &'a RuleIDOrCustom {
        let i = n.to_i();
        let end0 = self.prefix.len();
        let end1 = end0 + self.repl.len();
        let end2 = end1 + self.postfix.len();
        if i < end0 {
            return &self.prefix[i];
        }
        if i < end1 {
            return &self.repl[i - end0];
        }
        if i < end2 {
            return &self.postfix[i - end1];
        }
        panic!("index out of bound for rule access");
    }
}

impl<'a> TreeLike for TreeMutation<'a> {
    fn get_rule_id(&self, n: NodeID) -> RuleID {
        return self.get_at(n).id();
    }

    fn size(&self) -> usize {
        return self.prefix.len() + self.repl.len() + self.postfix.len();
    }
    fn get_rule_or_custom(&self, n: NodeID) -> &RuleIDOrCustom {
        self.get_at(n)
    }

    fn to_tree(&self, ctx: &Context) -> Tree {
        let mut vec = vec![];
        vec.extend_from_slice(&self.prefix);
        vec.extend_from_slice(&self.repl);
        vec.extend_from_slice(&self.postfix);
        return Tree::from_rule_vec(vec, ctx);
    }

    fn get_rule<'c>(&self, n: NodeID, ctx: &'c Context) -> &'c Rule {
        return ctx.get_rule(self.get_rule_id(n));
    }
    fn get_custom_rule_data(&self, n: NodeID) -> &[u8] {
        self.get_at(n).data()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{context::Context, newtypes::NodeID},
        *,
    };

    fn calc_subtree_sizes_and_parents_rec_test(tree: &mut Tree, n: NodeID, ctx: &Context) -> usize {
        let mut cur = n + 1;
        let mut size = 1;
        for _ in 0..tree.get_rule(n, ctx).number_of_nonterms() {
            tree.paren[cur.to_i()] = n;
            let sub_size = calc_subtree_sizes_and_parents_rec_test(tree, cur, ctx);
            cur = cur + sub_size;
            size += sub_size;
        }
        tree.sizes[n.to_i()] = size;
        return size;
    }

    #[test]
    fn check_calc_sizes_iter() {
        let mut ctx = Context::new();
        let _ = ctx.add_rule("C", b"c{B}c3");
        let _ = ctx.add_rule("B", b"b{A}b23");
        let _ = ctx.add_rule("A", b"aasdf {A}");
        let _ = ctx.add_rule("A", b"a2 {A}");
        let _ = ctx.add_rule("A", b"a sdf{A}");
        let _ = ctx.add_rule("A", b"a 34{A}");
        let _ = ctx.add_rule("A", b"adfe {A}");
        let _ = ctx.add_rule("A", b"a32");
        ctx.initialize(50);
        let mut tree = Tree::from_rule_vec(vec![], &ctx);
        for _ in 0..100 {
            tree.truncate();
            tree.generate_from_nt(ctx.nt_id("C"), 50, &ctx);
            calc_subtree_sizes_and_parents_rec_test(&mut tree, NodeID::from(0), &ctx);
            let vec1 = tree.sizes.clone();
            tree.calc_sizes();
            let vec2 = tree.sizes.clone();
            assert_eq!(vec1, vec2);
        }
    }

    #[test]
    fn check_calc_paren_iter() {
        let mut ctx = Context::new();
        let _ = ctx.add_rule("C", b"c{B}c3");
        let _ = ctx.add_rule("B", b"b{A}b23");
        let _ = ctx.add_rule("A", b"aasdf {A}");
        let _ = ctx.add_rule("A", b"a2 {A}");
        let _ = ctx.add_rule("A", b"a sdf{A}");
        let _ = ctx.add_rule("A", b"a 34{A}");
        let _ = ctx.add_rule("A", b"adfe {A}");
        let _ = ctx.add_rule("A", b"a32");
        ctx.initialize(50);
        let mut tree = Tree::from_rule_vec(vec![], &ctx);
        for _ in 0..100 {
            tree.truncate();
            tree.generate_from_nt(ctx.nt_id("C"), 50, &ctx);
            calc_subtree_sizes_and_parents_rec_test(&mut tree, NodeID::from(0), &ctx);
            let vec1 = tree.paren.clone();
            tree.calc_parents(&ctx);
            let vec2 = tree.paren.clone();
            assert_eq!(vec1, vec2);
        }
    }

    #[test]
    fn check_unparse_iter() {
        let mut ctx = Context::new();
        let _ = ctx.add_rule("C", b"c{B}c3");
        let _ = ctx.add_rule("B", b"b{A}b23");
        let _ = ctx.add_rule("A", b"aasdf {A}");
        let _ = ctx.add_rule("A", b"a2 {A}");
        let _ = ctx.add_rule("A", b"a sdf{A}");
        let _ = ctx.add_rule("A", b"a 34{A}");
        let _ = ctx.add_rule("A", b"adfe {A}");
        let _ = ctx.add_rule("A", b"a32");
        ctx.initialize(50);
        let mut tree = Tree::from_rule_vec(vec![], &ctx);
        for _ in 0..100 {
            tree.truncate();
            tree.generate_from_nt(ctx.nt_id("C"), 50, &ctx);
            let mut vec1 = vec![];
            let mut vec2 = vec![];
            tree.unparse(NodeID::from(0), &ctx, &mut vec1);
            tree.unparse(NodeID::from(0), &ctx, &mut vec2);
            assert_eq!(vec1, vec2);
        }
    }

    #[test]
    fn check_find_recursions() {
        let mut ctx = Context::new();
        let _ = ctx.add_rule("C", b"c{B}c");
        let _ = ctx.add_rule("B", b"b{A}b");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a {A}");
        let _ = ctx.add_rule("A", b"a");
        ctx.initialize(20);
        let mut tree = Tree::from_rule_vec(vec![], &ctx);
        let mut some_recursions = false;
        for _ in 0..100 {
            tree.truncate();
            tree.generate_from_nt(ctx.nt_id("C"), 20, &ctx);
            if let Some(recursions) = tree.calc_recursions(&ctx) {
                assert_ne!(recursions.len(), 0);
                for recursion_info in recursions {
                    for offset in 0..recursion_info.get_number_of_recursions() {
                        let tuple = recursion_info.get_recursion_pair_by_offset(offset);
                        some_recursions = true;
                        assert!(tuple.0.to_i() < tuple.1.to_i());
                    }
                }
            }
        }
        assert!(some_recursions);
    }
}
