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
use core::cell::OnceCell;

use context::Context;
use newtypes::{NTermID, NodeID, RuleID};
use pyo3::prelude::{PyObject, Python};
use rand::{thread_rng, Rng};
use regex;
use regex_syntax::hir::Hir;
use serde::{Deserialize, Serialize};
use tree::Tree;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum RuleChild {
    Term(Vec<u8>),
    NTerm(NTermID),
}

const SPLITTER: OnceCell<regex::Regex> = OnceCell::new();
const TOKENIZER: OnceCell<regex::bytes::Regex> = OnceCell::new();

fn show_bytes(bs: &[u8]) -> String {
    use std::{ascii::escape_default, str};

    let mut visible = String::new();
    for &b in bs {
        let part: Vec<u8> = escape_default(b).collect();
        visible.push_str(str::from_utf8(&part).unwrap());
    }
    return format!("\"{}\"", visible);
}

impl RuleChild {
    pub fn from_lit(lit: &[u8]) -> Self {
        return RuleChild::Term(lit.into());
    }

    pub fn from_nt(nt: &str, ctx: &mut Context) -> Self {
        let (nonterm, _) = RuleChild::split_nt_description(nt);
        return RuleChild::NTerm(ctx.aquire_nt_id(&nonterm));
    }

    fn split_nt_description(nonterm: &str) -> (String, String) {
        let splitter = SPLITTER;
        let splitter = splitter.get_or_init(|| {
            regex::Regex::new(r"^\{([A-Z][a-zA-Z_\-0-9]*)(?::([a-zA-Z_\-0-9]*))?\}$")
                .expect("RAND_1363289094")
        });

        //splits {A:a} or {A} into A and maybe a
        let descr = splitter.captures(nonterm).expect(&format!("could not interpret Nonterminal {:?}. Nonterminal Descriptions need to match start with a capital letter and con only contain [a-zA-Z_-0-9]",nonterm));
        //let name = descr.get(2).map(|m| m.as_str().into()).unwrap_or(default.to_string()));
        return (descr[1].into(), "".into());
    }

    fn debug_show(&self, ctx: &Context) -> String {
        match self {
            RuleChild::Term(d) => show_bytes(&d),
            RuleChild::NTerm(nt) => ctx.nt_id_to_s(*nt),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RuleIDOrCustom {
    Rule(RuleID),
    Custom(RuleID, Vec<u8>),
}
impl RuleIDOrCustom {
    pub fn id(&self) -> RuleID {
        match self {
            RuleIDOrCustom::Rule(id) => return *id,
            RuleIDOrCustom::Custom(id, _) => return *id,
        }
    }

    pub fn data(&self) -> &[u8] {
        match self {
            RuleIDOrCustom::Custom(_, data) => return data,
            RuleIDOrCustom::Rule(_) => panic!("cannot get data on a normal rule"),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Rule {
    Plain(PlainRule),
    Script(ScriptRule),
    RegExp(RegExpRule),
}

#[derive(Debug, Clone)]
pub struct RegExpRule {
    pub nonterm: NTermID,
    pub hir: Hir,
}

impl RegExpRule {
    pub fn debug_show(&self, ctx: &Context) -> String {
        return format!("{} => {:?}", ctx.nt_id_to_s(self.nonterm), self.hir);
    }
}

#[derive(Debug)]
pub struct ScriptRule {
    pub nonterm: NTermID,
    pub nonterms: Vec<NTermID>,
    pub script: PyObject,
}

impl ScriptRule {
    pub fn debug_show(&self, ctx: &Context) -> String {
        let args = self
            .nonterms
            .iter()
            .map(|nt| ctx.nt_id_to_s(*nt))
            .collect::<Vec<_>>()
            .join(", ");
        return format!("{} => func({})", ctx.nt_id_to_s(self.nonterm), args);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PlainRule {
    pub nonterm: NTermID,
    pub children: Vec<RuleChild>,
    pub nonterms: Vec<NTermID>,
}

impl PlainRule {
    pub fn debug_show(&self, ctx: &Context) -> String {
        let args = self
            .children
            .iter()
            .map(|child| child.debug_show(ctx))
            .collect::<Vec<_>>()
            .join(", ");
        return format!("{} => {}", ctx.nt_id_to_s(self.nonterm), args);
    }
}

impl Clone for ScriptRule {
    fn clone(&self) -> Self {
        let gil = Python::acquire_gil();
        let py = gil.python();
        return ScriptRule {
            nonterm: self.nonterm.clone(),
            nonterms: self.nonterms.clone(),
            script: self.script.clone_ref(py),
        };
    }
}

impl Rule {
    pub fn from_script(
        ctx: &mut Context,
        nonterm: &str,
        nterms: Vec<String>,
        script: PyObject,
    ) -> Self {
        return Self::Script(ScriptRule {
            nonterm: ctx.aquire_nt_id(nonterm),
            nonterms: nterms.iter().map(|s| ctx.aquire_nt_id(s)).collect(),
            script,
        });
    }

    pub fn from_regex(ctx: &mut Context, nonterm: &str, regex: &str) -> Self {
        use regex_syntax::ParserBuilder;

        let mut parser = ParserBuilder::new()
            .unicode(true)
            .allow_invalid_utf8(true)
            .build();

        let hir = parser.parse(regex).unwrap();

        return Self::RegExp(RegExpRule {
            nonterm: ctx.aquire_nt_id(nonterm),
            hir,
        });
    }

    pub fn debug_show(&self, ctx: &Context) -> String {
        match self {
            Self::Plain(r) => r.debug_show(ctx),
            Self::Script(r) => r.debug_show(ctx),
            Self::RegExp(r) => r.debug_show(ctx),
        }
    }

    pub fn from_format(ctx: &mut Context, nonterm: &str, format: &[u8]) -> Self {
        let children = Rule::tokenize(format, ctx);
        let nonterms = children
            .iter()
            .filter_map(|c| {
                if let &RuleChild::NTerm(n) = c {
                    Some(n)
                } else {
                    None
                }
            })
            .collect();
        return Self::Plain(PlainRule {
            nonterm: ctx.aquire_nt_id(nonterm),
            children,
            nonterms,
        });
    }

    pub fn from_term(ntermid: NTermID, term: &Vec<u8>) -> Self {
        let children = vec![RuleChild::Term(term.to_vec())];
        let nonterms = vec![];
        return Self::Plain(PlainRule {
            nonterm: ntermid,
            children,
            nonterms,
        });
    }

    fn unescape(bytes: &[u8]) -> Vec<u8> {
        if bytes.len() < 2 {
            return bytes.to_vec();
        }
        let mut res = vec![];
        let mut i = 0;
        while i < bytes.len() - 1 {
            if bytes[i] == 92 && bytes[i + 1] == 123 {
                // replace \{ with {
                res.push(123);
                i += 1;
            } else if bytes[i] == 92 && bytes[i + 1] == 125 {
                // replace \} with }
                res.push(125);
                i += 1;
            } else {
                res.push(bytes[i]);
            }
            i += 1;
        }
        if i < bytes.len() {
            res.push(bytes[bytes.len() - 1]);
        }
        return res;
    }

    fn tokenize(format: &[u8], ctx: &mut Context) -> Vec<RuleChild> {
        let tokenizer = TOKENIZER.get_or_init(|| {
            regex::bytes::RegexBuilder::new(r"(?-u)(\{[^}\\]+\})|((?:[^{\\]|\\\{|\\\}|\\)+)")
                .dot_matches_new_line(true)
                .build()
                .expect("RAND_994455541")
        });
        //RegExp Changed from (\{[^}\\]+\})|((?:[^{\\]|\\\{|\\\}|\\\\)+) because of problems with \\ (\\ was not matched and therefore thrown away)

        return tokenizer
            .captures_iter(format)
            .map(|cap| {
                if let Some(sub) = cap.get(1) {
                    //println!("cap.get(1): {}", sub.as_str());
                    RuleChild::from_nt(
                        std::str::from_utf8(&sub.as_bytes())
                            .expect("nonterminals need to be valid strings"),
                        ctx,
                    )
                } else if let Some(sub) = cap.get(2) {
                    RuleChild::from_lit(&Self::unescape(sub.as_bytes()))
                } else {
                    unreachable!()
                }
            })
            .collect::<Vec<_>>();
    }

    pub fn nonterms(&self) -> &[NTermID] {
        return match self {
            Rule::Script(r) => &r.nonterms,
            Rule::Plain(r) => &r.nonterms,
            Rule::RegExp(_) => &[],
        };
    }

    pub fn number_of_nonterms(&self) -> usize {
        return self.nonterms().len();
    }

    pub fn nonterm(&self) -> NTermID {
        return match self {
            Rule::Script(r) => r.nonterm,
            Rule::Plain(r) => r.nonterm,
            Rule::RegExp(r) => r.nonterm,
        };
    }

    pub fn generate(&self, tree: &mut Tree, ctx: &Context, len: usize) -> usize {
        // println!("Rhs: {:?}, len: {}", self.nonterms, len);
        // println!("Min needed len: {}", self.nonterms.iter().fold(0, |sum, nt| sum + ctx.get_min_len_for_nt(*nt) ));
        let minimal_needed_len = self
            .nonterms()
            .iter()
            .fold(0, |sum, nt| sum + ctx.get_min_len_for_nt(*nt));
        assert!(minimal_needed_len <= len);
        let mut remaining_len = len;
        remaining_len -= minimal_needed_len;

        //if we have no further children, we consumed no len
        let mut total_size = 1;
        let paren = NodeID::from(tree.rules.len() - 1);
        //generate each childs tree from the left to the right. That way the only operation we ever
        //perform is to push another node to the end of the tree_vec

        for (i, nt) in self.nonterms().iter().enumerate() {
            //sample how much len this child can use up (e.g. how big can
            //let cur_child_max_len = Rule::get_random_len(remaining_nts, remaining_len) + ctx.get_min_len_for_nt(*nt);
            let mut cur_child_max_len;
            let mut new_nterms = Vec::new();
            new_nterms.extend_from_slice(&self.nonterms()[i..]);
            if new_nterms.len() != 0 {
                cur_child_max_len = ctx.get_random_len(remaining_len, &new_nterms);
            } else {
                cur_child_max_len = remaining_len;
            }
            cur_child_max_len += ctx.get_min_len_for_nt(*nt);

            //get a rule that can be used with the remaining length
            let rid = ctx.get_random_rule_for_nt(*nt, cur_child_max_len);
            let rule_or_custom = match ctx.get_rule(rid) {
                Rule::Plain(_) => RuleIDOrCustom::Rule(rid),
                Rule::Script(_) => RuleIDOrCustom::Rule(rid),
                Rule::RegExp(RegExpRule { hir, .. }) => RuleIDOrCustom::Custom(
                    rid,
                    regex_mutator::generate(hir, thread_rng().gen::<u64>()),
                ),
            };

            assert_eq!(tree.rules.len(), tree.sizes.len());
            assert_eq!(tree.sizes.len(), tree.paren.len());
            let offset = tree.rules.len();

            tree.rules.push(rule_or_custom);
            tree.sizes.push(0);
            tree.paren.push(NodeID::from(0));

            //generate the subtree for this rule, return the total consumed len
            let consumed_len = ctx.get_rule(rid).generate(tree, ctx, cur_child_max_len - 1);
            tree.sizes[offset] = consumed_len;
            tree.paren[offset] = paren;

            //println!("{}: min_needed_len: {}, Min-len: {} Consumed len: {} cur_child_max_len: {} remaining len: {}, total_size: {}, len: {}", ctx.nt_id_to_s(nt.clone()), minimal_needed_len, ctx.get_min_len_for_nt(*nt), consumed_len, cur_child_max_len, remaining_len, total_size, len);
            assert!(consumed_len <= cur_child_max_len);

            //println!("Rule: {}, min_len: {}", ctx.nt_id_to_s(nt.clone()), ctx.get_min_len_for_nt(*nt));
            assert!(consumed_len >= ctx.get_min_len_for_nt(*nt));

            //we can use the len that where not consumed by this iteration during the next iterations,
            //therefore it will be redistributed evenly amongst the other

            remaining_len += ctx.get_min_len_for_nt(*nt);

            remaining_len -= consumed_len;
            //add the consumed len to the total_len
            total_size += consumed_len;
        }
        //println!("Rule: {}, Size: {}", ctx.nt_id_to_s(self.nonterm.clone()), total_size);
        return total_size;
    }
}
