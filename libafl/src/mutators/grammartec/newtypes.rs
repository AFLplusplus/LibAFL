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

use std::{iter::Step, ops::Add};

#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash, Serialize, Deserialize)]
pub struct RuleID(usize);

#[derive(PartialEq, PartialOrd, Eq, Clone, Copy, Debug, Hash, Serialize, Deserialize)]
pub struct NodeID(usize);

#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash, Serialize, Deserialize)]
pub struct NTermID(usize);

impl RuleID {
    pub fn to_i(&self) -> usize {
        self.0
    }
}

impl From<usize> for RuleID {
    fn from(i: usize) -> Self {
        return RuleID(i);
    }
}

impl Into<usize> for RuleID {
    fn into(self) -> usize {
        return self.0;
    }
}

impl Add<usize> for RuleID {
    type Output = RuleID;
    fn add(self, rhs: usize) -> RuleID {
        return RuleID(self.0 + rhs);
    }
}

impl NodeID {
    pub fn to_i(&self) -> usize {
        self.0
    }
}

impl From<usize> for NodeID {
    fn from(i: usize) -> Self {
        return NodeID(i);
    }
}

impl Into<usize> for NodeID {
    fn into(self) -> usize {
        return self.0;
    }
}

impl Add<usize> for NodeID {
    type Output = NodeID;
    fn add(self, rhs: usize) -> NodeID {
        return NodeID(self.0 + rhs);
    }
}

impl Step for NodeID {
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        let start_i = start.to_i();
        let end_i = end.to_i();
        if start > end {
            return None;
        }
        return Some(end_i - start_i);
    }
    fn replace_one(&mut self) -> Self {
        return NodeID::from(0);
    }
    fn replace_zero(&mut self) -> Self {
        return NodeID::from(1);
    }
    fn add_one(&self) -> Self {
        return self.add(1);
    }
    fn sub_one(&self) -> Self {
        return NodeID(self.0 - 1);
    }
    fn add_usize(&self, n: usize) -> Option<Self> {
        match self.0.checked_add(n) {
            Some(x) => return Some(NodeID::from(x)),
            None => return None,
        }
    }
}

impl NTermID {
    pub fn to_i(&self) -> usize {
        self.0
    }
}

impl From<usize> for NTermID {
    fn from(i: usize) -> Self {
        return NTermID(i);
    }
}

impl Into<usize> for NTermID {
    fn into(self) -> usize {
        return self.0;
    }
}

impl Add<usize> for NTermID {
    type Output = NTermID;
    fn add(self, rhs: usize) -> NTermID {
        return NTermID(self.0 + rhs);
    }
}

#[cfg(test)]
mod tests {
    use newtypes::{NTermID, NodeID, RuleID};

    #[test]
    fn rule_id() {
        let r1: RuleID = 1337.into();
        let r2 = RuleID::from(1338);
        let i1: usize = r1.into();
        assert_eq!(i1, 1337);
        let i2: usize = 1338;
        assert_eq!(i2, r2.into());
        let r3 = r2 + 3;
        assert_eq!(r3, 1341.into());
    }

    #[test]
    fn node_id() {
        let r1: NodeID = 1337.into();
        let r2 = NodeID::from(1338);
        let i1: usize = r1.into();
        assert_eq!(i1, 1337);
        let i2: usize = 1338;
        assert_eq!(i2, r2.into());
        let r3 = r2 + 3;
        assert_eq!(r3, 1341.into());
    }

    #[test]
    fn nterm_id() {
        let r1: NTermID = 1337.into();
        let r2 = NTermID::from(1338);
        let i1: usize = r1.into();
        assert_eq!(i1, 1337);
        let i2: usize = 1338;
        assert_eq!(i2, r2.into());
        let r3 = r2 + 3;
        assert_eq!(r3, 1341.into());
    }
    #[test]
    fn test_node_id_trait_step_impl() {
        let x = 1337;
        let y = 1360;
        let r1: NodeID = x.into();
        let r2 = NodeID::from(y);
        let mut sum_from_nodes = 0;
        for node in r1..r2 {
            sum_from_nodes += node.to_i();
        }
        let mut sum_from_ints = 0;
        for i in x..y {
            sum_from_ints += i;
        }
        assert_eq!(sum_from_ints, sum_from_nodes);
    }
}
