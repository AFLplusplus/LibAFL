use std::ops::Add;

use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash, Serialize, Deserialize)]
pub struct RuleId(usize);

#[derive(PartialEq, PartialOrd, Eq, Clone, Copy, Debug, Hash, Serialize, Deserialize)]
pub struct NodeId(usize);

#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash, Serialize, Deserialize)]
pub struct NTermId(usize);

impl RuleId {
    pub fn to_i(&self) -> usize {
        self.0
    }
}

impl From<usize> for RuleId {
    fn from(i: usize) -> Self {
        return RuleId(i);
    }
}

impl Into<usize> for RuleId {
    fn into(self) -> usize {
        return self.0;
    }
}

impl Add<usize> for RuleId {
    type Output = RuleId;
    fn add(self, rhs: usize) -> RuleId {
        return RuleId(self.0 + rhs);
    }
}

impl NodeId {
    pub fn to_i(&self) -> usize {
        self.0
    }
}

impl From<usize> for NodeId {
    fn from(i: usize) -> Self {
        return NodeId(i);
    }
}

impl Into<usize> for NodeId {
    fn into(self) -> usize {
        return self.0;
    }
}

impl Add<usize> for NodeId {
    type Output = NodeId;
    fn add(self, rhs: usize) -> NodeId {
        return NodeId(self.0 + rhs);
    }
}

impl NodeId {
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        let start_i = start.to_i();
        let end_i = end.to_i();
        if start > end {
            return None;
        }
        return Some(end_i - start_i);
    }
    fn replace_one(&mut self) -> Self {
        return NodeId::from(0);
    }
    fn replace_zero(&mut self) -> Self {
        return NodeId::from(1);
    }
    fn add_one(&self) -> Self {
        return self.add(1);
    }
    fn sub_one(&self) -> Self {
        return NodeId(self.0 - 1);
    }
    fn add_usize(&self, n: usize) -> Option<Self> {
        match self.0.checked_add(n) {
            Some(x) => return Some(NodeId::from(x)),
            None => return None,
        }
    }
}

impl NTermId {
    pub fn to_i(&self) -> usize {
        self.0
    }
}

impl From<usize> for NTermId {
    fn from(i: usize) -> Self {
        return NTermId(i);
    }
}

impl Into<usize> for NTermId {
    fn into(self) -> usize {
        return self.0;
    }
}

impl Add<usize> for NTermId {
    type Output = NTermId;
    fn add(self, rhs: usize) -> NTermId {
        return NTermId(self.0 + rhs);
    }
}

#[cfg(test)]
mod tests {
    use super::{NTermId, NodeId, RuleId};

    #[test]
    fn rule_id() {
        let r1: RuleId = 1337.into();
        let r2 = RuleId::from(1338);
        let i1: usize = r1.into();
        assert_eq!(i1, 1337);
        let i2: usize = 1338;
        assert_eq!(i2, r2.to_i());
        let r3 = r2 + 3;
        assert_eq!(r3, 1341.into());
    }

    #[test]
    fn node_id() {
        let r1: NodeId = 1337.into();
        let r2 = NodeId::from(1338);
        let i1: usize = r1.into();
        assert_eq!(i1, 1337);
        let i2: usize = 1338;
        assert_eq!(i2, r2.to_i());
        let r3 = r2 + 3;
        assert_eq!(r3, 1341.into());
    }

    #[test]
    fn nterm_id() {
        let r1: NTermId = 1337.into();
        let r2 = NTermId::from(1338);
        let i1: usize = r1.into();
        assert_eq!(i1, 1337);
        let i2: usize = 1338;
        assert_eq!(i2, r2.to_i());
        let r3 = r2 + 3;
        assert_eq!(r3, 1341.into());
    }
}
