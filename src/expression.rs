//! A representation of a subset of the wireshark display filter, in a form that can be executed.
//!
//! This is the final form that a filter expression is converted into.
//! It is what gets later executed against every packet.
use crate::mac_addr::MacAddr;
use ipnet::IpNet;
use memchr::memmem;
use regex::bytes::Regex;
use std::net::IpAddr;

/// A a wrapper around a bytes regex matcher to handle the issue that regex does not implement
/// PartialEq, Eq, PartialOrd, Ord
#[derive(Debug, Clone, derive_more::Deref, derive_more::Constructor, derive_more::From)]
#[repr(transparent)]
pub struct RegexMatcher(Regex);

impl PartialEq for RegexMatcher {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

impl std::fmt::Display for RegexMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self.0.as_str())
    }
}

impl Eq for RegexMatcher {}

/// List of the supported comparison operations
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
pub enum CmpOp {
    #[display("==")]
    Equal,
    #[display("!=")]
    NotEqual,
    #[display("<")]
    LessThan,
    #[display("<=")]
    LessEqual,
    #[display(">")]
    GreaterThan,
    #[display(">=")]
    GreaterEqual,
}

/// List of supported ethernet operations
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
pub enum EthOp {
    #[display("{op} {val}")]
    Compare { op: CmpOp, val: MacAddr },
    #[display("in {_0:?}")]
    MatchAny(Vec<MacAddr>),
    #[display("not in {_0:?}")]
    MatchNone(Vec<MacAddr>),
    #[display("contains {_0:?}")]
    Contains(Vec<u8>),
    #[display("matches {_0}")]
    RegexMatch(RegexMatcher),
}

impl EthOp {
    #[inline]
    pub(crate) fn compare(op: CmpOp, val: MacAddr) -> Self {
        Self::Compare { op, val }
    }

    #[inline]
    pub(crate) fn match_any(val: Vec<MacAddr>) -> Self {
        Self::MatchAny(val)
    }

    #[inline]
    pub(crate) fn match_none(val: Vec<MacAddr>) -> Self {
        Self::MatchNone(val)
    }

    #[inline]
    pub(crate) fn contains(val: Vec<u8>) -> Self {
        Self::Contains(val)
    }

    #[inline]
    pub(crate) fn regex_match(val: RegexMatcher) -> Self {
        Self::RegexMatch(val)
    }

    fn is_match(&self, addr: MacAddr) -> bool {
        match self {
            EthOp::Compare { op, val } => match op {
                CmpOp::Equal => addr == *val,
                CmpOp::NotEqual => addr != *val,
                CmpOp::LessThan => addr < *val,
                CmpOp::LessEqual => addr <= *val,
                CmpOp::GreaterThan => addr > *val,
                CmpOp::GreaterEqual => addr >= *val,
            },
            EthOp::MatchAny(list) => list.contains(&addr),
            EthOp::MatchNone(list) => !list.contains(&addr),
            EthOp::Contains(data) => memmem::find_iter(addr.as_slice(), data).next().is_some(),
            EthOp::RegexMatch(re) => re.is_match(addr.as_slice()),
        }
    }
}

/// List of supported IP operations
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
pub enum IpOp {
    #[display("{op} {val}")]
    Compare { op: CmpOp, val: IpNet },
    #[display("in {_0:?}")]
    MatchAny(Vec<IpNet>),
    #[display("not in {_0:?}")]
    MatchNone(Vec<IpNet>),
}

impl IpOp {
    #[inline]
    pub(crate) fn compare(op: CmpOp, val: IpNet) -> Self {
        Self::Compare { op, val }
    }

    #[inline]
    pub(crate) fn match_any(val: Vec<IpNet>) -> Self {
        Self::MatchAny(val)
    }

    #[inline]
    pub(crate) fn match_none(val: Vec<IpNet>) -> Self {
        Self::MatchNone(val)
    }

    fn is_match(&self, addr: IpNet) -> bool {
        match self {
            IpOp::Compare { op, val } => match op {
                CmpOp::Equal => val.contains(&addr),
                CmpOp::NotEqual => !val.contains(&addr),
                CmpOp::LessThan => addr < *val,
                CmpOp::LessEqual => addr <= *val,
                CmpOp::GreaterThan => addr > *val,
                CmpOp::GreaterEqual => addr >= *val,
            },
            IpOp::MatchAny(list) => list.iter().any(|net| net.contains(&addr)),
            IpOp::MatchNone(list) => !list.iter().any(|net| net.contains(&addr)),
        }
    }
}

/// List of supported Port operations
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
pub enum ValOp {
    #[display("{op} {val}")]
    Compare { op: CmpOp, val: u32 },
    #[display("in {_0:?}")]
    MatchAny(Vec<u32>),
    #[display("not in {_0:?}")]
    MatchNone(Vec<u32>),
}

impl ValOp {
    #[inline]
    pub(crate) fn compare(op: CmpOp, val: u32) -> Self {
        Self::Compare { op, val }
    }

    #[inline]
    pub(crate) fn match_any(val: Vec<u32>) -> Self {
        Self::MatchAny(val)
    }

    #[inline]
    pub(crate) fn match_none(val: Vec<u32>) -> Self {
        Self::MatchNone(val)
    }

    fn is_match(&self, x: u32) -> bool {
        match self {
            ValOp::Compare { op, val } => match op {
                CmpOp::Equal => x == *val,
                CmpOp::NotEqual => x != *val,
                CmpOp::LessThan => x < *val,
                CmpOp::LessEqual => x <= *val,
                CmpOp::GreaterThan => x > *val,
                CmpOp::GreaterEqual => x >= *val,
            },
            ValOp::MatchAny(list) => list.contains(&x),
            ValOp::MatchNone(list) => !list.contains(&x),
        }
    }
}

/// List of supported payload operations
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
pub enum PayloadOp {
    #[display("contains {_0:?}")]
    Contains(Vec<u8>),
    #[display("matches {_0}")]
    RegexMatch(RegexMatcher),
}

impl PayloadOp {
    #[inline]
    pub(crate) fn contains(val: Vec<u8>) -> Self {
        Self::Contains(val)
    }

    #[inline]
    pub(crate) fn regex_match(val: RegexMatcher) -> Self {
        Self::RegexMatch(val)
    }

    fn is_match(&self, payload: &[u8]) -> bool {
        match self {
            PayloadOp::Contains(data) => memmem::find_iter(payload, data).next().is_some(),
            PayloadOp::RegexMatch(re) => re.is_match(payload),
        }
    }
}

/// Byte order for reading integers from payload
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::Display)]
pub enum Endian {
    #[display("be")]
    Big,
    #[display("le")]
    Little,
}

/// Size of a byte read from payload
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteReadSize {
    U8,
    U16,
    U32,
    U64,
}

impl ByteReadSize {
    /// Number of bytes this size reads
    #[inline]
    pub(crate) fn byte_count(self) -> usize {
        match self {
            ByteReadSize::U8 => 1,
            ByteReadSize::U16 => 2,
            ByteReadSize::U32 => 4,
            ByteReadSize::U64 => 8,
        }
    }
}

impl std::fmt::Display for ByteReadSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ByteReadSize::U8 => write!(f, "u8"),
            ByteReadSize::U16 => write!(f, "16"),
            ByteReadSize::U32 => write!(f, "32"),
            ByteReadSize::U64 => write!(f, "64"),
        }
    }
}

/// Arithmetic operations for numeric expressions
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::Display)]
pub enum ArithOp {
    #[display("+")]
    Add,
    #[display("-")]
    Sub,
}

/// A numeric expression that can be evaluated against a payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NumExpr {
    /// A constant value
    Constant(u64),
    /// The length of the payload
    PayloadLen,
    /// Read bytes from payload as an integer
    ByteRead {
        offset: u16,
        size: ByteReadSize,
        endian: Endian,
    },
    /// Arithmetic between two numeric expressions
    Arith {
        op: ArithOp,
        lhs: Box<NumExpr>,
        rhs: Box<NumExpr>,
    },
}

impl NumExpr {
    /// Evaluate the numeric expression against a payload.
    /// Returns `None` if a byte read is out of bounds.
    #[inline]
    pub(crate) fn eval(&self, payload: &[u8]) -> Option<u64> {
        match self {
            NumExpr::Constant(v) => Some(*v),
            NumExpr::PayloadLen => Some(payload.len() as u64),
            NumExpr::ByteRead {
                offset,
                size,
                endian,
            } => {
                let start = *offset as usize;
                let len = size.byte_count();
                let end = start + len;
                if end > payload.len() {
                    return None;
                }
                let bytes = &payload[start..end];
                Some(match (size, endian) {
                    (ByteReadSize::U8, _) => bytes[0] as u64,
                    (ByteReadSize::U16, Endian::Big) => {
                        u16::from_be_bytes([bytes[0], bytes[1]]) as u64
                    }
                    (ByteReadSize::U16, Endian::Little) => {
                        u16::from_le_bytes([bytes[0], bytes[1]]) as u64
                    }
                    (ByteReadSize::U32, Endian::Big) => {
                        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
                    }
                    (ByteReadSize::U32, Endian::Little) => {
                        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
                    }
                    (ByteReadSize::U64, Endian::Big) => u64::from_be_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]),
                    (ByteReadSize::U64, Endian::Little) => u64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]),
                })
            }
            NumExpr::Arith { op, lhs, rhs } => {
                let l = lhs.eval(payload)?;
                let r = rhs.eval(payload)?;
                match op {
                    ArithOp::Add => l.checked_add(r),
                    ArithOp::Sub => l.checked_sub(r),
                }
            }
        }
    }
}

impl std::fmt::Display for NumExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NumExpr::Constant(v) => write!(f, "{v}"),
            NumExpr::PayloadLen => write!(f, "payload.len"),
            NumExpr::ByteRead {
                offset,
                size,
                endian,
            } => match size {
                ByteReadSize::U8 => write!(f, "payload.u8[{offset}]"),
                _ => write!(f, "payload.{endian}{size}[{offset}]"),
            },
            NumExpr::Arith { op, lhs, rhs } => write!(f, "{lhs} {op} {rhs}"),
        }
    }
}

/// A comparison between two numeric expressions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteReadOp {
    pub(crate) op: CmpOp,
    pub(crate) lhs: NumExpr,
    pub(crate) rhs: NumExpr,
}

impl ByteReadOp {
    #[inline]
    pub(crate) fn new(op: CmpOp, lhs: NumExpr, rhs: NumExpr) -> Self {
        Self { op, lhs, rhs }
    }

    fn is_match(&self, payload: &[u8]) -> bool {
        let (Some(l), Some(r)) = (self.lhs.eval(payload), self.rhs.eval(payload)) else {
            return false;
        };
        match self.op {
            CmpOp::Equal => l == r,
            CmpOp::NotEqual => l != r,
            CmpOp::LessThan => l < r,
            CmpOp::LessEqual => l <= r,
            CmpOp::GreaterThan => l > r,
            CmpOp::GreaterEqual => l >= r,
        }
    }
}

impl std::fmt::Display for ByteReadOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.lhs, self.op, self.rhs)
    }
}

/// All supported clauses
/// The clauses are ordered in term of how expensive it is to match their content.
/// That way if we can quit early when comparing, after a small calculation, we will.
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
pub enum Clause {
    /// Is Tcp
    #[display("tcp")]
    IsTcp,
    /// Is udp
    #[display("udp")]
    IsUdp,
    /// Is vlan
    #[display("vlan")]
    IsVlan,
    /// Match ARP
    #[display("arp")]
    IsArp,
    /// Match any of the vlans
    #[display("vlan.id {_0}")]
    VlanId(ValOp),
    /// Match any of destination ports
    #[display("dstport {_0}")]
    PortDst(ValOp),
    /// Match any of source ports
    #[display("srcport {_0}")]
    PortSrc(ValOp),
    /// Match any of either the source or destination ports
    #[display("port {_0}")]
    Port(ValOp),
    /// Ethernet destination match
    #[display("eth.dst {_0}")]
    EthDst(EthOp),
    /// Ethernet source match
    #[display("eth.src {_0}")]
    EthSrc(EthOp),
    /// Ethernet either source or destination match
    #[display("eth {_0}")]
    EthAddr(EthOp),
    /// Destination IP match
    #[display("ip.dst {_0}")]
    IpDst(IpOp),
    /// Source IP match
    #[display("ip.src {_0}")]
    IpSrc(IpOp),
    /// Either source or destination IP
    #[display("ip {_0}")]
    IpAddr(IpOp),
    /// Match payload
    #[display("payload {_0}")]
    Payload(PayloadOp),
    /// Byte read comparison
    #[display("{_0}")]
    ByteRead(ByteReadOp),
}

impl Clause {
    /// Match against a single clause
    fn is_match(&self, matcher: &Matcher) -> bool {
        match self {
            Clause::IsTcp => matcher.is_tcp.unwrap_or_default(),
            Clause::IsUdp => matcher.is_udp.unwrap_or_default(),
            Clause::IsVlan => matcher.is_vlan.unwrap_or_default(),
            Clause::IsArp => matcher.is_arp.unwrap_or_default(),
            Clause::VlanId(vlan_op) => matcher
                .vlan
                .map(|v| vlan_op.is_match(v))
                .unwrap_or_default(),
            Clause::PortDst(port_op) => matcher
                .dstport
                .map(|p| port_op.is_match(p.into()))
                .unwrap_or_default(),
            Clause::PortSrc(port_op) => matcher
                .srcport
                .map(|p| port_op.is_match(p.into()))
                .unwrap_or_default(),
            Clause::Port(port_op) => {
                matcher
                    .srcport
                    .map(|p| port_op.is_match(p.into()))
                    .unwrap_or_default()
                    || matcher
                        .dstport
                        .map(|p| port_op.is_match(p.into()))
                        .unwrap_or_default()
            }
            Clause::EthDst(eth_op) => matcher
                .dst_eth
                .map(|addr| eth_op.is_match(addr))
                .unwrap_or_default(),
            Clause::EthSrc(eth_op) => matcher
                .src_eth
                .map(|addr| eth_op.is_match(addr))
                .unwrap_or_default(),
            Clause::EthAddr(eth_op) => {
                matcher
                    .src_eth
                    .map(|addr| eth_op.is_match(addr))
                    .unwrap_or_default()
                    || matcher
                        .dst_eth
                        .map(|addr| eth_op.is_match(addr))
                        .unwrap_or_default()
            }
            Clause::IpDst(ip_op) => matcher
                .dst_ip
                .map(|ip| ip_op.is_match(ip))
                .unwrap_or_default(),
            Clause::IpSrc(ip_op) => matcher
                .src_ip
                .map(|ip| ip_op.is_match(ip))
                .unwrap_or_default(),
            Clause::IpAddr(ip_op) => {
                matcher
                    .src_ip
                    .map(|ip| ip_op.is_match(ip))
                    .unwrap_or_default()
                    || matcher
                        .dst_ip
                        .map(|ip| ip_op.is_match(ip))
                        .unwrap_or_default()
            }
            Clause::Payload(pl_op) => matcher
                .payload
                .map(|p| pl_op.is_match(p))
                .unwrap_or_default(),
            Clause::ByteRead(br_op) => matcher
                .payload
                .map(|p| br_op.is_match(p))
                .unwrap_or_default(),
        }
    }
}

/// Which logical operations we support
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expression {
    /// A single clause
    Single(Clause),
    /// Negate an expression
    Not(Box<Expression>),
    /// And together a group of expressions
    And(Vec<Expression>),
    /// Or together a group of expressions
    Or(Vec<Expression>),
}

impl std::fmt::Display for Expression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expression::Single(c) => write!(f, "{c}"),
            Expression::Not(e) => write!(f, "not {e}"),
            Expression::And(list) => {
                let list = list
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<String>>()
                    .join(" and ");
                write!(f, "({list})")
            }
            Expression::Or(list) => {
                let list = list
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<String>>()
                    .join(" or ");
                write!(f, "({list})")
            }
        }
    }
}

impl From<Clause> for Expression {
    fn from(val: Clause) -> Self {
        Expression::Single(val)
    }
}

impl Expression {
    /// Negate an expression
    pub(crate) fn not(expression: impl Into<Self>) -> Self {
        let expression = expression.into();
        let boxed = Box::new(expression);
        Self::Not(boxed)
    }

    /// "AND" together two expression
    ///
    /// The idea being, if we can reduce nesting levels we will
    pub(crate) fn and(self, other: impl Into<Self>) -> Self {
        match (self, other.into()) {
            (Expression::And(mut e1), Expression::And(mut e2)) => {
                e1.extend(e2.drain(0..));
                Expression::And(e1)
            }
            (Expression::And(mut e), other) => {
                e.push(other);
                Expression::And(e)
            }
            (other, Expression::And(mut e)) => {
                e.insert(0, other);
                Expression::And(e)
            }
            (other1, other2) => Expression::And(vec![other1, other2]),
        }
    }

    /// "OR" together two expression
    ///
    /// The idea being, if we can reduce nesting levels we will
    pub(crate) fn or(self, other: impl Into<Self>) -> Self {
        match (self, other.into()) {
            (Expression::Or(mut e1), Expression::Or(mut e2)) => {
                e1.extend(e2.drain(0..));
                Expression::Or(e1)
            }
            (Expression::Or(mut e), other) => {
                e.push(other);
                Expression::Or(e)
            }
            (other, Expression::Or(mut e)) => {
                e.insert(0, other);
                Expression::Or(e)
            }
            (other1, other2) => Expression::Or(vec![other1, other2]),
        }
    }

    /// Return a Matcher for the expression.
    /// This can later be use to see if the expression matches the packet.
    pub fn matcher(&self) -> Matcher<'_, '_> {
        Matcher {
            expression: self,
            is_tcp: None,
            is_udp: None,
            is_vlan: None,
            is_arp: None,
            src_eth: None,
            dst_eth: None,
            src_ip: None,
            dst_ip: None,
            srcport: None,
            dstport: None,
            vlan: None,
            payload: None,
        }
    }

    /// Perform the actually matching of the data entered to the expression
    fn is_match(&self, matcher: &Matcher) -> bool {
        match self {
            Expression::Single(clause) => clause.is_match(matcher),
            Expression::Not(expr) => !expr.is_match(matcher),
            Expression::And(list) => list.iter().all(|e| e.is_match(matcher)),
            Expression::Or(list) => list.iter().any(|e| e.is_match(matcher)),
        }
    }
}

/// Perform checking of an expression against packet data, as represented by the matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matcher<'e, 'p> {
    /// The expression to match against
    expression: &'e Expression,
    is_tcp: Option<bool>,
    is_udp: Option<bool>,
    is_vlan: Option<bool>,
    is_arp: Option<bool>,
    src_eth: Option<MacAddr>,
    dst_eth: Option<MacAddr>,
    src_ip: Option<IpNet>,
    dst_ip: Option<IpNet>,
    srcport: Option<u16>,
    dstport: Option<u16>,
    vlan: Option<u32>,
    payload: Option<&'p [u8]>,
}

impl<'p> Matcher<'_, 'p> {
    /// Whether the packet has tcp data
    pub fn tcp(mut self, val: bool) -> Self {
        self.is_tcp = Some(val);
        self
    }

    /// Whether the packet has udp data
    pub fn udp(mut self, val: bool) -> Self {
        self.is_udp = Some(val);
        self
    }

    /// Whether the packet has vlan data
    pub fn vlan(mut self, val: impl Into<u32>) -> Self {
        self.is_vlan = Some(true);
        self.vlan = Some(val.into());
        self
    }

    /// Whether the packet has arp data
    pub fn arp(mut self, val: bool) -> Self {
        self.is_arp = Some(val);
        self
    }

    /// The source ethernet address
    pub fn src_eth(mut self, val: MacAddr) -> Self {
        self.src_eth = Some(val);
        self
    }

    /// The destination ethernet address
    pub fn dst_eth(mut self, val: MacAddr) -> Self {
        self.dst_eth = Some(val);
        self
    }

    /// The source ip address
    pub fn src_ip(mut self, val: IpAddr) -> Self {
        self.src_ip = Some(val.into());
        self
    }

    /// The destination ip address
    pub fn dst_ip(mut self, val: IpAddr) -> Self {
        self.dst_ip = Some(val.into());
        self
    }

    /// The source port address
    pub fn srcport(mut self, val: u16) -> Self {
        self.srcport = Some(val);
        self
    }

    /// The destination port address
    pub fn dstport(mut self, val: u16) -> Self {
        self.dstport = Some(val);
        self
    }

    /// The payload
    pub fn payload(mut self, val: &'p [u8]) -> Self {
        self.payload = Some(val);
        self
    }

    /// Delegate to the expression to perform the match
    #[inline]
    pub fn is_match(&self) -> bool {
        self.expression.is_match(self)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ByteReadOp,
        Clause,
        CmpOp,
        EthOp,
        Expression,
        IpOp,
        NumExpr,
        PayloadOp,
        RegexMatcher,
    };
    use crate::{
        expression::ValOp,
        mac_addr::MacAddr,
        test_utils::init_test_logging,
    };
    use ipnet::IpNet;
    use regex::bytes::Regex;
    use std::net::IpAddr;
    use tracing::info;

    #[test]
    fn test_merge_and() {
        init_test_logging();

        let vlan_op = ValOp::match_any(vec![5]);
        let expression = Expression::Single(Clause::VlanId(vlan_op.clone()))
            .and(Clause::IsVlan)
            .and(Clause::IsTcp);
        let expected = Expression::And(vec![
            Clause::VlanId(vlan_op).into(),
            Clause::IsVlan.into(),
            Clause::IsTcp.into(),
        ]);
        assert_eq!(expression, expected);
    }

    #[test]
    fn test_merge_two_and() {
        init_test_logging();

        let expression1 = Expression::And(vec![Clause::IsVlan.into()]);
        let expression2 = Expression::And(vec![Clause::IsTcp.into()]);
        let and1 = expression1.clone().and(expression2.clone());
        let and2 = expression2.and(expression1);
        let expected1 = Expression::And(vec![Clause::IsVlan.into(), Clause::IsTcp.into()]);
        let expected2 = Expression::And(vec![Clause::IsTcp.into(), Clause::IsVlan.into()]);
        assert_eq!(and1, expected1);
        assert_eq!(and2, expected2);
    }

    #[test]
    fn test_merge_or() {
        init_test_logging();

        let vlan_op = ValOp::match_any(vec![5]);
        let expression = Expression::Single(Clause::VlanId(vlan_op.clone()))
            .or(Clause::IsVlan)
            .or(Clause::IsTcp);
        let expected = Expression::Or(vec![
            Clause::VlanId(vlan_op).into(),
            Clause::IsVlan.into(),
            Clause::IsTcp.into(),
        ]);
        assert_eq!(expression, expected);
    }

    #[test]
    fn test_merge_two_or() {
        init_test_logging();

        let expression1 = Expression::Or(vec![Clause::IsVlan.into()]);
        let expression2 = Expression::Or(vec![Clause::IsTcp.into()]);
        let or1 = expression1.clone().or(expression2.clone());
        let or2 = expression2.or(expression1);
        let expected1 = Expression::Or(vec![Clause::IsVlan.into(), Clause::IsTcp.into()]);
        let expected2 = Expression::Or(vec![Clause::IsTcp.into(), Clause::IsVlan.into()]);
        assert_eq!(or1, expected1);
        assert_eq!(or2, expected2);
    }

    #[test]
    fn test_no_merge_and() {
        init_test_logging();

        let vlan_op = ValOp::match_any(vec![5]);
        let expression = Expression::Single(Clause::VlanId(vlan_op.clone()))
            .or(Clause::IsVlan)
            .and(Clause::IsTcp);
        let expected = Expression::And(vec![
            Expression::Or(vec![
                Clause::VlanId(vlan_op.clone()).into(),
                Clause::IsVlan.into(),
            ]),
            Clause::IsTcp.into(),
        ]);

        assert_eq!(expression, expected);

        let expression = Expression::Single(Clause::VlanId(vlan_op.clone()))
            .and(Clause::IsVlan)
            .or(Clause::IsTcp)
            .and(Clause::IsUdp);
        let expected = Expression::And(vec![
            Expression::Or(vec![
                Expression::And(vec![Clause::VlanId(vlan_op).into(), Clause::IsVlan.into()]),
                Clause::IsTcp.into(),
            ]),
            Clause::IsUdp.into(),
        ]);

        assert_eq!(expression, expected);
    }

    #[test]
    fn test_no_merge_or() {
        init_test_logging();

        let vlan_op = ValOp::match_any(vec![5]);
        let expression = Expression::Single(Clause::VlanId(vlan_op.clone()))
            .and(Clause::IsVlan)
            .or(Clause::IsTcp);
        let expected = Expression::Or(vec![
            Expression::And(vec![
                Clause::VlanId(vlan_op.clone()).into(),
                Clause::IsVlan.into(),
            ]),
            Clause::IsTcp.into(),
        ]);

        assert_eq!(expression, expected);

        let expression = Expression::Single(Clause::VlanId(vlan_op.clone()))
            .or(Clause::IsVlan)
            .and(Clause::IsTcp)
            .or(Clause::IsUdp);
        let expected = Expression::Or(vec![
            Expression::And(vec![
                Expression::Or(vec![Clause::VlanId(vlan_op).into(), Clause::IsVlan.into()]),
                Clause::IsTcp.into(),
            ]),
            Clause::IsUdp.into(),
        ]);

        assert_eq!(expression, expected);
    }

    #[test]
    fn test_mixed_merging() {
        init_test_logging();

        let clause1 = Expression::from(Clause::IsTcp);
        let clause2 = Expression::from(Clause::IsUdp);
        let clause3 = Expression::from(Clause::IsVlan);
        let clause4 = Expression::from(Clause::VlanId(ValOp::MatchAny(vec![2])));
        let clause5 = Expression::from(Clause::VlanId(ValOp::MatchAny(vec![3])));
        let or_expr = Expression::Or(vec![clause1.clone(), clause2.clone()]);
        let and_expr = Expression::And(vec![clause3.clone(), clause4.clone()]);

        let expr1 = or_expr.clone().and(and_expr.clone()).or(clause5.clone());
        let expr2 = and_expr.clone().and(or_expr.clone()).or(clause5.clone());
        let expr3 = or_expr.clone().or(and_expr.clone()).and(clause5.clone());
        let expr4 = and_expr.clone().or(or_expr.clone()).and(clause5.clone());

        let expected_expr1 = Expression::Or(vec![
            Expression::And(vec![or_expr.clone(), clause3.clone(), clause4.clone()]),
            clause5.clone(),
        ]);
        let expected_expr2 = Expression::Or(vec![
            Expression::And(vec![clause3, clause4, or_expr]),
            clause5.clone(),
        ]);
        let expected_expr3 = Expression::And(vec![
            Expression::Or(vec![clause1.clone(), clause2.clone(), and_expr.clone()]),
            clause5.clone(),
        ]);
        let expected_expr4 = Expression::And(vec![
            Expression::Or(vec![and_expr, clause1, clause2]),
            clause5,
        ]);
        assert_eq!(expr1, expected_expr1);
        assert_eq!(expr2, expected_expr2);
        assert_eq!(expr3, expected_expr3);
        assert_eq!(expr4, expected_expr4);
    }
    #[test]
    fn test_empty_expression() {
        init_test_logging();

        let expressions = [Expression::And(vec![]), Expression::Or(vec![])];
        let results = [true, false];
        for (expression, expected) in expressions.into_iter().zip(results) {
            info!("Evaluating expression \"{expression:?}\"");
            let res = expression.matcher().is_match();
            assert_eq!(res, expected);
        }
    }

    #[test]
    fn test_single_clause_tcp_expression() {
        init_test_logging();

        let expression = Expression::from(Clause::IsTcp);
        info!("Evaluating expression \"{expression}\"");
        let res = expression.matcher().tcp(true).is_match();
        assert!(res);
    }

    #[test]
    fn test_single_clause_udp_expression() {
        init_test_logging();

        let expression = Expression::from(Clause::IsUdp);
        info!("Evaluating expression \"{expression}\"");
        let res = expression.matcher().udp(true).is_match();
        assert!(res);
    }

    #[test]
    fn test_single_clause_arp_expression() {
        init_test_logging();

        for (exp, is_arp, expected) in [
            (Expression::from(Clause::IsArp), true, true),
            (Expression::from(Clause::IsArp), false, false),
            (Expression::not(Clause::IsArp), true, false),
            (Expression::not(Clause::IsArp), false, true),
        ] {
            info!("Evaluating expression \"{exp}\"");
            let res = exp.matcher().arp(is_arp).is_match();
            assert_eq!(res, expected);
        }
    }

    #[test]
    fn test_complex_not_arp_expression() {
        init_test_logging();
        let expression =
            Expression::not(Clause::IsArp).and(Clause::Port(ValOp::match_any(vec![80, 443])));
        info!("Evaluating expression \"{expression}\"");
        let res = expression.matcher().arp(false).srcport(80).is_match();
        assert!(res);
    }

    #[test]
    fn test_single_clause_vlan_expressions() {
        init_test_logging();

        let vlan = 2;
        let clauses = [
            Clause::IsVlan,
            Clause::VlanId(ValOp::compare(CmpOp::Equal, vlan)),
            Clause::VlanId(ValOp::compare(CmpOp::NotEqual, 3)),
            Clause::VlanId(ValOp::compare(CmpOp::LessEqual, vlan)),
            Clause::VlanId(ValOp::compare(CmpOp::LessThan, 3)),
            Clause::VlanId(ValOp::compare(CmpOp::GreaterEqual, vlan)),
            Clause::VlanId(ValOp::compare(CmpOp::GreaterThan, 1)),
            Clause::VlanId(ValOp::match_any(vec![1, vlan, 3, 4])),
        ];
        for clause in clauses.into_iter() {
            let expression = Expression::from(clause);
            info!("Evaluating expression \"{expression}\"");
            let res = expression.matcher().vlan(vlan).is_match();
            assert!(res);
        }
    }

    #[test]
    fn test_single_clause_port_expressions() {
        init_test_logging();

        let srcport: u16 = 26112;
        let dstport: u16 = 80;
        let clauses = [
            Clause::Port(ValOp::compare(CmpOp::Equal, srcport.into())),
            Clause::Port(ValOp::compare(CmpOp::Equal, dstport.into())),
            Clause::PortSrc(ValOp::compare(CmpOp::Equal, srcport.into())),
            Clause::PortDst(ValOp::compare(CmpOp::Equal, dstport.into())),
            Clause::Port(ValOp::match_any(vec![srcport.into()])),
            Clause::Port(ValOp::match_any(vec![dstport.into()])),
            Clause::Port(ValOp::match_none(vec![1, 2, 3])),
            Clause::PortSrc(ValOp::match_any(vec![srcport.into()])),
            Clause::PortDst(ValOp::match_any(vec![dstport.into()])),
            Clause::PortDst(ValOp::match_none(vec![1, 2, 3])),
        ];
        for clause in clauses.into_iter() {
            let expression = Expression::from(clause);
            info!("Evaluating expression \"{expression}\"");
            let res = expression
                .matcher()
                .srcport(srcport)
                .dstport(dstport)
                .is_match();
            assert!(res);
        }
    }

    #[test]
    fn test_single_clause_ethernet_expressions() {
        init_test_logging();

        let src_mac_addr = MacAddr::from([0xab, 0xcd, 0xef, 0x01, 0x02, 0x03]);
        let dst_mac_addr = MacAddr::from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let dst_one_plus = MacAddr::from([0x01, 0x02, 0x03, 0x04, 0x05, 0x07]);
        let dst_one_minus = MacAddr::from([0x01, 0x02, 0x03, 0x04, 0x05, 0x04]);
        let src_match = b"\xab".to_vec();
        let dst_match = b"\x06".to_vec();
        let src_pattern = RegexMatcher::new(Regex::new(r"(?-u).*\x03$").unwrap());
        let dst_pattern = RegexMatcher::new(Regex::new(r"(?-u).*\x06$").unwrap());
        let clauses = [
            Clause::EthAddr(EthOp::compare(CmpOp::Equal, src_mac_addr)),
            Clause::EthSrc(EthOp::compare(CmpOp::Equal, src_mac_addr)),
            Clause::EthAddr(EthOp::compare(CmpOp::Equal, dst_mac_addr)),
            Clause::EthDst(EthOp::compare(CmpOp::Equal, dst_mac_addr)),
            Clause::EthAddr(EthOp::compare(CmpOp::GreaterEqual, src_mac_addr)),
            Clause::EthSrc(EthOp::compare(CmpOp::GreaterEqual, src_mac_addr)),
            Clause::EthAddr(EthOp::compare(CmpOp::GreaterEqual, dst_mac_addr)),
            Clause::EthDst(EthOp::compare(CmpOp::GreaterEqual, dst_mac_addr)),
            Clause::EthDst(EthOp::compare(CmpOp::GreaterThan, dst_one_minus)),
            Clause::EthAddr(EthOp::compare(CmpOp::LessEqual, src_mac_addr)),
            Clause::EthSrc(EthOp::compare(CmpOp::LessEqual, src_mac_addr)),
            Clause::EthAddr(EthOp::compare(CmpOp::LessEqual, dst_mac_addr)),
            Clause::EthDst(EthOp::compare(CmpOp::LessEqual, dst_mac_addr)),
            Clause::EthDst(EthOp::compare(CmpOp::LessThan, dst_one_plus)),
            Clause::EthSrc(EthOp::compare(CmpOp::NotEqual, dst_mac_addr)),
            Clause::EthDst(EthOp::compare(CmpOp::NotEqual, src_mac_addr)),
            Clause::EthAddr(EthOp::match_any(vec![src_mac_addr])),
            Clause::EthAddr(EthOp::match_any(vec![dst_mac_addr])),
            Clause::EthSrc(EthOp::match_any(vec![src_mac_addr])),
            Clause::EthSrc(EthOp::match_none(vec![dst_mac_addr])),
            Clause::EthDst(EthOp::match_any(vec![dst_mac_addr])),
            Clause::EthDst(EthOp::match_none(vec![src_mac_addr])),
            Clause::EthAddr(EthOp::contains(src_match.clone())),
            Clause::EthAddr(EthOp::contains(dst_match.clone())),
            Clause::EthDst(EthOp::contains(dst_match)),
            Clause::EthSrc(EthOp::contains(src_match)),
            Clause::EthAddr(EthOp::regex_match(src_pattern.clone())),
            Clause::EthAddr(EthOp::regex_match(dst_pattern.clone())),
            Clause::EthDst(EthOp::regex_match(dst_pattern)),
            Clause::EthSrc(EthOp::regex_match(src_pattern)),
        ];
        for clause in clauses.into_iter() {
            let expression = Expression::from(clause);
            info!("Evaluating expression \"{expression}\"");
            let res = expression
                .matcher()
                .src_eth(src_mac_addr)
                .dst_eth(dst_mac_addr)
                .is_match();
            assert!(res);
        }
    }

    #[test]
    fn test_single_clause_ip_expressions() {
        init_test_logging();

        let src_ip_addr: IpAddr = "10.1.1.2".parse().unwrap();
        let dst_ip_addr: IpAddr = "192.168.66.1".parse().unwrap();
        let src_net: IpNet = "10.1.1.0/16".parse().unwrap();
        let dst_net: IpNet = "192.168.66.1/24".parse().unwrap();
        let clauses = [
            Clause::IpAddr(IpOp::compare(CmpOp::Equal, src_net)),
            Clause::IpAddr(IpOp::compare(CmpOp::Equal, dst_net)),
            Clause::IpSrc(IpOp::compare(CmpOp::Equal, src_net)),
            Clause::IpDst(IpOp::compare(CmpOp::Equal, dst_net)),
            Clause::IpAddr(IpOp::match_any(vec![src_net])),
            Clause::IpAddr(IpOp::match_any(vec![dst_net])),
            Clause::IpSrc(IpOp::match_any(vec![src_net])),
            Clause::IpDst(IpOp::match_any(vec![dst_net])),
            Clause::IpSrc(IpOp::match_none(vec![dst_net])),
            Clause::IpDst(IpOp::match_none(vec![src_net])),
        ];
        for clause in clauses.into_iter() {
            let expression = Expression::from(clause);
            info!("Evaluating expression \"{expression}\"");
            let res = expression
                .matcher()
                .src_ip(src_ip_addr)
                .dst_ip(dst_ip_addr)
                .is_match();
            assert!(res);
        }
    }

    #[test]
    fn test_single_clause_ip_comparison_expressions() {
        init_test_logging();

        let src_ip_addr: IpAddr = "10.1.1.2".parse().unwrap();
        let dst_ip_addr: IpAddr = "192.168.66.1".parse().unwrap();
        let src_plus_one: IpNet = "10.1.1.3/32".parse().unwrap();
        let src_exact: IpNet = "10.1.1.2/32".parse().unwrap();
        let src_minus_one: IpNet = "10.1.1.1/32".parse().unwrap();
        let dst_plus_one: IpNet = "192.168.66.2/32".parse().unwrap();
        let dst_exact: IpNet = "192.168.66.1/32".parse().unwrap();
        let dst_minus_one: IpNet = "192.168.66.0/32".parse().unwrap();
        let clauses = [
            Clause::IpSrc(IpOp::compare(CmpOp::Equal, src_exact)),
            Clause::IpSrc(IpOp::compare(CmpOp::NotEqual, dst_exact)),
            Clause::IpDst(IpOp::compare(CmpOp::Equal, dst_exact)),
            Clause::IpDst(IpOp::compare(CmpOp::NotEqual, src_exact)),
            Clause::IpSrc(IpOp::compare(CmpOp::GreaterEqual, src_exact)),
            Clause::IpSrc(IpOp::compare(CmpOp::GreaterEqual, src_minus_one)),
            Clause::IpSrc(IpOp::compare(CmpOp::GreaterThan, src_minus_one)),
            Clause::IpDst(IpOp::compare(CmpOp::GreaterEqual, dst_exact)),
            Clause::IpDst(IpOp::compare(CmpOp::GreaterEqual, dst_minus_one)),
            Clause::IpDst(IpOp::compare(CmpOp::GreaterThan, dst_minus_one)),
            Clause::IpSrc(IpOp::compare(CmpOp::LessEqual, src_exact)),
            Clause::IpSrc(IpOp::compare(CmpOp::LessEqual, src_plus_one)),
            Clause::IpSrc(IpOp::compare(CmpOp::LessThan, src_plus_one)),
            Clause::IpDst(IpOp::compare(CmpOp::LessEqual, dst_exact)),
            Clause::IpDst(IpOp::compare(CmpOp::LessEqual, dst_plus_one)),
            Clause::IpDst(IpOp::compare(CmpOp::LessThan, dst_plus_one)),
        ];
        for clause in clauses.into_iter() {
            let expression = Expression::from(clause);
            info!("Evaluating expression \"{expression}\"");
            let res = expression
                .matcher()
                .src_ip(src_ip_addr)
                .dst_ip(dst_ip_addr)
                .is_match();
            assert!(res);
        }
    }

    #[test]
    fn test_single_clause_payload_expressions() {
        init_test_logging();

        let payload =
            b"The trouble with thinking was that, once you started, you went on doing it.";
        let regex_match = Regex::new("(?i)^THE TROUBLE.+$").unwrap().into();
        let operations = [
            PayloadOp::contains(b"once you".to_vec()),
            PayloadOp::contains(b"The ".to_vec()),
            PayloadOp::contains(b"it.".to_vec()),
            PayloadOp::regex_match(regex_match),
        ];
        for operation in operations.into_iter() {
            let expression = Expression::Single(Clause::Payload(operation));
            info!("Evaluating expression \"{expression}\"");
            let res = expression.matcher().payload(payload).is_match();
            assert!(res);
        }
    }

    #[test]
    fn test_single_clause_payload_len_expressions() {
        init_test_logging();

        let payload =
            b"The trouble with thinking was that, once you started, you went on doing it.";
        let operations = [
            ByteReadOp::new(
                CmpOp::GreaterEqual,
                NumExpr::PayloadLen,
                NumExpr::Constant(0),
            ),
            ByteReadOp::new(
                CmpOp::GreaterThan,
                NumExpr::PayloadLen,
                NumExpr::Constant(0),
            ),
            ByteReadOp::new(
                CmpOp::LessEqual,
                NumExpr::PayloadLen,
                NumExpr::Constant(100),
            ),
            ByteReadOp::new(CmpOp::LessThan, NumExpr::PayloadLen, NumExpr::Constant(100)),
            ByteReadOp::new(CmpOp::Equal, NumExpr::PayloadLen, NumExpr::Constant(75)),
            ByteReadOp::new(CmpOp::NotEqual, NumExpr::PayloadLen, NumExpr::Constant(16)),
        ];
        for operation in operations.into_iter() {
            let expression = Expression::Single(Clause::ByteRead(operation));
            info!("Evaluating expression \"{expression}\"");
            let res = expression.matcher().payload(payload).is_match();
            assert!(res);
        }
    }

    #[test]
    fn test_not_expression() {
        init_test_logging();

        let expression = Expression::not(Clause::IsTcp);
        info!("Evaluating expression \"{expression}\"");
        let res = expression.matcher().tcp(false).is_match();
        assert!(res);
    }

    #[test]
    fn test_composite_expression() {
        init_test_logging();

        let src_ip_addr: IpAddr = "10.1.1.2".parse().unwrap();
        let dst_ip_addr: IpAddr = "192.168.66.1".parse().unwrap();
        let src_net: IpNet = "10.1.1.0/30".parse().unwrap();
        let dst_net: IpNet = "192.168.66.0/24".parse().unwrap();
        let payload = b"some payload";
        let re_matcher: RegexMatcher = Regex::new(r"\D+").unwrap().into();

        let expression = Expression::Single(Clause::IsTcp)
            .or(Expression::not(Clause::IsUdp))
            .and(Expression::And(vec![
                Clause::IpDst(IpOp::compare(CmpOp::Equal, dst_net)).into(),
                Clause::IpSrc(IpOp::compare(CmpOp::Equal, src_net)).into(),
                Clause::Payload(PayloadOp::regex_match(re_matcher)).into(),
            ]));

        info!("Evaluating expression \"{expression}\"");
        let res = expression
            .matcher()
            .tcp(true)
            .udp(false)
            .src_ip(src_ip_addr)
            .dst_ip(dst_ip_addr)
            .payload(payload)
            .is_match();
        assert!(res);
    }

    #[test]
    fn test_matcher_usage() {
        init_test_logging();

        let expression = Expression::Single(Clause::IsUdp);
        let mut matcher1 = expression.matcher();
        let matcher2 = expression.matcher();
        assert_eq!(matcher1, matcher2);
        matcher1 = matcher1.tcp(false).udp(true);
        assert_ne!(matcher1, matcher2);
        assert!(matcher1.is_match());
        assert!(!matcher2.is_match());
    }

    #[test]
    fn test_byte_read_u8() {
        init_test_logging();

        let payload = &[0xAB, 0xCD, 0xEF, 0x01];
        let op = super::ByteReadOp::new(
            CmpOp::Equal,
            super::NumExpr::ByteRead {
                offset: 0,
                size: super::ByteReadSize::U8,
                endian: super::Endian::Big,
            },
            super::NumExpr::Constant(0xAB),
        );
        let expression = Expression::Single(Clause::ByteRead(op));
        assert!(expression.matcher().payload(payload).is_match());
    }

    #[test]
    fn test_byte_read_be16() {
        init_test_logging();

        let payload = &[0x12, 0x34, 0x56, 0x78];
        let op = super::ByteReadOp::new(
            CmpOp::Equal,
            super::NumExpr::ByteRead {
                offset: 0,
                size: super::ByteReadSize::U16,
                endian: super::Endian::Big,
            },
            super::NumExpr::Constant(0x1234),
        );
        let expression = Expression::Single(Clause::ByteRead(op));
        assert!(expression.matcher().payload(payload).is_match());
    }

    #[test]
    fn test_byte_read_le16() {
        init_test_logging();

        // Little-endian: bytes [0x34, 0x12] → 0x1234
        let payload = &[0x34, 0x12, 0x00, 0x00];
        let op = super::ByteReadOp::new(
            CmpOp::Equal,
            super::NumExpr::ByteRead {
                offset: 0,
                size: super::ByteReadSize::U16,
                endian: super::Endian::Little,
            },
            super::NumExpr::Constant(0x1234),
        );
        let expression = Expression::Single(Clause::ByteRead(op));
        assert!(expression.matcher().payload(payload).is_match());
    }

    #[test]
    fn test_byte_read_be32() {
        init_test_logging();

        let payload = &[0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        let op = super::ByteReadOp::new(
            CmpOp::Equal,
            super::NumExpr::ByteRead {
                offset: 0,
                size: super::ByteReadSize::U32,
                endian: super::Endian::Big,
            },
            super::NumExpr::Constant(0xDEADBEEF),
        );
        let expression = Expression::Single(Clause::ByteRead(op));
        assert!(expression.matcher().payload(payload).is_match());
    }

    #[test]
    fn test_byte_read_out_of_bounds() {
        init_test_logging();

        let payload = &[0x01, 0x02]; // only 2 bytes
        let op = super::ByteReadOp::new(
            CmpOp::Equal,
            super::NumExpr::ByteRead {
                offset: 0,
                size: super::ByteReadSize::U32, // needs 4 bytes
                endian: super::Endian::Big,
            },
            super::NumExpr::Constant(0),
        );
        let expression = Expression::Single(Clause::ByteRead(op));
        // Out of bounds → false
        assert!(!expression.matcher().payload(payload).is_match());
    }

    #[test]
    fn test_byte_read_no_payload() {
        init_test_logging();

        let op = super::ByteReadOp::new(
            CmpOp::Equal,
            super::NumExpr::ByteRead {
                offset: 0,
                size: super::ByteReadSize::U8,
                endian: super::Endian::Big,
            },
            super::NumExpr::Constant(0),
        );
        let expression = Expression::Single(Clause::ByteRead(op));
        // No payload set → false
        assert!(!expression.matcher().is_match());
    }

    #[test]
    fn test_byte_read_with_payload_len_arithmetic() {
        init_test_logging();

        // Payload of 10 bytes, first 4 bytes (be32) contain value 7 = 10 - 3
        let mut payload = vec![0u8; 10];
        payload[0] = 0;
        payload[1] = 0;
        payload[2] = 0;
        payload[3] = 7; // 7 == payload.len(10) - 3
        let op = super::ByteReadOp::new(
            CmpOp::Equal,
            super::NumExpr::ByteRead {
                offset: 0,
                size: super::ByteReadSize::U32,
                endian: super::Endian::Big,
            },
            super::NumExpr::Arith {
                op: super::ArithOp::Sub,
                lhs: Box::new(super::NumExpr::PayloadLen),
                rhs: Box::new(super::NumExpr::Constant(3)),
            },
        );
        let expression = Expression::Single(Clause::ByteRead(op));
        assert!(expression.matcher().payload(&payload).is_match());
    }

    #[test]
    fn test_byte_read_two_reads_arithmetic() {
        init_test_logging();

        // payload.be16[0] + payload.be16[2] == payload.le32[4]
        // be16[0] = 0x0001 = 1, be16[2] = 0x0002 = 2, le32[4] = 3
        let payload = &[
            0x00, 0x01, // be16[0] = 1
            0x00, 0x02, // be16[2] = 2
            0x03, 0x00, 0x00, 0x00, // le32[4] = 3
        ];
        let op = super::ByteReadOp::new(
            CmpOp::Equal,
            super::NumExpr::Arith {
                op: super::ArithOp::Add,
                lhs: Box::new(super::NumExpr::ByteRead {
                    offset: 0,
                    size: super::ByteReadSize::U16,
                    endian: super::Endian::Big,
                }),
                rhs: Box::new(super::NumExpr::ByteRead {
                    offset: 2,
                    size: super::ByteReadSize::U16,
                    endian: super::Endian::Big,
                }),
            },
            super::NumExpr::ByteRead {
                offset: 4,
                size: super::ByteReadSize::U32,
                endian: super::Endian::Little,
            },
        );
        let expression = Expression::Single(Clause::ByteRead(op));
        assert!(expression.matcher().payload(payload).is_match());
    }

    #[test]
    fn test_byte_read_be64() {
        init_test_logging();

        let payload = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]; // be64 = 256
        let op = ByteReadOp::new(
            CmpOp::Equal,
            super::NumExpr::ByteRead {
                offset: 0,
                size: super::ByteReadSize::U64,
                endian: super::Endian::Big,
            },
            super::NumExpr::Constant(256),
        );
        let expression = Expression::Single(Clause::ByteRead(op));
        assert!(expression.matcher().payload(payload).is_match());
    }

    #[test]
    fn test_byte_read_le64() {
        init_test_logging();

        let payload = &[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // le64 = 256
        let op = ByteReadOp::new(
            CmpOp::Equal,
            super::NumExpr::ByteRead {
                offset: 0,
                size: super::ByteReadSize::U64,
                endian: super::Endian::Little,
            },
            super::NumExpr::Constant(256),
        );
        let expression = Expression::Single(Clause::ByteRead(op));
        assert!(expression.matcher().payload(payload).is_match());
    }

    #[test]
    fn test_byte_read_le32() {
        init_test_logging();

        let payload = &[0x01, 0x00, 0x00, 0x00]; // le32 = 1
        let op = ByteReadOp::new(
            CmpOp::Equal,
            super::NumExpr::ByteRead {
                offset: 0,
                size: super::ByteReadSize::U32,
                endian: super::Endian::Little,
            },
            super::NumExpr::Constant(1),
        );
        let expression = Expression::Single(Clause::ByteRead(op));
        assert!(expression.matcher().payload(payload).is_match());
    }

    #[test]
    fn test_byte_read_all_cmp_ops() {
        init_test_logging();

        let payload = &[0x0A]; // u8 = 10
        let make_op = |cmp: CmpOp, rhs: u64| {
            ByteReadOp::new(
                cmp,
                super::NumExpr::ByteRead {
                    offset: 0,
                    size: super::ByteReadSize::U8,
                    endian: super::Endian::Big,
                },
                super::NumExpr::Constant(rhs),
            )
        };

        // GreaterThan: 10 > 5
        let expr = Expression::Single(Clause::ByteRead(make_op(CmpOp::GreaterThan, 5)));
        assert!(expr.matcher().payload(payload).is_match());

        // LessEqual: 10 <= 10
        let expr = Expression::Single(Clause::ByteRead(make_op(CmpOp::LessEqual, 10)));
        assert!(expr.matcher().payload(payload).is_match());

        // LessEqual: 10 <= 9 → false
        let expr = Expression::Single(Clause::ByteRead(make_op(CmpOp::LessEqual, 9)));
        assert!(!expr.matcher().payload(payload).is_match());

        // GreaterThan: 10 > 10 → false
        let expr = Expression::Single(Clause::ByteRead(make_op(CmpOp::GreaterThan, 10)));
        assert!(!expr.matcher().payload(payload).is_match());
    }

    #[test]
    fn test_arithmetic_overflow_returns_none() {
        init_test_logging();

        let payload = &[0x01];
        // u64::MAX + 1 should overflow → checked_add returns None → no match
        let op = ByteReadOp::new(
            CmpOp::Equal,
            super::NumExpr::Arith {
                op: super::ArithOp::Add,
                lhs: Box::new(super::NumExpr::Constant(u64::MAX)),
                rhs: Box::new(super::NumExpr::Constant(1)),
            },
            super::NumExpr::Constant(0),
        );
        let expression = Expression::Single(Clause::ByteRead(op));
        assert!(!expression.matcher().payload(payload).is_match());
    }

    #[test]
    fn test_arithmetic_underflow_returns_none() {
        init_test_logging();

        let payload = &[0x01];
        // 0 - 1 should underflow → checked_sub returns None → no match
        let op = ByteReadOp::new(
            CmpOp::Equal,
            super::NumExpr::Arith {
                op: super::ArithOp::Sub,
                lhs: Box::new(super::NumExpr::Constant(0)),
                rhs: Box::new(super::NumExpr::Constant(1)),
            },
            super::NumExpr::Constant(0),
        );
        let expression = Expression::Single(Clause::ByteRead(op));
        assert!(!expression.matcher().payload(payload).is_match());
    }

    #[test]
    fn test_regex_matcher_partial_eq() {
        let re1 = RegexMatcher::new(Regex::new("abc").unwrap());
        let re2 = RegexMatcher::new(Regex::new("abc").unwrap());
        let re3 = RegexMatcher::new(Regex::new("def").unwrap());
        assert_eq!(re1, re2);
        assert_ne!(re1, re3);
    }

    #[test]
    fn test_regex_matcher_display() {
        let re = RegexMatcher::new(Regex::new("abc.*xyz").unwrap());
        assert_eq!(format!("{re}"), "\"abc.*xyz\"");
    }

    #[test]
    fn test_num_expr_display() {
        // Constant
        assert_eq!(format!("{}", super::NumExpr::Constant(42)), "42");
        // PayloadLen
        assert_eq!(format!("{}", super::NumExpr::PayloadLen), "payload.len");
        // ByteRead u8
        let expr = super::NumExpr::ByteRead {
            offset: 5,
            size: super::ByteReadSize::U8,
            endian: super::Endian::Big,
        };
        assert_eq!(format!("{expr}"), "payload.u8[5]");
        // ByteRead be32
        let expr = super::NumExpr::ByteRead {
            offset: 0,
            size: super::ByteReadSize::U32,
            endian: super::Endian::Big,
        };
        assert_eq!(format!("{expr}"), "payload.be32[0]");
        // ByteRead le16
        let expr = super::NumExpr::ByteRead {
            offset: 2,
            size: super::ByteReadSize::U16,
            endian: super::Endian::Little,
        };
        assert_eq!(format!("{expr}"), "payload.le16[2]");
        // ByteRead be64
        let expr = super::NumExpr::ByteRead {
            offset: 0,
            size: super::ByteReadSize::U64,
            endian: super::Endian::Big,
        };
        assert_eq!(format!("{expr}"), "payload.be64[0]");
        // Arith
        let expr = super::NumExpr::Arith {
            op: super::ArithOp::Add,
            lhs: Box::new(super::NumExpr::PayloadLen),
            rhs: Box::new(super::NumExpr::Constant(3)),
        };
        assert_eq!(format!("{expr}"), "payload.len + 3");
    }
}
