#![forbid(unsafe_code)]

mod driver;
mod expression;
mod input;
mod lexer;
mod mac_addr;
mod parser;
#[cfg(test)]
mod test_utils;
mod value_parsers;

pub use driver::{
    parse,
    ParseError,
};
pub use expression::{
    Expression,
    Matcher,
};
pub use mac_addr::MacAddr;

pub const EXPRESSION_GUIDE: &str = include_str!("../docs/syntax.md");
