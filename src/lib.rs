#![forbid(unsafe_code)]

mod driver;
mod expression;
mod lexer;
mod mac_addr;
mod parser;
#[cfg(test)]
mod test_utils;

pub use driver::{
    parse,
    ParseError,
};
pub use expression::{
    Expression,
    Matcher,
};

pub const EXPRESSION_GUIDE: &str = include_str!("../docs/syntax.md");
