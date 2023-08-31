use crate::{
    expression::{
        Clause,
        CmpOp,
        EthOp,
        IpOp,
        PayloadLenOp,
        PayloadOp,
        RegexMatcher,
        ValOp,
    },
    lexer::{
        Spanned,
        Token,
    },
    mac_addr::MacAddr,
    Expression,
};
use chumsky::prelude::*;
use ipnet::IpNet;
use regex::bytes::Regex;
use std::net::IpAddr;

/// Parse a given string as a u16
fn parse_u16(val: &str) -> Result<u16, &'static str> {
    val.parse().map_err(|_| "value is not a valid number")
}

/// Parse a given string as a mac-address
fn parse_mac_addr(val: &str) -> Result<MacAddr, &'static str> {
    MacAddr::try_from(val).map_err(|_| "value is not a valid mac-address")
}

/// Parse a given string as a regex
fn parse_regex(val: &str) -> Result<RegexMatcher, String> {
    Regex::new(val)
        .map(RegexMatcher::new)
        .map_err(|e| format!("{e}"))
}

/// Parse a given string as a byte-string (i.e. groups of two hex values, separated by ':' or not)
fn parse_byte_string(val: &str) -> Result<Vec<u8>, &'static str> {
    let byte = any::<_, extra::Err<Simple<char>>>()
        .filter(char::is_ascii_hexdigit)
        .repeated()
        .exactly(2)
        .map_slice(|s| u8::from_str_radix(s, 16).unwrap());

    let hex = byte
        .separated_by(just(':'))
        .at_least(2)
        .collect::<Vec<_>>()
        .or(byte.repeated().at_least(1).collect());

    hex.parse(val)
        .into_result()
        .map_err(|_| "value is not a colon separated byte string")
}

/// Parse a string as bytes, including un-escaping escaped characters.
/// (code taken from https://github.com/BurntSushi/ripgrep/blob/master/crates/cli/src/escape.rs)
/// The string passed here is expected to have been a quoted string. That is validated up the stack.
fn parse_escaped_byte_string(val: &str) -> Result<Vec<u8>, &'static str> {
    /// A single state in the state machine used by `unescape`.
    #[derive(PartialEq, Eq)]
    enum State {
        /// The state after seeing a `\`.
        Escape,
        /// The state after seeing a `\x`.
        HexFirst,
        /// The state after seeing a `\x[0-9A-Fa-f]`.
        HexSecond(char),
        /// Default state.
        Literal,
    }

    let mut bytes = vec![];
    let mut state = State::Literal;
    for c in val.chars() {
        match state {
            State::Escape => match c {
                '\\' => {
                    bytes.push(b'\\');
                    state = State::Literal;
                }
                'n' => {
                    bytes.push(b'\n');
                    state = State::Literal;
                }
                'r' => {
                    bytes.push(b'\r');
                    state = State::Literal;
                }
                't' => {
                    bytes.push(b'\t');
                    state = State::Literal;
                }
                'x' => {
                    state = State::HexFirst;
                }
                c => {
                    bytes.extend(format!(r"\{}", c).into_bytes());
                    state = State::Literal;
                }
            },
            State::HexFirst => match c {
                '0'..='9' | 'A'..='F' | 'a'..='f' => {
                    state = State::HexSecond(c);
                }
                c => {
                    bytes.extend(format!(r"\x{}", c).into_bytes());
                    state = State::Literal;
                }
            },
            State::HexSecond(first) => match c {
                '0'..='9' | 'A'..='F' | 'a'..='f' => {
                    let ordinal = format!("{}{}", first, c);
                    let byte = u8::from_str_radix(&ordinal, 16).unwrap();
                    bytes.push(byte);
                    state = State::Literal;
                }
                c => {
                    let original = format!(r"\x{}{}", first, c);
                    bytes.extend(original.into_bytes());
                    state = State::Literal;
                }
            },
            State::Literal => match c {
                '\\' => {
                    state = State::Escape;
                }
                c => {
                    bytes.extend(c.to_string().as_bytes());
                }
            },
        }
    }
    match state {
        State::Escape => bytes.push(b'\\'),
        State::HexFirst => bytes.extend(b"\\x"),
        State::HexSecond(c) => bytes.extend(format!("\\x{}", c).into_bytes()),
        State::Literal => {}
    }
    Ok(bytes)
}

/// Parse a given string as an ip or a CIDR ip/net
fn parse_ip_net(val: &str) -> Result<IpNet, String> {
    // Try to parse first as a single ip address, if it does not work, try as a cidr
    val.parse::<IpAddr>()
        .map(IpNet::from)
        .or_else(|_| val.parse::<IpNet>())
        .map_err(|e| format!("{e}"))
}

/// Used in the `value_to_t` parser to choose whether to support quoted string, plain string,
/// or both
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueMode {
    Quoted,
    Unquoted,
    Both,
}

/// Parse a value as a t
fn value_to_t<'src, 'a, F, T, E>(
    conversion_fn: &'a F,
    mode: ValueMode,
) -> impl Parser<'src, &'src [Token], T, extra::Err<Rich<'src, Token>>> + Clone
where
    F: Fn(&str) -> Result<T, E> + 'a,
    E: std::fmt::Display,
    'a: 'src,
{
    select! {
        Token::QuotedValue(t) if mode == ValueMode::Quoted || mode == ValueMode::Both => t,
        Token::Value(t) if mode == ValueMode::Unquoted || mode == ValueMode::Both => t,
    }
    .try_map(|val, span| {
        conversion_fn(val.as_str()).map_err(|e| Rich::custom(span, format!("{e}")))
    })
}

/// Parse a list of values, i.e. `{ one, two, three }`, to a vector
fn values_to_t<'src, 'a, F, T, E>(
    conversion_fn: &'a F,
    mode: ValueMode,
) -> impl Parser<'src, &'src [Token], Vec<T>, extra::Err<Rich<'src, Token>>> + Clone
where
    F: Fn(&str) -> Result<T, E> + 'a,
    E: std::fmt::Display,
    'a: 'src,
{
    select! {
        Token::QuotedValue(t) if mode == ValueMode::Quoted || mode == ValueMode::Both => t,
        Token::Value(t) if mode == ValueMode::Unquoted || mode == ValueMode::Both => t,
    }
    .separated_by(just(Token::Comma))
    .at_least(1)
    .collect()
    .delimited_by(just(Token::OpenBrace), just(Token::CloseBrace))
    .try_map(|list: Vec<String>, span: SimpleSpan| {
        let mut result = Vec::new();
        for (i, val) in list.into_iter().enumerate() {
            let span = SimpleSpan::new(span.start() + i, span.start() + i + 1);
            match conversion_fn(val.as_str()) {
                Ok(val) => result.push(val),
                Err(e) => return Err(Rich::custom(span, format!("{e}"))),
            }
        }
        Ok(result)
    })
}

/// Parse a comparison token
fn comparison_operations<'src>()
-> impl Parser<'src, &'src [Token], CmpOp, extra::Err<Rich<'src, Token>>> + Clone {
    choice((
        just(Token::Equal).to(CmpOp::Equal),
        just(Token::NotEqual).to(CmpOp::NotEqual),
        just(Token::LessThan).to(CmpOp::LessThan),
        just(Token::LessEqual).to(CmpOp::LessEqual),
        just(Token::GreaterThan).to(CmpOp::GreaterThan),
        just(Token::GreaterEqual).to(CmpOp::GreaterEqual),
    ))
    .labelled("comparison operations")
}

/// Parse the set of possible tokens that create a `EthernetOperations`
fn parse_ethernet_operations<'src>()
-> impl Parser<'src, &'src [Token], EthOp, extra::Err<Rich<'src, Token>>> + Clone {
    let compare = comparison_operations()
        .then(value_to_t(&parse_mac_addr, ValueMode::Unquoted).labelled("mac-address"))
        .map(|(op, val)| EthOp::compare(op, val));
    let match_any = just(Token::In)
        .then(values_to_t(&parse_mac_addr, ValueMode::Unquoted).labelled("list of mac-address"))
        .map(|(_, list)| EthOp::match_any(list));
    let contains = just(Token::Contains)
        .ignore_then(
            value_to_t(&parse_byte_string, ValueMode::Unquoted)
                .labelled("byte-string")
                .or(value_to_t(&parse_escaped_byte_string, ValueMode::Quoted)
                    .labelled("quoted escaped byte-string")),
        )
        .map(EthOp::contains);
    let regex = just(Token::RegexMatch)
        .ignore_then(value_to_t(&parse_regex, ValueMode::Quoted).labelled("quoted regex"))
        .map(EthOp::regex_match);
    compare
        .or(match_any)
        .or(contains)
        .or(regex)
        .labelled("ethernet operations")
}

/// Parse the set of possible tokens that create a `IpOperations`
fn parse_ip_operations<'src>()
-> impl Parser<'src, &'src [Token], IpOp, extra::Err<Rich<'src, Token>>> + Clone {
    let compare = comparison_operations()
        .then(value_to_t(&parse_ip_net, ValueMode::Unquoted).labelled("ip-address or cidr"))
        .map(|(op, val)| IpOp::compare(op, val));
    let match_any = just(Token::In)
        .then(
            values_to_t(&parse_ip_net, ValueMode::Unquoted).labelled("list of ip-address or cidr"),
        )
        .map(|(_, list)| IpOp::match_any(list));
    compare.or(match_any).labelled("ip operations")
}

/// Parse the set of possible tokens that create a `ValOperations`
fn parse_val_operations<'src>()
-> impl Parser<'src, &'src [Token], ValOp, extra::Err<Rich<'src, Token>>> + Clone {
    let compare = comparison_operations()
        .then(value_to_t(&parse_u16, ValueMode::Unquoted).labelled("number"))
        .map(|(op, val)| ValOp::compare(op, val));
    let match_any = just(Token::In)
        .then(values_to_t(&parse_u16, ValueMode::Unquoted).labelled("list of numbers"))
        .map(|(_, list)| ValOp::match_any(list));
    compare.or(match_any).labelled("value operations")
}

/// Parse the set of possible tokens that create a `PayloadOperations`
fn parse_payload_operations<'src>()
-> impl Parser<'src, &'src [Token], PayloadOp, extra::Err<Rich<'src, Token>>> + Clone {
    let contains = just(Token::Contains)
        .ignore_then(
            value_to_t(&parse_byte_string, ValueMode::Unquoted)
                .labelled("byte-string")
                .or(value_to_t(&parse_escaped_byte_string, ValueMode::Quoted)
                    .labelled("quoted escaped byte-string")),
        )
        .map(PayloadOp::contains);
    let regex = just(Token::RegexMatch)
        .ignore_then(value_to_t(&parse_regex, ValueMode::Quoted).labelled("quoted regex"))
        .map(PayloadOp::regex_match);
    contains.or(regex).labelled("payload operations")
}

/// Parse the set of possible tokens that create a `PayloadLenOperations`
fn parse_payload_len_operations<'src>()
-> impl Parser<'src, &'src [Token], PayloadLenOp, extra::Err<Rich<'src, Token>>> + Clone {
    let compare = comparison_operations()
        .then(value_to_t(&parse_u16, ValueMode::Unquoted).labelled("number"))
        .map(|(op, val)| PayloadLenOp::compare(op, val));
    compare.labelled("payload length operations")
}

/// Parse a clause composed of a single term, in the form of `tcp`, `udp`, `vlan`
fn parse_single_term_clause<'src>()
-> impl Parser<'src, &'src [Token], Clause, extra::Err<Rich<'src, Token>>> + Clone {
    just(Token::LitTcp)
        .to(Clause::IsTcp)
        .or(just(Token::LitUdp).to(Clause::IsUdp))
        .or(just(Token::LitVlan).to(Clause::IsVlan))
        .labelled("single term clause")
}

/// Parse a clause composed of a single term, in the form of `tcp`, `udp`, `vlan`
fn parse_multiple_terms_clause<'src>()
-> impl Parser<'src, &'src [Token], Clause, extra::Err<Rich<'src, Token>>> + Clone {
    choice((
        just(Token::LitEthAddr)
            .ignore_then(parse_ethernet_operations())
            .map(Clause::EthAddr),
        just(Token::LitEthDst)
            .ignore_then(parse_ethernet_operations())
            .map(Clause::EthDst),
        just(Token::LitEthSrc)
            .ignore_then(parse_ethernet_operations())
            .map(Clause::EthSrc),
        just(Token::LitIpAddr)
            .ignore_then(parse_ip_operations())
            .map(Clause::IpAddr),
        just(Token::LitIpDst)
            .ignore_then(parse_ip_operations())
            .map(Clause::IpDst),
        just(Token::LitIpSrc)
            .ignore_then(parse_ip_operations())
            .map(Clause::IpSrc),
        just(Token::LitVlanId)
            .ignore_then(parse_val_operations())
            .map(Clause::VlanId),
        just(Token::LitPort)
            .ignore_then(parse_val_operations())
            .map(Clause::Port),
        just(Token::LitPortDst)
            .ignore_then(parse_val_operations())
            .map(Clause::PortDst),
        just(Token::LitPortSrc)
            .ignore_then(parse_val_operations())
            .map(Clause::PortSrc),
        just(Token::LitPayload)
            .ignore_then(parse_payload_operations())
            .map(Clause::Payload),
        just(Token::LitPayloadLen)
            .ignore_then(parse_payload_len_operations())
            .map(Clause::PayloadLen),
    ))
    .labelled("multiple terms clause")
}

/// Parse an AST made of `Token` into a `Expression`
pub(crate) fn expression_parser<'src>()
-> impl Parser<'src, &'src [Token], Spanned<Expression>, extra::Err<Rich<'src, Token>>> {
    let clause = parse_single_term_clause()
        .or(parse_multiple_terms_clause())
        .map(Expression::Single);

    recursive(|nested| {
        let plain_or_nested =
            clause.or(nested.delimited_by(just(Token::OpenParen), just(Token::CloseParen)));

        let not_expr = just(Token::Not)
            .ignore_then(plain_or_nested.clone())
            .map(Expression::not);

        let expr = plain_or_nested.or(not_expr);

        expr.clone()
            .then(
                just(Token::Or)
                    .or(just(Token::And))
                    .then(expr.clone())
                    .repeated()
                    .collect::<Vec<_>>(),
            )
            .map(|(lhs, mut list)| {
                // We want to preserve the order of operations that the user requested
                list.reverse();
                let mut lhs = lhs;
                while let Some((op, rhs)) = list.pop() {
                    lhs = match op {
                        Token::And => lhs.and(rhs),
                        Token::Or => lhs.or(rhs),
                        _ => unreachable!(),
                    }
                }
                lhs
            })
    }) // Add span information
    .map_with_span(Spanned)
}

#[cfg(test)]
mod tests {
    use super::{
        expression_parser,
        parse_byte_string,
        parse_escaped_byte_string,
        parse_ethernet_operations,
        parse_ip_net,
        parse_ip_operations,
        parse_mac_addr,
        parse_multiple_terms_clause,
        parse_payload_len_operations,
        parse_payload_operations,
        parse_regex,
        parse_single_term_clause,
        parse_u16,
        parse_val_operations,
    };
    use crate::{
        expression::{
            Clause,
            CmpOp,
            EthOp,
            IpOp,
            PayloadLenOp,
            PayloadOp,
            RegexMatcher,
            ValOp,
        },
        lexer::Token,
        mac_addr::MacAddr,
        test_utils::init_test_logging,
        Expression,
    };
    use chumsky::Parser;
    use ipnet::IpNet;
    use regex::bytes::Regex;
    use tracing::info;

    #[test]
    fn test_parse_u16() {
        init_test_logging();

        for val in [u16::MIN, u16::MAX] {
            info!("Parsing \"{val}\" as u16 - should succeed");
            let num = parse_u16(val.to_string().as_str()).unwrap();
            assert_eq!(val, num);
        }

        for val in [
            "25d".to_string(),
            "-1".to_string(),
            (u16::MAX as u32 + 1).to_string(),
            "".to_string(),
        ] {
            info!("Parsing \"{val}\" as u16 - should fail");
            let res = parse_u16(val.to_string().as_str());
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_parse_mac_addr() {
        init_test_logging();

        let expected_mac_addr = MacAddr::from([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]);

        for val in [
            "ab-cd-ef-01-23-45".to_string(),
            "ab-cd-ef-01-23-45".to_ascii_uppercase(),
            "ab:cd:ef:01:23:45".to_string(),
            "ab:cd:ef:01:23:45".to_ascii_uppercase(),
            "abcdef012345".to_string(),
            "abcdef012345".to_ascii_uppercase(),
            "abc.def.012.345".to_string(),
            "abc.def.012.345".to_ascii_uppercase(),
        ] {
            info!("Parsing \"{val}\" as mac-address - should succeed");
            let mac_addr = parse_mac_addr(val.as_str()).unwrap();
            assert_eq!(mac_addr, expected_mac_addr);
        }

        for val in [
            "ab-cd-ef-01-23",
            "12345",
            "some words",
            "-ab-cd-ef-01-23-45",
            "ab-cd-ef-01-23-45-",
            "",
        ] {
            info!("Parsing \"{val}\" as mac-address - should fail");
            let res = parse_mac_addr(val);
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_parse_regex() {
        init_test_logging();

        for val in [
            r"(ASCII|\x22\x12)",
            "(?i)CaSeInSeNsItIvE",
            "some words",
            r"^\x00BOOM\x00",
            "[[:ascii:]]{100}",
            "GET /(secret|password)",
        ] {
            info!("Parsing \"{val}\" as regex - should succeed");
            let res = parse_regex(val);
            assert!(res.is_ok());
        }

        for val in ["(1234", r"\"] {
            info!("Parsing \"{val}\" as regex - should fail");
            let res = parse_regex(val);
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_parse_byte_string() {
        init_test_logging();

        for (val, expected) in [
            ("00", vec![0]),
            ("0E", vec![14]),
            ("001122334455", vec![0, 17, 34, 51, 68, 85]),
            ("00:11:22:33:44:55", vec![0, 17, 34, 51, 68, 85]),
        ] {
            info!("Parsing \"{val}\" as byte string - should succeed");
            let res = parse_byte_string(val).unwrap();
            assert_eq!(res, expected);
        }

        for val in ["", "0", "1", "a", "A", "x1", "~1", "10Z1"] {
            info!("Parsing \"{val}\" as byte string - should fail");
            let res = parse_byte_string(val);
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_parse_escaped_string_as_byte() {
        init_test_logging();

        for (val, expected) in [
            ("", b"".to_vec()),
            (r"\", b"\\".to_vec()),
            ("simple string", b"simple string".to_vec()),
            (r"\\escaped \\ slash \\", b"\\escaped \\ slash \\".to_vec()),
            (r"not an escape \w", b"not an escape \\w".to_vec()),
            (r"foo\nbar\xFFbaz", b"foo\nbar\xFFbaz".to_vec()),
            (r"\n", b"\n".to_vec()),
            (r"new line at the end\n", b"new line at the end\n".to_vec()),
            (
                r"\nnew line at the start",
                b"\nnew line at the start".to_vec(),
            ),
            (r"something \t else", b"something \t else".to_vec()),
            (r"Null NULL NUL \x00", b"Null NULL NUL \x00".to_vec()),
            (r"maybe nul \x0", b"maybe nul \\x0".to_vec()),
            (r"windows style nl \r\n", b"windows style nl \r\n".to_vec()),
            (r"\xa", b"\\xa".to_vec()),
            (r"\x1", b"\\x1".to_vec()),
            (r"\x-", b"\\x-".to_vec()),
            (r"\x12\xa1\xA1", b"\x12\xa1\xA1".to_vec()),
            (r"\xaa\xbb\xcc", b"\xaa\xbb\xcc".to_vec()),
            (r"invalid escape \xa~", b"invalid escape \\xa~".to_vec()),
            (r"invalid escape \x~~", b"invalid escape \\x~~".to_vec()),
            (r"invalid escape \x~a", b"invalid escape \\x~a".to_vec()),
            (r"invalid escape \x", b"invalid escape \\x".to_vec()),
        ] {
            info!("Parsing \"{val}\" as escaped bytes - should succeed");
            let res = parse_escaped_byte_string(val).unwrap();
            assert_eq!(res, expected);
        }
    }

    #[test]
    fn test_parse_ip_net() {
        init_test_logging();

        for val in [
            "127.0.0.1",
            "192.168.12.34/16",
            "10.1.1.0/24",
            "10.1.1.0/32",
            "10.1.1.0",
            "fd00::/32",
            "fd00::/16",
            "fd00::1:2:3:4/16",
            "1:2::3:4",
            "1:2:3:4:5:6:77.77.88.88",
            "1:2:3:4:5:6:4d4d:5858",
            "fe80::1.2.3.4",
            "::1",
            "1::",
            "::",
        ] {
            info!("Parsing \"{val}\" as ip - should succeed");
            let res = parse_ip_net(val);
            assert!(res.is_ok());
        }

        for val in ["10.1.1", "fd00:", ""] {
            info!("Parsing \"{val}\" as ip - should fail");
            let res = parse_ip_net(val);
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_parse_ethernet_operations_success() {
        init_test_logging();

        let expected_mac_addr = MacAddr::from([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]);
        let mac_val = Token::Value("ab-cd-ef-01-23-45".into());
        let regex_matcher = Regex::new("string").unwrap().into();

        let cases = [
            vec![Token::Equal, mac_val.clone()],
            vec![Token::NotEqual, mac_val.clone()],
            vec![Token::GreaterThan, mac_val.clone()],
            vec![Token::GreaterEqual, mac_val.clone()],
            vec![Token::LessThan, mac_val.clone()],
            vec![Token::LessEqual, mac_val],
            vec![Token::Equal, Token::Value("abcdef012345".into())],
            vec![Token::Equal, Token::Value("ab:cd:ef:01:23:45".into())],
            vec![Token::Equal, Token::Value("abc.def.012.345".into())],
            vec![
                Token::In,
                Token::OpenBrace,
                Token::Value("abcdef012345".into()),
                Token::Comma,
                Token::Value("abc.def.012.345".into()),
                Token::CloseBrace,
            ],
            vec![
                Token::In,
                Token::OpenBrace,
                Token::Value("abcdef012345".into()),
                Token::CloseBrace,
            ],
            vec![Token::Contains, Token::Value("ab".into())],
            vec![Token::Contains, Token::Value("ab:cd:ef".into())],
            vec![Token::Contains, Token::QuotedValue("string".into())],
            vec![Token::Contains, Token::QuotedValue(r"\x00string".into())],
            vec![Token::RegexMatch, Token::QuotedValue(r"string".into())],
        ];
        let expected_results = [
            EthOp::compare(CmpOp::Equal, expected_mac_addr),
            EthOp::compare(CmpOp::NotEqual, expected_mac_addr),
            EthOp::compare(CmpOp::GreaterThan, expected_mac_addr),
            EthOp::compare(CmpOp::GreaterEqual, expected_mac_addr),
            EthOp::compare(CmpOp::LessThan, expected_mac_addr),
            EthOp::compare(CmpOp::LessEqual, expected_mac_addr),
            EthOp::compare(CmpOp::Equal, expected_mac_addr),
            EthOp::compare(CmpOp::Equal, expected_mac_addr),
            EthOp::compare(CmpOp::Equal, expected_mac_addr),
            EthOp::match_any(vec![expected_mac_addr, expected_mac_addr]),
            EthOp::match_any(vec![expected_mac_addr]),
            EthOp::contains(vec![0xab]),
            EthOp::contains(vec![0xab, 0xcd, 0xef]),
            EthOp::contains(b"string".to_vec()),
            EthOp::contains(b"\x00string".to_vec()),
            EthOp::regex_match(regex_matcher),
        ];

        for (tokens, expected) in cases.into_iter().zip(expected_results) {
            info!("Parsing {tokens:?} as ethernet operations - should succeed");
            let res = parse_ethernet_operations().parse(&tokens).unwrap();
            assert_eq!(res, expected);
        }
    }

    #[test]
    fn test_parse_ethernet_operations_failure() {
        init_test_logging();

        let cases = [
            vec![Token::Equal, Token::Value("".into())],
            vec![Token::Equal, Token::QuotedValue("ab-cd-ef-01-23-45".into())],
            vec![Token::Equal, Token::Value("string".into())],
            vec![
                Token::In,
                Token::OpenBrace,
                Token::Value("ab-cd-ef-01-23-45".into()),
                Token::Comma,
            ],
            vec![
                Token::In,
                Token::OpenBrace,
                Token::Value("01-23-45".into()),
                Token::Comma,
                Token::CloseBrace,
            ],
            vec![Token::In, Token::OpenBrace, Token::CloseBrace],
        ];

        for tokens in cases {
            info!("Parsing {tokens:?} as ethernet operations - should fail");
            let res = parse_ethernet_operations().parse(&tokens);
            assert!(res.has_errors());
        }
    }

    #[test]
    fn test_parse_ip_operations_success() {
        init_test_logging();

        let ip: IpNet = "192.168.1.1/32".parse().unwrap();

        let cases = [
            vec![Token::Equal, Token::Value("192.168.1.1".into())],
            vec![Token::Equal, Token::Value("192.168.1.1/32".into())],
            vec![Token::NotEqual, Token::Value("192.168.1.1".into())],
            vec![Token::GreaterThan, Token::Value("192.168.1.1".into())],
            vec![Token::GreaterEqual, Token::Value("192.168.1.1".into())],
            vec![Token::LessThan, Token::Value("192.168.1.1".into())],
            vec![Token::LessEqual, Token::Value("192.168.1.1".into())],
            vec![
                Token::In,
                Token::OpenBrace,
                Token::Value("192.168.1.1".into()),
                Token::Comma,
                Token::Value("192.168.1.1/32".into()),
                Token::CloseBrace,
            ],
        ];
        let expected_results = [
            IpOp::compare(CmpOp::Equal, ip),
            IpOp::compare(CmpOp::Equal, ip),
            IpOp::compare(CmpOp::NotEqual, ip),
            IpOp::compare(CmpOp::GreaterThan, ip),
            IpOp::compare(CmpOp::GreaterEqual, ip),
            IpOp::compare(CmpOp::LessThan, ip),
            IpOp::compare(CmpOp::LessEqual, ip),
            IpOp::match_any(vec![ip, ip]),
        ];

        for (tokens, expected) in cases.into_iter().zip(expected_results) {
            info!("Parsing {tokens:?} as ip operations - should succeed");
            let res = parse_ip_operations().parse(&tokens).unwrap();
            assert_eq!(res, expected);
        }
    }

    #[test]
    fn test_parse_ip_operations_failure() {
        init_test_logging();

        let cases = [
            vec![Token::Equal, Token::QuotedValue("55".into())],
            vec![Token::Equal, Token::Value("not an ip".into())],
            vec![Token::In, Token::Value("192.168.1.1".into())],
            vec![Token::GreaterThan, Token::Equal],
            vec![
                Token::In,
                Token::OpenBrace,
                Token::Value("192.168.1.1".into()),
                Token::Comma,
                Token::Value("192.168.1.1".into()),
            ],
            vec![
                Token::In,
                Token::OpenBrace,
                Token::Value("192.168.1.1".into()),
                Token::Comma,
                Token::CloseBrace,
            ],
            vec![Token::In, Token::OpenBrace, Token::CloseBrace],
        ];

        for tokens in cases {
            info!("Parsing {tokens:?} as ip operations - should fail");
            let res = parse_ip_operations().parse(&tokens);
            assert!(res.has_errors());
        }
    }

    #[test]
    fn test_parse_val_operations_success() {
        init_test_logging();

        let cases = [
            vec![Token::Equal, Token::Value("55".into())],
            vec![Token::NotEqual, Token::Value("55".into())],
            vec![Token::GreaterThan, Token::Value("55".into())],
            vec![Token::GreaterEqual, Token::Value("55".into())],
            vec![Token::LessThan, Token::Value("55".into())],
            vec![Token::LessEqual, Token::Value("55".into())],
            vec![
                Token::In,
                Token::OpenBrace,
                Token::Value("1".into()),
                Token::Comma,
                Token::Value("2".into()),
                Token::CloseBrace,
            ],
        ];
        let expected_results = [
            ValOp::compare(CmpOp::Equal, 55),
            ValOp::compare(CmpOp::NotEqual, 55),
            ValOp::compare(CmpOp::GreaterThan, 55),
            ValOp::compare(CmpOp::GreaterEqual, 55),
            ValOp::compare(CmpOp::LessThan, 55),
            ValOp::compare(CmpOp::LessEqual, 55),
            ValOp::match_any(vec![1, 2]),
        ];

        for (tokens, expected) in cases.into_iter().zip(expected_results) {
            info!("Parsing {tokens:?} as value operations - should succeed");
            let res = parse_val_operations().parse(&tokens).unwrap();
            assert_eq!(res, expected);
        }
    }

    #[test]
    fn test_parse_val_operations_failure() {
        init_test_logging();

        let cases = [
            vec![Token::Equal, Token::QuotedValue("55".into())],
            vec![Token::Equal, Token::Value("not a number".into())],
            vec![Token::In, Token::Value("55".into())],
            vec![Token::GreaterThan, Token::Equal],
            vec![
                Token::In,
                Token::OpenBrace,
                Token::Value("1".into()),
                Token::Comma,
                Token::Value("2".into()),
            ],
            vec![
                Token::In,
                Token::OpenBrace,
                Token::Value("1".into()),
                Token::Comma,
                Token::CloseBrace,
            ],
            vec![Token::In, Token::OpenBrace, Token::CloseBrace],
        ];

        for tokens in cases {
            info!("Parsing {tokens:?} as value operations - should fail");
            let res = parse_val_operations().parse(&tokens);
            assert!(res.has_errors());
        }
    }

    #[test]
    fn test_parse_payload_operations_success() {
        init_test_logging();

        let regex_matcher = Regex::new("string").unwrap().into();

        let cases = [
            vec![Token::Contains, Token::Value("ab".into())],
            vec![Token::Contains, Token::Value("ab:cd:ef".into())],
            vec![Token::Contains, Token::QuotedValue("string".into())],
            vec![Token::Contains, Token::QuotedValue(r"\x00string".into())],
            vec![Token::RegexMatch, Token::QuotedValue(r"string".into())],
        ];
        let expected_results = [
            PayloadOp::contains(vec![0xab]),
            PayloadOp::contains(vec![0xab, 0xcd, 0xef]),
            PayloadOp::contains(b"string".to_vec()),
            PayloadOp::contains(b"\x00string".to_vec()),
            PayloadOp::regex_match(regex_matcher),
        ];

        for (tokens, expected) in cases.into_iter().zip(expected_results) {
            info!("Parsing {tokens:?} as payload operations - should succeed");
            let res = parse_payload_operations().parse(&tokens).unwrap();
            assert_eq!(res, expected);
        }
    }

    #[test]
    fn test_parse_payload_operations_failure() {
        init_test_logging();

        let cases = [
            vec![Token::Contains, Token::Value("".into())],
            vec![Token::RegexMatch, Token::Value("string".into())],
            vec![Token::RegexMatch, Token::Value(r"\".into())],
        ];

        for tokens in cases {
            info!("Parsing {tokens:?} as payload operations - should fail");
            let res = parse_payload_operations().parse(&tokens);
            assert!(res.has_errors());
        }
    }

    #[test]
    fn test_parse_payload_len_operations_success() {
        init_test_logging();

        let cases = [
            vec![Token::Equal, Token::Value("55".into())],
            vec![Token::NotEqual, Token::Value("55".into())],
            vec![Token::GreaterThan, Token::Value("55".into())],
            vec![Token::GreaterEqual, Token::Value("55".into())],
            vec![Token::LessThan, Token::Value("55".into())],
            vec![Token::LessEqual, Token::Value("55".into())],
        ];
        let expected_results = [
            PayloadLenOp::compare(CmpOp::Equal, 55),
            PayloadLenOp::compare(CmpOp::NotEqual, 55),
            PayloadLenOp::compare(CmpOp::GreaterThan, 55),
            PayloadLenOp::compare(CmpOp::GreaterEqual, 55),
            PayloadLenOp::compare(CmpOp::LessThan, 55),
            PayloadLenOp::compare(CmpOp::LessEqual, 55),
        ];

        for (tokens, expected) in cases.into_iter().zip(expected_results) {
            info!("Parsing {tokens:?} as payload length operations - should succeed");
            let res = parse_payload_len_operations().parse(&tokens).unwrap();
            assert_eq!(res, expected);
        }
    }

    #[test]
    fn test_parse_payload_len_operations_failure() {
        init_test_logging();

        let cases = [
            vec![Token::Equal, Token::QuotedValue("55".into())],
            vec![Token::Equal, Token::Value("not a number".into())],
            vec![Token::In, Token::Value("55".into())],
            vec![Token::GreaterThan, Token::Equal],
        ];

        for tokens in cases {
            info!("Parsing {tokens:?} as payload length operations - should fail");
            let res = parse_payload_len_operations().parse(&tokens);
            assert!(res.has_errors());
        }
    }

    #[test]
    fn test_parse_single_term() {
        init_test_logging();

        let cases = [Token::LitTcp, Token::LitUdp, Token::LitVlan];
        let expected_results = [Clause::IsTcp, Clause::IsUdp, Clause::IsVlan];

        for (token, expected) in cases.into_iter().zip(expected_results) {
            info!("Parsing {token} as single term clause - should succeed");
            let tokens = &[token];
            let res = parse_single_term_clause().parse(tokens).unwrap();
            assert_eq!(res, expected);
        }
    }

    #[test]
    fn test_parse_multiple_terms_clause() {
        init_test_logging();

        let mac_addr = MacAddr::from([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]);
        let mac_val = "ab-cd-ef-01-23-45".to_string();
        let regex_matcher: RegexMatcher = Regex::new("string").unwrap().into();
        let ip: IpNet = "192.168.1.1/32".parse().unwrap();

        let cases = [
            vec![Token::LitVlanId, Token::Equal, Token::Value("1".into())],
            vec![
                Token::LitVlanId,
                Token::In,
                Token::OpenBrace,
                Token::Value("1".into()),
                Token::CloseBrace,
            ],
            vec![Token::LitPort, Token::Equal, Token::Value("1".into())],
            vec![
                Token::LitPort,
                Token::In,
                Token::OpenBrace,
                Token::Value("1".into()),
                Token::CloseBrace,
            ],
            vec![Token::LitPortDst, Token::Equal, Token::Value("1".into())],
            vec![
                Token::LitPortDst,
                Token::In,
                Token::OpenBrace,
                Token::Value("1".into()),
                Token::CloseBrace,
            ],
            vec![Token::LitPortSrc, Token::Equal, Token::Value("1".into())],
            vec![
                Token::LitPortSrc,
                Token::In,
                Token::OpenBrace,
                Token::Value("1".into()),
                Token::CloseBrace,
            ],
            vec![
                Token::LitEthAddr,
                Token::Equal,
                Token::Value(mac_val.clone()),
            ],
            vec![
                Token::LitEthAddr,
                Token::In,
                Token::OpenBrace,
                Token::Value(mac_val.clone()),
                Token::CloseBrace,
            ],
            vec![
                Token::LitEthAddr,
                Token::Contains,
                Token::Value("00:11".into()),
            ],
            vec![
                Token::LitEthAddr,
                Token::RegexMatch,
                Token::QuotedValue("string".into()),
            ],
            vec![
                Token::LitEthDst,
                Token::Equal,
                Token::Value(mac_val.clone()),
            ],
            vec![
                Token::LitEthDst,
                Token::In,
                Token::OpenBrace,
                Token::Value(mac_val.clone()),
                Token::CloseBrace,
            ],
            vec![
                Token::LitEthDst,
                Token::Contains,
                Token::Value("00:11".into()),
            ],
            vec![
                Token::LitEthDst,
                Token::RegexMatch,
                Token::QuotedValue("string".into()),
            ],
            vec![
                Token::LitEthSrc,
                Token::Equal,
                Token::Value(mac_val.clone()),
            ],
            vec![
                Token::LitEthSrc,
                Token::In,
                Token::OpenBrace,
                Token::Value(mac_val),
                Token::CloseBrace,
            ],
            vec![
                Token::LitEthSrc,
                Token::Contains,
                Token::Value("00:11".into()),
            ],
            vec![
                Token::LitEthSrc,
                Token::RegexMatch,
                Token::QuotedValue("string".into()),
            ],
            vec![
                Token::LitIpAddr,
                Token::Equal,
                Token::Value("192.168.1.1".into()),
            ],
            vec![
                Token::LitIpAddr,
                Token::In,
                Token::OpenBrace,
                Token::Value("192.168.1.1".into()),
                Token::CloseBrace,
            ],
            vec![
                Token::LitIpDst,
                Token::Equal,
                Token::Value("192.168.1.1".into()),
            ],
            vec![
                Token::LitIpDst,
                Token::In,
                Token::OpenBrace,
                Token::Value("192.168.1.1".into()),
                Token::CloseBrace,
            ],
            vec![
                Token::LitIpSrc,
                Token::Equal,
                Token::Value("192.168.1.1".into()),
            ],
            vec![
                Token::LitIpSrc,
                Token::In,
                Token::OpenBrace,
                Token::Value("192.168.1.1".into()),
                Token::CloseBrace,
            ],
            vec![
                Token::LitPayload,
                Token::Contains,
                Token::Value("00:11".into()),
            ],
            vec![
                Token::LitPayload,
                Token::RegexMatch,
                Token::QuotedValue("string".into()),
            ],
            vec![Token::LitPayloadLen, Token::Equal, Token::Value("1".into())],
        ];
        let expected_results = [
            Clause::VlanId(ValOp::compare(CmpOp::Equal, 1)),
            Clause::VlanId(ValOp::match_any(vec![1])),
            Clause::Port(ValOp::compare(CmpOp::Equal, 1)),
            Clause::Port(ValOp::match_any(vec![1])),
            Clause::PortDst(ValOp::compare(CmpOp::Equal, 1)),
            Clause::PortDst(ValOp::match_any(vec![1])),
            Clause::PortSrc(ValOp::compare(CmpOp::Equal, 1)),
            Clause::PortSrc(ValOp::match_any(vec![1])),
            Clause::EthAddr(EthOp::compare(CmpOp::Equal, mac_addr)),
            Clause::EthAddr(EthOp::match_any(vec![mac_addr])),
            Clause::EthAddr(EthOp::contains(vec![0x00, 0x11])),
            Clause::EthAddr(EthOp::regex_match(regex_matcher.clone())),
            Clause::EthDst(EthOp::compare(CmpOp::Equal, mac_addr)),
            Clause::EthDst(EthOp::match_any(vec![mac_addr])),
            Clause::EthDst(EthOp::contains(vec![0x00, 0x11])),
            Clause::EthDst(EthOp::regex_match(regex_matcher.clone())),
            Clause::EthSrc(EthOp::compare(CmpOp::Equal, mac_addr)),
            Clause::EthSrc(EthOp::match_any(vec![mac_addr])),
            Clause::EthSrc(EthOp::contains(vec![0x00, 0x11])),
            Clause::EthSrc(EthOp::regex_match(regex_matcher.clone())),
            Clause::IpAddr(IpOp::compare(CmpOp::Equal, ip)),
            Clause::IpAddr(IpOp::match_any(vec![ip])),
            Clause::IpDst(IpOp::compare(CmpOp::Equal, ip)),
            Clause::IpDst(IpOp::match_any(vec![ip])),
            Clause::IpSrc(IpOp::compare(CmpOp::Equal, ip)),
            Clause::IpSrc(IpOp::match_any(vec![ip])),
            Clause::Payload(PayloadOp::contains(vec![0x00, 0x11])),
            Clause::Payload(PayloadOp::regex_match(regex_matcher)),
            Clause::PayloadLen(PayloadLenOp::compare(CmpOp::Equal, 1)),
        ];

        for (tokens, expected) in cases.into_iter().zip(expected_results) {
            info!("Parsing {tokens:?} as multiple term clause - should succeed");
            let res = parse_multiple_terms_clause().parse(&tokens).unwrap();
            assert_eq!(res, expected);
            let res = expression_parser().parse(&tokens).unwrap().0;
            assert_eq!(res, expected.into());
        }
    }

    #[test]
    fn test_parse_complex_statement_01() {
        use Token::*;

        init_test_logging();

        let tokens = [
            LitVlan,
            And,
            OpenParen,
            LitVlanId,
            In,
            OpenBrace,
            Value("1".into()),
            Comma,
            Value("2".into()),
            CloseBrace,
            Or,
            LitIpAddr,
            Equal,
            Value("10.1.0.0/16".into()),
            CloseParen,
            And,
            Not,
            LitUdp,
        ];
        let expected = Expression::And(vec![
            Clause::IsVlan.into(),
            Expression::Or(vec![
                Clause::VlanId(ValOp::match_any(vec![1, 2])).into(),
                Clause::IpAddr(IpOp::compare(CmpOp::Equal, "10.1.0.0/16".parse().unwrap())).into(),
            ]),
            Expression::not(Clause::IsUdp),
        ]);

        info!("Validating parse of {tokens:?} as an expression {expected:?}");
        let expr = expression_parser().parse(&tokens).unwrap().0;
        assert_eq!(expr, expected);
    }

    #[test]
    fn test_parse_complex_statement_02() {
        use Token::*;

        init_test_logging();
        let ip: IpNet = "10.1.0.0/16".parse().unwrap();
        let mac1 = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mac2 = MacAddr::from([0x55, 0x44, 0x33, 0x22, 0x11, 0x00]);
        let tokens = [
            OpenParen,
            LitVlan,
            Or,
            OpenParen,
            LitEthAddr,
            In,
            OpenBrace,
            Value("00:11:22:33:44:55".into()),
            Comma,
            Value("55:44:33:22:11:00".into()),
            CloseBrace,
            And,
            LitIpAddr,
            Equal,
            Value("10.1.0.0/16".into()),
            And,
            Not,
            LitUdp,
            CloseParen,
            CloseParen,
        ];
        let expected = Expression::Or(vec![
            Clause::IsVlan.into(),
            Expression::And(vec![
                Clause::EthAddr(EthOp::match_any(vec![mac1, mac2])).into(),
                Clause::IpAddr(IpOp::compare(CmpOp::Equal, ip)).into(),
                Expression::not(Clause::IsUdp),
            ]),
        ]);

        info!("Validating parse of {tokens:?} as an expression {expected:?}");
        let expr = expression_parser().parse(&tokens).unwrap().0;
        assert_eq!(expr, expected);
    }

    #[test]
    fn test_parse_complex_statement_03() {
        use Token::*;

        init_test_logging();
        let ip: IpNet = "10.1.0.0/16".parse().unwrap();
        let regex: RegexMatcher = Regex::new("something").unwrap().into();
        let tokens = [
            Not,
            OpenParen,
            LitEthAddr,
            RegexMatch,
            QuotedValue("something".into()),
            And,
            LitIpAddr,
            Equal,
            Value("10.1.0.0/16".into()),
            CloseParen,
        ];
        let expected = Expression::not(Expression::And(vec![
            Clause::EthAddr(EthOp::regex_match(regex)).into(),
            Clause::IpAddr(IpOp::compare(CmpOp::Equal, ip)).into(),
        ]));

        info!("Validating parse of {tokens:?} as an expression {expected:?}");
        let expr = expression_parser().parse(&tokens).unwrap().0;
        assert_eq!(expr, expected);
    }

    #[test]
    fn test_parse_complex_statement_04() {
        use Token::*;

        init_test_logging();
        let regex1: RegexMatcher = Regex::new("something").unwrap().into();
        let regex2: RegexMatcher = Regex::new("else").unwrap().into();
        let regex3: RegexMatcher = Regex::new("last").unwrap().into();
        let tokens = [
            LitPayload,
            RegexMatch,
            QuotedValue("something".into()),
            And,
            Not,
            LitPayload,
            RegexMatch,
            QuotedValue("else".into()),
            And,
            LitPayload,
            RegexMatch,
            QuotedValue("last".into()),
        ];
        let expected = Expression::And(vec![
            Clause::Payload(PayloadOp::regex_match(regex1)).into(),
            Expression::not(Clause::Payload(PayloadOp::regex_match(regex2))),
            Clause::Payload(PayloadOp::regex_match(regex3)).into(),
        ]);

        info!("Validating parse of {tokens:?} as an expression {expected:?}");
        let expr = expression_parser().parse(&tokens).unwrap().0;
        assert_eq!(expr, expected);
    }
}
