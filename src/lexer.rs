use chumsky::{
    prelude::*,
    text::keyword,
};
use std::hash::Hash;

#[derive(Debug, PartialEq)]
pub struct Spanned<T>(pub T, pub SimpleSpan<usize>);

/// Tokens for each clause/expression.
/// The syntax attempts to be very sparse, and match the syntax to the tshark filter expression
/// that is already familiar
#[derive(Clone, Debug, PartialEq, Eq, Hash, derive_more::Display)]
pub enum Token {
    /// Literal `tcp`
    #[display(fmt = "tcp")]
    LitTcp,
    /// Literal `udp`
    #[display(fmt = "udp")]
    LitUdp,
    /// Literal `vlan`
    #[display(fmt = "vlan")]
    LitVlan,
    /// Literal `eth.addr`
    #[display(fmt = "eth.addr")]
    LitEthAddr,
    /// Literal `eth.dst`
    #[display(fmt = "eth.dst")]
    LitEthDst,
    /// Literal `eth.src`
    #[display(fmt = "eth.src")]
    LitEthSrc,
    /// Literal `ip.addr`
    #[display(fmt = "ip.addr")]
    LitIpAddr,
    /// Literal `ip.dst`
    #[display(fmt = "ip.dst")]
    LitIpDst,
    /// Literal `ip.src`
    #[display(fmt = "ip.src")]
    LitIpSrc,
    /// Literal `vlan.id`
    #[display(fmt = "vlan.id")]
    LitVlanId,
    /// Literal `port`
    #[display(fmt = "port")]
    LitPort,
    /// Literal `dstport`
    #[display(fmt = "dstport")]
    LitPortDst,
    /// Literal `srcport`
    #[display(fmt = "srcport")]
    LitPortSrc,
    /// Literal `payload`
    #[display(fmt = "payload")]
    LitPayload,
    /// Literal `payload.len`
    #[display(fmt = "payload.len")]
    LitPayloadLen,
    /// `,`
    #[display(fmt = ",")]
    Comma,
    /// `not` or `!`
    #[display(fmt = "not")]
    Not,
    /// `or` or `||`
    #[display(fmt = "or")]
    Or,
    /// `and` or `&&`
    #[display(fmt = "and")]
    And,
    /// `in`
    #[display(fmt = "in")]
    In,
    /// `contains`
    #[display(fmt = "contains")]
    Contains,
    /// `~` or `matches` for regex matching
    #[display(fmt = "matches")]
    RegexMatch,
    /// `==` or `eq`
    #[display(fmt = "eq")]
    Equal,
    /// `!=` or `ne`
    #[display(fmt = "ne")]
    NotEqual,
    /// `<` or `lt`
    #[display(fmt = "lt")]
    LessThan,
    /// `<=` or `le`
    #[display(fmt = "le")]
    LessEqual,
    /// `>` or `gt`
    #[display(fmt = "gt")]
    GreaterThan,
    /// `>=` or `ge`
    #[display(fmt = "ge")]
    GreaterEqual,
    /// `(`
    #[display(fmt = "(")]
    OpenParen,
    /// `)`
    #[display(fmt = ")")]
    CloseParen,
    /// `{`
    #[display(fmt = "{{")]
    OpenBrace,
    /// `}`
    #[display(fmt = "}}")]
    CloseBrace,
    /// A value
    #[display(fmt = "{_0}")]
    Value(String),
    /// A quoted value, either with "" or ''
    #[display(fmt = "\"{_0}\"")]
    QuotedValue(String),
    /// For good errors, it's better to lex everything and handle failure at parsing.
    #[display(fmt = "{_0}")]
    Error(String),
}

/// A parser that accepts an unquoted string that can be a key or a value.
/// The regex pattern for it is `[a-zA-Z0-9_.-:/]*`.
///
/// Returns: The token that was parsed
fn key_or_value_parser<'src>() -> impl Parser<'src, &'src str, Token> {
    any()
        .filter(|c: &char| c.is_ascii_alphanumeric() || ['_', '.', '-', ':', '/'].contains(c))
        .repeated()
        .at_least(1)
        .collect()
        .map(|key: String| match key.as_str() {
            "tcp" => Token::LitTcp,
            "udp" => Token::LitUdp,
            "vlan" => Token::LitVlan,
            "eth.addr" => Token::LitEthAddr,
            "eth.dst" => Token::LitEthDst,
            "eth.src" => Token::LitEthSrc,
            "ip.addr" => Token::LitIpAddr,
            "ip.dst" => Token::LitIpDst,
            "ip.src" => Token::LitIpSrc,
            "vlan.id" => Token::LitVlanId,
            "port" => Token::LitPort,
            "dstport" => Token::LitPortDst,
            "srcport" => Token::LitPortSrc,
            "payload" => Token::LitPayload,
            "payload.len" => Token::LitPayloadLen,
            _ => Token::Value(key),
        })
}

/// A parser to extract a quoted string.
///
/// Either ' or " can be used as the quote character.
///
/// Returns: The quoted string without the quotes.
fn string_parser<'src>(delimiter: char) -> impl Parser<'src, &'src str, String> {
    // map escaped quote to just quote
    let escape = just(format!("\\{delimiter}")).to(delimiter);
    none_of(delimiter)
        .and_is(escape.clone().not())
        .or(escape)
        .repeated()
        .collect()
        .padded_by(just(delimiter))
}

/// Lex a selector expression string into tokens
/// The lexer is composed of multiple little parsers stitched together
pub(crate) fn lexer<'src>() -> impl Parser<'src, &'src str, Vec<Spanned<Token>>> {
    // The `.map(|_| ())` below is necessary to match the output value of `just` to the output
    // value of `keyword`
    let comma = just(",");
    let less_equal = keyword("le").or(just("<="));
    let less_than = keyword("lt").or(just("<"));
    let greater_equal = keyword("ge").or(just(">="));
    let greater_than = keyword("gt").or(just(">"));
    let equal = keyword("eq").or(just("=="));
    let not_equal = keyword("ne").or(just("!="));
    let not = keyword("not").or(just("!"));
    let or = keyword("or").or(just("||"));
    let and = keyword("and").or(just("&&"));
    let in_ = keyword("in");
    let contains = keyword("contains");
    let regex_match = keyword("matches").or(just("~"));
    let open_paren = just('(');
    let close_paren = just(')');
    let open_brace = just('{');
    let close_brace = just('}');
    // A parser for string values, e.g. 'some value'
    let quoted_val1 = string_parser('"');
    // A parser for string values, e.g. "some value"
    let quoted_val2 = string_parser('\'');
    // A parser for keys or unquoted values
    let key_or_val = key_or_value_parser();
    // Anything else is error.
    // Also, if we get one error, it will have the rest of the data to the end.
    let error = any().repeated().at_least(1).collect();

    // A single token can be one of the above
    // Order matters, since if we start to match and fail we will not continue to the next
    // mini parser
    let token = choice((
        comma.to(Token::Comma),
        less_equal.to(Token::LessEqual),
        less_than.to(Token::LessThan),
        greater_equal.to(Token::GreaterEqual),
        greater_than.to(Token::GreaterThan),
        equal.to(Token::Equal),
        not_equal.to(Token::NotEqual),
        not.to(Token::Not),
        or.to(Token::Or),
        and.to(Token::And),
        in_.to(Token::In),
        contains.to(Token::Contains),
        regex_match.to(Token::RegexMatch),
        open_paren.to(Token::OpenParen),
        close_paren.to(Token::CloseParen),
        open_brace.to(Token::OpenBrace),
        close_brace.to(Token::CloseBrace),
        quoted_val1.map(Token::QuotedValue),
        quoted_val2.map(Token::QuotedValue),
        key_or_val,
        error.map(Token::Error),
    ));

    token
        // Add span information
        .map_with_span(Spanned)
        // Ignore whitespace around tokens
        .padded()
        // Take as many as there are
        .repeated()
        // Collect into a vector
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        lexer,
        string_parser,
        Token,
    };
    use crate::test_utils::init_test_logging;
    use chumsky::Parser;
    use tracing::info;

    #[test]
    fn test_quoted_string_parsing() {
        init_test_logging();

        let cases = [
            ('\'', "'test'", "test"),
            ('"', r#""test""#, "test"),
            ('"', r#""two \\ backslashes""#, r"two \\ backslashes"),
            ('"', r#""one \" quote""#, "one \" quote"),
            ('\'', r#"'one \" quote'"#, r#"one \" quote"#),
            ('\'', r"'one \' quote'", "one \' quote"),
        ];
        for (delimiter, expr, expected) in cases {
            info!("Parsing escaped string with delimiter {delimiter}: {expr} --> {expected}");
            let res = string_parser(delimiter).parse(expr).unwrap();
            assert_eq!(res, expected);
        }
    }

    /// Parse an expression, assume success, and strip the resulting tokens of their spans,
    /// for easier testing
    fn lex_tokens_only(expression: &str) -> Vec<Token> {
        lexer()
            .parse(expression)
            .unwrap()
            .into_iter()
            .map(|st| st.0)
            .collect()
    }

    #[test]
    fn test_lex_empty_expression() {
        init_test_logging();

        let tokens = lex_tokens_only("");
        assert_eq!(tokens, Vec::new());
    }

    #[test]
    fn test_lex_single_clause() {
        use Token::*;
        init_test_logging();

        let expressions = [
            "tcp",
            "udp",
            "vlan",
            "eth.addr == 00-B0-D0-63-C2-26",
            "eth.src == 00-B0-D0-63-C2-26",
            "eth.dst == 00-B0-D0-63-C2-26",
            "ip.addr == 1.2.3.4",
            "ip.src == 1.2.3.4",
            "ip.dst == 1.2.3.4",
            "vlan.id == 12",
            "port == 80",
            "srcport == 80",
            "dstport == 80",
            "payload contains '00'",
            "payload.len == 16",
        ];
        let tokens = [
            vec![LitTcp],
            vec![LitUdp],
            vec![LitVlan],
            vec![LitEthAddr, Equal, Value("00-B0-D0-63-C2-26".into())],
            vec![LitEthSrc, Equal, Value("00-B0-D0-63-C2-26".into())],
            vec![LitEthDst, Equal, Value("00-B0-D0-63-C2-26".into())],
            vec![LitIpAddr, Equal, Value("1.2.3.4".into())],
            vec![LitIpSrc, Equal, Value("1.2.3.4".into())],
            vec![LitIpDst, Equal, Value("1.2.3.4".into())],
            vec![LitVlanId, Equal, Value("12".into())],
            vec![LitPort, Equal, Value("80".into())],
            vec![LitPortSrc, Equal, Value("80".into())],
            vec![LitPortDst, Equal, Value("80".into())],
            vec![LitPayload, Contains, QuotedValue("00".into())],
            vec![LitPayloadLen, Equal, Value("16".into())],
        ];

        for (expression, expected_tokens) in expressions.into_iter().zip(tokens) {
            info!("Lexing expression \"{expression}\"");
            let tokens: Vec<Token> = lex_tokens_only(expression);
            assert_eq!(tokens, expected_tokens);
        }
    }

    #[test]
    fn test_lex_comparison_operations() {
        use Token::*;
        init_test_logging();

        let expressions = [
            "ip.addr == 1.2.3.4/32",
            "ip.addr eq 1.2.3.4/32",
            "ip.addr != 1.2.3.4/32",
            "ip.addr ne 1.2.3.4/32",
            "ip.addr > 1.2.3.4/32",
            "ip.addr gt 1.2.3.4/32",
            "ip.addr >= 1.2.3.4/32",
            "ip.addr ge 1.2.3.4/32",
            "ip.addr < 1.2.3.4/32",
            "ip.addr lt 1.2.3.4/32",
            "ip.addr <= 1.2.3.4/32",
            "ip.addr le 1.2.3.4/32",
        ];
        let tokens = [
            vec![LitIpAddr, Equal, Value("1.2.3.4/32".into())],
            vec![LitIpAddr, Equal, Value("1.2.3.4/32".into())],
            vec![LitIpAddr, NotEqual, Value("1.2.3.4/32".into())],
            vec![LitIpAddr, NotEqual, Value("1.2.3.4/32".into())],
            vec![LitIpAddr, GreaterThan, Value("1.2.3.4/32".into())],
            vec![LitIpAddr, GreaterThan, Value("1.2.3.4/32".into())],
            vec![LitIpAddr, GreaterEqual, Value("1.2.3.4/32".into())],
            vec![LitIpAddr, GreaterEqual, Value("1.2.3.4/32".into())],
            vec![LitIpAddr, LessThan, Value("1.2.3.4/32".into())],
            vec![LitIpAddr, LessThan, Value("1.2.3.4/32".into())],
            vec![LitIpAddr, LessEqual, Value("1.2.3.4/32".into())],
            vec![LitIpAddr, LessEqual, Value("1.2.3.4/32".into())],
        ];

        for (expression, expected_tokens) in expressions.into_iter().zip(tokens) {
            info!("Lexing expression \"{expression}\"");
            let tokens: Vec<Token> = lex_tokens_only(expression);
            assert_eq!(tokens, expected_tokens);
        }
    }

    #[test]
    fn test_lex_set_operations() {
        use Token::*;
        init_test_logging();

        let expressions = [
            "srcport in { 22 , 80 }",
            "ip.src in {192.168.1.0/24}",
            "ip.dst in {192.168.3.1, 10.0.0.0/8}",
            "ip.src in{192.168.1.0/24}",
            "ip.dst in{192.168.3.1,10.0.0.0/8}",
        ];
        let tokens = [
            vec![
                LitPortSrc,
                In,
                OpenBrace,
                Value("22".into()),
                Comma,
                Value("80".into()),
                CloseBrace,
            ],
            vec![
                LitIpSrc,
                In,
                OpenBrace,
                Value("192.168.1.0/24".into()),
                CloseBrace,
            ],
            vec![
                LitIpDst,
                In,
                OpenBrace,
                Value("192.168.3.1".into()),
                Comma,
                Value("10.0.0.0/8".into()),
                CloseBrace,
            ],
            vec![
                LitIpSrc,
                In,
                OpenBrace,
                Value("192.168.1.0/24".into()),
                CloseBrace,
            ],
            vec![
                LitIpDst,
                In,
                OpenBrace,
                Value("192.168.3.1".into()),
                Comma,
                Value("10.0.0.0/8".into()),
                CloseBrace,
            ],
        ];

        for (expression, expected_tokens) in expressions.into_iter().zip(tokens) {
            info!("Lexing expression \"{expression}\"");
            let tokens: Vec<Token> = lex_tokens_only(expression);
            assert_eq!(tokens, expected_tokens);
        }
    }

    #[test]
    fn test_lex_multiple_clauses() {
        use Token::*;
        init_test_logging();

        let expressions = [
            "not tcp and (ip.src == 10.10.0.0/16 or (dstport > 80 and dstport <= 100))",
            "!tcp && (ip.src == 10.10.0.0/16 || (dstport > 80 && dstport <= 100))",
            "!tcp&&(ip.src==10.10.0.0/16||(dstport>80&&dstport<=100))",
        ];
        let expected = [
            Not,
            LitTcp,
            And,
            OpenParen,
            LitIpSrc,
            Equal,
            Value("10.10.0.0/16".into()),
            Or,
            OpenParen,
            LitPortDst,
            GreaterThan,
            Value("80".into()),
            And,
            LitPortDst,
            LessEqual,
            Value("100".into()),
            CloseParen,
            CloseParen,
        ];
        for expression in expressions {
            info!("Lexing expression \"{expression}\"");
            let tokens: Vec<Token> = lex_tokens_only(expression);
            assert_eq!(tokens, expected);
        }
    }

    #[test]
    fn test_lex_real_life_examples() {
        use Token::*;
        init_test_logging();

        let expressions = [
            r#"payload ~ "\r\n\x45\xdb""#,
            r#"payload ~ "GET /(secret|password)""#,
            r#"payload ~ "[[:ascii:]]{100}""#,
            r#"payload matches ".*Philips\\.HIF.*""#,
            "port <= 0x16",
            "port <= 0b1100_1100",
        ];
        let tokens = [
            vec![
                LitPayload,
                RegexMatch,
                QuotedValue("\\r\\n\\x45\\xdb".into()),
            ],
            vec![
                LitPayload,
                RegexMatch,
                QuotedValue("GET /(secret|password)".into()),
            ],
            vec![
                LitPayload,
                RegexMatch,
                QuotedValue("[[:ascii:]]{100}".into()),
            ],
            vec![
                LitPayload,
                RegexMatch,
                QuotedValue(".*Philips\\\\.HIF.*".into()),
            ],
            vec![LitPort, LessEqual, Value("0x16".into())],
            vec![LitPort, LessEqual, Value("0b1100_1100".into())],
        ];
        for (expression, expected_tokens) in expressions.into_iter().zip(tokens) {
            info!("Lexing expression \"{expression}\"");
            let tokens: Vec<Token> = lex_tokens_only(expression);
            assert_eq!(tokens, expected_tokens);
        }
    }

    #[test]
    fn test_lex_no_whitespace() {
        init_test_logging();

        let expression = "eth.addr==00-B0-D0-63-C2-26";
        let expected = [
            Token::LitEthAddr,
            Token::Equal,
            Token::Value("00-B0-D0-63-C2-26".into()),
        ];
        info!("Lexing expression \"{expression}\"");
        let tokens: Vec<Token> = lex_tokens_only(expression);
        assert_eq!(tokens, expected);
    }

    #[test]
    fn test_lex_contains() {
        init_test_logging();

        let expressions = [
            "payload contains 00:11:22:33",
            "payload contains    00:11:22:33   ",
        ];
        let expected = [
            Token::LitPayload,
            Token::Contains,
            Token::Value("00:11:22:33".into()),
        ];
        for expression in expressions {
            info!("Lexing expression \"{expression}\"");
            let tokens: Vec<Token> = lex_tokens_only(expression);
            assert_eq!(tokens, expected);
        }
    }

    #[test]
    fn test_lex_matches() {
        init_test_logging();

        let expressions = [
            "payload ~ '^something[0-9]+'",
            "payload matches '^something[0-9]+'",
        ];
        let expected = [
            Token::LitPayload,
            Token::RegexMatch,
            Token::QuotedValue("^something[0-9]+".into()),
        ];
        for expression in expressions {
            info!("Lexing expression \"{expression}\"");
            let tokens: Vec<Token> = lex_tokens_only(expression);
            assert_eq!(tokens, expected);
        }
    }

    // Everything will pass lexing
    #[test]
    fn test_lex_nonsensical_expressions() {
        init_test_logging();

        let expressions = ["om nom nom", "'boo'((boom-------", "==)('')"];
        let result = [
            vec![
                Token::Value("om".into()),
                Token::Value("nom".into()),
                Token::Value("nom".into()),
            ],
            vec![
                Token::QuotedValue("boo".into()),
                Token::OpenParen,
                Token::OpenParen,
                Token::Value("boom-------".into()),
            ],
            vec![
                Token::Equal,
                Token::CloseParen,
                Token::OpenParen,
                Token::QuotedValue("".into()),
                Token::CloseParen,
            ],
        ];
        for (expression, expected) in expressions.into_iter().zip(result) {
            info!("Lexing expression \"{expression}\"");
            let tokens: Vec<Token> = lex_tokens_only(expression);
            assert_eq!(tokens, expected);
        }
    }

    // But some as error token
    #[test]
    fn test_lex_errors() {
        init_test_logging();

        let expressions = ["om =nom", "'", "\"", "^", "%"];
        let result = [
            vec![Token::Value("om".into()), Token::Error("=nom".into())],
            vec![Token::Error("'".into())],
            vec![Token::Error("\"".into())],
            vec![Token::Error("^".into())],
            vec![Token::Error("%".into())],
        ];
        for (expression, expected) in expressions.into_iter().zip(result) {
            info!("Lexing expression \"{expression}\"");
            let tokens: Vec<Token> = lex_tokens_only(expression);
            assert_eq!(tokens, expected);
        }
    }

    // The only case where lexing fails
    #[test]
    fn test_lex_only_failure() {
        init_test_logging();

        let expressions = ["  ", "\t", "\r\n", "\n"];
        for expression in expressions {
            info!("Lexing expression \"{expression}\"");
            let res = lexer().parse(expression);
            assert!(res.has_errors());
        }
    }
}
