//! This is the main driver of the wireshark-like filter expression creator.
//! It manages the following phases, in order:
//! * Lex the filter expression string into a set of tokens, or return the lexing error.
//! * Parse the list of tokens into an Expression object, or return the parsing error.
//! * For errors, try to figure out the root and to present it in a human friendly manner.
use crate::{
    Expression,
    input::Input,
    lexer::{
        Lexer,
        Token,
        TokenKind,
    },
    parser::Parser,
};

/// What we expected to find where we found the error
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expected {
    TokenKind(TokenKind),
    Label(String),
}

impl Expected {
    pub(crate) fn token_kind(kind: TokenKind) -> Self {
        Self::TokenKind(kind)
    }

    pub(crate) fn label(val: impl Into<String>) -> Self {
        Self::Label(val.into())
    }
}

/// That which were found instead
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Found(Token);

#[derive(Debug, Clone, PartialEq, Eq, derive_more::Constructor)]
pub(crate) struct ValParse {
    pub(crate) token: Token,
    pub(crate) err: String,
}

/// Hold the type of error we might encounter while parsing
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    InputTooLong,
    ExpectedFound(Expected, Found),
    ValParse(ValParse),
}

impl ErrorKind {
    pub(crate) fn unexpected(expected: Expected, found: Token) -> Self {
        Self::ExpectedFound(expected, Found(found))
    }

    pub(crate) fn parse(token: Token, err: impl Into<String>) -> Self {
        Self::ValParse(ValParse::new(token, err.into()))
    }
}

/// The error returned when lexing/parsing fails
#[derive(Debug, Clone)]
pub struct ParseError {
    input: String,
    kind: ErrorKind,
}

impl std::error::Error for ParseError {}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "error: {}", self.message())?;
        writeln!(f, "filter: \"{}\"", &self.input)?;
        let span = self.error_span();
        let start = usize::from(span.0);
        let end = usize::from(span.1);
        let prefix_len = 9;
        let indentation = " ".repeat(start + prefix_len);
        let err_pointer = "^".repeat(end - start);
        writeln!(f, "{indentation}{err_pointer}")
    }
}

impl ParseError {
    pub(crate) fn new(input: String, kind: ErrorKind) -> Self {
        Self { input, kind }
    }

    /// The filter expression
    pub fn input(&self) -> &str {
        &self.input
    }

    /// The error message
    pub fn message(&self) -> String {
        match &self.kind {
            ErrorKind::InputTooLong => {
                format!(
                    "filter is too long. size: {}, max allowed: {}",
                    self.input.len(),
                    u16::MAX
                )
            }
            ErrorKind::ExpectedFound(expected, found) => {
                let found_str = match found.0.kind == TokenKind::EoF {
                    true => String::from("end of input"),
                    false => {
                        let start = usize::from(found.0.start);
                        let end = usize::from(found.0.end);
                        format!("\"{}\"", &self.input[start..end])
                    }
                };
                match expected {
                    Expected::TokenKind(tk) => {
                        format!("expected {tk} found {found_str}")
                    }
                    Expected::Label(label) => {
                        format!("expected {label} found {found_str}")
                    }
                }
            }
            ErrorKind::ValParse(value_parse) => {
                let start = usize::from(value_parse.token.start);
                let end = usize::from(value_parse.token.end);
                let found_str = &self.input[start..end];
                format!("could not parse \"{found_str}\". {}", value_parse.err)
            }
        }
    }

    /// Return where in the input the error occurred
    pub fn error_span(&self) -> (u16, u16) {
        match &self.kind {
            ErrorKind::InputTooLong => (u16::MAX, u16::MAX),
            ErrorKind::ExpectedFound(_, f) => (f.0.start, f.0.end),
            ErrorKind::ValParse(v) => (v.token.start, v.token.end),
        }
    }
}

/// Parse a filter expression into a `Expression`
pub fn parse(filter_expr: &str) -> Result<Expression, ParseError> {
    let input = Input::new(filter_expr).map_err(|ek| ParseError::new(filter_expr.into(), ek))?;
    let tokens = Lexer::new(input).lex();
    Parser::new(input, tokens)
        .parse()
        .map_err(|ek| ParseError::new(filter_expr.into(), ek))
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::{
        Expression,
        driver::ErrorKind,
        expression::{
            Clause,
            CmpOp,
            EthOp,
            IpOp,
            PayloadLenOp,
            PayloadOp,
            ValOp,
        },
        mac_addr::MacAddr,
        test_utils::init_test_logging,
    };
    use regex::bytes::Regex;
    use tracing::info;

    #[test]
    fn test_simple_expression_e2e() {
        init_test_logging();

        let inputs = [
            "tcp",
            "not udp",
            "not udp and (not tcp or vlan)",
            "port eq 25 or udp",
            "eth.addr contains 00:06:5B",
            "ip.addr == 10.43.54.65",
            "ip.src == 10.43.54.65 or ip.dst == 10.43.54.65",
            "! ( ip.addr == 10.43.54.65 )",
            "srcport in {8011, 8012, 8013} and tcp",
            "port in {8011, 8012, 8013} and tcp and payload contains 'MSH'",
            "payload matches \"(?i)Workflowrx\"",
            "eth.src == 00:10:9b:3a:53:fc or eth.dst == 00:10:9b:3a:53:fc",
            "ip.src != 192.168.0.1",
            "ip.dst == 2606:4700:4700::1111",
            "ip.dst >= 173.245.48.0 && ip.dst < 173.245.49.0",
            "ip.addr in {192.168.1.0/24}",
            "ip.dst in {192.168.3.1, 10.0.0.0/8}",
            "srcport < 1024",
            "payload.len > 50 and payload.len < 500",
            "payload matches \"GET /secret\"",
            r"payload ~ '\r\n\x45\xdb'",
            r#"payload ~ "[[:ascii:]]{100}""#,
            r#"payload ~ "^\x00BOOM\x00""#,
            "ip.src == 192.168.1.7 || ip.dst == 1.2.3.4 && (srcport == 9 || dstport == 9)",
            "payload contains 'something'",
            "eth.src == 3f:43:9a:2c:00:00 or eth.dst contains 2c:9a:bb",
        ];
        let expected_results = [
            Clause::IsTcp.into(),
            Expression::not(Clause::IsUdp),
            Expression::And(vec![
                Expression::not(Clause::IsUdp),
                Expression::Or(vec![Expression::not(Clause::IsTcp), Clause::IsVlan.into()]),
            ]),
            Expression::Or(vec![
                Clause::Port(ValOp::compare(CmpOp::Equal, 25)).into(),
                Clause::IsUdp.into(),
            ]),
            Clause::EthAddr(EthOp::contains(vec![0x00, 0x06, 0x5b])).into(),
            Clause::IpAddr(IpOp::compare(
                CmpOp::Equal,
                "10.43.54.65/32".parse().unwrap(),
            ))
            .into(),
            Expression::Or(vec![
                Clause::IpSrc(IpOp::compare(
                    CmpOp::Equal,
                    "10.43.54.65/32".parse().unwrap(),
                ))
                .into(),
                Clause::IpDst(IpOp::compare(
                    CmpOp::Equal,
                    "10.43.54.65/32".parse().unwrap(),
                ))
                .into(),
            ]),
            Expression::not(Clause::IpAddr(IpOp::compare(
                CmpOp::Equal,
                "10.43.54.65/32".parse().unwrap(),
            ))),
            Expression::And(vec![
                Clause::PortSrc(ValOp::match_any(vec![8011, 8012, 8013])).into(),
                Clause::IsTcp.into(),
            ]),
            Expression::And(vec![
                Clause::Port(ValOp::match_any(vec![8011, 8012, 8013])).into(),
                Clause::IsTcp.into(),
                Clause::Payload(PayloadOp::contains(b"MSH".to_vec())).into(),
            ]),
            Clause::Payload(PayloadOp::regex_match(
                Regex::new("(?i)Workflowrx").unwrap().into(),
            ))
            .into(),
            Expression::Or(vec![
                Clause::EthSrc(EthOp::compare(
                    CmpOp::Equal,
                    MacAddr::try_from("00:10:9b:3a:53:fc".as_bytes()).unwrap(),
                ))
                .into(),
                Clause::EthDst(EthOp::compare(
                    CmpOp::Equal,
                    MacAddr::try_from("00:10:9b:3a:53:fc".as_bytes()).unwrap(),
                ))
                .into(),
            ]),
            Clause::IpSrc(IpOp::compare(
                CmpOp::NotEqual,
                "192.168.0.1/32".parse().unwrap(),
            ))
            .into(),
            Clause::IpDst(IpOp::compare(
                CmpOp::Equal,
                "2606:4700:4700::1111/128".parse().unwrap(),
            ))
            .into(),
            Expression::And(vec![
                Clause::IpDst(IpOp::compare(
                    CmpOp::GreaterEqual,
                    "173.245.48.0/32".parse().unwrap(),
                ))
                .into(),
                Clause::IpDst(IpOp::compare(
                    CmpOp::LessThan,
                    "173.245.49.0/32".parse().unwrap(),
                ))
                .into(),
            ]),
            Clause::IpAddr(IpOp::MatchAny(vec!["192.168.1.0/24".parse().unwrap()])).into(),
            Clause::IpDst(IpOp::MatchAny(vec![
                "192.168.3.1/32".parse().unwrap(),
                "10.0.0.0/8".parse().unwrap(),
            ]))
            .into(),
            Clause::PortSrc(ValOp::compare(CmpOp::LessThan, 1024)).into(),
            Expression::And(vec![
                Clause::PayloadLen(PayloadLenOp::compare(CmpOp::GreaterThan, 50)).into(),
                Clause::PayloadLen(PayloadLenOp::compare(CmpOp::LessThan, 500)).into(),
            ]),
            Clause::Payload(PayloadOp::regex_match(
                Regex::new("GET /secret").unwrap().into(),
            ))
            .into(),
            Clause::Payload(PayloadOp::regex_match(
                Regex::new(r"\r\n\x45\xdb").unwrap().into(),
            ))
            .into(),
            Clause::Payload(PayloadOp::regex_match(
                Regex::new("[[:ascii:]]{100}").unwrap().into(),
            ))
            .into(),
            Clause::Payload(PayloadOp::regex_match(
                Regex::new(r"^\x00BOOM\x00").unwrap().into(),
            ))
            .into(),
            Expression::And(vec![
                Expression::Or(vec![
                    Clause::IpSrc(IpOp::compare(
                        CmpOp::Equal,
                        "192.168.1.7/32".parse().unwrap(),
                    ))
                    .into(),
                    Clause::IpDst(IpOp::compare(CmpOp::Equal, "1.2.3.4/32".parse().unwrap()))
                        .into(),
                ]),
                Expression::Or(vec![
                    Clause::PortSrc(ValOp::compare(CmpOp::Equal, 9)).into(),
                    Clause::PortDst(ValOp::compare(CmpOp::Equal, 9)).into(),
                ]),
            ]),
            Clause::Payload(PayloadOp::contains(b"something".to_vec())).into(),
            Expression::Or(vec![
                Clause::EthSrc(EthOp::compare(
                    CmpOp::Equal,
                    MacAddr::try_from("3f:43:9a:2c:00:00".as_bytes()).unwrap(),
                ))
                .into(),
                Clause::EthDst(EthOp::contains(vec![0x2c, 0x9a, 0xbb])).into(),
            ]),
        ];
        for (input, expected) in inputs.into_iter().zip(expected_results) {
            info!("Parsing input \"{input}\"");
            let expr = parse(input).unwrap();
            assert_eq!(expr, expected);
        }
    }

    #[test]
    fn test_filter_too_long() {
        init_test_logging();

        let input = " ".repeat(usize::from(u16::MAX) + 1);
        let err = parse(&input).unwrap_err();

        assert_eq!(err.input(), input);
        assert_eq!(
            err.message(),
            "filter is too long. size: 65536, max allowed: 65535"
        );
        assert_eq!(err.error_span(), (u16::MAX, u16::MAX));
        assert_eq!(err.kind, ErrorKind::InputTooLong);
    }

    #[test]
    fn test_parse_error_empty_filter() {
        init_test_logging();

        let input = "";
        let err = parse(input).unwrap_err();

        assert_eq!(err.input(), input);

        let pretty_message = err.to_string();
        let lines: Vec<_> = pretty_message.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "error: expected an expression found end of input");
        assert_eq!(lines[1], r#"filter: """#);
        assert_eq!(lines[2], "         ");
    }

    #[test]
    fn test_parse_error_whitespace() {
        init_test_logging();

        let input = " ";
        let err = parse(input).unwrap_err();

        assert_eq!(err.input(), input);

        let pretty_message = err.to_string();
        let lines: Vec<_> = pretty_message.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "error: expected an expression found end of input");
        assert_eq!(lines[1], r#"filter: " ""#);
        assert_eq!(lines[2], "          ");
    }

    #[test]
    fn test_parse_error_bad_ip_val_01() {
        init_test_logging();

        let input = "ip.addr == &6645";
        let err = parse(input).unwrap_err();

        assert_eq!(err.input(), input);

        let pretty_message = err.to_string();
        let lines: Vec<_> = pretty_message.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "error: expected ip-address found \"&6645\"");
        assert_eq!(lines[1], r#"filter: "ip.addr == &6645""#);
        assert_eq!(lines[2], "                    ^^^^^");
    }

    #[test]
    fn test_parse_error_bad_ip_val_02() {
        init_test_logging();

        let input = "ip.addr == 6645";
        let err = parse(input).unwrap_err();

        assert_eq!(err.input(), input);

        let pretty_message = err.to_string();
        let lines: Vec<_> = pretty_message.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[0],
            "error: could not parse \"6645\". invalid IP address syntax"
        );
        assert_eq!(lines[1], r#"filter: "ip.addr == 6645""#);
        assert_eq!(lines[2], "                    ^^^^");
    }

    #[test]
    fn test_parse_error_bad_comparison_op() {
        init_test_logging();

        let input = "ip.addr === 6645";
        let err = parse(input).unwrap_err();

        assert_eq!(err.input(), input);
        assert_eq!(err.message(), "expected ip-address found \"= 6645\"");
    }

    #[test]
    fn test_parse_error_missing_closing_brace_ip() {
        init_test_logging();

        let input = "ip.addr in { 192.168.1.0/24";
        let err = parse(input).unwrap_err();

        assert_eq!(err.input(), input);
        assert_eq!(err.message(), "expected } found end of input");
    }

    #[test]
    fn test_parse_error_wrong_closing_brace_ip() {
        init_test_logging();

        let input = "ip.addr in { 192.168.1.0/24 )";
        let err = parse(input).unwrap_err();

        assert_eq!(err.input(), input);
        assert_eq!(err.message(), "expected } found \")\"");
    }

    #[test]
    fn test_parse_error_wrong_missing_brace_eth() {
        init_test_logging();

        let input = "eth.addr in { 10:20:30:40:50:60";
        let err = parse(input).unwrap_err();

        assert_eq!(err.input(), input);
        assert_eq!(err.message(), "expected } found end of input");
    }

    #[test]
    fn test_parse_error_bad_byte_string() {
        init_test_logging();

        let input = "payload contains 44:da:a";
        let err = parse(input).unwrap_err();

        assert_eq!(err.input(), input);
        assert_eq!(
            err.message(),
            "could not parse \"44:da:a\". invalid byte-string format"
        );
    }

    #[test]
    fn test_parse_error_missing_operation_eth() {
        init_test_logging();

        let inputs = [
            "eth.addr",
            "ip.addr",
            "port",
            "vlan.id",
            "payload",
            "payload.len",
        ];
        let error_messages = [
            "expected an ethernet operation found end of input",
            "expected an ip operation found end of input",
            "expected a value operation found end of input",
            "expected a value operation found end of input",
            "expected a payload operation found end of input",
            "expected a payload length operation found end of input",
        ];

        assert_eq!(inputs.len(), error_messages.len());

        for (input, error_message) in inputs.into_iter().zip(error_messages) {
            let err = parse(input).unwrap_err();
            assert_eq!(err.message(), error_message);
        }
    }

    #[test]
    fn test_parse_error_extraneous_data() {
        init_test_logging();

        let input = "payload contains 10:20:30 boom";
        let err = parse(input).unwrap_err();

        assert_eq!(err.message(), "expected end of input found \"boom\"");
    }
}
