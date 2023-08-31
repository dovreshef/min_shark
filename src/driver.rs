//! This is the main driver of the wireshark-like filter expression creator.
//! It manages the following phases, in order:
//! * Lex the filter expression string into a set of tokens, or return the lexing error.
//! * Parse the list of tokens into an Expression object, or return the parsing error.
//! * For errors, try to figure out the root and to present it in a human friendly manner.
use crate::{
    lexer::{
        lexer,
        Token,
    },
    parser::expression_parser,
    Expression,
};
use chumsky::prelude::*;

/// Parse a filter expression into a `Expression`
pub fn parse(filter_expr: &str) -> Result<Expression, ParseError> {
    // Handle edge case
    if filter_expr.trim().is_empty() {
        let message = "filter expression cannot be empty".into();
        let span = SimpleSpan::new(0, filter_expr.len());
        return Err(ParseError::new(filter_expr.into(), message, span));
    }
    let (tokens, spans): (Vec<_>, Vec<_>) = lexer()
        .parse(filter_expr)
        .into_result()
        // lexing should never fail, even in the presence of errors. Only return the error token.
        .unwrap()
        .into_iter()
        .map(|st| (st.0, st.1))
        .unzip();
    let spanned_expr = expression_parser()
        .parse(tokens.as_slice())
        .into_result()
        .map_err(|err_list| ParseError::from_parse_errors(filter_expr, err_list, spans))?;
    Ok(spanned_expr.0)
}

/// An expression that failed to parse.
#[derive(Debug, Clone, derive_more::Constructor)]
pub struct ParseError {
    /// The expression that failed to parse
    pub expression: String,
    /// The main error message
    pub message: String,
    /// The span of the error part
    pub span: SimpleSpan,
}

impl ParseError {
    /// Create an error from RichError that occurred while parsing
    fn from_parse_errors(
        expression: &str,
        mut errors: Vec<Rich<'_, Token>>,
        span_map: Vec<SimpleSpan>,
    ) -> Self {
        // We expect there to be a single error
        let error = errors.pop().unwrap();
        let message = error.to_string();
        let token_span = error.span();
        let span = SimpleSpan::new(
            span_map[token_span.start].start,
            span_map[token_span.end - 1].end,
        );
        ParseError::new(expression.into(), message, span)
    }
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::{
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
        Expression,
    };
    use chumsky::span::SimpleSpan;
    use regex::bytes::Regex;
    use tracing::info;

    #[test]
    fn test_simple_expression_e2e() {
        init_test_logging();

        let expressions = [
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
                    MacAddr::try_from("00:10:9b:3a:53:fc").unwrap(),
                ))
                .into(),
                Clause::EthDst(EthOp::compare(
                    CmpOp::Equal,
                    MacAddr::try_from("00:10:9b:3a:53:fc").unwrap(),
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
                    MacAddr::try_from("3f:43:9a:2c:00:00").unwrap(),
                ))
                .into(),
                Clause::EthDst(EthOp::contains(vec![0x2c, 0x9a, 0xbb])).into(),
            ]),
        ];
        for (expr, expected) in expressions.into_iter().zip(expected_results) {
            info!("Parsing expression \"{expr}\"");
            let expr = parse(expr).unwrap();
            assert_eq!(expr, expected);
        }
    }

    #[test]
    fn test_the_only_tokenize_error() {
        init_test_logging();

        let expr = " ";
        let err = parse(expr).unwrap_err();
        assert_eq!(err.expression, expr);
        assert_eq!(err.message, "filter expression cannot be empty");
        assert_eq!(err.span, SimpleSpan::new(0, 1));
    }

    #[test]
    fn test_parse_error_01() {
        init_test_logging();

        let expr = "ip.addr == &6645";
        let err = parse(expr).unwrap_err();
        assert_eq!(err.expression, expr);
        assert_eq!(err.message, "found '&6645' expected ip-address or cidr");
        assert_eq!(err.span, SimpleSpan::new(11, 16));
    }

    #[test]
    fn test_parse_error_02() {
        init_test_logging();

        let expr = "ip.addr === 6645";
        let err = parse(expr).unwrap_err();
        assert_eq!(err.expression, expr);
        assert_eq!(err.message, "found '= 6645' expected ip-address or cidr");
        assert_eq!(err.span, SimpleSpan::new(10, 16));
    }
}
