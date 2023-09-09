use crate::{
    driver::{
        ErrorKind,
        Expected,
    },
    expression::{
        Clause,
        CmpOp,
        EthOp,
        IpOp,
        PayloadLenOp,
        PayloadOp,
        ValOp,
    },
    input::Input,
    lexer::{
        Token,
        TokenKind,
    },
    value_parsers::{
        parse_byte_string,
        parse_escaped_byte_string,
        parse_ip_net,
        parse_mac_addr,
        parse_regex,
        parse_u16,
    },
    Expression,
};
use bstr::BStr;
use std::vec::IntoIter;

#[derive(Debug)]
pub(crate) struct Parser<'a> {
    input: Input<'a>,
    tokens: IntoIter<Token>,
    current: Token,
}

impl<'a> Parser<'a> {
    pub(crate) fn new(input: Input<'a>, tokens: Vec<Token>) -> Self {
        let mut tokens = tokens.into_iter();
        // There must be at least an Eof token
        let current = tokens.next().unwrap();
        Self {
            input,
            tokens,
            current,
        }
    }

    /// Retrieve the source matching the current token
    fn current_data(&self) -> &BStr {
        &self.input[self.current.start..self.current.end]
    }

    /// Advance to the next token and return it.
    /// If we have reached the end we'll stay with the Eof token.
    fn advance(&mut self) {
        if let Some(token) = self.tokens.next() {
            self.current = token;
        }
    }

    /// Advance to the next token, only if the current token kind is `kind`.
    /// Otherwise return an error.
    fn advance_if(&mut self, kind: TokenKind) -> Result<(), ErrorKind> {
        if self.current.kind != kind {
            return Err(ErrorKind::unexpected(
                Expected::token_kind(kind),
                self.current,
            ));
        }
        self.advance();
        Ok(())
    }

    /// Expects a token kind of Token::Value or a Token::QuotedValue.
    /// Parses the value data with the help of `value_parser`.
    /// If succeeds, advances the token.
    fn parse_value<F, T, E>(
        &mut self,
        value_kind: TokenKind,
        value_parser: &F,
        of_kind: &'static str,
    ) -> Result<T, ErrorKind>
    where
        F: Fn(&BStr) -> Result<T, E>,
        E: Into<String>,
    {
        let val = match self.current.kind {
            TokenKind::QuotedValue if value_kind == TokenKind::QuotedValue => {
                let val = self.current_data();
                // Remove the quotes
                &val[1..val.len() - 1]
            }
            TokenKind::Value if value_kind == TokenKind::Value => self.current_data(),
            _ => {
                return Err(ErrorKind::unexpected(
                    Expected::label(of_kind),
                    self.current,
                ));
            }
        };
        let val = value_parser(val).map_err(|e| ErrorKind::parse(self.current, e))?;
        // We've parse the value. Advance the current token to point to the next token
        self.advance();
        Ok(val)
    }

    /// Parses the upcoming tokens as a list of values.
    /// Expected a list in the format of: `{ <val>, <val>, <val> }` where each of the
    /// `<val>` are parsed with the help of `parse_value`.
    fn parse_list<F, T, E>(
        &mut self,
        value_kind: TokenKind,
        value_parser: &F,
        of_kind: &'static str,
    ) -> Result<Vec<T>, ErrorKind>
    where
        F: Fn(&BStr) -> Result<T, E>,
        E: Into<String>,
    {
        let mut values = Vec::new();
        self.advance_if(TokenKind::OpenBrace)?;
        loop {
            let value = self.parse_value(value_kind, value_parser, of_kind)?;
            values.push(value);
            match self.current.kind {
                TokenKind::Comma => {
                    self.advance();
                    continue;
                }
                TokenKind::CloseBrace => {
                    self.advance();
                    break;
                }
                _ => {
                    return Err(ErrorKind::unexpected(
                        Expected::token_kind(TokenKind::CloseBrace),
                        self.current,
                    ));
                }
            }
        }
        Ok(values)
    }

    /// Parse a token as a comparison operator
    fn parse_comparison_operator(&mut self) -> Result<CmpOp, ErrorKind> {
        let cmp_op = match self.current.kind {
            TokenKind::Equal => CmpOp::Equal,
            TokenKind::NotEqual => CmpOp::NotEqual,
            TokenKind::LessThan => CmpOp::LessThan,
            TokenKind::LessEqual => CmpOp::LessEqual,
            TokenKind::GreaterThan => CmpOp::GreaterThan,
            TokenKind::GreaterEqual => CmpOp::GreaterEqual,
            _ => {
                return Err(ErrorKind::unexpected(
                    Expected::label("comparison operator"),
                    self.current,
                ));
            }
        };
        self.advance();
        Ok(cmp_op)
    }

    fn parse_ethernet_operations(&mut self) -> Result<EthOp, ErrorKind> {
        let eth_op = match self.parse_comparison_operator() {
            Ok(cmp_op) => {
                let mac = self.parse_value(TokenKind::Value, &parse_mac_addr, "mac-address")?;
                EthOp::compare(cmp_op, mac)
            }
            _ => match self.current.kind {
                TokenKind::In => {
                    self.advance();
                    let values =
                        self.parse_list(TokenKind::Value, &parse_mac_addr, "list of mac-address")?;
                    EthOp::match_any(values)
                }
                TokenKind::Contains => {
                    self.advance();
                    let bytes = match self.current.kind == TokenKind::QuotedValue {
                        true => self.parse_value(
                            TokenKind::QuotedValue,
                            &parse_escaped_byte_string,
                            "quoted escaped byte-string",
                        )?,
                        false => {
                            self.parse_value(TokenKind::Value, &parse_byte_string, "byte-string")?
                        }
                    };
                    EthOp::contains(bytes)
                }
                TokenKind::RegexMatch => {
                    self.advance();
                    let regex = self.parse_value(
                        TokenKind::QuotedValue,
                        &parse_regex,
                        "quoted regex string",
                    )?;
                    EthOp::regex_match(regex)
                }
                _ => {
                    return Err(ErrorKind::unexpected(
                        Expected::label("an ethernet operation"),
                        self.current,
                    ));
                }
            },
        };
        Ok(eth_op)
    }

    fn parse_ip_operations(&mut self) -> Result<IpOp, ErrorKind> {
        let ip_op = match self.parse_comparison_operator() {
            Ok(cmp_op) => {
                let ip = self.parse_value(TokenKind::Value, &parse_ip_net, "ip-address")?;
                IpOp::compare(cmp_op, ip)
            }
            _ => match self.current.kind {
                TokenKind::In => {
                    self.advance();
                    let values =
                        self.parse_list(TokenKind::Value, &parse_ip_net, "a list of ip-addresses")?;
                    IpOp::match_any(values)
                }
                _ => {
                    return Err(ErrorKind::unexpected(
                        Expected::label("an ip operation"),
                        self.current,
                    ));
                }
            },
        };
        Ok(ip_op)
    }

    fn parse_value_operations(&mut self) -> Result<ValOp, ErrorKind> {
        let val_op = match self.parse_comparison_operator() {
            Ok(cmp_op) => {
                let num = self.parse_value(TokenKind::Value, &parse_u16, "number")?;
                ValOp::compare(cmp_op, num)
            }
            _ => match self.current.kind {
                TokenKind::In => {
                    self.advance();
                    let values =
                        self.parse_list(TokenKind::Value, &parse_u16, "list of numbers")?;
                    ValOp::match_any(values)
                }
                _ => {
                    return Err(ErrorKind::unexpected(
                        Expected::label("a value operation"),
                        self.current,
                    ));
                }
            },
        };
        Ok(val_op)
    }

    fn parse_payload_operations(&mut self) -> Result<PayloadOp, ErrorKind> {
        let payload_op = match self.current.kind {
            TokenKind::Contains => {
                self.advance();
                let bytes = match self.current.kind == TokenKind::QuotedValue {
                    true => self.parse_value(
                        TokenKind::QuotedValue,
                        &parse_escaped_byte_string,
                        "quoted escaped byte-string",
                    )?,
                    false => {
                        self.parse_value(TokenKind::Value, &parse_byte_string, "byte-string")?
                    }
                };
                PayloadOp::contains(bytes)
            }
            TokenKind::RegexMatch => {
                self.advance();
                let regex =
                    self.parse_value(TokenKind::QuotedValue, &parse_regex, "regex string")?;
                PayloadOp::regex_match(regex)
            }
            _ => {
                return Err(ErrorKind::unexpected(
                    Expected::label("a payload operation"),
                    self.current,
                ));
            }
        };
        Ok(payload_op)
    }

    fn parse_payload_len_operations(&mut self) -> Result<PayloadLenOp, ErrorKind> {
        let val_op = match self.parse_comparison_operator() {
            Ok(cmp_op) => {
                let num = self.parse_value(TokenKind::Value, &parse_u16, "number")?;
                PayloadLenOp::compare(cmp_op, num)
            }
            _ => {
                return Err(ErrorKind::unexpected(
                    Expected::label("a payload length operation"),
                    self.current,
                ));
            }
        };
        Ok(val_op)
    }

    fn parse_single_clause_expression(&mut self) -> Result<Expression, ErrorKind> {
        let clause = match self.current.kind {
            TokenKind::LitTcp => {
                self.advance();
                Clause::IsTcp
            }
            TokenKind::LitUdp => {
                self.advance();
                Clause::IsUdp
            }
            TokenKind::LitVlan => {
                self.advance();
                Clause::IsVlan
            }
            TokenKind::LitEthAddr => {
                self.advance();
                self.parse_ethernet_operations().map(Clause::EthAddr)?
            }
            TokenKind::LitEthDst => {
                self.advance();
                self.parse_ethernet_operations().map(Clause::EthDst)?
            }
            TokenKind::LitEthSrc => {
                self.advance();
                self.parse_ethernet_operations().map(Clause::EthSrc)?
            }
            TokenKind::LitIpAddr => {
                self.advance();
                self.parse_ip_operations().map(Clause::IpAddr)?
            }
            TokenKind::LitIpDst => {
                self.advance();
                self.parse_ip_operations().map(Clause::IpDst)?
            }
            TokenKind::LitIpSrc => {
                self.advance();
                self.parse_ip_operations().map(Clause::IpSrc)?
            }
            TokenKind::LitVlanId => {
                self.advance();
                self.parse_value_operations().map(Clause::VlanId)?
            }
            TokenKind::LitPort => {
                self.advance();
                self.parse_value_operations().map(Clause::Port)?
            }
            TokenKind::LitPortDst => {
                self.advance();
                self.parse_value_operations().map(Clause::PortDst)?
            }
            TokenKind::LitPortSrc => {
                self.advance();
                self.parse_value_operations().map(Clause::PortSrc)?
            }
            TokenKind::LitPayload => {
                self.advance();
                self.parse_payload_operations().map(Clause::Payload)?
            }
            TokenKind::LitPayloadLen => {
                self.advance();
                self.parse_payload_len_operations()
                    .map(Clause::PayloadLen)?
            }
            _ => {
                return Err(ErrorKind::unexpected(
                    Expected::label("an expression"),
                    self.current,
                ));
            }
        };

        Ok(Expression::Single(clause))
    }

    fn parse_nested_expression(&mut self) -> Result<Expression, ErrorKind> {
        match self.current.kind {
            TokenKind::OpenParen => {
                self.advance();
                let expr = self.parse_expression()?;
                self.advance_if(TokenKind::CloseParen)?;
                Ok(expr)
            }
            TokenKind::Not => {
                self.advance();
                let expr = self.parse_nested_expression()?;
                Ok(Expression::not(expr))
            }
            _ => self.parse_single_clause_expression(),
        }
    }

    /// Parse a complete expression. Recursive.
    fn parse_expression(&mut self) -> Result<Expression, ErrorKind> {
        // Parse first clause or grouped/not expression
        let mut expr = self.parse_nested_expression()?;
        loop {
            match self.current.kind {
                TokenKind::And => {
                    self.advance();
                    let next_expr = self.parse_nested_expression()?;
                    expr = expr.and(next_expr);
                }
                TokenKind::Or => {
                    self.advance();
                    let next_expr = self.parse_nested_expression()?;
                    expr = expr.or(next_expr);
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    /// parser entrypoint. Can only be called once per tokens set.
    pub(crate) fn parse(mut self) -> Result<Expression, ErrorKind> {
        let expr = self.parse_expression()?;
        // Validate we have reached the end of the input
        match self.current.kind == TokenKind::EoF {
            true => Ok(expr),
            false => Err(ErrorKind::unexpected(
                Expected::token_kind(TokenKind::EoF),
                self.current,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ErrorKind,
        Parser,
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
        input::Input,
        lexer::{
            Lexer,
            TokenKind,
        },
        mac_addr::MacAddr,
        test_utils::init_test_logging,
        Expression,
    };
    use ipnet::IpNet;
    use regex::bytes::Regex;
    use tracing::info;

    // A helper function to fully parse an expression
    fn parse(input: &str) -> Result<Expression, ErrorKind> {
        let input = Input::new(input).unwrap();
        let tokens = Lexer::new(input).lex();
        // Assert that the lexing stage finished successfully
        assert!(tokens.iter().all(|t| t.kind != TokenKind::Error));
        Parser::new(input, tokens).parse()
    }

    #[test]
    fn test_parse_ethernet_operations_success() {
        init_test_logging();

        let inputs = [
            "eth.addr == ab-cd-ef-01-23-45",
            "eth.addr ne ab:cd:ef:01:23:45",
            "eth.dst > ab:cd:ef:01:23:45",
            "eth.src >= ab-cd-ef-01-23-45",
            "eth.src < ab-cd-ef-01-23-45",
            "eth.addr <= ab-cd-ef-01-23-45",
            "eth.addr eq abcdef012345",
            "eth.addr == ab:cd:ef:01:23:45",
            "eth.addr == abc.def.012.345",
            "eth.src in {abcdef012345, abc.def.012.345}",
            "eth.dst in { abcdef012345 }",
            "eth.addr contains ab",
            "eth.addr contains ab:cd:ef",
            "eth.addr contains 'string'",
            r#"eth.dst contains "\x00string""#,
            "eth.dst ~ 'string'",
        ];
        let expected_mac_addr = MacAddr::from([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]);
        let regex_matcher = Regex::new("string").unwrap().into();
        let expected = [
            Clause::EthAddr(EthOp::compare(CmpOp::Equal, expected_mac_addr)),
            Clause::EthAddr(EthOp::compare(CmpOp::NotEqual, expected_mac_addr)),
            Clause::EthDst(EthOp::compare(CmpOp::GreaterThan, expected_mac_addr)),
            Clause::EthSrc(EthOp::compare(CmpOp::GreaterEqual, expected_mac_addr)),
            Clause::EthSrc(EthOp::compare(CmpOp::LessThan, expected_mac_addr)),
            Clause::EthAddr(EthOp::compare(CmpOp::LessEqual, expected_mac_addr)),
            Clause::EthAddr(EthOp::compare(CmpOp::Equal, expected_mac_addr)),
            Clause::EthAddr(EthOp::compare(CmpOp::Equal, expected_mac_addr)),
            Clause::EthAddr(EthOp::compare(CmpOp::Equal, expected_mac_addr)),
            Clause::EthSrc(EthOp::match_any(vec![expected_mac_addr, expected_mac_addr])),
            Clause::EthDst(EthOp::match_any(vec![expected_mac_addr])),
            Clause::EthAddr(EthOp::contains(vec![0xab])),
            Clause::EthAddr(EthOp::contains(vec![0xab, 0xcd, 0xef])),
            Clause::EthAddr(EthOp::contains(b"string".to_vec())),
            Clause::EthDst(EthOp::contains(b"\x00string".to_vec())),
            Clause::EthDst(EthOp::regex_match(regex_matcher)),
        ];

        // Validate we have an expected result for every input
        assert_eq!(inputs.len(), expected.len());

        for (input, clause) in inputs.into_iter().zip(expected) {
            info!("Parsing '{input}' as ethernet operations - should succeed");
            let expression = parse(input).unwrap();
            assert_eq!(expression, Expression::Single(clause));
        }
    }

    #[test]
    fn test_parse_ethernet_operations_failure() {
        init_test_logging();

        let inputs = [
            "eth.src ==   ",
            "eth.src == ''",
            "eth.src == 'ab-cd-ef-01-23-45'",
            "eth.src == string",
            "eth.src in { ab-cd-ef-01-23-45,",
            "eth.src in { ab-cd-ef-01-23-45, }",
            "eth.src in { }",
        ];

        for input in inputs {
            info!("Parsing '{input}' as ethernet operations - should fail");
            let res = parse(input);
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_parse_ip_operations_success() {
        init_test_logging();

        let ip: IpNet = "192.168.1.1/32".parse().unwrap();

        let inputs = [
            "ip.addr eq 192.168.1.1",
            "ip.src == 192.168.1.1/32",
            "ip.dst != 192.168.1.1",
            "ip.addr gt 192.168.1.1",
            "ip.addr ge 192.168.1.1",
            "ip.addr lt 192.168.1.1",
            "ip.addr le 192.168.1.1",
            "ip.addr in {192.168.1.1, 192.168.1.1/32}",
        ];
        let expected = [
            Clause::IpAddr(IpOp::compare(CmpOp::Equal, ip)),
            Clause::IpSrc(IpOp::compare(CmpOp::Equal, ip)),
            Clause::IpDst(IpOp::compare(CmpOp::NotEqual, ip)),
            Clause::IpAddr(IpOp::compare(CmpOp::GreaterThan, ip)),
            Clause::IpAddr(IpOp::compare(CmpOp::GreaterEqual, ip)),
            Clause::IpAddr(IpOp::compare(CmpOp::LessThan, ip)),
            Clause::IpAddr(IpOp::compare(CmpOp::LessEqual, ip)),
            Clause::IpAddr(IpOp::match_any(vec![ip, ip])),
        ];

        // Validate we have an expected result for every input
        assert_eq!(inputs.len(), expected.len());

        for (input, clause) in inputs.into_iter().zip(expected) {
            info!("Parsing '{input}' as ip operations - should succeed");
            let expression = parse(input).unwrap();
            assert_eq!(expression, Expression::Single(clause));
        }
    }

    #[test]
    fn test_parse_ip_operations_failure() {
        init_test_logging();

        let inputs = [
            "ip.addr == 55",
            "ip.addr == not-an-ip",
            "ip.addr in 192.168.1.1",
            "ip.addr > ==",
            "ip.addr in { 192.168.1.1, 192.168.1.1",
            "ip.addr in { 192.168.1.1, 192.168.1.1, }",
            "ip.addr in { }",
        ];

        for input in inputs {
            info!("Parsing '{input}' as ip operations - should fail");
            let res = parse(input);
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_parse_val_operations_success() {
        init_test_logging();

        let inputs = [
            "vlan.id == 55",
            "vlan.id != 55",
            "vlan.id > 55",
            "vlan.id >= 55",
            "vlan.id < 55",
            "vlan.id <= 55",
            "vlan.id in {1, 2}",
        ];
        let expected = [
            Clause::VlanId(ValOp::compare(CmpOp::Equal, 55)),
            Clause::VlanId(ValOp::compare(CmpOp::NotEqual, 55)),
            Clause::VlanId(ValOp::compare(CmpOp::GreaterThan, 55)),
            Clause::VlanId(ValOp::compare(CmpOp::GreaterEqual, 55)),
            Clause::VlanId(ValOp::compare(CmpOp::LessThan, 55)),
            Clause::VlanId(ValOp::compare(CmpOp::LessEqual, 55)),
            Clause::VlanId(ValOp::match_any(vec![1, 2])),
        ];

        // Validate we have an expected result for every input
        assert_eq!(inputs.len(), expected.len());

        for (input, clause) in inputs.into_iter().zip(expected) {
            info!("Parsing '{input}' as a value operations - should succeed");
            let expression = parse(input).unwrap();
            assert_eq!(expression, Expression::Single(clause));
        }
    }

    #[test]
    fn test_parse_val_operations_failure() {
        init_test_logging();

        let inputs = [
            r#"vlan.id == """#,
            r#"vlan.id == "55""#,
            "vlan.id == not-a-number",
            "vlan.id in 55",
            "vlan.id > ==",
            "vlan.id in {1, 2",
            "vlan.id in {1, }",
            "vlan.id in {}",
            "vlan.id in {,2}",
        ];

        for input in inputs {
            info!("Parsing '{input}' as a value operations - should fail");
            let res = parse(input);
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_parse_payload_operations_success() {
        init_test_logging();

        let regex_matcher = Regex::new("string").unwrap().into();

        let inputs = [
            "payload contains ab",
            "payload contains ab:cd:ef",
            "payload contains ab-cd-ef",
            "payload contains 'string'",
            r#"payload contains "\x00string""#,
            r#"payload matches "string""#,
        ];
        let expected = [
            Clause::Payload(PayloadOp::contains(vec![0xab])),
            Clause::Payload(PayloadOp::contains(vec![0xab, 0xcd, 0xef])),
            Clause::Payload(PayloadOp::contains(vec![0xab, 0xcd, 0xef])),
            Clause::Payload(PayloadOp::contains(b"string".to_vec())),
            Clause::Payload(PayloadOp::contains(b"\x00string".to_vec())),
            Clause::Payload(PayloadOp::regex_match(regex_matcher)),
        ];

        // Validate we have an expected result for every input
        assert_eq!(inputs.len(), expected.len());

        for (input, clause) in inputs.into_iter().zip(expected) {
            info!("Parsing '{input}' as a payload operations - should succeed");
            let expression = parse(input).unwrap();
            assert_eq!(expression, Expression::Single(clause));
        }
    }

    #[test]
    fn test_parse_payload_operations_failure() {
        init_test_logging();

        let inputs = [
            //"payload contains  ",
            "payload contains '' ",
            "payload ~ string",
            r#"payload ~ "" "#,
        ];

        for input in inputs {
            info!("Parsing '{input}' as a payload operations - should fail");
            let res = parse(input);
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_parse_payload_len_operations_success() {
        init_test_logging();

        let inputs = [
            "payload.len == 55",
            "payload.len eq 55",
            "payload.len != 55",
            "payload.len ne 55",
            "payload.len > 55",
            "payload.len gt 55",
            "payload.len >= 55",
            "payload.len ge 55",
            "payload.len < 55",
            "payload.len lt 55",
            "payload.len <= 55",
            "payload.len le 55",
        ];
        let expected = [
            Clause::PayloadLen(PayloadLenOp::compare(CmpOp::Equal, 55)),
            Clause::PayloadLen(PayloadLenOp::compare(CmpOp::Equal, 55)),
            Clause::PayloadLen(PayloadLenOp::compare(CmpOp::NotEqual, 55)),
            Clause::PayloadLen(PayloadLenOp::compare(CmpOp::NotEqual, 55)),
            Clause::PayloadLen(PayloadLenOp::compare(CmpOp::GreaterThan, 55)),
            Clause::PayloadLen(PayloadLenOp::compare(CmpOp::GreaterThan, 55)),
            Clause::PayloadLen(PayloadLenOp::compare(CmpOp::GreaterEqual, 55)),
            Clause::PayloadLen(PayloadLenOp::compare(CmpOp::GreaterEqual, 55)),
            Clause::PayloadLen(PayloadLenOp::compare(CmpOp::LessThan, 55)),
            Clause::PayloadLen(PayloadLenOp::compare(CmpOp::LessThan, 55)),
            Clause::PayloadLen(PayloadLenOp::compare(CmpOp::LessEqual, 55)),
            Clause::PayloadLen(PayloadLenOp::compare(CmpOp::LessEqual, 55)),
        ];

        // Validate we have an expected result for every input
        assert_eq!(inputs.len(), expected.len());

        for (input, clause) in inputs.into_iter().zip(expected) {
            info!("Parsing '{input}' as a payload length operations - should succeed");
            let expression = parse(input).unwrap();
            assert_eq!(expression, Expression::Single(clause));
        }
    }

    #[test]
    fn test_parse_payload_len_operations_failure() {
        init_test_logging();

        let inputs = [
            "payload.len == '55'",
            "payload.len == not_a_number",
            "payload.len == s0me",
            "payload.len in 55",
            "payload.len < ==",
        ];

        for input in inputs {
            info!("Parsing '{input}' as a payload length operations - should fail");
            let res = parse(input);
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_parse_single_term() {
        init_test_logging();

        let inputs = ["tcp", "udp", "vlan"];
        let expected = [Clause::IsTcp, Clause::IsUdp, Clause::IsVlan];

        // Validate we have an expected result for every input
        assert_eq!(inputs.len(), expected.len());

        for (input, clause) in inputs.into_iter().zip(expected) {
            info!("Parsing '{input}' as single term clause - should succeed");
            let expression = parse(input).unwrap();
            assert_eq!(expression, Expression::Single(clause));
        }
    }

    #[test]
    fn test_parse_multiple_terms_clause() {
        init_test_logging();

        let mac_addr = MacAddr::from([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]);
        let regex_matcher: RegexMatcher = Regex::new("string").unwrap().into();
        let ip: IpNet = "192.168.1.1/32".parse().unwrap();

        let inputs = [
            "vlan.id == 1",
            "vlan.id in{1}",
            "port eq 1",
            "port in { 1 }",
            "dstport == 1",
            "dstport in { 1 }",
            "srcport == 1",
            "srcport in { 1 }",
            "eth.addr == ab-cd-ef-01-23-45",
            "eth.addr in {ab-cd-ef-01-23-45}",
            "eth.addr contains 00:11",
            "eth.addr matches 'string'",
            "eth.dst == ab-cd-ef-01-23-45",
            "eth.dst in {ab-cd-ef-01-23-45}",
            "eth.dst contains 00:11",
            "eth.dst matches 'string'",
            "eth.src == ab-cd-ef-01-23-45",
            "eth.src in {ab-cd-ef-01-23-45}",
            "eth.src contains 00:11",
            "eth.src matches 'string'",
            "ip.addr == 192.168.1.1",
            "ip.addr in { 192.168.1.1 }",
            "ip.dst == 192.168.1.1",
            "ip.dst in { 192.168.1.1 }",
            "ip.src == 192.168.1.1",
            "ip.src in { 192.168.1.1 }",
            "payload contains 00:11",
            "payload matches 'string'",
            "payload.len eq 1",
        ];
        let expected = [
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

        // Validate we have an expected result for every input
        assert_eq!(inputs.len(), expected.len());

        for (input, clause) in inputs.into_iter().zip(expected) {
            info!("Parsing '{input}' as multiple term clause - should succeed");
            let expression = parse(input).unwrap();
            assert_eq!(expression, Expression::Single(clause));
        }
    }

    #[test]
    fn test_parse_complex_statement_01() {
        init_test_logging();

        let input = "vlan and (vlan.id in {1, 2} or ip.addr == 10.1.0.0/16) and not udp";
        let expected = Expression::And(vec![
            Clause::IsVlan.into(),
            Expression::Or(vec![
                Clause::VlanId(ValOp::match_any(vec![1, 2])).into(),
                Clause::IpAddr(IpOp::compare(CmpOp::Equal, "10.1.0.0/16".parse().unwrap())).into(),
            ]),
            Expression::not(Clause::IsUdp),
        ]);

        info!("Validating parse of {input} as an expression {expected:?}");
        let expression = parse(input).unwrap();
        assert_eq!(expression, expected);
    }

    #[test]
    fn test_parse_complex_statement_02() {
        init_test_logging();

        let ip: IpNet = "10.1.0.0/16".parse().unwrap();
        let mac1 = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let mac2 = MacAddr::from([0x55, 0x44, 0x33, 0x22, 0x11, 0x00]);
        let input = "(vlan or (eth.addr in {00:11:22:33:44:55, 55:44:33:22:11:00} and ip.addr == 10.1.0.0/16 and not udp))";
        let expected = Expression::Or(vec![
            Clause::IsVlan.into(),
            Expression::And(vec![
                Clause::EthAddr(EthOp::match_any(vec![mac1, mac2])).into(),
                Clause::IpAddr(IpOp::compare(CmpOp::Equal, ip)).into(),
                Expression::not(Clause::IsUdp),
            ]),
        ]);

        info!("Validating parse of {input} as an expression {expected:?}");
        let expression = parse(input).unwrap();
        assert_eq!(expression, expected);
    }

    #[test]
    fn test_parse_complex_statement_03() {
        init_test_logging();

        let ip: IpNet = "10.1.0.0/16".parse().unwrap();
        let regex: RegexMatcher = Regex::new("something").unwrap().into();
        let input = "not (eth.addr ~ 'something' and ip.addr == 10.1.0.0/16)";
        let expected = Expression::not(Expression::And(vec![
            Clause::EthAddr(EthOp::regex_match(regex)).into(),
            Clause::IpAddr(IpOp::compare(CmpOp::Equal, ip)).into(),
        ]));

        info!("Validating parse of {input} as an expression {expected:?}");
        let expression = parse(input).unwrap();
        assert_eq!(expression, expected);
    }

    #[test]
    fn test_parse_complex_statement_04() {
        init_test_logging();

        let regex1: RegexMatcher = Regex::new("something").unwrap().into();
        let regex2: RegexMatcher = Regex::new("else").unwrap().into();
        let regex3: RegexMatcher = Regex::new("last").unwrap().into();
        let input = "payload matches 'something' and not payload ~ 'else' and payload ~ 'last'";
        let expected = Expression::And(vec![
            Clause::Payload(PayloadOp::regex_match(regex1)).into(),
            Expression::not(Clause::Payload(PayloadOp::regex_match(regex2))),
            Clause::Payload(PayloadOp::regex_match(regex3)).into(),
        ]);

        info!("Validating parse of {input} as an expression {expected:?}");
        let expression = parse(input).unwrap();
        assert_eq!(expression, expected);
    }
}
