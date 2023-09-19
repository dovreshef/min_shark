use crate::input::Input;
use derive_more::Constructor;

/// Token types for each clause/input.
/// The syntax attempts to be very sparse, and match the syntax to the tshark filter input
/// that is already familiar
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::Display)]
pub(crate) enum TokenKind {
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
    #[display(fmt = "==")]
    Equal,
    /// `!=` or `ne`
    #[display(fmt = "!=")]
    NotEqual,
    /// `<` or `lt`
    #[display(fmt = "<")]
    LessThan,
    /// `<=` or `le`
    #[display(fmt = "<=")]
    LessEqual,
    /// `>` or `gt`
    #[display(fmt = ">")]
    GreaterThan,
    /// `>=` or `ge`
    #[display(fmt = ">=")]
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
    #[display(fmt = "a value")]
    Value,
    /// A quoted value, either with "" or ''
    #[display(fmt = "a quoted value")]
    QuotedValue,
    /// For good errors, it's better to lex everything and handle failure at parsing.
    #[display(fmt = "an error")]
    Error,
    /// End of input
    #[display(fmt = "end of input")]
    EoF,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Constructor)]
pub(crate) struct Token {
    pub(crate) kind: TokenKind,
    pub(crate) start: u16,
    pub(crate) end: u16,
}

#[derive(Debug)]
pub(crate) struct Lexer<'a> {
    input: Input<'a>,
    pos: u16,
}

impl<'a> Lexer<'a> {
    /// Create a new lexer
    pub(crate) fn new(input: Input<'a>) -> Self {
        Self { input, pos: 0 }
    }

    /// Skip all whitespace between tokens.
    fn skip_whitespace(&mut self) {
        while self
            .input
            .get(self.pos)
            .map_or(false, |c| c.is_ascii_whitespace())
        {
            self.pos += 1;
        }
    }

    /// Lex a (possibly) escaped quoted string, delimited by either " or '
    /// The result is always a token, either the string (without the quotes) or an error
    fn lex_quoted_string(&mut self, delimiter: u8) -> Token {
        /// This helper enum les us know if the previous character was
        /// an escape character \
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum CharMode {
            Regular,
            Escaped,
        }
        let mut mode = CharMode::Regular;
        // we start with the input at the location right after the delimiter
        for (count, c) in self.input[self.pos + 1..].iter().copied().enumerate() {
            let count = count as u16;
            if c == b'\\' {
                mode = match mode {
                    CharMode::Regular => CharMode::Escaped,
                    CharMode::Escaped => CharMode::Regular,
                }
            } else if mode == CharMode::Escaped {
                mode = CharMode::Regular;
            } else if c == delimiter {
                let start = self.pos;
                let end = self.pos + count + 2;
                let st = Token::new(TokenKind::QuotedValue, start, end);
                self.consume(count + 2);
                return st;
            }
        }
        self.lex_as_error()
    }

    /// Lex a key, a keyword, or a value
    /// The result is always a token, either the key/value or an error
    fn lex_keyword_or_value(&mut self) -> Token {
        let count = self.input[self.pos..]
            .iter()
            .copied()
            .take_while(|c| c.is_ascii_alphanumeric() || b"_.-:/".contains(c))
            .count() as u16;
        let found = &self.input[self.pos..self.pos + count];
        let found_str = std::str::from_utf8(found).unwrap();
        // Error case
        if found.is_empty() {
            return self.lex_as_error();
        }
        let token = match found_str {
            "tcp" => TokenKind::LitTcp,
            "udp" => TokenKind::LitUdp,
            "vlan" => TokenKind::LitVlan,
            "eth.addr" => TokenKind::LitEthAddr,
            "eth.dst" => TokenKind::LitEthDst,
            "eth.src" => TokenKind::LitEthSrc,
            "ip.addr" => TokenKind::LitIpAddr,
            "ip.dst" => TokenKind::LitIpDst,
            "ip.src" => TokenKind::LitIpSrc,
            "vlan.id" => TokenKind::LitVlanId,
            "port" => TokenKind::LitPort,
            "dstport" => TokenKind::LitPortDst,
            "srcport" => TokenKind::LitPortSrc,
            "payload" => TokenKind::LitPayload,
            "payload.len" => TokenKind::LitPayloadLen,
            "le" => TokenKind::LessEqual,
            "lt" => TokenKind::LessThan,
            "ge" => TokenKind::GreaterEqual,
            "gt" => TokenKind::GreaterThan,
            "eq" => TokenKind::Equal,
            "ne" => TokenKind::NotEqual,
            "not" => TokenKind::Not,
            "or" => TokenKind::Or,
            "and" => TokenKind::And,
            "in" => TokenKind::In,
            "contains" => TokenKind::Contains,
            "matches" => TokenKind::RegexMatch,
            _ => TokenKind::Value,
        };
        let st = Token::new(token, self.pos, self.pos + count);
        self.consume(count);
        st
    }

    /// Helper function to check if we've reached the end of the input.
    fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Helper function to consume characters from the input.
    fn consume(&mut self, count: u16) {
        self.pos += count;
    }

    /// Helper function to create an error token which consumes all remaining input.
    fn lex_as_error(&mut self) -> Token {
        let st = Token::new(TokenKind::Error, self.pos, self.input.len());
        self.pos = self.input.len();
        st
    }

    pub(crate) fn lex(&mut self) -> Vec<Token> {
        let mut tokens = Vec::new();

        // Skip any whitespace that may occur in the beginning
        self.skip_whitespace();

        while !self.is_eof() {
            match (self.input[self.pos], self.input.get(self.pos + 1).copied()) {
                (b'<', Some(b'=')) => {
                    let st = Token::new(TokenKind::LessEqual, self.pos, self.pos + 2);
                    tokens.push(st);
                    self.consume(2);
                }
                (b'>', Some(b'=')) => {
                    let st = Token::new(TokenKind::GreaterEqual, self.pos, self.pos + 2);
                    tokens.push(st);
                    self.consume(2);
                }
                (b'=', Some(b'=')) => {
                    let st = Token::new(TokenKind::Equal, self.pos, self.pos + 2);
                    tokens.push(st);
                    self.consume(2);
                }
                (b'!', Some(b'=')) => {
                    let st = Token::new(TokenKind::NotEqual, self.pos, self.pos + 2);
                    tokens.push(st);
                    self.consume(2);
                }
                (b'|', Some(b'|')) => {
                    let st = Token::new(TokenKind::Or, self.pos, self.pos + 2);
                    tokens.push(st);
                    self.consume(2);
                }
                (b'&', Some(b'&')) => {
                    let st = Token::new(TokenKind::And, self.pos, self.pos + 2);
                    tokens.push(st);
                    self.consume(2);
                }
                (b'(', _) => {
                    let st = Token::new(TokenKind::OpenParen, self.pos, self.pos + 1);
                    tokens.push(st);
                    self.consume(1);
                }
                (b')', _) => {
                    let st = Token::new(TokenKind::CloseParen, self.pos, self.pos + 1);
                    tokens.push(st);
                    self.consume(1);
                }
                (b'{', _) => {
                    let st = Token::new(TokenKind::OpenBrace, self.pos, self.pos + 1);
                    tokens.push(st);
                    self.consume(1);
                }
                (b'}', _) => {
                    let st = Token::new(TokenKind::CloseBrace, self.pos, self.pos + 1);
                    tokens.push(st);
                    self.consume(1);
                }
                (b',', _) => {
                    let st = Token::new(TokenKind::Comma, self.pos, self.pos + 1);
                    tokens.push(st);
                    self.consume(1);
                }
                (b'<', _) => {
                    let st = Token::new(TokenKind::LessThan, self.pos, self.pos + 1);
                    tokens.push(st);
                    self.consume(1);
                }
                (b'>', _) => {
                    let st = Token::new(TokenKind::GreaterThan, self.pos, self.pos + 1);
                    tokens.push(st);
                    self.consume(1);
                }
                (b'!', _) => {
                    let st = Token::new(TokenKind::Not, self.pos, self.pos + 1);
                    tokens.push(st);
                    self.consume(1);
                }
                (b'~', _) => {
                    let st = Token::new(TokenKind::RegexMatch, self.pos, self.pos + 1);
                    tokens.push(st);
                    self.consume(1);
                }
                (delimiter @ (b'"' | b'\''), _) => {
                    let token = self.lex_quoted_string(delimiter);
                    tokens.push(token);
                }
                _ => {
                    let token = self.lex_keyword_or_value();
                    tokens.push(token);
                }
            }

            self.skip_whitespace();
        }

        let eof = Token::new(TokenKind::EoF, self.input.len(), self.input.len());
        tokens.push(eof);
        tokens
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Lexer,
        TokenKind,
    };
    use crate::{
        input::Input,
        test_utils::init_test_logging,
    };
    use tracing::info;

    /// Parse an input, assume success, and strip the resulting tokens of their spans,
    /// for easier testing
    fn compare_input_tokens(input: &str, expected: &[(TokenKind, &str)]) {
        let (expected_kinds, expected_values): (Vec<TokenKind>, Vec<&str>) =
            expected.iter().cloned().unzip();

        info!("Lexing input \"{input}\"");
        let input = Input::new(input).unwrap();
        let mut lexer = Lexer::new(input);
        let mut tokens = lexer.lex();
        // remove end of input token
        let eof = tokens.pop().unwrap();
        assert_eq!(eof.start, input.len());
        assert_eq!(eof.end, input.len());
        assert_eq!(eof.kind, TokenKind::EoF);

        let kinds: Vec<_> = tokens.iter().map(|t| t.kind).collect();
        assert_eq!(kinds, expected_kinds);

        let values: Vec<_> = tokens
            .iter()
            .map(|t| {
                let val = &input[t.start..t.end];
                let val = std::str::from_utf8(val).unwrap();
                val
            })
            .collect();
        assert_eq!(values, expected_values);
    }

    #[test]
    fn test_lex_empty_input() {
        init_test_logging();

        compare_input_tokens("", &[]);
    }

    #[test]
    fn test_lex_single_term() {
        use TokenKind::*;
        init_test_logging();

        let inputs = ["tcp", "udp", "vlan"];
        let expected = &[[(LitTcp, "tcp")], [(LitUdp, "udp")], [(LitVlan, "vlan")]];
        for (input, expected) in inputs.into_iter().zip(expected) {
            compare_input_tokens(input, expected);
        }
    }

    #[test]
    fn test_lex_single_clause() {
        use TokenKind::*;
        init_test_logging();

        let inputs = [
            "eth.addr == 00-B0-D0-63-C2-26",
            "eth.src != 00-B0-D0-63-C2-26",
            "eth.dst eq 00-B0-D0-63-C2-26",
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
        let expected = &[
            vec![
                (LitEthAddr, "eth.addr"),
                (Equal, "=="),
                (Value, "00-B0-D0-63-C2-26"),
            ],
            vec![
                (LitEthSrc, "eth.src"),
                (NotEqual, "!="),
                (Value, "00-B0-D0-63-C2-26"),
            ],
            vec![
                (LitEthDst, "eth.dst"),
                (Equal, "eq"),
                (Value, "00-B0-D0-63-C2-26"),
            ],
            vec![(LitIpAddr, "ip.addr"), (Equal, "=="), (Value, "1.2.3.4")],
            vec![(LitIpSrc, "ip.src"), (Equal, "=="), (Value, "1.2.3.4")],
            vec![(LitIpDst, "ip.dst"), (Equal, "=="), (Value, "1.2.3.4")],
            vec![(LitVlanId, "vlan.id"), (Equal, "=="), (Value, "12")],
            vec![(LitPort, "port"), (Equal, "=="), (Value, "80")],
            vec![(LitPortSrc, "srcport"), (Equal, "=="), (Value, "80")],
            vec![(LitPortDst, "dstport"), (Equal, "=="), (Value, "80")],
            vec![
                (LitPayload, "payload"),
                (Contains, "contains"),
                (QuotedValue, "'00'"),
            ],
            vec![(LitPayloadLen, "payload.len"), (Equal, "=="), (Value, "16")],
        ];
        for (input, expected) in inputs.into_iter().zip(expected) {
            compare_input_tokens(input, expected);
        }
    }

    #[test]
    fn test_lex_comparison_operations() {
        use TokenKind::*;
        init_test_logging();

        let inputs = [
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
        let expected = &[
            vec![(LitIpAddr, "ip.addr"), (Equal, "=="), (Value, "1.2.3.4/32")],
            vec![(LitIpAddr, "ip.addr"), (Equal, "eq"), (Value, "1.2.3.4/32")],
            vec![
                (LitIpAddr, "ip.addr"),
                (NotEqual, "!="),
                (Value, "1.2.3.4/32"),
            ],
            vec![
                (LitIpAddr, "ip.addr"),
                (NotEqual, "ne"),
                (Value, "1.2.3.4/32"),
            ],
            vec![
                (LitIpAddr, "ip.addr"),
                (GreaterThan, ">"),
                (Value, "1.2.3.4/32"),
            ],
            vec![
                (LitIpAddr, "ip.addr"),
                (GreaterThan, "gt"),
                (Value, "1.2.3.4/32"),
            ],
            vec![
                (LitIpAddr, "ip.addr"),
                (GreaterEqual, ">="),
                (Value, "1.2.3.4/32"),
            ],
            vec![
                (LitIpAddr, "ip.addr"),
                (GreaterEqual, "ge"),
                (Value, "1.2.3.4/32"),
            ],
            vec![
                (LitIpAddr, "ip.addr"),
                (LessThan, "<"),
                (Value, "1.2.3.4/32"),
            ],
            vec![
                (LitIpAddr, "ip.addr"),
                (LessThan, "lt"),
                (Value, "1.2.3.4/32"),
            ],
            vec![
                (LitIpAddr, "ip.addr"),
                (LessEqual, "<="),
                (Value, "1.2.3.4/32"),
            ],
            vec![
                (LitIpAddr, "ip.addr"),
                (LessEqual, "le"),
                (Value, "1.2.3.4/32"),
            ],
        ];

        for (input, expected) in inputs.into_iter().zip(expected) {
            compare_input_tokens(input, expected);
        }
    }

    #[test]
    fn test_lex_set_operations() {
        use TokenKind::*;
        init_test_logging();

        let inputs = [
            "srcport in { 22 , 80 }",
            "ip.src in {192.168.1.0/24}",
            "ip.dst in {192.168.3.1, 10.0.0.0/8}",
            "ip.src in{192.168.1.0/24}",
            "ip.dst in{192.168.3.1,10.0.0.0/8}",
        ];
        let expected = &[
            vec![
                (LitPortSrc, "srcport"),
                (In, "in"),
                (OpenBrace, "{"),
                (Value, "22"),
                (Comma, ","),
                (Value, "80"),
                (CloseBrace, "}"),
            ],
            vec![
                (LitIpSrc, "ip.src"),
                (In, "in"),
                (OpenBrace, "{"),
                (Value, "192.168.1.0/24"),
                (CloseBrace, "}"),
            ],
            vec![
                (LitIpDst, "ip.dst"),
                (In, "in"),
                (OpenBrace, "{"),
                (Value, "192.168.3.1"),
                (Comma, ","),
                (Value, "10.0.0.0/8"),
                (CloseBrace, "}"),
            ],
            vec![
                (LitIpSrc, "ip.src"),
                (In, "in"),
                (OpenBrace, "{"),
                (Value, "192.168.1.0/24"),
                (CloseBrace, "}"),
            ],
            vec![
                (LitIpDst, "ip.dst"),
                (In, "in"),
                (OpenBrace, "{"),
                (Value, "192.168.3.1"),
                (Comma, ","),
                (Value, "10.0.0.0/8"),
                (CloseBrace, "}"),
            ],
        ];
        for (input, expected) in inputs.into_iter().zip(expected) {
            compare_input_tokens(input, expected);
        }
    }

    #[test]
    fn test_lex_multiple_clauses() {
        use TokenKind::*;
        init_test_logging();

        let inputs = [
            "not tcp and (ip.src == 10.10.0.0/16 or (dstport > 80 and dstport <= 100))",
            "!tcp && (ip.src == 10.10.0.0/16 || (dstport > 80 && dstport <= 100))",
            "!tcp&&(ip.src==10.10.0.0/16||(dstport>80&&dstport<=100))",
        ];
        let expected = &[
            vec![
                (Not, "not"),
                (LitTcp, "tcp"),
                (And, "and"),
                (OpenParen, "("),
                (LitIpSrc, "ip.src"),
                (Equal, "=="),
                (Value, "10.10.0.0/16"),
                (Or, "or"),
                (OpenParen, "("),
                (LitPortDst, "dstport"),
                (GreaterThan, ">"),
                (Value, "80"),
                (And, "and"),
                (LitPortDst, "dstport"),
                (LessEqual, "<="),
                (Value, "100"),
                (CloseParen, ")"),
                (CloseParen, ")"),
            ],
            vec![
                (Not, "!"),
                (LitTcp, "tcp"),
                (And, "&&"),
                (OpenParen, "("),
                (LitIpSrc, "ip.src"),
                (Equal, "=="),
                (Value, "10.10.0.0/16"),
                (Or, "||"),
                (OpenParen, "("),
                (LitPortDst, "dstport"),
                (GreaterThan, ">"),
                (Value, "80"),
                (And, "&&"),
                (LitPortDst, "dstport"),
                (LessEqual, "<="),
                (Value, "100"),
                (CloseParen, ")"),
                (CloseParen, ")"),
            ],
            vec![
                (Not, "!"),
                (LitTcp, "tcp"),
                (And, "&&"),
                (OpenParen, "("),
                (LitIpSrc, "ip.src"),
                (Equal, "=="),
                (Value, "10.10.0.0/16"),
                (Or, "||"),
                (OpenParen, "("),
                (LitPortDst, "dstport"),
                (GreaterThan, ">"),
                (Value, "80"),
                (And, "&&"),
                (LitPortDst, "dstport"),
                (LessEqual, "<="),
                (Value, "100"),
                (CloseParen, ")"),
                (CloseParen, ")"),
            ],
        ];
        for (input, expected) in inputs.into_iter().zip(expected) {
            compare_input_tokens(input, expected);
        }
    }

    #[test]
    fn test_lex_real_life_examples() {
        use TokenKind::*;
        init_test_logging();

        let inputs = [
            r#"payload ~ "\r\n\x45\xdb""#,
            r#"payload ~ "GET /(secret|password)""#,
            r#"payload ~ "[[:ascii:]]{100}""#,
            r#"payload matches ".*Philips\\.HIF.*""#,
            "port <= 0x16",
            "port <= 0b1100_1100",
        ];
        let expected = &[
            vec![
                (LitPayload, "payload"),
                (RegexMatch, "~"),
                (QuotedValue, r#""\r\n\x45\xdb""#),
            ],
            vec![
                (LitPayload, "payload"),
                (RegexMatch, "~"),
                (QuotedValue, r#""GET /(secret|password)""#),
            ],
            vec![
                (LitPayload, "payload"),
                (RegexMatch, "~"),
                (QuotedValue, r#""[[:ascii:]]{100}""#),
            ],
            vec![
                (LitPayload, "payload"),
                (RegexMatch, "matches"),
                (QuotedValue, r#"".*Philips\\.HIF.*""#),
            ],
            vec![(LitPort, "port"), (LessEqual, "<="), (Value, "0x16")],
            vec![(LitPort, "port"), (LessEqual, "<="), (Value, "0b1100_1100")],
        ];
        for (input, expected) in inputs.into_iter().zip(expected) {
            compare_input_tokens(input, expected);
        }
    }

    #[test]
    fn test_lex_no_whitespace() {
        init_test_logging();

        let input = "eth.addr==00-B0-D0-63-C2-26";
        let expected = &[
            (TokenKind::LitEthAddr, "eth.addr"),
            (TokenKind::Equal, "=="),
            (TokenKind::Value, "00-B0-D0-63-C2-26"),
        ];
        compare_input_tokens(input, expected);
    }

    #[test]
    fn test_lex_lots_of_whitespace() {
        init_test_logging();

        let input = "   \t\t \n \r\n eth.addr   ==   \t        00-B0-D0-63-C2-26      ";
        let expected = &[
            (TokenKind::LitEthAddr, "eth.addr"),
            (TokenKind::Equal, "=="),
            (TokenKind::Value, "00-B0-D0-63-C2-26"),
        ];
        compare_input_tokens(input, expected);
    }

    #[test]
    fn test_lex_contains() {
        init_test_logging();

        let inputs = [
            "payload contains 00:11:22:33",
            "payload contains    00:11:22:33   ",
        ];
        let expected = &[
            (TokenKind::LitPayload, "payload"),
            (TokenKind::Contains, "contains"),
            (TokenKind::Value, "00:11:22:33"),
        ];
        for input in inputs {
            compare_input_tokens(input, expected);
        }
    }

    #[test]
    fn test_lex_matches() {
        init_test_logging();

        let inputs = [
            "payload ~ '^something[0-9]+'",
            "payload matches '^something[0-9]+'",
        ];
        let expected = &[
            vec![
                (TokenKind::LitPayload, "payload"),
                (TokenKind::RegexMatch, "~"),
                (TokenKind::QuotedValue, "'^something[0-9]+'"),
            ],
            vec![
                (TokenKind::LitPayload, "payload"),
                (TokenKind::RegexMatch, "matches"),
                (TokenKind::QuotedValue, "'^something[0-9]+'"),
            ],
        ];
        for (input, expected) in inputs.into_iter().zip(expected) {
            compare_input_tokens(input, expected);
        }
    }

    #[test]
    fn test_lex_quotes() {
        use TokenKind::*;
        init_test_logging();

        let inputs = [
            "''",
            r#"''""''"#,
            r#"'"'"#,
            r#""t""#,
            "    ''  ",
            r#"   ""      "#,
        ];
        let expected = &[
            vec![(QuotedValue, "''")],
            vec![
                (QuotedValue, "''"),
                (QuotedValue, r#""""#),
                (QuotedValue, "''"),
            ],
            vec![(QuotedValue, "'\"'")],
            vec![(QuotedValue, r#""t""#)],
            vec![(QuotedValue, "''")],
            vec![(QuotedValue, r#""""#)],
        ];
        for (input, expected) in inputs.into_iter().zip(expected) {
            compare_input_tokens(input, expected);
        }
    }

    // Everything will pass lexing
    #[test]
    fn test_lex_nonsensical_inputs() {
        init_test_logging();

        let inputs = ["om nom nom", "'boo'((boom-------", "==)('')"];
        let expected = &[
            vec![
                (TokenKind::Value, "om"),
                (TokenKind::Value, "nom"),
                (TokenKind::Value, "nom"),
            ],
            vec![
                (TokenKind::QuotedValue, "'boo'"),
                (TokenKind::OpenParen, "("),
                (TokenKind::OpenParen, "("),
                (TokenKind::Value, "boom-------"),
            ],
            vec![
                (TokenKind::Equal, "=="),
                (TokenKind::CloseParen, ")"),
                (TokenKind::OpenParen, "("),
                (TokenKind::QuotedValue, "''"),
                (TokenKind::CloseParen, ")"),
            ],
        ];
        for (input, expected) in inputs.into_iter().zip(expected) {
            compare_input_tokens(input, expected);
        }
    }

    // But some as error token
    #[test]
    fn test_lex_errors() {
        init_test_logging();

        let inputs = ["om =nom", "'", "\"", "^", "%"];
        let expected = &[
            vec![(TokenKind::Value, "om"), (TokenKind::Error, "=nom")],
            vec![(TokenKind::Error, "'")],
            vec![(TokenKind::Error, "\"")],
            vec![(TokenKind::Error, "^")],
            vec![(TokenKind::Error, "%")],
        ];
        for (input, expected) in inputs.into_iter().zip(expected) {
            compare_input_tokens(input, expected);
        }
    }
}
