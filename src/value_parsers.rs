//! A set of small one function parsers for each of the different type of values we support
use crate::{
    expression::RegexMatcher,
    mac_addr::MacAddr,
};
use bstr::BStr;
use ipnet::IpNet;
use regex::bytes::Regex;
use std::net::IpAddr;

/// Parse a given string as a u16
pub fn parse_u16(val: &BStr) -> Result<u16, &'static str> {
    let val = std::str::from_utf8(val).map_err(|_| "not a valid utf-8 string")?;
    val.parse().map_err(|_| "not a valid number")
}

/// Parse a given string as a mac-address
pub fn parse_mac_addr(val: &BStr) -> Result<MacAddr, &'static str> {
    MacAddr::try_from(val.as_ref()).map_err(|_| "not a valid mac-address")
}

/// Parse a given string as a regex description
pub fn parse_regex(val: &BStr) -> Result<RegexMatcher, String> {
    if val.is_empty() {
        return Err("regex must not be empty".into());
    }
    let val = std::str::from_utf8(val).map_err(|_| "not a valid utf-8 string".to_string())?;
    Regex::new(val)
        .map(RegexMatcher::new)
        .map_err(|e| format!("{e}"))
}

/// Parse two u8 as an ascii byte
fn parse_ascii_byte(n1: u8, n2: u8) -> Result<u8, &'static str> {
    let mut byte = 0;
    for n in [n1, n2] {
        let nibble;
        // 0-9
        if n > 47 && n < 58 {
            // The letter "0" is in the ASCII table at position 48
            nibble = n - 48;
        }
        // A-F
        else if n > 64 && n < 71 {
            // The letter "A" (dec 10) in the ASCII table at position 65
            nibble = n - 55
        }
        // a-f
        else if n > 96 && n < 103 {
            // The letter "a" (dec 10) in the ASCII table at position 97
            nibble = n - 87
        } else {
            return Err("not a valid ascii hex character");
        }
        byte <<= 4;
        byte |= nibble;
    }
    Ok(byte)
}

/// Parse a byte string in the format 10:e3:33:22 or 23-ff-ff-aa.
/// The regex for the format is "^[:xdigit:]{2}([-:][:xdigit:]{2})*$" or "^[:xdigit:]{2}+$"
pub fn parse_byte_string(val: &BStr) -> Result<Vec<u8>, &'static str> {
    if val.len() < 2 {
        return Err("byte-string must contain at least one byte");
    }
    let mut bytes = Vec::new();
    let (first, rest) = val.split_at(2);
    let byte = parse_ascii_byte(first[0], first[1])?;
    bytes.push(byte);
    match rest.first() {
        Some(b':' | b'-') => {
            if rest.len() % 3 != 0 {
                return Err("invalid byte-string format");
            }
            for group in rest.chunks_exact(3) {
                if ![b':', b'-'].contains(&group[0]) {
                    return Err("invalid byte-string separator");
                }
                let byte = parse_ascii_byte(group[1], group[2])?;
                bytes.push(byte);
            }
        }
        _ => {
            if rest.len() % 2 != 0 {
                return Err("invalid byte-string format");
            }
            for group in rest.chunks_exact(2) {
                let byte = parse_ascii_byte(group[0], group[1])?;
                bytes.push(byte);
            }
        }
    }
    Ok(bytes)
}

/// Parse a string as bytes, including un-escaping escaped characters.
/// (code taken from https://github.com/BurntSushi/ripgrep/blob/master/crates/cli/src/escape.rs)
/// The string passed here is expected to have been a quoted string. That is validated up the stack.
pub fn parse_escaped_byte_string(val: &BStr) -> Result<Vec<u8>, &'static str> {
    if val.is_empty() {
        return Err("byte-string must not be empty");
    }
    let val = std::str::from_utf8(val).map_err(|_| "byte-string is not valid utf-8")?;
    /// Monitor where we we are in the parsing escape state
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

    let mut bytes = Vec::new();
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
                    let byte = parse_ascii_byte(first as u8, c as u8)?;
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
pub fn parse_ip_net(val: &BStr) -> Result<IpNet, String> {
    let val = std::str::from_utf8(val).map_err(|_| "Not a valid utf-8 string".to_string())?;
    // Try to parse first as a single ip address, if it does not work, try as a cidr
    val.parse::<IpAddr>()
        .map(IpNet::from)
        .or_else(|_| val.parse::<IpNet>())
        .map_err(|e| format!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::{
        parse_ascii_byte,
        parse_byte_string,
        parse_escaped_byte_string,
        parse_ip_net,
        parse_mac_addr,
        parse_regex,
        parse_u16,
    };
    use crate::{
        mac_addr::MacAddr,
        test_utils::init_test_logging,
    };
    use bstr::ByteSlice;
    use tracing::info;

    #[test]
    fn test_parse_u16() {
        init_test_logging();

        for val in [u16::MIN, u16::MAX] {
            info!("Parsing \"{val}\" as u16 - should succeed");
            let num = parse_u16(val.to_string().as_str().into()).unwrap();
            assert_eq!(val, num);
        }

        let num = (u16::MAX as u32 + 1).to_string();
        for val in [
            "25d".as_bytes(),
            "-1".as_bytes(),
            num.as_bytes(),
            "".as_bytes(),
            b"\xFF\xFF",
        ] {
            let val = val.into();
            info!("Parsing \"{val}\" as u16 - should fail");
            let res = parse_u16(val);
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
            let mac_addr = parse_mac_addr(val.as_str().into()).unwrap();
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
            let res = parse_mac_addr(val.into());
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
            let res = parse_regex(val.into());
            assert!(res.is_ok());
        }

        for val in [
            "(1234".as_bytes(),
            r"\".as_bytes(),
            "".as_bytes(),
            b"\xFF\xFF",
        ] {
            let val = val.into();
            info!("Parsing \"{val}\" as regex - should fail");
            let res = parse_regex(val);
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_parse_ascii_byte() {
        init_test_logging();

        for (val, expected) in [
            ((b'0', b'0'), 0),
            ((b'a', b'0'), 160),
            ((b'a', b'2'), 162),
            ((b'A', b'b'), 171),
        ] {
            info!("Parsing \"{val:?}\" as ascii byte - should succeed");
            let res = parse_ascii_byte(val.0, val.1).unwrap();
            assert_eq!(res, expected);
        }

        for val in [(0, 0), (b'z', b'0'), (255, b'0')] {
            info!("Parsing \"{val:?}\" as ascii byte - should fail");
            let res = parse_ascii_byte(val.0, val.1);
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
            ("00-11-22-33-44-55", vec![0, 17, 34, 51, 68, 85]),
            ("00:11-22:33-44:55", vec![0, 17, 34, 51, 68, 85]),
        ] {
            info!("Parsing \"{val}\" as byte string - should succeed");
            let res = parse_byte_string(val.into()).unwrap();
            assert_eq!(res, expected);
        }

        for val in [
            "",
            "0",
            "1",
            "a",
            "A",
            "x1",
            "~1",
            "10Z1",
            "10&20$30",
            "10-1",
            "101",
            "00-11^22",
            "00:11:22:Zz",
        ] {
            info!("Parsing \"{val}\" as byte string - should fail");
            let res = parse_byte_string(val.into());
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_parse_escaped_string_as_byte() {
        init_test_logging();

        for (val, expected) in [
            (r"\", b"\\".to_vec()),
            ("simple string", b"simple string".to_vec()),
            (r"\\escaped \\ slash \\", b"\\escaped \\ slash \\".to_vec()),
            (r"not an escape \w", b"not an escape \\w".to_vec()),
            (r"\xFF", b"\xFF".to_vec()),
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
            let res = parse_escaped_byte_string(val.into()).unwrap();
            assert_eq!(res, expected);
        }

        for val in [b"".as_bstr(), b"\xFF\xFF".as_bstr()] {
            info!("Parsing \"{val}\" as escaped bytes - should fail");
            let res = parse_escaped_byte_string(val);
            assert!(res.is_err());
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
            let res = parse_ip_net(val.into());
            assert!(res.is_ok());
        }

        for val in [
            "10.1.1".as_bytes(),
            "fd00:".as_bytes(),
            "".as_bytes(),
            b"\xFF\xFF",
        ] {
            let val = val.into();
            info!("Parsing \"{val}\" as ip - should fail");
            let res = parse_ip_net(val);
            assert!(res.is_err());
        }
    }
}
