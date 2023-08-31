use std::fmt::{
    Display,
    Error,
    Formatter,
};

pub const MAC_ADDR_LEN: usize = 6;

/// A MAC address is a unique identifier assigned to most network adapters
/// or network interface cards (NICs) by the manufacturer for identification,
/// IEEE 802 standards use 48 bites or 6 bytes to represent a MAC address.
/// This format gives 281,474,976,710,656 possible unique MAC addresses.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    derive_more::Constructor,
    derive_more::From,
    derive_more::Deref,
)]
pub struct MacAddr([u8; MAC_ADDR_LEN]);

impl Display for MacAddr {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl std::fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl TryFrom<&str> for MacAddr {
    type Error = ();

    /// Parse MAC Address from a string.
    ///
    /// # Arguments:
    /// * `value` - A buffer containing the mac-address in string representation.
    ///
    /// IEEE 802 standards define 3 commonly used formats to print a MAC address
    /// in hexadecimal digits:
    ///
    /// Six groups of two hexadecimal digits separated by hyphens (-), like 01-23-45-67-89-ab
    /// Six groups of two hexadecimal digits separated by colons (:), like 01:23:45:67:89:ab
    /// Three groups of four hexadecimal digits separated by dots (.), like 0123.4567.89ab
    ///
    /// See also:
    /// 1. https://en.wikipedia.org/wiki/MAC_address#Notational_conventions
    /// 2. IEEE Std 802-2014 - https://standards.ieee.org/standard/802-2014.html (clause 8)
    ///
    /// NB: while the IEEE reserves the colon notation for bit reversed representation
    ///    the IETF uses it for regular representation (see the wikipedia article and
    ///    https://www.ieee802.org/1/files/public/docs2020/yangsters-smansfield-mac-address-format-0420-v01.pdf).
    #[rustfmt::skip]
    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        const COLON: u8 = b':';
        const DASH: u8 = b'-';
        const DOT: u8 = b'.';
        match value.as_bytes() {
              &[a, b, COLON, c, d, COLON, e, f, COLON, g, h, COLON, i, j, COLON, k, l]
            | &[a, b, DASH, c, d, DASH, e, f, DASH, g, h, DASH, i, j, DASH, k, l]
            | &[a, b, c, DOT, d, e, f, DOT, g, h, i, DOT, j, k, l]
            | &[a, b, c, d, e, f, g, h, i, j, k, l] => {
                let mac = [
                    hex2byte(a, b)?,
                    hex2byte(c, d)?,
                    hex2byte(e, f)?,
                    hex2byte(g, h)?,
                    hex2byte(i, j)?,
                    hex2byte(k, l)?,
                ];
                Ok(mac.into())
            }
            _ => Err(()),
        }
    }
}

/// Convert ASCII hex char to a nibble.
#[inline]
fn hex2nibble(c: u8) -> Result<u8, ()> {
    match c {
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'0'..=b'9' => Ok(c - b'0'),
        _ => Err(()),
    }
}

/// Convert two ASCII hex chars to a byte.
#[inline]
fn hex2byte(a: u8, b: u8) -> Result<u8, ()> {
    let upper = hex2nibble(a)?;
    let lower = hex2nibble(b)?;
    Ok((upper << 4) | lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_string() {
        let mac = MacAddr::from([0xab, 0xcd, 0xef, 0x01, 0x02, 0x03]);
        assert_eq!("abcdef010203", mac.to_string());
    }

    #[test]
    fn test_hex2byte() {
        let good = b"0123456789abcdefABCDEF";
        let expected: &[u8] = &[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 10, 11, 12, 13, 14, 15,
        ];

        for i in 0..good.len() {
            assert_eq!(hex2nibble(good[i]), Ok(expected[i]));
        }
    }

    #[test]
    fn test_hex2byte_invalid() {
        let invalid = &[0x2f, 0x2F, 0x3a, 0x3A, b'@', b'G', b'`', b'g'];
        for &i in invalid {
            assert_eq!(hex2nibble(i), Err(()));
        }
    }

    #[test]
    fn test_mac_try_from_colon() {
        let buf1 = "ab:cd:ef:01:23:45";
        let buf2 = buf1.to_ascii_uppercase();
        let buf3 = "68:79:a1:b2:c3:fd";
        let buf4 = buf3.to_ascii_uppercase();

        let expected12 = MacAddr::from([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]);
        let expected34 = MacAddr::from([0x68, 0x79, 0xa1, 0xb2, 0xc3, 0xfd]);

        assert_eq!(MacAddr::try_from(buf1), Ok(expected12));
        assert_eq!(MacAddr::try_from(buf2.as_str()), Ok(expected12));
        assert_eq!(MacAddr::try_from(buf3), Ok(expected34));
        assert_eq!(MacAddr::try_from(buf4.as_str()), Ok(expected34));
    }

    #[test]
    fn test_mac_try_from_dash() {
        let buf1 = "ab-cd-ef-01-23-45";
        let buf2 = buf1.to_ascii_uppercase();
        let buf3 = "68-79-a1-b2-c3-fd";
        let buf4 = buf3.to_ascii_uppercase();

        let expected12 = MacAddr::from([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]);
        let expected34 = MacAddr::from([0x68, 0x79, 0xa1, 0xb2, 0xc3, 0xfd]);

        assert_eq!(MacAddr::try_from(buf1), Ok(expected12));
        assert_eq!(MacAddr::try_from(buf2.as_str()), Ok(expected12));
        assert_eq!(MacAddr::try_from(buf3), Ok(expected34));
        assert_eq!(MacAddr::try_from(buf4.as_str()), Ok(expected34));
    }

    #[test]
    fn test_mac_try_from_dot() {
        let buf1 = "abc.def.012.345";
        let buf2 = buf1.to_ascii_uppercase();
        let buf3 = "687.9a1.b2c.3fd";
        let buf4 = buf3.to_ascii_uppercase();

        let expected12 = MacAddr::from([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]);
        let expected34 = MacAddr::from([0x68, 0x79, 0xa1, 0xb2, 0xc3, 0xfd]);

        assert_eq!(MacAddr::try_from(buf1), Ok(expected12));
        assert_eq!(MacAddr::try_from(buf2.as_str()), Ok(expected12));
        assert_eq!(MacAddr::try_from(buf3), Ok(expected34));
        assert_eq!(MacAddr::try_from(buf4.as_str()), Ok(expected34));
    }

    #[test]
    fn test_mac_try_from_plain() {
        let buf1 = "abcdef012345";
        let buf2 = buf1.to_ascii_uppercase();
        let buf3 = "6879a1b2c3fd";
        let buf4 = buf3.to_ascii_uppercase();

        let expected12 = MacAddr::from([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]);
        let expected34 = MacAddr::from([0x68, 0x79, 0xa1, 0xb2, 0xc3, 0xfd]);

        assert_eq!(MacAddr::try_from(buf1), Ok(expected12));
        assert_eq!(MacAddr::try_from(buf2.as_str()), Ok(expected12));
        assert_eq!(MacAddr::try_from(buf3), Ok(expected34));
        assert_eq!(MacAddr::try_from(buf4.as_str()), Ok(expected34));
    }

    #[test]
    fn test_mac_eq() {
        let buf1 = "abcdef012345";
        let buf2 = buf1.to_ascii_uppercase();
        let buf3 = "ab:cd:ef:01:23:45";
        let buf4 = buf3.to_ascii_uppercase();
        let buf5 = "ab-cd-ef-01-23-45";
        let buf6 = buf5.to_ascii_uppercase();
        let buf7 = "abc.def.012.345";
        let buf8 = buf7.to_ascii_uppercase();

        let expected = MacAddr::new([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]);
        let m1 = MacAddr::try_from(buf1).unwrap();
        let m2 = MacAddr::try_from(buf2.as_str()).unwrap();
        let m3 = MacAddr::try_from(buf3).unwrap();
        let m4 = MacAddr::try_from(buf4.as_str()).unwrap();
        let m5 = MacAddr::try_from(buf5).unwrap();
        let m6 = MacAddr::try_from(buf6.as_str()).unwrap();
        let m7 = MacAddr::try_from(buf7).unwrap();
        let m8 = MacAddr::try_from(buf8.as_str()).unwrap();

        assert!(m1 == expected);
        assert!(m2 == expected);
        assert!(m3 == expected);
        assert!(m4 == expected);
        assert!(m5 == expected);
        assert!(m6 == expected);
        assert!(m7 == expected);
        assert!(m8 == expected);
    }

    #[test]
    fn test_mac_try_from_invalid() {
        let buf0 = "";
        let buf1 = "ab:cd:ef:01:23:4g";
        let buf2 = "ab:cd:ef:01:23:4";
        let buf3 = buf1.to_ascii_uppercase();
        let buf4 = buf2.to_ascii_uppercase();
        assert!(MacAddr::try_from(buf0).is_err());
        assert!(MacAddr::try_from(buf1).is_err());
        assert!(MacAddr::try_from(buf2).is_err());
        assert!(MacAddr::try_from(buf3.as_str()).is_err());
        assert!(MacAddr::try_from(buf4.as_str()).is_err());
    }
}
