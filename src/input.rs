use crate::driver::ErrorKind;
use bstr::BStr;
use std::ops::{
    Index,
    Range,
    RangeFrom,
};

/// A wrapper over the input that validate that the input is not too long.
/// Additionally it enables indexing the input using u16s.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::Deref)]
pub(crate) struct Input<'a>(&'a BStr);

impl<'a> Input<'a> {
    pub(crate) fn new(input: &'a str) -> Result<Self, ErrorKind> {
        if input.len() >= usize::from(u16::MAX) {
            return Err(ErrorKind::InputTooLong);
        }
        Ok(Self(input.as_bytes().into()))
    }

    /// Return the length of the input as u16
    #[inline]
    pub(crate) fn len(&self) -> u16 {
        self.0.len() as u16
    }

    /// Get an item from the input using u16 as index
    #[inline]
    pub(crate) fn get(&self, index: u16) -> Option<&u8> {
        let index = usize::from(index);
        self.0.get(index)
    }
}

impl Index<u16> for Input<'_> {
    type Output = u8;

    #[inline]
    fn index(&self, index: u16) -> &Self::Output {
        let index = usize::from(index);
        &self.0[index]
    }
}

impl Index<Range<u16>> for Input<'_> {
    type Output = BStr;

    #[inline]
    fn index(&self, index: Range<u16>) -> &Self::Output {
        let index = usize::from(index.start)..usize::from(index.end);
        &self.0[index]
    }
}

impl Index<RangeFrom<u16>> for Input<'_> {
    type Output = [u8];

    #[inline]
    fn index(&self, index: RangeFrom<u16>) -> &Self::Output {
        let index = usize::from(index.start)..;
        &self.0[index]
    }
}

#[cfg(test)]
mod tests {
    use super::Input;
    use crate::driver::ErrorKind;

    #[test]
    fn test_input_error() {
        let filter = " ".repeat(usize::from(u16::MAX) + 1);
        let err = Input::new(&filter).unwrap_err();

        assert_eq!(err, ErrorKind::InputTooLong);
    }

    #[test]
    fn test_input_success() {
        let filter = "some string";
        let input = Input::new(filter).unwrap();

        // Index works
        assert_eq!(input[0], b's');
        // Deref works
        assert!(input.is_ascii());

        assert_eq!(input.clone(), input);

        let fmt = format!("{input:?}");
        let expected = format!("Input(\"{filter}\")");
        assert_eq!(fmt, expected);
    }
}
