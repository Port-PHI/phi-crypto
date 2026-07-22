// SPDX-License-Identifier: Apache-2.0
//! Handing a secret across a foreign-function boundary without leaving a copy behind.

use zeroize::{Zeroize, Zeroizing};

/// Moves a secret out of its [`Zeroizing`] wrapper for hand-off across an FFI boundary, without copying it.
pub fn into_boundary_owned<T: Zeroize + Default>(mut secret: Zeroizing<T>) -> T {
    core::mem::take(&mut *secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The value comes out intact — a move, not a reinterpretation.
    #[test]
    fn moves_the_value_out_unchanged() {
        let bytes = vec![9u8, 8, 7, 6];
        assert_eq!(into_boundary_owned(Zeroizing::new(bytes.clone())), bytes);

        let phrase = String::from("abandon abandon art");
        assert_eq!(into_boundary_owned(Zeroizing::new(phrase.clone())), phrase);
    }

    /// It is the SAME allocation, not a copy: the heap pointer is unchanged across the move.
    #[test]
    fn does_not_reallocate() {
        let held = Zeroizing::new(vec![1u8; 64]);
        let before = held.as_ptr();
        let owned = into_boundary_owned(held);
        assert_eq!(
            before,
            owned.as_ptr(),
            "the secret must be moved, not copied into a fresh allocation"
        );

        let held = Zeroizing::new("a long enough phrase to be heap allocated".to_string());
        let before = held.as_ptr();
        let owned = into_boundary_owned(held);
        assert_eq!(
            before,
            owned.as_ptr(),
            "the phrase must be moved, not copied"
        );
    }

    /// The wrapper is left empty, so the value cannot be read back out of it after the move and the wrapper's own drop has nothing to wipe.
    #[test]
    fn leaves_the_wrapper_empty() {
        let mut held = Zeroizing::new(vec![5u8; 32]);
        let owned = core::mem::take(&mut *held);
        assert_eq!(owned.len(), 32);
        assert!(held.is_empty(), "the wrapper must be emptied by the move");
    }
}
