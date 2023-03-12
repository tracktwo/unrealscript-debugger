//! Variable References
//!
//! DAP refers to variables with references, see "Lifetime of Object References" in
//! <https://microsoft.github.io/debug-adapter-protocol/overview>. DAP specifies these as 'numbers',
//! which are mapped to i64 values by the dap-rs crate but DAP only supports variable references in
//! the open interval (0-2^31). That is, it must be a non-negative number that fits in an i32.
//!
//! When we emit a scope or a variable to DAP we assign it a variable reference, and DAP can
//! request children of that scope or variable (for structured variables) by issuing a 'variables'
//! request with the reference we previously assigned. These assignments are valid for as long as
//! the debugger is stopped, so we don't need to maintain them across resumes.
//!
//! The VariableReference struct represents a way to identify a particular variable (or scope), and
//! exposes ways to convert that to or from an i64 value for DAP to work with. The variable
//! reference contains the following info:
//!
//! - The unreal watch kind (local var, global var, or user watch) - The frame index for this
//! variable - An index for this particular variable within the frame and watch kind.
//!
//! This information gets encoded into an i32 value according to the following scheme:
//!
//! <Bit 31> 0WWFFFFF FFFFVVVV VVVVVVVV VVVVVVVV <bit 0>
//!
//! - The topmost bit 31 is always 0.
//! - 2 bits 29-30 are allocated to the watch kind.
//! - 9 bits 20-28 are allocated to the frame index.
//! - 20 bits 0-19 are allocated to the variable index.
//!
//! This scheme puts some severe limits on the total number of frames and variables within
//! a frame that can be supported, but it allows trivial mapping between variable references
//! and the internal data structures that hold variable values without requiring a complex
//! data structure to record that mapping. This scheme still allows for 512 stack frames and
//! one million variables (including children) per frame and these limits are unlikely to be
//! exceeded by Unreal.
//!
//! Note: 0 is not a valid variable reference. Avoid this we map the watch kind so that the
//! 00 bit pattern is not used.

use common::{FrameIndex, VariableIndex, WatchKind};

use bit_field::BitField;

#[derive(Debug)]
pub struct VariableReference {
    kind: WatchKind,
    frame: FrameIndex,
    variable: VariableIndex,
}

const VARIABLE_RANGE: std::ops::Range<usize> = 0..20;
const FRAME_RANGE: std::ops::Range<usize> = 20..29;
const WATCH_RANGE: std::ops::Range<usize> = 29..31;

impl VariableReference {
    /// Create a new variable reference for the given watch kind, frame, and variable.
    pub fn new(kind: WatchKind, frame: FrameIndex, variable: VariableIndex) -> VariableReference {
        VariableReference {
            kind,
            frame,
            variable,
        }
    }

    /// Decode an i64 from DAP back into a variable reference, or None if it is not
    /// a valid encoding.
    pub fn from_int(v: i64) -> Option<VariableReference> {
        // Treat the value as unsigned. This is safe since we should never have a variable
        // reference that is negative, and all the sub-components are considered unsigned.
        //
        // This is necessary so that 'get_bits' gives us unsigned values, not signed.
        let v: u64 = v as u64;

        // Extract the watch value. This may fail if we have a bad encoding.
        let kind = match v.get_bits(WATCH_RANGE) {
            1 => WatchKind::Local,
            2 => WatchKind::Global,
            3 => WatchKind::User,
            _ => return None,
        };

        // Extract the frame index. This cannot fail since all values in this bit range
        // should be representable as a frame index.
        let frame: FrameIndex =
            FrameIndex::create(v.get_bits(FRAME_RANGE).try_into().unwrap()).unwrap();

        // Extract the variable index. This cannot fail since all values in this bit range
        // should be representable as a variable index.
        let variable =
            VariableIndex::create(v.get_bits(VARIABLE_RANGE).try_into().unwrap()).unwrap();

        Some(VariableReference {
            kind,
            frame,
            variable,
        })
    }

    /// Encode a variable reference to an i64 for DAP. In reality this will
    /// always be a non-negative value that fits in an i32.
    pub fn to_int(&self) -> i64 {
        let mut v: u64 = 0;
        v.set_bits(VARIABLE_RANGE, self.variable.into());
        v.set_bits(FRAME_RANGE, self.frame.into());
        match self.kind {
            WatchKind::Local => v.set_bits(WATCH_RANGE, 1),
            WatchKind::Global => v.set_bits(WATCH_RANGE, 2),
            WatchKind::User => v.set_bits(WATCH_RANGE, 3),
        };

        // This should always succeed: we never set the topmost bit.
        v.try_into().unwrap()
    }

    /// Obtain the kind
    pub fn kind(&self) -> WatchKind {
        self.kind
    }

    /// Obtain the frame
    pub fn frame(&self) -> FrameIndex {
        self.frame
    }

    // Obtain the variable
    pub fn variable(&self) -> VariableIndex {
        self.variable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_watch() {
        let v = VariableReference::new(
            WatchKind::Local,
            FrameIndex::create(0).unwrap(),
            VariableIndex::create(0).unwrap(),
        );
        assert_eq!(v.to_int(), 0x20000000);
    }

    #[test]
    fn global_watch() {
        let v = VariableReference::new(
            WatchKind::Global,
            FrameIndex::create(0).unwrap(),
            VariableIndex::create(0).unwrap(),
        );
        assert_eq!(v.to_int(), 0x4000_0000);
    }

    #[test]
    fn user_watch() {
        let v = VariableReference::new(
            WatchKind::User,
            FrameIndex::create(0).unwrap(),
            VariableIndex::create(0).unwrap(),
        );
        assert_eq!(v.to_int(), 0x60000000);
    }

    #[test]
    fn test_big_frame() {
        let v = VariableReference::new(
            WatchKind::Global,
            FrameIndex::create(0x1FF).unwrap(),
            VariableIndex::create(0).unwrap(),
        );
        assert_eq!(v.to_int(), 0x5FF00000);
    }

    #[test]
    fn test_big_variable() {
        let v = VariableReference::new(
            WatchKind::Global,
            FrameIndex::create(2).unwrap(),
            VariableIndex::create(0xF_FFFF).unwrap(),
        );
        assert_eq!(v.to_int(), 0x402F_FFFF);
    }

    #[test]
    fn test_non_zero() {
        // 0 is not a valid DAP variable reference. Ensure none of the watch kinds encode the 0th
        // frame and variable to the zero value.
        assert_ne!(
            VariableReference::new(
                WatchKind::Local,
                FrameIndex::create(0).unwrap(),
                VariableIndex::create(0).unwrap()
            )
            .to_int(),
            0
        );
        assert_ne!(
            VariableReference::new(
                WatchKind::Global,
                FrameIndex::create(0).unwrap(),
                VariableIndex::create(0).unwrap()
            )
            .to_int(),
            0
        );
        assert_ne!(
            VariableReference::new(
                WatchKind::User,
                FrameIndex::create(0).unwrap(),
                VariableIndex::create(0).unwrap()
            )
            .to_int(),
            0
        );
    }
}
