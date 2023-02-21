//! Variable References

use common::WatchKind;

use bit_field::BitField;

/// DAP refers to variables with references, see "Lifetime of Object References"
/// in https://microsoft.github.io/debug-adapter-protocol/overview. DAP specifies
/// these as 'numbers', which are mapped to i64 values by the dap-rs crate. When
/// we emit a scope or a variable to DAP we assign it a variable reference, and
/// DAP can request children of that scope or variable (for structured variables)
/// by issuing a 'variables' request with the reference we previously assigned.
///
/// The VariableReference struct represents a way to identify a particular variable
/// (or scope), and exposes ways to convert that to or from an i64 value for DAP
/// to work with. The variable reference contains the following info:
///
/// - The unreal watch kind (local var, global var, or user watch)
/// - The frame index for this variable (always 0 for user watches)
/// - The index for this particular variable within the appropriate watch list.
///
/// This information gets encoded into an i64 value according to the following
/// scheme:
///
/// <Bit 63> 000000WW FFFFFFFF FFFFFFFF FFFFFFFF VVVVVVVV VVVVVVVV VVVVVVVV VVVVVVVV <Bit 0>
///
/// - The watch kind is encoded in the upper-most byte.
/// - 24 bits are allocated to the frame index (16.7 million frames)
/// - 32 bits are allocated to the variable index (4.2 billion variables per frame)
///
/// This scheme wastes some bits, but the client is unlikely to be able to support
/// any situation where we'd exceed these limits.
#[derive(Debug)]
struct VariableReference {
    kind: WatchKind,
    frame: u32,
    variable: u32,
}

impl VariableReference {
    /// Create a new variable reference for the given watch kind, frame, and variable.
    ///
    /// Panics: If the frame index is too big to encode.
    pub fn new(kind: WatchKind, frame: u32, variable: u32) -> VariableReference {
        if frame > 0xFFFFFF {
            panic!("Frame limit exceeded!");
        }

        VariableReference{ kind, frame, variable }
    }

    /// Decode an i64 from DAP back into a variable reference, or None if it is not
    /// a valid encoding.
    pub fn from_int(v: i64) -> Option<VariableReference> {

        // Extract the watch kind from the upper 8 bits. This may fail if the value
        // does not match the required format.
        let kind = match v.get_bits(56..63) {
            0 => WatchKind::Local,
            1 => WatchKind::Global,
            2 => WatchKind::User,
            _ => return None
        };

        // Extract the frame index. This cannot fail.
        let frame:u32 = v.get_bits(32..55).try_into().unwrap();

        // Extract the variable index. This cannot fail.
        let variable:u32 = v.get_bits(0..31).try_into().unwrap();

        Some(VariableReference{ kind, frame, variable })
    }

    /// Encode a variable reference to an i64 for DAP.
    pub fn to_int(&self) -> i64 {
        let mut v: i64 = 0;
        match self.kind {
            WatchKind::Local => v.set_bits(56..63, 0),
            WatchKind::Global => v.set_bits(56..63, 1),
            WatchKind::User => v.set_bits(56..63, 2),
        };

        v.set_bits(32..55, self.frame.into());
        v.set_bits(0..31, self.variable.into());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_watch() {
        let v = VariableReference::new(WatchKind::Local, 1, 0);
        assert_eq!(v.to_int(), 0x00000001_00000000);
    }

    #[test]
    fn global_watch() {
        let v = VariableReference::new(WatchKind::Global, 1, 0);
        assert_eq!(v.to_int(), 0x01000001_00000000);
    }
}
