//! Big hacks for improved stack trace behavior
//!
//! # Background
//!
//! The Unreal debugger interface documentation claims that the `AddCallStack` function provides a
//! string "that contains the class name as well as the line number". This is not true - at least
//! not in XCOM EW or XCOM 2 - it has only the class name. We only get the line number for the
//! topmost entry on the stack, because that comes through the EditorLoadClass/EditorGotoLine calls
//! that come before populating the stack. We get the qualified name for each class in the other
//! frames so we can derive their source files, but we don't have any line info.
//!
//! This is not a problem for the uscript debugger available on Google Code that plugs directly
//! into Unreal with its own window system, as that implementation doesn't print any line numbers
//! on the stack frames at all. It just uses the `EditorLoadClass` and `EditorGotoLine` calls to
//! jump to the right file and line for the top-most entry. When switching stacks we get refreshed
//! watch data and EditorLoadClass/EditorGotoLine for the new frame, so the debugger is able to
//! jump to the correct line on a frame switch.
//!
//! It is a problem for DAP, because on each break DAP will send a "StackTrace" request and the
//! response is expected to have all the source file and line number positions for each entry in
//! the call stack, and we don't have the line for anything except the top frame. The editor also
//! displays this info for the entire callstack, so we wind up with 0 for everything except the top
//! one.
//!
//! # Safe behavior
//!
//! The default behavior in this implementation is to send "0" as lines for all the frames we don't
//! have line info for. When the user clicks on a stack frame other than the top-most DAP will
//! inform us of the stack switch by requesting the variables for that frame. This gets forwarded
//! to the adapter, which must trigger a `changestack` command to Unreal to request the variables
//! for that frame. This has the side effect of giving us the EditorLoadClass/EditorGotoLine pair,
//! so we get the line number for this frame. The adapter then sends an `Invalidated` event to the
//! client to invalidate the stack, prompting DAP to re-request this stack info and we can then
//! provide the line we now have.
//!
//! The end result is that it works, but is a little ugly. Clicking on a frame will cause the
//! editor to load the file but since the line number is not available it leaves the view at the
//! top of the file with no highlighted line (at least for VSCode). The frame invalidation will
//! immediately activate and update the line number for that frame to the correct value. Clicking
//! again on the same frame will then jump to and highlight the correct line. So it works, as long
//! as you double-click each new stack entry instead of single-clicking.
//!
//! # Unsafe behavior
//!
//! The full call stack with line info is available in Unreal, but not exposed through the
//! debugging interface. With a little reverse engineering for specific games we can locate this
//! info to display the line number for each call stack entry when we get the break event without
//! needing to wait for any given frame to be selected by the user. This is unsafe, and not just in
//! the Rust terminology (although it is that too) because the data structures involved are not
//! documented as part of the public interface and are subject to change. But since nobody is
//! releasing Unreal 3.x games anymore and existing ones are no longer regluarly patched this
//! should be safe enough for specific games with an opt-in mechanism.
//!
//! This has been tested with XCOM 2 War of the Chosen (64-bit) and XCOM: Enemy Within (32-bit),
//! as well as both the 32 and 64-bit versions of the generic 2011-09 UDK. The constants are
//! the same for all tested games of the same architecture, so the values included here should have
//! a good chance of working for other games too unless the debugger integration is heavily
//! modified.
//!
//! ## Implementation
//!
//! The names listed here are only the ones I gave to the particular data structures based on what
//! I could figure out they did or in some cases from looking at assertion strings in the binary.
//! They are almost certainly not the correct names used in the UDK source.
//!
//! The game loads the debugger interface DLL via `LoadLibrary` and uses `GetProcAddress` on all
//! the documented API names for the debugger interface. These are all recorded in an object I've
//! called `DebuggerInterface` which holds onto the function pointers and the handle to the DLL, as
//! well as various functions for calling into the interface DLL and handling the callback.
//!
//! The `DebuggerInterface` object is itself contained in another object I've called the
//! `DebuggerCore`. This object is responsible for managing the interface instance, as well as
//! containing logic for handling the higher level parts of the debugging process. For example,
//! when a breakpoint is it this object has a function responsible for processing all the various
//! steps of managing a break, such as building and sending the call stack and all the watch data
//! to the interface object which in turn dispatches them to the external interface DLL.
//!
//! The `DebuggerCore` instance is also exposed through an export in the game exe called
//! `GDebugger`. Using `GetProcAddress` on this name in the exe module will give you a pointer to
//! the debugger core instance, giving us access to everything in the `DebuggerCore` provided we
//! can figure out where it lives in that object.
//!
//! The debugger core has a member pointing to an object holding call stack information. I've
//! called this the _callstack manager_.
//!
//! The callstack manager contains a member with the current callstack depth, and another that
//! points to an array of _callstack entry_ objects.
//!
//! Unreal special-cases the last entry of the array (the top-most frame) and pulls from it the
//! package name, class name, line number, and current object name. These are sent to the interface
//! object and then to the interface DLL's various API points such as `EditorLoadClass`,
//! `EditorGotoLine`, and `SetCurrentObjectName`, as well as locking the watch lists, sending all
//! watch data, and then unlocking the watch lists. This is the same set of steps that are run when
//! switching stack frames, except there they are done for a frame that isn't the top-most. After
//! sending the top frame state it builds the call stack by walking the array and pulling only the
//! package and class names, then passing those to build the callstack the interface DLL sees.
//!
//! Within each callstack entry there is a member pointing to an array of line numbers, and another
//! member that indicates the index into this array. This index counts from 1, so to find the line
//! for any given callstack entry we just take the index, subtract 1, and use this to index into
//! the array of 32bit integer values for the line data.
//!
//! # Hints for locating structures for other games
//!
//! This section may be useful for anyone trying to get this working for other games if the default
//! settings I've included here don't work. I've included a lot of detail to also remind myself
//! the steps taken if I need to do it again.
//!
//! This example uses the 32-bit version of the generic UDK 2011-09 build. This is available from
//! Nexus and was reversed using IDA Pro. The steps are only hints, and especially on 32-bit
//! platforms the decompiler performs poorly on some functions without more type hints so adding
//! structure types and filling out some of the fields as you work through this can help a lot.
//!
//! The goal is to figure out all the constant values for the [`StackHackModel`] struct. If the
//! game is similar to the stock UDK 3 implementation all of these constants can be found starting
//! from a single function responsible for sending the current file, line, and watch info when
//! you issue the `changestacks` command. The simplest method is to simply search for this string
//! and find the function that is called when this string matches, but this will also describe
//! the much longer process to better build up some definitions for the structure and help make
//! sure we are in the right place. Skip to the `Deriving the Constants` section to skip the
//! initial setup and verification.
//!
//! ## Getting started the long way
//!
//! Start by looking for the `GDebugger` export, which should be in the export list for the
//! game executable.
//!
//! Search XREFs for writes to this symbol. In the sample UDK there is only a single write. Jump
//! to this function, and it occurs in the constructor for the `DebuggerCore` object. This can be
//! verified by checking that it writes a fixed data offset into the first _size_ bytes of the
//! parameter to the function, and later writes `this` to `GDebugger`. This gives us the virtual
//! function table of `DebuggerCore` as well as the initialization of all fields including the
//! callstack manager. This would tell us the offset of the callstack manager, but it is not
//! obvious which field it is at this point since the only thing this function does is allocate
//! it, initialize it to zeros, and store the pointer in `this`. It does the same thing to a
//! few other fields, so we don't really know which is important. Note the vtable offset: give it
//! a name and optionally bookmark it. You can also check XREFs for calls to this function (in my
//! case there is only 1) and this caller should look relevant: there's a test of GDebugger and
//! if it's set there is a reference to a string "The debugger can only be initialized once". It
//! also calls a function with a fixed small value that should be an allocation, which tells you
//! the size of the debugger core object (in this case for 32 bit, 144 bytes). Create a struct
//! type of this size with a bunch of unknown fields and change the type of the parameter of the
//! constructor to this type. This should improve the decompilation of the debugger core ctor.
//!
//! Another thing this function does is allocate and initialize the interface object. The pattern
//! to search for here is:
//!   - A call to some function that takes a relatively small constant as the first argument. This
//!   is the alloation call, and in the UDK version I used it allocates 188 bytes. This seems
//!   reasonable and can be used to start fleshing out a struct type for the `DebuggerInterface`
//!   object.
//!   - This memory is then passed as an argument to some other function, which should be the
//!   constructor for the `DebuggerInterface` object. This takes an additional parameter which is
//!   the name of the interface dll.
//!   - The pointer is stored into `this`, in my case at offset 0x60. Rename this field to
//!   `interface`.
//!
//! From inside the interface ctor you can find the vtbl for the interface, note this too.
//!
//! Near the bottom of the the core ctor there is a virtual call through the interface's
//! vtbl at index 0 that passes the debugger core instance as the next parameter afer the
//! interface 'this'. Go to the definition of the interface vtbl and jump to the first function
//! in that table. In this function there is a test of something that looks like a flag against
//! 0 (likely an "are we already initialized" test), and if it's zero it invokes a function
//! and then makes 4 non-virtual but indirect calls through fields in the interface object.
//! Finally there is virtual call outside the test.
//!
//! Jump to the directly called funtion and note the calls and strings: a call to `LoadLibrary`,
//! many calls to `GetProcAddress` with constants that name the various entry points to the
//! interface DLL. This is the function that loads the external DLL and hooks up all the
//! API entries and verifies we have been looking in the right spot so far.
//!
//! Next is to find the code responsible for switching call stacks. From this setup function
//! we can see the call to `GetProcAddress` that loates `SetCallback` and stores it into the
//! interface object. Name this offset (in the UDK case it's at 0x80). Head back to the calling
//! function (the virtual function in `DebuggerInstance` and you should now see that one of
//! the indirect calls is through the offset that received the address of `SetCallback`. It
//! takes a fixed address as an argument, jump to that address to see the function pointer
//! that gets passed to the interface DLL. This contains a direct call to a non-virtual function
//! in the debugger core, passing `GDebugger` as the receiver. Jump into this function, and note
//! that it has a bunch of if tests against various fixed strings for the different commands
//! you can send unreal. In particular we want `changestack`. (Note also that there is an
//! undocumented `setcondition` command). The block for `changestack` has some calls and then
//! a call to `wtoi` to convert the stack ID to an integer, and passes this to another function.
//! This is the one we're after - go into it.
//!
//! ## Deriving the Constants
//!
//! (If you skipped ahead, find this function by looking for references to the `changestack`
//! string and then finding the function that gets invoked after a `wtoi` call and is passed
//! the parsed index argument).
//!
//! This function is responsible for sending the bits of info related to a single stack frame:
//! it will eventually call through the interface to invoke the `EditorLoadClass`,
//! `EditorGotoLine`, and `SetCurrentObjectName` to set the current position, as well as locking
//! all watches, sending all watch data, and unlocking the watches. Near the bottom of this
//! function is a call through the interface vtbl passing a whole bunch of parameters, and one
//! of these should be the line number that `EditorGotoLine` needs. We need to figure out
//! which one is the line number and then how that is derived. IDA automatically determined most
//! of the function signature (including several widechar pointers for strings) but has two
//! possible `int` parameters. Looking at how they are computed one is the result of a function
//! call and the other is the result of dereferencing a computed pointer. This computation is the
//! one we want, and is the 2nd last parameter in this case. You can also verify this dynamically
//! by setting a breakpoint here, loading the game in the debugger, and toggling debug mode. You
//! can also peek into the function call the other parameter makes and note that it does a bunch of
//! string compares against different constants that don't look relevant.
//!
//! In the UDK the decompiled line number is `v14`, which has the initial value
//! `v14 = *(_DWORD*)(v4[3] + 4 * v4[4] - 4)`. Building up some more types can help
//! make this less mysterious, but from earlier reversing knowledge we know that the line
//! number comes from indexing some properties in a callstack entry structure. From this raw
//! format we can tell that `v4` is the entry, `v4[3]` is the address of the start of the line
//! array, and `v4[4]` has the line index. Translating from a `DWORD*` index 3 means an offset of
//! 0xc to the line array pointer and index 4 means an offset of 0x10 to the line index. The -4
//! is to account for the line index being 1-indexed. So for the default UDK this gives us the
//! values 0xc for the `entry_line_array_offset` part of the model, and 0x10 for
//! `entry_line_index_offset`.
//!
//! Now figure out where `v4` comes from. In the UDK this is:
//!
//! > `v4 = (DWORD*)sub_EF6690((*DWORD)(v3 + 12) - stackIdx - 1);`
//! 
//! Where `stackIdx` is the parameter to this function. In turn v3 comes from:
//!
//! > `v3 = this->field_5C`
//!
//! Again from previous knowledge this 0x5c offset is the offset to the callstack
//! manager pointer, so `core_callstack_manager_offset` is 0x5c. We can also see
//! that this code is inside an if check:
//!
//! > `if (stackIdx < *(DWORD*)(v3 + 12)`
//!
//! Which looks like the bounds check against the stack size. The +12 means that
//! the `manager_callstack_depth_offset` value is 0xc and this is also used in
//! the argument to the function that presumably returns the address of the callstack
//! entry. The logic in the argument determines the callstack entry which are internally
//! stored from the bottom of the stack to the top of the stack. Since stack index 0
//! means "topmost entry" if the callstack depth is N we actually want to fetch the entry
//! at index N-1. Jump into this function.
//!
//! NOTE: The version of IDA I used does not correctly decompile the function we just
//! left with the logic described above unless you have correctly set up structures
//! to model these different types and their fields. In particular the call to
//! `sub_EF6690` appeared decompiled to be a member call on `this` (`DebuggerCore*`),
//! but it's actually a member call on the callstack mgr. This is more obvious looking
//! at the disassembly than the pseudocode if you have incomplete type info.
//!
//! This function has some more bounds checking, but the return value is:
//!     `return this->field_8 + (idx << 6);`
//!
//! So the address of the callstack entry array is at offset 8 from the manager,
//! and each callstack entry is 2^6=64 bytes. This gives us `entry_size` and
//! `manager_callstack_entry_array_offset`, the last two pieces of information.

use std::ffi::c_char;

/// A model representing the expected layout within a `DebuggerCore` instance.
///
/// This is definitely architecture-dependent and may be game-dependent.
///
/// The formula to find the line for a particular stack entry `idx` in the given
/// core instance `core` is roughly:
///
/// ```c
/// char *manager = *(char**)(core + core_callstack_manager_offset);
/// int depth = *(int*)(manager + manager_callstack_depth_offset);
/// assert (idx <= depth);
/// char *entry = *(char**)(manager + manager_callstack_entry_array_offset + (entry_size * idx));
/// int line_idx = *(int*)(entry + entry_line_index_offset);
/// int *line_array = *(int**)(entry + entry_line_array_offset);
/// int line = line_array[line_idx - 1];
/// ```
pub struct StackHackModel {
    /// The offset from the start of the `DebuggerCore` instance to the manager
    /// pointer.
    pub core_callstack_manager_offset: usize,

    /// The offset from the start of the `CallstackManager` instance to the callstack
    /// depth value.
    pub manager_callstack_depth_offset: usize,

    /// The offset from the start of the `CallstackManager` instance to the pointer
    /// to the start of the callstack entry array.
    pub manager_callstack_entry_array_offset: usize,

    /// The size of a callstack entry in the entry array.
    pub entry_size: usize,

    /// The offset from the start of a `CallstackEntry` to the line index value.
    pub entry_line_array_offset: usize,

    /// The offset from the start of a `CallstackEntry` to the pointer to the
    /// start of the line array.
    pub entry_line_index_offset: usize,
}

/// The model for 32-bit Unreal games. Verified with the stock UDK 2011-09 32-bit
/// build and the implementation in XCOM: Enemy Within.
#[cfg(target_pointer_width = "32")]
pub const DEFAULT_MODEL: StackHackModel = StackHackModel {
    core_callstack_manager_offset: 0x5c,
    manager_callstack_depth_offset: 0x0c,
    manager_callstack_entry_array_offset: 0x8,
    entry_size: 0x40,
    entry_line_array_offset: 0xc,
    entry_line_index_offset: 0x10,
};

/// The model for 64-bit Unreal games. Verified with the stock UDK 2011-09 64-bit
/// build and the implementation in XCOM 2 War of the Chosen.
#[cfg(target_pointer_width = "64")]
pub const DEFAULT_MODEL: StackHackModel = StackHackModel {
    core_callstack_manager_offset: 0x78,
    manager_callstack_depth_offset: 0x14,
    manager_callstack_entry_array_offset: 0xc,
    entry_size: 0x5c,
    entry_line_array_offset: 0x18,
    entry_line_index_offset: 0x20,
};

/// A representation of a StackHack implementation.
pub struct StackHack {
    core: *const c_char,
    model: StackHackModel,
}

impl StackHack {
    /// Construct a new StackHack instance from the given pointer and a model.
    pub fn new(core: *const c_char, model: StackHackModel) -> Self {
        Self { core, model }
    }

    /// Look up the line for the given entry index in the current stack frame.
    ///
    /// # Returns
    /// A Some holding the line number for this stack entry, or None
    /// if the given index is out of bounds of the current stack.
    ///
    /// # Safety
    /// Not even a little. If the chosen model does not match the game
    /// we're attached to this will either crash or just return garbage.
    pub unsafe fn line_for(&self, idx: usize) -> Option<i32> {
        let core_usize = self.core as usize;
        let manager_usize = core_usize + self.model.core_callstack_manager_offset;
        let manager_addr = self.core.add(self.model.core_callstack_manager_offset);
        let manager_add_usize = manager_addr as usize;
        let manager = *manager_addr as *const u8;
        let depth_addr = manager.add(self.model.manager_callstack_depth_offset) as *const u32;
        let depth_usize = depth_addr as usize;
        let depth = *depth_addr as usize;
        if idx >= depth {
            return None;
        }

        // The index given uses index 0 as "top-most stack entry", but Unreal
        // stores the frames in order from bottom-most to top-most so we need
        // to compute the actual index into the array. For example 0 would be
        // the element at depth-1.
        let inverted_idx = depth - idx - 1;

        let entry_addr = manager
            .add(self.model.manager_callstack_entry_array_offset)
            .add(self.model.entry_size * inverted_idx);

        let entry = *entry_addr as *const u8;
        let line_idx_addr = entry.add(self.model.entry_line_index_offset) as *const u32;

        let line_idx = *line_idx_addr as usize;
        let line_array_addr = entry.add(self.model.entry_line_array_offset);
        let line_array = *line_array_addr as *const i32;
        let line = *line_array.add(line_idx - 1);

        Some(line)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[cfg(target_pointer_width = "64")]
    mod harness {
        #[repr(C, packed(4))]
        pub struct DebugCore {
            pub padding: [u64; 15],
            pub callstack_mgr: *const CallstackMgr,
        }

        #[repr(C, packed(4))]
        pub struct CallstackMgr {
            pub padding1: u64,
            pub padding2: u32,
            pub entry_ptr: *const CallstackEntry,
            pub depth: u32,
        }

        #[repr(C, packed(4))]
        pub struct CallstackEntry {
            pub padding1: [u64; 3],
            pub line_array: *const u32,
            pub line_index: u32,
            pub padding2: u32,
            pub padding3: [u64; 6],
            pub padding4: u32,
        }

        pub fn make_test_entry(line_array: *const u32) -> CallstackEntry {
            CallstackEntry {
                padding1: [0; 3],
                line_array,
                line_index: 2,
                padding2: 0,
                padding3: [0; 6],
                padding4: 0,
            }
        }

        pub fn make_test_manager(entry: *const CallstackEntry) -> CallstackMgr {
            CallstackMgr {
                padding1: 0,
                padding2: 0,
                entry_ptr: entry,
                depth: 7,
            }
        }

        pub fn make_core(mgr: *const CallstackMgr) -> DebugCore {
            DebugCore {
                padding: [0; 15],
                callstack_mgr: mgr,
            }
        }
    }

    #[cfg(target_pointer_width = "32")]
    mod harness {
        #[repr(C, packed(4))]
        pub struct DebugCore {
            pub padding: [u32; 23],
            pub callstack_mgr: *const CallstackMgr,
        }

        #[repr(C, packed(4))]
        pub struct CallstackMgr {
            pub padding1: u32,
            pub padding2: u32,
            pub entry_ptr: *const CallstackEntry,
            pub depth: u32,
        }

        #[repr(C, packed(4))]
        pub struct CallstackEntry {
            pub padding1: [u32; 3],
            pub line_array: *const u32,
            pub line_index: u32,
            pub padding2: [u32; 11],
        }

        pub fn make_test_entry(line_array: *const u32) -> CallstackEntry {
            CallstackEntry {
                padding1: [0; 3],
                line_array,
                line_index: 2,
                padding2: [0; 11],
            }
        }

        pub fn make_test_manager(entry: *const CallstackEntry) -> CallstackMgr {
            CallstackMgr {
                padding1: 0,
                padding2: 0,
                entry_ptr: entry,
                depth: 7,
            }
        }

        pub fn make_core(mgr: *const CallstackMgr) -> DebugCore {
            DebugCore {
                padding: [0; 23],
                callstack_mgr: mgr,
            }
        }
    }

    use harness::*;

    fn make_line_array() -> [u32; 12] {
        [2, 73, 179, 283, 419, 547, 661, 811, 947, 1087, 1229, 1381]
    }

    #[test]
    fn check_entry() {
        let line_array = make_line_array();
        let entry = make_test_entry(line_array.as_ptr());
        let ptr = std::ptr::addr_of!(entry);
        let base = ptr as usize;
        let line_array_addr = std::ptr::addr_of!(entry.line_array) as usize;
        let line_index_addr = std::ptr::addr_of!(entry.line_index) as usize;
        assert_eq!(
            line_array_addr - base,
            DEFAULT_MODEL.entry_line_array_offset
        );
        assert_eq!(
            line_index_addr - base,
            DEFAULT_MODEL.entry_line_index_offset
        );
        assert_eq!(
            core::mem::size_of::<harness::CallstackEntry>(),
            DEFAULT_MODEL.entry_size
        );
    }

    #[test]
    fn check_callstack_manager() {
        let line_array = make_line_array();
        let entry: [CallstackEntry; 1] = [make_test_entry(line_array.as_ptr())];
        let mgr = make_test_manager(entry.as_ptr());

        let base = std::ptr::addr_of!(mgr) as usize;
        let callstack_depth_addr = std::ptr::addr_of!(mgr.depth) as usize;
        let callstack_entry_array_addr = std::ptr::addr_of!(mgr.entry_ptr) as usize;

        assert_eq!(
            callstack_depth_addr - base,
            DEFAULT_MODEL.manager_callstack_depth_offset
        );
        assert_eq!(
            callstack_entry_array_addr - base,
            DEFAULT_MODEL.manager_callstack_entry_array_offset
        );
    }

    #[test]
    fn check_core() {
        let line_array = make_line_array();
        let entry: [CallstackEntry; 1] = [make_test_entry(line_array.as_ptr())];
        let mgr = make_test_manager(entry.as_ptr());
        let core = make_core(&mgr as *const CallstackMgr);

        let base = std::ptr::addr_of!(core) as usize;
        let mgr_addr = std::ptr::addr_of!(core.callstack_mgr) as usize;

        assert_eq!(mgr_addr - base, DEFAULT_MODEL.core_callstack_manager_offset);
    }

    #[test]
    fn it_works() {
        let line_array = make_line_array();
        let entry: [CallstackEntry; 1] = [make_test_entry(line_array.as_ptr())];
        let mgr = make_test_manager(entry.as_ptr());
        let core = make_core(&mgr as *const CallstackMgr);
        let core_usize = &core as *const DebugCore as usize;
        let core_ptr = &core as *const DebugCore;
        let hack = StackHack::new(core_ptr as *const c_char, DEFAULT_MODEL);
        let line = unsafe { hack.line_for(0) };
        assert_eq!(line.unwrap(), 37);
    }
}
