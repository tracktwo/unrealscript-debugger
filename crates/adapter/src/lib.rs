
pub mod client;

mod comm;

use std::{
    collections::BTreeMap,
    path::{Component, Path},
};

use dap::{
    prelude::*,
    requests::{AttachRequestArguments, InitializeArguments, SetBreakpointsArguments},
    responses::ErrorMessage,
    types::{Capabilities, Source, Thread},
};
use serde_json::Value;
use thiserror::Error;

use common::{Breakpoint, DEFAULT_PORT};

use comm::UnrealChannel;

pub struct UnrealscriptAdapter {
    class_map: BTreeMap<String, ClassInfo>,
    channel: Option<Box<dyn UnrealChannel>>,
    // If true (the default and Unreal's native mode) the client expects lines to start at 1.
    // Otherwise they start at 0.
    one_based_lines: bool,
}

impl UnrealscriptAdapter {
    pub fn new() -> UnrealscriptAdapter {
        UnrealscriptAdapter {
            class_map: BTreeMap::new(),
            channel: None,
            one_based_lines: true,
        }
    }
}

#[derive(Error, Debug)]
pub enum UnrealscriptAdapterError {
    #[error("Unhandled command: {0}")]
    UnhandledCommandError(String),

    #[error("Invalid filename: {0}")]
    InvalidFilename(String),

    #[error("Not connected")]
    NotConnected,

    #[error("Connection failed")]
    ConnectionError,
}

impl UnrealscriptAdapterError {
    fn id(&self) -> i64 {
        match self {
            UnrealscriptAdapterError::UnhandledCommandError(_) => 1,
            UnrealscriptAdapterError::InvalidFilename(_) => 2,
            UnrealscriptAdapterError::NotConnected => 3,
            UnrealscriptAdapterError::ConnectionError => 4,
        }
    }

    pub fn to_error_message(&self) -> ErrorMessage {
        ErrorMessage {
            id: self.id(),
            format: self.to_string(),
            show_user: true,
        }
    }
}

type Error = UnrealscriptAdapterError;

impl Adapter for UnrealscriptAdapter {
    type Error = UnrealscriptAdapterError;
    fn accept(&mut self, request: Request, ctx: &mut dyn Context) -> Result<Response, Self::Error> {
        log::info!("Got request {request:#?}");
        let response = match &request.command {
            Command::Initialize(args) => self.initialize(args),
            Command::SetBreakpoints(args) => self.set_breakpoints(args),
            Command::Threads => self.threads(),
            Command::ConfigurationDone => {
                return Ok(Response::make_ack(ctx.next_seq(), &request)
                    .expect("ConfigurationDone can be acked"))
            }
            Command::Attach(args) => self.attach(args),
            Command::Disconnect(_args) => {
                return Ok(
                    Response::make_ack(ctx.next_seq(), &request).expect("disconnect can be acked")
                )
            }
            _ => Err(UnrealscriptAdapterError::UnhandledCommandError(
                request.command.name().to_string(),
            )),
        };

        match response {
            Ok(body) => Ok(Response::make_success(ctx.next_seq(), &request, body)),
            Err(e) => Ok(Response::make_error(
                ctx.next_seq(),
                &request,
                e.to_error_message(),
            )),
        }
    }
}

impl UnrealscriptAdapter {
    /// Handle an initialize request
    fn initialize(
        &mut self,
        args: &InitializeArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        // If the client sends linesStartAt1: false then we need to adjust
        // all the line numbers we receive.
        if let Some(false) = args.lines_start_at1 {
            self.one_based_lines = false;
        }

        Ok(ResponseBody::Initialize(Some(Capabilities {
            supports_configuration_done_request: Some(true),
            supports_delayed_stack_trace_loading: Some(true),
            supports_value_formatting_options: Some(true),
            ..Default::default()
        })))
    }

    /// Handle a setBreakpoints request
    fn set_breakpoints(
        &mut self,
        args: &SetBreakpointsArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        log::info!("Set breakpoints request");

        // If we are not connected we cannot proceed
        if self.channel.is_none() {
            return Err(UnrealscriptAdapterError::NotConnected);
        }
        // Break the source file out into sections and record it in our map of
        // known classes if necessary.
        let path = args
            .source
            .path
            .as_ref()
            .expect("Clients should provide sources as paths");
        let class_info =
            ClassInfo::make(path.to_string()).or(Err(Error::InvalidFilename(path.to_string())))?;
        let mut qualified_class_name = class_info.qualify();
        qualified_class_name.make_ascii_uppercase();
        let class_info = self
            .class_map
            .entry(qualified_class_name.clone())
            .or_insert(class_info);
        // Remove all the existing breakpoints from this class.
        for bp in class_info.breakpoints.iter() {
            let removed = self
                .channel
                .as_mut()
                .unwrap()
                .remove_breakpoint(Breakpoint::new(&qualified_class_name, *bp));
            assert!(removed.line == *bp);
        }

        class_info.breakpoints.clear();

        let mut dap_breakpoints: Vec<dap::types::Breakpoint> = Vec::new();

        // Now add the new ones (if any)
        if let Some(breakpoints) = &args.breakpoints {
            for bp in breakpoints {
                // Note that Unreal only accepts 32-bit lines.
                if let Ok(mut line) = bp.line.try_into() {
                    // The line number received may require adjustment
                    line += if self.one_based_lines { 0 } else { 1 };

                    let new_bp = self
                        .channel
                        .as_mut()
                        .unwrap()
                        .add_breakpoint(Breakpoint::new(&qualified_class_name, line));

                    // Record this breakpoint in our data structure
                    class_info.breakpoints.push(new_bp.line);

                    // Record it in the response
                    dap_breakpoints.push(dap::types::Breakpoint {
                        verified: true,
                        // Line number may require adjustment before sending back out to the
                        // client.
                        line: Some(
                            (new_bp.line + if self.one_based_lines { 0 } else { -1 }).into(),
                        ),
                        source: Some(Source {
                            path: Some(path.to_string()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    });
                }
            }
        }

        Ok(ResponseBody::SetBreakpoints(
            responses::SetBreakpointsResponse {
                breakpoints: dap_breakpoints,
            },
        ))
    }

    /// Handle a threads request
    fn threads(&mut self) -> Result<ResponseBody, UnrealscriptAdapterError> {
        log::info!("Threads request");
        Ok(ResponseBody::Threads(responses::ThreadsResponse {
            threads: vec![Thread {
                id: 1,
                name: "main".to_string(),
            }],
        }))
    }

    // Extract the port number from an attach arguments value map.
    fn extract_port(value: &Option<Value>) -> Option<i32> {
        value.as_ref()?
        ["port"]
        .as_i64()?
        .try_into()
        .ok()
    }

    /// Attach to a running unreal process
    fn attach(
        &mut self,
        args: &AttachRequestArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        log::info!("Attach request");

        let port = Self::extract_port(&args.other).unwrap_or(DEFAULT_PORT);
        // Connect to the unrealscript interface and set up the communications channel between
        // it and this adapter.
        self.channel = Some(comm::connect(port).or(Err(UnrealscriptAdapterError::ConnectionError))?);
        
        Ok(ResponseBody::Attach)
    }
}

/// Information about a class.
#[derive(Debug)]
pub struct ClassInfo {
    pub file_name: String,
    pub package_name: String,
    pub class_name: String,
    pub breakpoints: Vec<i32>,
}

/// The filename does not conform to the Unreal path conventions for class naming.
#[derive(Debug)]
pub struct BadFilenameError;

impl ClassInfo {
    pub fn make(file_name: String) -> Result<ClassInfo, BadFilenameError> {
        let (package_name, class_name) = split_source(&file_name)?;
        Ok(ClassInfo {
            file_name,
            package_name,
            class_name,
            breakpoints: Vec::new(),
        })
    }

    /// Return a string containing a qualified classname: "package.class"
    pub fn qualify(&self) -> String {
        format!("{}.{}", self.package_name, self.class_name)
    }
}

/// Process a Source entry to obtain information about a class.
///
/// For Unrealscript the details of a class can be determined from its source file.
/// Given a Source entry with a full path to a source file we expect the path to always
/// be of the form:
///
/// <arbitrary leading directories>\Src\PackageName\Classes\ClassName.uc
///
/// From a path of this form we can isolate the package and class names. This naming
/// scheme is mandatory: the Unreal debugger only talks about package and class names,
/// and the client only talks about source files. The Unrealscript compiler uses these
/// same conventions.
pub fn split_source(path_str: &str) -> Result<(String, String), BadFilenameError> {
    let path = Path::new(&path_str);
    let mut iter = path.components().rev();

    // Isolate the filename. This is the last component of the path and should have an extension to
    // strip.
    let component = iter.next().ok_or(BadFilenameError)?;
    let class_name = match component {
        Component::Normal(file_name) => Path::new(file_name).file_stem().ok_or(BadFilenameError),
        _ => Err(BadFilenameError),
    }?
    .to_str()
    .expect("Source path should be valid utf-8")
    .to_owned();

    // Skip the parent
    iter.next();

    // the package name should be the next component.
    let component = iter.next().ok_or(BadFilenameError)?;
    let package_name = match component {
        Component::Normal(file_name) => Ok(file_name),
        _ => Err(BadFilenameError),
    }?
    .to_str()
    .expect("Source path should be vaild utf-8")
    .to_owned();
    Ok((package_name, class_name))
}

#[cfg(test)]
mod tests {
    use dap::types::Source;

    use super::*;

    struct MockChannel;

    impl UnrealChannel for MockChannel {
        fn add_breakpoint(&mut self, bp: Breakpoint) -> Breakpoint {
            bp
        }
        fn remove_breakpoint(&mut self, bp: Breakpoint) -> Breakpoint {
            bp
        }
    }

    const GOOD_PATH: &str = if cfg!(windows) {
            "C:\\foo\\src\\MyPackage\\classes\\SomeClass.uc"
        } else {
            "/home/somebody/src/MyPackage/classes/SomeClass.uc"
        };

    #[test]
    fn can_split_source() {
        let (package, class) =
            split_source(GOOD_PATH).unwrap();
        assert_eq!(package, "MyPackage");
        assert_eq!(class, "SomeClass");
    }

    #[test]
    fn split_source_bad_classname() {
        let path = if cfg!(windows) {
            "C:\\MyMod\\BadClass.uc"
        } else {
            "/MyMod/BadClass.uc"
        };
        let info = split_source(path);
        assert!(matches!(info, Err(BadFilenameError)));
    }

    #[test]
    fn split_source_forward_slashes() {
        let (package, class) = split_source(GOOD_PATH).unwrap();
        assert_eq!(package, "MyPackage");
        assert_eq!(class, "SomeClass");
    }

    #[test]
    fn qualify_name() {
        let class = ClassInfo::make(GOOD_PATH.to_string()).unwrap();
        let qual = class.qualify();
        assert_eq!(qual, "MyPackage.SomeClass")
    }

    #[test]
    #[allow(deprecated)]
    fn add_breakpoint_registers_class() {
        let mut adapter = UnrealscriptAdapter::new();
        adapter.channel = Some(Box::new(MockChannel{}));
        let args = SetBreakpointsArguments {
            source: Source {
                name: None,
                path: Some(GOOD_PATH.to_string()),
                source_reference: None,
                presentation_hint: None,
                origin: None,
                sources: None,
                adapter_data: None,
                checksums: None,
            },
            lines: None,
            breakpoints: None,
            source_modified: None,
        };
        let _response = adapter.set_breakpoints(&args).unwrap();
        // Class cache should be keyed on UPCASED qualified names.
        assert!(adapter.class_map.contains_key("MYPACKAGE.SOMECLASS"));
    }
}
