use std::{
    collections::BTreeMap,
    path::{Component, Path},
};

use dap::{
    prelude::*,
    requests::{InitializeArguments, SetBreakpointsArguments},
    responses::ErrorMessage,
    types::Capabilities,
};
use thiserror::Error;

pub struct UnrealscriptAdapter {
    class_map: BTreeMap<String, ClassInfo>,
}

impl UnrealscriptAdapter {
    pub fn new() -> UnrealscriptAdapter {
        UnrealscriptAdapter {
            class_map: BTreeMap::new(),
        }
    }
}

#[derive(Error, Debug)]
pub enum UnrealscriptAdapterError {
    #[error("Unhandled command: {0}")]
    UnhandledCommandError(String),

    #[error("Invalid filename: {0}")]
    InvalidFilename(String),
}

impl UnrealscriptAdapterError {
    fn id(&self) -> i64 {
        match self {
            UnrealscriptAdapterError::UnhandledCommandError(_) => 1,
            UnrealscriptAdapterError::InvalidFilename(_) => 2,
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
            Command::Attach(_) => {
                return Ok(
                    Response::make_ack(ctx.next_seq(), &request).expect("attach can be acked")
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
    fn initialize(
        &self,
        _args: &InitializeArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        Ok(ResponseBody::Initialize(Some(Capabilities {
            supports_configuration_done_request: Some(true),
            supports_delayed_stack_trace_loading: Some(true),
            supports_value_formatting_options: Some(true),
            ..Default::default()
        })))
    }

    fn set_breakpoints(
        &mut self,
        args: &SetBreakpointsArguments,
    ) -> Result<ResponseBody, UnrealscriptAdapterError> {
        log::info!("Set breakpoints request");

        // Break the source file out into sections and record it in our map of
        // known classes if necessary.
        let path = args
            .source
            .path
            .as_ref()
            .expect("Clients should provide sources as paths");
        let class_info = split_source(path)?;
        let mut class_name = class_info.qualify();
        class_name.make_ascii_uppercase();
        self.class_map.entry(class_name).or_insert(class_info);

        if let Some(breakpoints) = &args.breakpoints {
            for _bp in breakpoints {
                // Ask the debugger to set each breapoint in turn, and wait for the corresponding
                // response message to be delivered.
            }
        }
        Err(UnrealscriptAdapterError::UnhandledCommandError(
            "setBreakpoints".to_string(),
        ))
    }
}

/// Information about a class.
#[derive(Debug)]
pub struct ClassInfo {
    pub file_name: String,
    pub package_name: String,
    pub class_name: String,
}

impl ClassInfo {
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
pub fn split_source(path_str: &str) -> Result<ClassInfo, UnrealscriptAdapterError> {
    let path = Path::new(&path_str);
    let mut iter = path.components().rev();

    // Isolate the filename. This is the last component of the path and should have an extension to
    // strip.
    let component = iter.next().ok_or(Error::InvalidFilename(format!(
        "Path {path_str} is missing a filename"
    )))?;
    let class_name = match component {
        Component::Normal(file_name) => {
            Path::new(file_name)
                .file_stem()
                .ok_or(Error::InvalidFilename(format!(
                    "Path {path_str} is missing an extension"
                )))
        }
        _ => Err(Error::InvalidFilename(format!(
            "Path {path_str} is missing a filename"
        ))),
    }?
    .to_str()
    .expect("Source path should be valid utf-8")
    .to_owned();

    // Skip the parent
    iter.next();

    // the package name should be the next component.
    let component = iter.next().ok_or(Error::InvalidFilename(format!(
        "Path {path_str} has no package"
    )))?;
    let package_name = match component {
        Component::Normal(file_name) => Ok(file_name),
        _ => Err(Error::InvalidFilename(format!(
            "Path {path_str} is missing a filename"
        ))),
    }?
    .to_str()
    .expect("Source path should be vaild utf-8")
    .to_owned();
    Ok(ClassInfo {
        file_name: path_str.to_owned(),
        package_name,
        class_name,
    })
}

#[cfg(test)]
mod tests {
    use dap::types::Source;

    use super::*;

    #[test]
    fn can_split_source() {
        let info = split_source("C:\\foo\\src\\MyPackage\\classes\\SomeClass.uc").unwrap();
        assert_eq!(info.class_name, "SomeClass");
        assert_eq!(info.package_name, "MyPackage");
    }

    #[test]
    fn split_source_bad_classname() {
        let info = split_source("C:\\MyMod\\BadClass.uc");
        assert!(matches!(
            info,
            Err(UnrealscriptAdapterError::InvalidFilename(_))
        ));
    }

    #[test]
    fn split_source_forward_slashes() {
        let info = split_source("C:/foo/src/MyPackage/classes/SomeClass.uc").unwrap();
        assert_eq!(info.class_name, "SomeClass");
        assert_eq!(info.package_name, "MyPackage");
    }

    #[test]
    #[allow(deprecated)]
    fn add_breakpoint_registers_class() {
        let mut adapter = UnrealscriptAdapter::new();
        let args = SetBreakpointsArguments {
            source: Source {
                name: None,
                path: Some("C:\\Projects\\Src\\SomePackage\\Classes\\Classname.uc".to_string()),
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
        let _response = adapter.set_breakpoints(&args);
        // Class cache should be keyed on UPCASED qualified names.
        assert!(adapter.class_map.contains_key("SOMEPACKAGE.CLASSNAME"));
    }

    #[test]
    fn qualify_name() {
        let class = ClassInfo {
            package_name: "package".to_string(),
            file_name: "C:\\foo\\src\\package\\classes\\cls.uc".to_string(),
            class_name: "cls".to_string(),
        };
        let qual = class.qualify();
        assert_eq!(qual, "package.cls")
    }
}
