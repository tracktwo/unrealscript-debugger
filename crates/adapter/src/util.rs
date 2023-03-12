use std::path::{Component, Path};

/// The filename does not conform to the Unreal path conventions for class naming.
#[derive(Debug)]
pub struct BadFilenameError;

/// Process a Source entry to obtain information about a class.
///
/// For Unrealscript the details of a class can be determined from its source file.
/// Given a Source entry with a full path to a source file we expect the path to always
/// be of the form:
///
/// &lt;arbitrary leading directories&gt;\Src\PackageName\Classes\ClassName.uc
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
    use super::*;

    const GOOD_PATH: &str = if cfg!(windows) {
        "C:\\foo\\src\\MyPackage\\classes\\SomeClass.uc"
    } else {
        "/home/somebody/src/MyPackage/classes/SomeClass.uc"
    };

    #[test]
    fn can_split_source() {
        let (package, class) = split_source(GOOD_PATH).unwrap();
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
}
