#![forbid(unsafe_code)]

mod generate;
mod openapi_contract;

use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

const SPEC_DIRECTORY: &str = "hubuum_reconcile/specs";
const OUTPUT_DIRECTORY: &str = "src/resources/generated";
const RESOURCE_SPECS: &[&str] = &[
    "class",
    "collection",
    "export_template",
    "group",
    "object",
    "service_account",
    "user",
];

type DynError = Box<dyn std::error::Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Check,
    Update,
}

fn main() -> Result<(), DynError> {
    let mode = parse_mode(env::args().skip(1))?;
    reconcile(mode)
}

fn reconcile(mode: Mode) -> Result<(), DynError> {
    let root = repository_root()?;
    openapi_contract::check(&root)?;
    let mut stale = Vec::new();
    let mut updated = 0;

    for name in RESOURCE_SPECS {
        let spec_path = root.join(SPEC_DIRECTORY).join(format!("{name}.rs"));
        let output_path = root.join(OUTPUT_DIRECTORY).join(format!("{name}.rs"));
        let generated = generate::generate_file(&spec_path)?;
        let current = read_existing_output(&output_path)?;

        match mode {
            Mode::Check if current.as_deref() != Some(&generated) => stale.push(output_path),
            Mode::Update if current.as_deref() != Some(&generated) => {
                let parent = output_path
                    .parent()
                    .ok_or("generated output has no parent")?;
                fs::create_dir_all(parent)?;
                fs::write(&output_path, generated)?;
                println!("updated {}", display_path(&root, &output_path));
                updated += 1;
            }
            Mode::Check | Mode::Update => {}
        }
    }

    if !stale.is_empty() {
        for path in stale {
            eprintln!("stale: {}", display_path(&root, &path));
        }
        return Err(
            "generated resource code is stale; run `cargo run -p hubuum_reconcile -- update`"
                .into(),
        );
    }

    match mode {
        Mode::Check => println!("generated resource code is current"),
        Mode::Update if updated == 0 => println!("generated resource code is already current"),
        Mode::Update => {}
    }
    Ok(())
}

fn parse_mode(args: impl IntoIterator<Item = String>) -> Result<Mode, DynError> {
    let mut args = args.into_iter();
    let mode = match args.next().as_deref() {
        Some("check") => Mode::Check,
        Some("update") => Mode::Update,
        Some(other) => {
            return Err(format!("unknown mode `{other}`; use `check` or `update`").into());
        }
        None => return Err("missing mode; use `check` or `update`".into()),
    };
    if args.next().is_some() {
        return Err("expected exactly one mode: `check` or `update`".into());
    }
    Ok(mode)
}

fn read_existing_output(path: &Path) -> io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn repository_root() -> Result<PathBuf, DynError> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "hubuum_reconcile must live directly below the repository root".into())
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{Mode, parse_mode};

    #[test]
    fn parses_supported_modes() {
        assert_eq!(parse_mode(["check".to_owned()]).unwrap(), Mode::Check);
        assert_eq!(parse_mode(["update".to_owned()]).unwrap(), Mode::Update);
    }

    #[test]
    fn rejects_missing_mode() {
        let missing = parse_mode([]).unwrap_err();
        assert!(missing.to_string().contains("missing mode"));
    }

    #[test]
    fn rejects_unknown_mode() {
        let unknown = parse_mode(["generate".to_owned()]).unwrap_err();
        assert!(unknown.to_string().contains("unknown mode `generate`"));
    }

    #[test]
    fn rejects_extra_arguments() {
        let extra = parse_mode(["check".to_owned(), "extra".to_owned()]).unwrap_err();
        assert!(extra.to_string().contains("exactly one mode"));
    }
}
