use super::*;

pub(crate) fn temporary_download_file(
    destination: &Path,
) -> std::io::Result<tempfile::NamedTempFile> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    tempfile::Builder::new()
        .prefix(".hubuum-download-")
        .tempfile_in(parent)
}

pub(crate) fn persist_download_file(
    temporary: tempfile::NamedTempFile,
    destination: &Path,
) -> std::io::Result<()> {
    temporary
        .persist(destination)
        .map(drop)
        .map_err(|error| error.error)
}
